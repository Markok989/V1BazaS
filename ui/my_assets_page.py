# FILENAME: ui/my_assets_page.py
# (FILENAME: ui/my_assets_page.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/my_assets_page.py

Moja oprema (MY scope):
- Lista sredstava koja korisnik trenutno duži
- Pretraga + dvoklik otvara AssetDetailDialog
- Metrologija: status + važi do (za sredstva koja korisnik duži)
- Metrologija: dugme / dvoklik otvara listu metrologija zapisa za sredstvo
- Ctrl+C kopiranje selekcije (TSV) + header copy fallback

Napomena:
- UI RBAC gating je fail-closed (ako can() ne radi -> tretira se kao "nema prava")
- Service-level RBAC ostaje glavni autoritet.

FIX (2026-02-08):
- _connect_db koristi core.db.db_conn() (uvek zatvara konekciju) i core.db.get_db_path()
  da izbegnemo curenje konekcija i “database is locked” + scenario “dve baze”.

FIX (2026-02-09):
- _load_my_assets_fallback: MY filter se pomera u SQL (WHERE holder matches me) pre LIMIT-a,
  da ne bi ispao scenario kad asset nije u prvih N redova zbog ORDER BY (smoke_test v4).
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from datetime import date
from typing import List, Dict, Any, Tuple, Set

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QAbstractItemView,
    QComboBox,
    QDialog,
    QMenu,
)

# MY assets: prefer dedicated MY service (ako postoji), inače dashboard_service
try:
    from services.my_assets_service import list_my_assets as _list_my_assets_service  # type: ignore
except Exception:  # pragma: no cover
    try:
        from services.dashboard_service import list_my_assets as _list_my_assets_service  # type: ignore
    except Exception:  # pragma: no cover
        _list_my_assets_service = None  # type: ignore

from services.metrology_service import list_metrology_records_for_asset  # service-level RBAC

from ui.utils.datetime_fmt import fmt_dt_sr, fmt_date_sr
from ui.utils.table_copy import (
    wire_table_selection_plus_copy,
    wire_table_header_plus_copy,
    copy_selected_cells,
)

# -------------------- RBAC helpers (UI-level, fail-closed) --------------------
try:
    from core.rbac import PERM_METRO_VIEW, PERM_ASSETS_MY_VIEW  # type: ignore
except Exception:  # pragma: no cover
    PERM_METRO_VIEW = "metrology.view"
    PERM_ASSETS_MY_VIEW = "assets.my.view"


def _can(perm: str) -> bool:
    """
    UI nivo: FAIL-CLOSED.
    Ako session.can() pukne ili nije dostupno -> False.
    """
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _actor_name_safe() -> str:
    try:
        from core.session import actor_name  # type: ignore
        return (actor_name() or "user").strip() or "user"
    except Exception:
        import os
        return (os.environ.get("USERNAME") or os.environ.get("USER") or "user").strip() or "user"


def _actor_key_safe() -> str:
    try:
        from core.session import actor_key  # type: ignore
        return (actor_key() or "").strip()
    except Exception:
        return ""


def _get_current_user_dict() -> Dict[str, Any]:
    try:
        from core.session import get_current_user  # type: ignore
        return dict(get_current_user() or {})
    except Exception:
        return {}


def _copy_text_to_clipboard(text: str) -> None:
    try:
        from PySide6.QtWidgets import QApplication  # type: ignore
        cb = QApplication.clipboard()
        cb.setText(text or "")
    except Exception:
        pass


def _wire_table_selection_plus_copy(table: QTableWidget) -> None:
    """
    Standard ponašanje:
    - selekcija ćelija + multi-select
    - Ctrl+C kopira selekciju kao TSV
    - fallback: header copy (ako helper nije dostupan)
    """
    try:
        table.setSelectionBehavior(QAbstractItemView.SelectItems)
        table.setSelectionMode(QAbstractItemView.ExtendedSelection)
    except Exception:
        pass

    try:
        wire_table_selection_plus_copy(table)
        return
    except Exception:
        pass

    try:
        wire_table_header_plus_copy(table)
    except Exception:
        pass


# -------------------- DB helpers (SQL fallback za MY scope) --------------------
def _db_path_str() -> str:
    """
    Jedna istina: koristi core.db.get_db_path() (koji resolve-uje apsolutno i pravi folder).
    """
    try:
        from core.db import get_db_path  # type: ignore
        p = str(get_db_path() or "").strip()
        return p
    except Exception:
        # ultra fallback
        return "data/db/bazas2.sqlite"


@contextmanager
def _connect_db():
    """
    Prefer core.db.db_conn() (uvek zatvara konekciju), fallback na direktan sqlite connect.
    """
    # 1) Prefer db_conn (najstabilnije)
    try:
        from core.db import db_conn  # type: ignore
        with db_conn() as conn:
            try:
                conn.row_factory = sqlite3.Row
            except Exception:
                pass
            yield conn
            return
    except Exception:
        pass

    # 2) Fallback: direktan connect (ali zatvaramo u finally)
    db_path = _db_path_str()
    try:
        conn = sqlite3.connect(db_path)
    except Exception:
        # poslednji fallback
        conn = sqlite3.connect("baza.db")

    try:
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute("PRAGMA busy_timeout=2500;")
        except Exception:
            pass
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    try:
        r = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
            (name,),
        ).fetchone()
        return bool(r)
    except Exception:
        return False


def _table_columns(conn: sqlite3.Connection, name: str) -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({name});").fetchall()
        out: List[str] = []
        for r in rows:
            try:
                out.append(str(r["name"]))
            except Exception:
                out.append(str(r[1]))
        return out
    except Exception:
        return []


def _pick_first_existing(cols: List[str], candidates: List[str]) -> str:
    s = set(cols or [])
    for c in candidates:
        if c in s:
            return c
    return ""


def _norm(s: Any) -> str:
    return ("" if s is None else str(s)).strip().casefold()


def _identity_candidates() -> List[str]:
    """
    Tolerantni identiteti za match sa holder-om u assets:
    - actor_key / actor_name
    - username/login/email/display_name/name
    - id/user_id/uid
    """
    u = _get_current_user_dict()
    cand: List[str] = []

    ak = _actor_key_safe()
    if ak:
        cand.append(ak)

    an = _actor_name_safe()
    if an:
        cand.append(an)

    for k in ("username", "login", "email", "display_name", "name", "full_name", "user"):
        v = u.get(k)
        if v:
            cand.append(str(v))

    for k in ("id", "user_id", "uid"):
        v = u.get(k)
        if v is not None and str(v).strip():
            cand.append(str(v).strip())

    out: List[str] = []
    seen: Set[str] = set()
    for c in cand:
        cc = _norm(c)
        if cc and cc not in seen:
            seen.add(cc)
            out.append(cc)
    return out


def _load_my_assets_fallback(limit: int = 2000) -> List[Dict[str, Any]]:
    """
    Fallback bez service-a ili kad service puca.
    Čita direktno assets tabelu i filtrira MY scope.

    FIX 2026-02-09:
    - MY filter ide u SQL (WHERE) pre LIMIT-a, da ne propadne kada asset nije u prvih N redova.
    """
    lim = int(limit or 0)
    if lim <= 0:
        lim = 2000

    with _connect_db() as conn:
        if not _table_exists(conn, "assets"):
            return []

        cols = _table_columns(conn, "assets")
        if not cols:
            return []

        col_uid = _pick_first_existing(cols, ["asset_uid", "uid"])
        col_name = _pick_first_existing(cols, ["name", "naziv", "asset_name"])
        col_cat = _pick_first_existing(cols, ["category", "kategorija", "cat"])
        col_status = _pick_first_existing(cols, ["status", "state"])
        col_loc = _pick_first_existing(cols, ["location", "lokacija", "loc"])
        col_holder = _pick_first_existing(cols, ["current_holder", "assigned_to", "holder", "zaduzeno_kod", "kod_koga"])
        col_assigned_at = _pick_first_existing(cols, ["last_assigned_at", "assigned_at", "zaduzeno_od", "assigned_time"])
        col_updated = _pick_first_existing(cols, ["updated_at", "modified_at", "updated", "last_update"])

        if not col_uid or not col_holder:
            return []

        select_cols = [col_uid, col_holder]
        for c in [col_name, col_cat, col_status, col_loc, col_assigned_at, col_updated]:
            if c and c not in select_cols:
                select_cols.append(c)

        order_col = col_assigned_at or col_updated or col_uid

        # ✅ MY filter u SQL (pre LIMIT-a)
        cands = _identity_candidates()
        where_sql = ""
        params: List[Any] = []
        if cands:
            conds: List[str] = []
            # exact match
            for c in cands:
                conds.append(f"lower(COALESCE({col_holder}, '')) = ?")
                params.append(c)
            # tolerant contains match (npr "Basic User (3)")
            for c in cands:
                conds.append(f"lower(COALESCE({col_holder}, '')) LIKE ?")
                params.append(f"%{c}%")
            where_sql = "WHERE (" + " OR ".join(conds) + ")"

        sql = f"""
            SELECT {", ".join(select_cols)}
            FROM assets
            {where_sql}
            ORDER BY COALESCE({order_col}, '') DESC
            LIMIT ?;
        """
        params.append(lim)

        try:
            rows = conn.execute(sql, tuple(params)).fetchall()
        except Exception:
            return []

        out: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            item = {
                "asset_uid": str(d.get(col_uid, "") or "").strip(),
                "name": str(d.get(col_name, "") or "").strip() if col_name else "",
                "category": str(d.get(col_cat, "") or "").strip() if col_cat else "",
                "status": str(d.get(col_status, "") or "").strip() if col_status else "",
                "location": str(d.get(col_loc, "") or "").strip() if col_loc else "",
                "last_assigned_at": str(
                    d.get(col_assigned_at, "") if col_assigned_at else (d.get(col_updated, "") if col_updated else "")
                ).strip(),
            }
            if item["asset_uid"]:
                out.append(item)

        return out


# -------------------- Metrology helpers (summary/latest) --------------------
def _met_status(valid_until_iso: str, warn_days: int) -> str:
    vu = (valid_until_iso or "").strip()
    if not vu:
        return "NEPOZNATO"
    try:
        y, m, d = [int(x) for x in vu.split("-")]
        vu_date = date(y, m, d)
    except Exception:
        return "NEPOZNATO"

    today = date.today()
    if vu_date < today:
        return "ISTEKLO"

    try:
        wd = int(warn_days)
    except Exception:
        wd = 30

    if (vu_date - today).days <= wd:
        return "ISTICE"
    return "OK"


def _load_metrology_latest_for_assets(asset_uids: List[str]) -> Dict[str, Tuple[str, str]]:
    """
    Vrati mapu:
      asset_uid -> (valid_until_iso, met_uid)

    Uzimamo zapis sa NAJVEĆIM valid_until (date DESC), pa updated_at DESC.
    Radi u chunk-ovima zbog SQLite limita varijabli (~999).
    """
    out: Dict[str, Tuple[str, str]] = {}
    uids = [u.strip() for u in (asset_uids or []) if (u or "").strip()]
    if not uids:
        return out

    try:
        from services.metrology_service import ensure_metrology_schema  # type: ignore
        ensure_metrology_schema()
    except Exception:
        pass

    CHUNK = 400

    with _connect_db() as conn:
        if not _table_exists(conn, "metrology_records"):
            return out

        for i in range(0, len(uids), CHUNK):
            part = uids[i:i + CHUNK]
            ph = ",".join(["?"] * len(part))

            sql = f"""
                SELECT asset_uid, met_uid, COALESCE(valid_until,'') AS valid_until, COALESCE(updated_at,'') AS updated_at
                FROM metrology_records
                WHERE is_deleted=0
                  AND COALESCE(valid_until,'') <> ''
                  AND asset_uid IN ({ph})
                ORDER BY asset_uid ASC, date(valid_until) DESC, datetime(updated_at) DESC;
            """
            rows = conn.execute(sql, tuple(part)).fetchall()

            for row in rows:
                try:
                    asset_uid = row["asset_uid"]
                    met_uid = row["met_uid"]
                    valid_until = row["valid_until"]
                except Exception:
                    asset_uid, met_uid, valid_until = row[0], row[1], row[2]

                au = (asset_uid or "").strip()
                if not au or au in out:
                    continue
                out[au] = ((valid_until or "").strip(), (met_uid or "").strip())

    return out


# -------------------- Metrology dialog for asset --------------------
class MetrologyForAssetDialog(QDialog):
    """
    Lista metrologija zapisa za jedno sredstvo (MY scope use-case).
    """
    COLS = ["Status", "Met UID", "Tip", "Datum", "Važi do", "Izvršilac/Lab", "Sertifikat", "Ažurirano"]

    def __init__(self, asset_uid: str, warn_days: int = 30, parent=None):
        super().__init__(parent)
        self.asset_uid = (asset_uid or "").strip()
        self.warn_days = int(warn_days or 30)

        self.setWindowTitle(f"Metrologija — {self.asset_uid}")
        self.resize(980, 520)

        top = QHBoxLayout()
        self.lbl = QLabel(f"Sredstvo: <b>{self.asset_uid}</b>")
        top.addWidget(self.lbl)
        top.addStretch(1)

        self.btn_close = QPushButton("Zatvori")
        top.addWidget(self.btn_close)

        self.tbl = QTableWidget(0, len(self.COLS))
        self.tbl.setHorizontalHeaderLabels(self.COLS)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.horizontalHeader().setStretchLastSection(True)

        _wire_table_selection_plus_copy(self.tbl)

        self.tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tbl.customContextMenuRequested.connect(self._on_context_menu)

        main = QVBoxLayout(self)
        main.addLayout(top)
        main.addWidget(self.tbl, 1)

        self.btn_close.clicked.connect(self.reject)
        self.tbl.cellDoubleClicked.connect(self._open_met_details)

        self._load()

    def _selected_met_uid(self) -> str:
        r = self.tbl.currentRow()
        if r < 0:
            return ""
        it = self.tbl.item(r, 1)
        return it.text().strip() if it else ""

    def _on_context_menu(self, pos):
        try:
            it = self.tbl.itemAt(pos)
            if it is not None:
                self.tbl.setCurrentCell(it.row(), it.column())

            cur = self.tbl.currentItem()
            cell_text = cur.text() if cur else ""

            menu = QMenu(self)
            act_copy_cell = menu.addAction("Kopiraj ćeliju")
            act_copy_sel = menu.addAction("Kopiraj selekciju (TSV)")
            menu.addSeparator()

            met_uid = self._selected_met_uid()
            act_copy_met = menu.addAction("Kopiraj Met UID") if met_uid else None

            chosen = menu.exec(self.tbl.viewport().mapToGlobal(pos))
            if chosen == act_copy_cell:
                _copy_text_to_clipboard(cell_text)
            elif chosen == act_copy_sel:
                copy_selected_cells(self.tbl)
            elif act_copy_met is not None and chosen == act_copy_met:
                _copy_text_to_clipboard(met_uid)
        except Exception:
            pass

    def _open_met_details(self, r: int, c: int):
        met_uid = self._selected_met_uid()
        if not met_uid:
            return
        try:
            from ui.metrology_page import MetrologyDetailsDialog  # type: ignore
            dlg = MetrologyDetailsDialog(met_uid, parent=self, warn_days=self.warn_days)
            dlg.exec()
        except Exception as e:
            QMessageBox.information(self, "Info", f"Ne mogu da otvorim detalje metrologije.\n\n{e}")

    def _load(self):
        if not _can(PERM_METRO_VIEW):
            QMessageBox.information(self, "RBAC", "Nemaš pravo da vidiš metrologiju (metrology.view).")
            return

        try:
            rows = list_metrology_records_for_asset(self.asset_uid, warn_days=self.warn_days, limit=1000) or []
        except PermissionError as e:
            rows = []
            QMessageBox.information(self, "RBAC", f"Nemaš pravo.\n\n{e}")
        except Exception as e:
            rows = []
            QMessageBox.critical(self, "Greška", f"Ne mogu da učitam metrologiju.\n\n{e}")

        self.tbl.setRowCount(0)
        for rr in rows:
            i = self.tbl.rowCount()
            self.tbl.insertRow(i)
            vals = [
                rr.get("status", ""),
                rr.get("met_uid", ""),
                rr.get("calib_type", ""),
                fmt_date_sr(rr.get("calib_date", "") or ""),
                fmt_date_sr(rr.get("valid_until", "") or ""),
                rr.get("provider_name", "") or "",
                rr.get("cert_no", "") or "",
                fmt_dt_sr(rr.get("updated_at", "") or ""),
            ]
            for cc, v in enumerate(vals):
                self.tbl.setItem(i, cc, QTableWidgetItem(str(v)))


# -------------------- MyAssetsPage --------------------
class MyAssetsPage(QWidget):
    """
    Lista sredstava koja korisnik trenutno duži.
    Koristi se u:
    - BASIC UI (obavezan)
    - FULL UI (dodatno)
    - METRO UI (MY scope)
    """
    def __init__(self, logger: logging.Logger, parent=None):
        super().__init__(parent)
        self.logger = logger

        self._rows: List[Dict[str, Any]] = []
        self._met_latest: Dict[str, Tuple[str, str]] = {}  # asset_uid -> (valid_until_iso, met_uid)

        top = QHBoxLayout()
        title = QLabel("Moja oprema")
        title.setStyleSheet("font-size: 18px; font-weight: 600;")
        top.addWidget(title)
        top.addStretch(1)

        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("Pretraga (UID / naziv / kategorija / lokacija / status)...")
        self.ed_search.setClearButtonEnabled(True)
        self.ed_search.setFixedWidth(420)
        top.addWidget(self.ed_search)

        self.lbl_warn = QLabel("Met alarm (dana):")
        self.cb_warn = QComboBox()
        self.cb_warn.addItems(["7", "14", "30", "60", "90"])
        self.cb_warn.setCurrentText("30")

        self.btn_met = QPushButton("Metrologija")
        self.btn_met.setToolTip("Otvori metrologija zapise za izabrano sredstvo")

        can_metro_view = _can(PERM_METRO_VIEW)
        self.lbl_warn.setVisible(can_metro_view)
        self.cb_warn.setVisible(can_metro_view)
        self.btn_met.setVisible(can_metro_view)
        self.btn_met.setEnabled(False)

        top.addWidget(self.lbl_warn)
        top.addWidget(self.cb_warn)
        top.addWidget(self.btn_met)

        self.lbl_count = QLabel("")
        self.lbl_count.setStyleSheet("color: #666;")
        top.addWidget(self.lbl_count)

        self.btn_refresh = QPushButton("Osveži")
        top.addWidget(self.btn_refresh)

        self.tbl = QTableWidget(0, 8)
        self.tbl.setHorizontalHeaderLabels([
            "UID", "Naziv", "Kategorija", "Status", "Lokacija", "Zaduženo od", "Metrologija", "Važi do"
        ])
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.horizontalHeader().setStretchLastSection(True)

        _wire_table_selection_plus_copy(self.tbl)

        self.tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tbl.customContextMenuRequested.connect(self._on_context_menu)

        self.lbl_rbac = QLabel("")
        self.lbl_rbac.setStyleSheet("color: #a00;")
        self.lbl_rbac.setVisible(False)

        main = QVBoxLayout(self)
        main.addLayout(top)
        main.addWidget(self.lbl_rbac)
        main.addWidget(self.tbl, 1)

        self.btn_refresh.clicked.connect(self.refresh)
        self.ed_search.textChanged.connect(self._apply_filter)
        self.cb_warn.currentIndexChanged.connect(self._apply_filter)

        self.tbl.cellDoubleClicked.connect(self._on_double_click)
        self.tbl.itemSelectionChanged.connect(self._sync_buttons)
        self.btn_met.clicked.connect(self._open_metrology_for_selected)

        self._apply_rbac()
        self.refresh()

    def _apply_rbac(self) -> None:
        okk = _can(PERM_ASSETS_MY_VIEW)

        self.tbl.setEnabled(okk)
        self.ed_search.setEnabled(okk)
        self.btn_refresh.setEnabled(okk)
        if not okk:
            self.tbl.setRowCount(0)
            self.lbl_count.setText("")
            self.lbl_rbac.setText("RBAC: nemaš pravo za 'Moja oprema' (assets.my.view).")
            self.lbl_rbac.setVisible(True)
        else:
            self.lbl_rbac.setVisible(False)

        can_metro = _can(PERM_METRO_VIEW)
        self.lbl_warn.setVisible(okk and can_metro)
        self.cb_warn.setVisible(okk and can_metro)
        self.btn_met.setVisible(okk and can_metro)

    def _warn_days(self) -> int:
        try:
            return int(self.cb_warn.currentText())
        except Exception:
            return 30

    def _selected_asset_uid(self) -> str:
        row = self.tbl.currentRow()
        if row < 0:
            return ""
        it = self.tbl.item(row, 0)
        return it.text().strip() if it else ""

    def _sync_buttons(self) -> None:
        has_sel = self.tbl.currentRow() >= 0
        if self.btn_met.isVisible():
            self.btn_met.setEnabled(has_sel)

    def _on_double_click(self, r: int, c: int) -> None:
        if c in (6, 7) and _can(PERM_METRO_VIEW):
            self._open_metrology_for_selected()
            return
        self._open_detail()

    def _open_detail(self) -> None:
        try:
            asset_uid = self._selected_asset_uid()
            if not asset_uid:
                return
            from ui.asset_detail_dialog import AssetDetailDialog  # type: ignore
            dlg = AssetDetailDialog(asset_uid, self)
            dlg.exec()
        except Exception as e:
            QMessageBox.information(self, "Info", f"Ne mogu da otvorim detalje sredstva.\n\n{e}")

    def _open_metrology_for_selected(self) -> None:
        if not _can(PERM_METRO_VIEW):
            QMessageBox.information(self, "RBAC", "Nemaš pravo da vidiš metrologiju (metrology.view).")
            return
        asset_uid = self._selected_asset_uid()
        if not asset_uid:
            QMessageBox.information(self, "Info", "Prvo izaberi sredstvo u tabeli.")
            return
        try:
            dlg = MetrologyForAssetDialog(asset_uid, warn_days=self._warn_days(), parent=self)
            dlg.exec()
        except Exception as e:
            QMessageBox.information(self, "Info", f"Ne mogu da otvorim metrologiju za sredstvo.\n\n{e}")

    def _on_context_menu(self, pos):
        try:
            it = self.tbl.itemAt(pos)
            if it is not None:
                self.tbl.setCurrentCell(it.row(), it.column())

            cur = self.tbl.currentItem()
            cell_text = cur.text() if cur else ""

            menu = QMenu(self)
            act_copy_cell = menu.addAction("Kopiraj ćeliju")
            act_copy_sel = menu.addAction("Kopiraj selekciju (TSV)")
            menu.addSeparator()

            uid = self._selected_asset_uid()
            act_copy_uid = menu.addAction("Kopiraj UID") if uid else None

            menu.addSeparator()
            act_open_asset = menu.addAction("Otvori detalje sredstva") if uid else None
            act_open_metro = menu.addAction("Otvori metrologiju") if (uid and _can(PERM_METRO_VIEW)) else None

            chosen = menu.exec(self.tbl.viewport().mapToGlobal(pos))
            if chosen == act_copy_cell:
                _copy_text_to_clipboard(cell_text)
            elif chosen == act_copy_sel:
                copy_selected_cells(self.tbl)
            elif act_copy_uid is not None and chosen == act_copy_uid:
                _copy_text_to_clipboard(uid)
            elif act_open_asset is not None and chosen == act_open_asset:
                self._open_detail()
            elif act_open_metro is not None and chosen == act_open_metro:
                self._open_metrology_for_selected()
        except Exception:
            pass

    def refresh(self) -> None:
        if not _can(PERM_ASSETS_MY_VIEW):
            self._apply_rbac()
            return

        rows: List[Dict[str, Any]] = []

        if _list_my_assets_service is not None:
            try:
                rows = _list_my_assets_service(limit=2000) or []
            except TypeError:
                try:
                    rows = _list_my_assets_service(_actor_name_safe(), limit=2000) or []
                except Exception as e2:
                    try:
                        self.logger.warning(f"MyAssetsPage: list_my_assets(service) failed -> fallback SQL. err={e2}")
                    except Exception:
                        pass
                    rows = _load_my_assets_fallback(limit=2000)
            except Exception as e:
                try:
                    self.logger.warning(f"MyAssetsPage: list_my_assets(service) failed -> fallback SQL. err={e}")
                except Exception:
                    pass
                rows = _load_my_assets_fallback(limit=2000)
        else:
            rows = _load_my_assets_fallback(limit=2000)

        self._rows = rows or []

        if _can(PERM_METRO_VIEW):
            try:
                uids = [str(r.get("asset_uid", "") or "").strip() for r in (self._rows or [])]
                self._met_latest = _load_metrology_latest_for_assets(uids)
            except Exception:
                self._met_latest = {}
        else:
            self._met_latest = {}

        self._apply_filter()

    def _apply_filter(self) -> None:
        q = (self.ed_search.text() or "").strip().lower()
        warn_days = self._warn_days()

        def ok_row(rr: Dict[str, Any]) -> bool:
            if not q:
                return True
            s = " ".join(
                [
                    str(rr.get("asset_uid", "")),
                    str(rr.get("name", "")),
                    str(rr.get("category", "")),
                    str(rr.get("location", "")),
                    str(rr.get("status", "")),
                ]
            ).lower()
            return q in s

        rows = [r for r in (self._rows or []) if ok_row(r)]

        can_metro_view = _can(PERM_METRO_VIEW)
        try:
            self.tbl.setColumnHidden(6, not can_metro_view)
            self.tbl.setColumnHidden(7, not can_metro_view)
        except Exception:
            pass

        try:
            self.tbl.setUpdatesEnabled(False)
            self.tbl.setRowCount(0)

            for rr in rows:
                i = self.tbl.rowCount()
                self.tbl.insertRow(i)

                asset_uid = str(rr.get("asset_uid", "") or "").strip()

                met_status = ""
                met_valid_until_iso = ""
                if can_metro_view and asset_uid:
                    tup = self._met_latest.get(asset_uid)
                    if tup:
                        met_valid_until_iso = tup[0]
                        met_status = _met_status(met_valid_until_iso, warn_days)
                    else:
                        met_status = "NEPOZNATO"
                        met_valid_until_iso = ""

                vals = [
                    asset_uid,
                    rr.get("name", "") or "",
                    rr.get("category", "") or "",
                    rr.get("status", "") or "",
                    rr.get("location", "") or "",
                    fmt_dt_sr(rr.get("last_assigned_at", "") or ""),
                    met_status if can_metro_view else "",
                    fmt_date_sr(met_valid_until_iso) if (can_metro_view and met_valid_until_iso) else "",
                ]

                for cc, v in enumerate(vals):
                    self.tbl.setItem(i, cc, QTableWidgetItem(str(v)))

        finally:
            try:
                self.tbl.setUpdatesEnabled(True)
            except Exception:
                pass

        try:
            self.lbl_count.setText(f"{len(rows)} / {len(self._rows or [])}")
        except Exception:
            pass

        self._sync_buttons()

# (FILENAME: ui/my_assets_page.py - END)
# END FILENAME: ui/my_assets_page.py