# FILENAME: ui/assignments_page.py
# (FILENAME: ui/assignments_page.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/assignments_page.py

Zaduženja (V1) — UI:
- Lista zaduženja + filteri (server pretraga / akcija)
- Novo zaduženje / prenos / razduženje
- Detalji (read-only)
- Demo seed (test)

RBAC (V1):
- assignments.view: pregled liste
- assignments.create: novo zaduženje
- assets.create: demo seed (jer kreira sredstva)

STANDARD tabela (V1.x):
- ✅ Rb (#) kao prva kolona
- ✅ Sortiranje klikom na header (ON)
- ✅ Drag&Drop kolona po headeru (perzistira preko wire_columns)
- ✅ Kolone dijalog + perzistencija (wire_columns)
- ✅ Ctrl+C TSV (wire_table_header_plus_copy)
- ✅ Users-style filter bar (TableToolsBar) — client-side hideRow filter
- ✅ Renumeracija posle sortiranja i posle filtera
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QComboBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QDialog,
    QFormLayout,
    QDialogButtonBox,
    QPlainTextEdit,
    QGroupBox,
    QAbstractItemView,
)

from core.session import actor_name, can
from core.rbac import PERM_ASSIGN_VIEW, PERM_ASSIGN_CREATE, PERM_ASSETS_CREATE

from services.assets_service import create_asset, list_assets_brief
from services.assignments_service import create_assignment, list_assignments

from ui.columns_dialog import ColSpec
from ui.utils.datetime_fmt import fmt_dt_sr
from ui.utils.table_columns import wire_columns
from ui.utils.table_copy import wire_table_header_plus_copy

# Users-style filter bar (optional)
try:
    from ui.utils.table_search_sort import TableToolsBar, TableToolsConfig  # type: ignore
except Exception:  # pragma: no cover
    TableToolsBar = None  # type: ignore
    TableToolsConfig = None  # type: ignore

# Optional: sector-scoped user listing (service-side RBAC should enforce scope!)
try:
    from services.users_service import list_users_for_assignment  # type: ignore
except Exception:  # pragma: no cover
    list_users_for_assignment = None  # type: ignore


# -------------------- UI helpers --------------------
def _actor() -> str:
    try:
        return actor_name() or ""
    except Exception:
        return ""


def _safe_can(perm: str) -> bool:
    """
    FAIL-CLOSED: ako session/can pukne, tretiramo kao da nema prava.
    """
    try:
        return bool(can(perm))
    except Exception:
        return False


def _info(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.information(parent, title, text)


def _warn(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.warning(parent, title, text)


def _err(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.critical(parent, title, text)


def _norm(s: Any, max_len: int = 300) -> str:
    t = "" if s is None else str(s)
    t = t.replace("\r", " ").replace("\n", " ").strip()
    return t[:max_len]


def _action_ui_to_service(action_ui: str) -> str:
    """
    "SVE" (UI) -> "" (bez filtera).
    """
    a = (action_ui or "").strip()
    if a.upper() == "SVE":
        return ""
    return a


# -------------------- Dialogs --------------------
class NewAssignmentDialog(QDialog):
    """
    Novi zapis zaduženja (assign/transfer/return).

    UX:
    - Asset izbor iz liste + opcija ručnog unosa UID
    - "Kome ide" ima: (1) izbor korisnika (ako servis podržava) + (2) ručni unos
      => tražio si "da ima jedno i drugo"
    - Inline status + popup validacije
    """

    def __init__(
        self,
        assets_brief: List[Dict[str, Any]],
        *,
        users_brief: Optional[List[Dict[str, Any]]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Novo zaduženje / prenos / razduženje")
        self.resize(620, 420)

        self.assets_brief = assets_brief or []
        self.users_brief = users_brief or []

        self.lb_inline = QLabel("")
        self.lb_inline.setWordWrap(True)
        self.lb_inline.hide()

        # --- Asset select ---
        self.cb_asset = QComboBox()
        self.cb_asset.setEditable(False)
        self.cb_asset.addItem("— RUČNI UNOS (upiši UID) —", "")
        for a in self.assets_brief:
            uid = _norm(a.get("asset_uid", ""), 80)
            name = _norm(a.get("name", ""), 80)
            cat = _norm(a.get("category", ""), 40)
            st = _norm(a.get("status", ""), 40)
            holder = _norm(a.get("current_holder", "") or "-", 80)
            label = f"{uid} | {name} | {cat} | {st} | kod: {holder}"
            self.cb_asset.addItem(label, uid)

        self.ed_asset_uid = QLineEdit()
        self.ed_asset_uid.setPlaceholderText("npr. A-2026-0000001")

        # --- Action ---
        self.cb_action = QComboBox()
        self.cb_action.addItems(["assign", "transfer", "return"])

        # --- To holder (picker + manual) ---
        self.cb_to_user = QComboBox()
        self.cb_to_user.setEditable(False)
        self.cb_to_user.addItem("— IZABERI KORISNIKA (opciono) —", "")
        for u in self.users_brief:
            un = _norm(u.get("username", ""), 60)
            dn = _norm(u.get("display_name", "") or u.get("name", ""), 120)
            sec = _norm(u.get("sector", ""), 60)
            if dn and un:
                label = f"{dn} ({un})" + (f" — {sec}" if sec else "")
            else:
                label = un or dn or "—"
            if un:
                self.cb_to_user.addItem(label, un)

        self.ed_to_holder = QLineEdit()
        self.ed_to_holder.setPlaceholderText("Ručni unos: kome ide (za assign/transfer)")

        self.ed_to_location = QLineEdit()
        self.ed_to_location.setPlaceholderText("Nova lokacija (opciono)")

        self.ed_note = QPlainTextEdit()
        self.ed_note.setPlaceholderText("Napomena (opciono)")

        # Layout
        lay = QVBoxLayout(self)
        lay.addWidget(self.lb_inline)

        box = QGroupBox("Unos")
        form = QFormLayout(box)
        form.addRow("Izaberi sredstvo:", self.cb_asset)
        form.addRow("Asset UID *:", self.ed_asset_uid)
        form.addRow("Akcija *:", self.cb_action)
        form.addRow("Kome ide (izbor):", self.cb_to_user)
        form.addRow("Kome ide (ručno):", self.ed_to_holder)
        form.addRow("Lokacija:", self.ed_to_location)
        form.addRow("Napomena:", self.ed_note)
        lay.addWidget(box, 1)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._on_ok)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

        # Signals
        self.cb_action.currentIndexChanged.connect(self._sync_ui)
        self.cb_asset.currentIndexChanged.connect(self._sync_asset_from_combo)
        self.cb_to_user.currentIndexChanged.connect(self._sync_user_to_manual)

        self._sync_ui()

    def _set_inline(self, text: str, *, kind: str = "info") -> None:
        t = _norm(text, 500)
        if not t:
            self.lb_inline.hide()
            self.lb_inline.setText("")
            return

        self.lb_inline.setText(t)
        self.lb_inline.show()
        if kind == "error":
            self.lb_inline.setStyleSheet(
                "padding:8px 10px; border-radius:10px;"
                "background:#3b1d1d; border:1px solid #a33; color:#fff; font-weight:700;"
            )
        elif kind == "warn":
            self.lb_inline.setStyleSheet(
                "padding:8px 10px; border-radius:10px;"
                "background:#2b2416; border:1px solid #c9a13b; color:#fff; font-weight:700;"
            )
        else:
            self.lb_inline.setStyleSheet(
                "padding:8px 10px; border-radius:10px;"
                "background:#16242b; border:1px solid #2f7f96; color:#fff; font-weight:650;"
            )

    def _sync_asset_from_combo(self) -> None:
        uid = self.cb_asset.currentData()
        if uid:
            self.ed_asset_uid.setText(str(uid))

    def _sync_user_to_manual(self) -> None:
        """
        Ako je korisnik izabran u combobox-u, prepiši u ručni unos (da korisnik vidi šta ide u bazu).
        Ne zaključavamo ručni unos — korisnik može i ručno da prepravi.
        """
        un = self.cb_to_user.currentData()
        if un:
            self.ed_to_holder.setText(str(un))

    def _sync_ui(self) -> None:
        act = (self.cb_action.currentText() or "").strip().lower()
        need_holder = act in ("assign", "transfer")

        self.cb_to_user.setEnabled(need_holder and self.cb_to_user.count() > 1)
        self.ed_to_holder.setEnabled(need_holder)
        if not need_holder:
            self.ed_to_holder.setText("")
            self.cb_to_user.setCurrentIndex(0)

        self._set_inline(
            "Tip: možeš izabrati korisnika iz liste ili uneti ručno. "
            "Ako lista korisnika nije dostupna (servis nije ažuriran), ručni unos radi normalno.",
            kind="info",
        )

    def _on_ok(self) -> None:
        uid = _norm(self.ed_asset_uid.text(), 80)
        if not uid:
            self._set_inline("Asset UID je obavezan.", kind="error")
            _warn(self, "Validacija", "Asset UID je obavezan.")
            return

        act = (self.cb_action.currentText() or "").strip().lower()
        if act in ("assign", "transfer"):
            to_holder = _norm(self.ed_to_holder.text(), 120)
            if not to_holder:
                self._set_inline("Za assign/transfer moraš uneti ili izabrati 'Kome ide'.", kind="error")
                _warn(self, "Validacija", "Za assign/transfer moraš uneti ili izabrati 'Kome ide'.")
                return

        self.accept()

    def values(self) -> Dict[str, str]:
        return {
            "asset_uid": _norm(self.ed_asset_uid.text(), 80),
            "action": _norm(self.cb_action.currentText(), 30),
            "to_holder": _norm(self.ed_to_holder.text(), 120),
            "to_location": _norm(self.ed_to_location.text(), 120),
            "note": _norm(self.ed_note.toPlainText(), 800),
        }


class _AssignmentDetailsDialog(QDialog):
    """Detalji zaduženja (V1) — read-only pregled (tekst selektabilan)."""

    def __init__(self, data: Dict[str, str], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Detalji zaduženja")
        self.resize(640, 360)

        def mk_label(txt: str) -> QLabel:
            lb = QLabel(txt or "")
            lb.setWordWrap(True)
            lb.setTextInteractionFlags(Qt.TextSelectableByMouse)
            return lb

        box = QGroupBox("Podaci")
        form = QFormLayout(box)
        form.addRow("Vreme:", mk_label(data.get("time", "")))
        form.addRow("Asset UID:", mk_label(data.get("asset_uid", "")))
        form.addRow("Naziv:", mk_label(data.get("asset_name", "")))
        form.addRow("Akcija:", mk_label(data.get("action", "")))
        form.addRow("Od:", mk_label(data.get("from_holder", "")))
        form.addRow("Ka:", mk_label(data.get("to_holder", "")))
        form.addRow("Lokacija:", mk_label(data.get("location", "")))
        form.addRow("Napomena:", mk_label(data.get("note", "")))

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(self.reject)
        btns.accepted.connect(self.accept)

        lay = QVBoxLayout(self)
        lay.addWidget(box, 1)
        lay.addWidget(btns)


# -------------------- Page --------------------
class AssignmentsPage(QWidget):
    # ✅ Rb (#) prva kolona
    COLS = ["#", "Vreme", "Asset UID", "Naziv", "Akcija", "Od", "Ka", "Lokacija", "Napomena"]

    def __init__(self, logger: logging.Logger, assets_page: Any, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.logger = logger
        self.assets_page = assets_page

        # Inline status (uz popup)
        self.lb_status = QLabel("")
        self.lb_status.setWordWrap(True)
        self.lb_status.hide()

        self.lb_rbac = QLabel("")
        self.lb_rbac.setWordWrap(True)
        self.lb_rbac.hide()

        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("Pretraga (server): UID / naziv / od / ka / napomena")

        self.cb_action = QComboBox()
        self.cb_action.addItems(["SVE", "assign", "transfer", "return"])

        self.btn_search = QPushButton("Pretraži")
        self.btn_refresh = QPushButton("Osveži")
        self.btn_columns = QPushButton("Kolone")
        self.btn_details = QPushButton("Detalji")
        self.btn_new = QPushButton("Novo zaduženje")
        self.btn_seed = QPushButton("Ubaci demo sredstva")

        self.btn_details.setEnabled(False)

        top = QHBoxLayout()
        top.addWidget(self.ed_search, 3)
        top.addWidget(self.btn_search)
        top.addWidget(QLabel("Akcija:"))
        top.addWidget(self.cb_action, 1)
        top.addWidget(self.btn_refresh)
        top.addWidget(self.btn_columns)
        top.addWidget(self.btn_details)
        top.addWidget(self.btn_new)
        top.addWidget(self.btn_seed)

        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)

        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(True)

        # ✅ FULL CONTROL + Ctrl+C TSV (STANDARD)
        self.table.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        wire_table_header_plus_copy(self.table)

        # ✅ Sort ON + header DnD (kolone)
        self.table.setSortingEnabled(True)
        hdr.setSortIndicatorShown(True)
        hdr.setSectionsClickable(True)
        hdr.setSectionsMovable(True)
        try:
            hdr.setDragEnabled(True)  # type: ignore[attr-defined]
        except Exception:
            pass

        lay = QVBoxLayout(self)
        lay.addLayout(top)

        # ✅ Users-style filter bar (client-side)
        self.tools = None
        if TableToolsBar is not None and TableToolsConfig is not None:
            try:
                cfg = TableToolsConfig(
                    placeholder="Brza pretraga u tabeli… (UID/naziv/od/ka/lokacija/napomena/vreme/akcija)",
                    show_sort_toggle=False,
                    default_sort_enabled=True,
                    filter_columns=None,
                )
                self.tools = TableToolsBar(self.table, cfg, parent=self)
                lay.addWidget(self.tools)
                self.tools.ed.textChanged.connect(lambda _t: self._renumber_rows_visible())
            except Exception:
                self.tools = None

        lay.addWidget(self.lb_status)
        lay.addWidget(self.lb_rbac)
        lay.addWidget(self.table, 1)

        # Signals
        self.btn_refresh.clicked.connect(self.load_assignments)
        self.btn_search.clicked.connect(self.load_assignments)
        self.btn_new.clicked.connect(self.new_assignment)
        self.btn_seed.clicked.connect(self.seed_demo)
        self.btn_details.clicked.connect(self.open_details)
        self.ed_search.returnPressed.connect(self.load_assignments)
        self.cb_action.currentIndexChanged.connect(self.load_assignments)

        self.table.itemSelectionChanged.connect(self._sync_buttons)
        self.table.cellDoubleClicked.connect(lambda _r, _c: self.open_details())

        # ✅ Renumeracija posle sortiranja
        try:
            hdr.sortIndicatorChanged.connect(lambda _i, _o: self._renumber_rows_visible())
        except Exception:
            pass

        specs = [
            ColSpec("rownum", "#", True, 60),
            ColSpec("time", "Vreme", True, 160),
            ColSpec("uid", "Asset UID", True, 160),
            ColSpec("name", "Naziv", True, 220),
            ColSpec("action", "Akcija", True, 120),
            ColSpec("from", "Od", True, 160),
            ColSpec("to", "Ka", True, 160),
            ColSpec("loc", "Lokacija", True, 160),
            ColSpec("note", "Napomena", True, 240),
        ]
        self._apply_cols_assign = wire_columns(self, self.table, self.btn_columns, "assignments_table_v1", specs)

        self._apply_rbac()
        self.load_assignments()

    # -------------------- status helpers --------------------
    def _set_status(self, text: str, *, kind: str = "info") -> None:
        t = _norm(text, 500)
        if not t:
            self.lb_status.hide()
            self.lb_status.setText("")
            return

        self.lb_status.setText(t)
        self.lb_status.show()
        if kind == "error":
            self.lb_status.setStyleSheet(
                "padding:8px 10px; border-radius:10px;"
                "background:#3b1d1d; border:1px solid #a33; color:#fff; font-weight:700;"
            )
        elif kind == "warn":
            self.lb_status.setStyleSheet(
                "padding:8px 10px; border-radius:10px;"
                "background:#2b2416; border:1px solid #c9a13b; color:#fff; font-weight:700;"
            )
        else:
            self.lb_status.setStyleSheet(
                "padding:8px 10px; border-radius:10px;"
                "background:#16242b; border:1px solid #2f7f96; color:#fff; font-weight:650;"
            )

    # -------------------- RBAC --------------------
    def _apply_rbac(self) -> None:
        view_ok = _safe_can(PERM_ASSIGN_VIEW)
        create_ok = _safe_can(PERM_ASSIGN_CREATE)
        seed_ok = _safe_can(PERM_ASSETS_CREATE)

        self.btn_new.setEnabled(bool(create_ok))
        self.btn_seed.setEnabled(bool(seed_ok))

        if not view_ok:
            self.lb_rbac.setText("Nemaš pravo pregleda zaduženja (assignments.view).")
            self.lb_rbac.show()
            for w in [
                self.table,
                self.btn_search,
                self.btn_refresh,
                self.btn_columns,
                self.btn_details,
                self.ed_search,
                self.cb_action,
            ]:
                try:
                    w.setEnabled(False)
                except Exception:
                    pass
            try:
                if self.tools:
                    self.tools.setEnabled(False)
            except Exception:
                pass
        else:
            self.lb_rbac.hide()
            for w in [self.table, self.btn_search, self.btn_refresh, self.btn_columns, self.ed_search, self.cb_action]:
                try:
                    w.setEnabled(True)
                except Exception:
                    pass
            try:
                if self.tools:
                    self.tools.setEnabled(True)
            except Exception:
                pass
            self._sync_buttons()

    # -------------------- selection helpers --------------------
    def _current_row_any(self) -> int:
        r = self.table.currentRow()
        if r >= 0:
            return r
        try:
            sm = self.table.selectionModel()
            if sm:
                idx = sm.selectedIndexes()
                if idx:
                    return idx[0].row()
        except Exception:
            pass
        return -1

    def _sync_buttons(self) -> None:
        self.btn_details.setEnabled(self._current_row_any() >= 0)

    def _selected_row_data(self) -> Dict[str, str]:
        row = self._current_row_any()
        if row < 0:
            return {}

        def txt(c: int) -> str:
            it = self.table.item(row, c)
            return it.text().strip() if it else ""

        return {
            "time": txt(1),
            "asset_uid": txt(2),
            "asset_name": txt(3),
            "action": txt(4),
            "from_holder": txt(5),
            "to_holder": txt(6),
            "location": txt(7),
            "note": txt(8),
        }

    def open_details(self) -> None:
        data = self._selected_row_data()
        if not data:
            self._set_status("Prvo izaberi red/ćeliju u tabeli.", kind="warn")
            _info(self, "Info", "Prvo izaberi red/ćeliju u tabeli.")
            return
        dlg = _AssignmentDetailsDialog(data, self)
        dlg.exec()

    # -------------------- renumber (visible rows) --------------------
    def _renumber_rows_visible(self) -> None:
        """
        Rb (#) prati trenutni prikaz:
        - posle sortiranja
        - posle filtera (hideRow)
        Numeriše samo vidljive redove.
        """
        try:
            n = 0
            rc = self.table.rowCount()
            for r in range(rc):
                if self.table.isRowHidden(r):
                    continue
                n += 1
                it = self.table.item(r, 0)
                if it is None:
                    it = QTableWidgetItem("")
                    self.table.setItem(r, 0, it)
                it.setText(str(n))
                it.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        except Exception:
            pass

    def _reapply_table_filter_if_any(self) -> None:
        """
        Posle reload-a, ako je korisnik uneo tekst u TableToolsBar,
        re-primeni filter nad tabelom.
        """
        try:
            if not self.tools:
                return
            q = self.tools.ed.text()
            if q:
                # TableToolsBar već radi apply_table_filter u _on_text_changed
                self.tools._on_text_changed(q)  # type: ignore[attr-defined]
        except Exception:
            pass

    # -------------------- data --------------------
    def load_assignments(self) -> None:
        if not _safe_can(PERM_ASSIGN_VIEW):
            try:
                self.table.setRowCount(0)
            except Exception:
                pass
            return

        rows: List[Dict[str, Any]] = []
        self._set_status("Učitavam zaduženja…", kind="info")

        was_sorting = False
        try:
            was_sorting = self.table.isSortingEnabled()
            self.table.setSortingEnabled(False)
        except Exception:
            pass

        try:
            search = _norm(self.ed_search.text(), 120)
            action = _action_ui_to_service(self.cb_action.currentText())

            rows_raw = list_assignments(search=search, action=action, limit=2000)
            if isinstance(rows_raw, list):
                rows = rows_raw
            else:
                rows = []

            self.table.setUpdatesEnabled(False)
            self.table.setRowCount(0)

            for r in rows:
                i = self.table.rowCount()
                self.table.insertRow(i)

                loc = (r.get("to_location") or r.get("from_location") or "") or ""
                values = [
                    "",  # 0: # (popuni posle)
                    fmt_dt_sr(r.get("created_at", "") or ""),  # 1: vreme
                    r.get("asset_uid", "") or "",  # 2
                    r.get("asset_name", "") or "",  # 3
                    r.get("action", "") or "",  # 4
                    r.get("from_holder", "") or "",  # 5
                    r.get("to_holder", "") or "",  # 6
                    loc,  # 7
                    r.get("note", "") or "",  # 8
                ]
                for c, v in enumerate(values):
                    self.table.setItem(i, c, QTableWidgetItem(str(v)))

            self._set_status(f"Učitano: {len(rows)} zapisa.", kind="info")

        except Exception as e:
            self._set_status(f"Ne mogu da učitam zaduženja: {e}", kind="error")
            _err(self, "Greška", f"Ne mogu da učitam zaduženja.\n\n{e}")
            return
        finally:
            try:
                self.table.setUpdatesEnabled(True)
            except Exception:
                pass
            try:
                self.table.setSortingEnabled(was_sorting)
            except Exception:
                pass

        # primeni kolone prefs (redosled/vidljivost/širine)
        try:
            self._apply_cols_assign()
        except Exception:
            pass

        # re-primeni filter (client-side), pa numeriši vidljive
        self._reapply_table_filter_if_any()
        self._renumber_rows_visible()
        self._sync_buttons()

        try:
            self.logger.info("AssignmentsPage: učitano %s zapisa.", len(rows))
        except Exception:
            pass

    # -------------------- actions --------------------
    def seed_demo(self) -> None:
        if not _safe_can(PERM_ASSETS_CREATE):
            self._set_status("Nemaš pravo za demo seed (assets.create).", kind="warn")
            _warn(self, "RBAC", "Nemaš pravo za demo seed (assets.create).")
            return

        try:
            samples = [
                ("Laptop Dell 7490", "IT", "TOC-1001", "SN-IT-001", "S2 LAB", "active"),
                ("Fluke 289 Multimeter", "Metrologija", "TOC-2001", "SN-MET-001", "S2 LAB", "active"),
                ("Stolica kancelarijska", "OS", "TOC-3001", "SN-OS-001", "Magacin", "active"),
            ]
            created: List[str] = []
            for name, cat, toc, sn, loc, st in samples:
                uid = create_asset(
                    actor=_actor(),
                    name=name,
                    category=cat,
                    toc_number=toc,
                    serial_number=sn,
                    location=loc,
                    status=st,
                    source="ui_seed_demo",
                )
                created.append(uid)

            try:
                self.assets_page.load_assets()
            except Exception:
                pass

            self.load_assignments()
            self._set_status("Ubačena demo sredstva.", kind="info")
            _info(self, "OK", "Ubačena demo sredstva:\n" + "\n".join(created))

        except Exception as e:
            self._set_status(f"Ne mogu da ubacim demo sredstva: {e}", kind="error")
            _err(self, "Greška", f"Ne mogu da ubacim demo sredstva.\n\n{e}")

    def _load_users_brief_best_effort(self) -> List[Dict[str, Any]]:
        """
        Najbitnije za tvoj bug: user lista mora biti sector-scoped.
        Ovo mora primarno da se reši u SERVISU (RBAC + scope filter u SQL upitu).
        UI ovde samo zove funkciju koja *treba* da vrati već filtrirano.

        Fail-soft: ako funkcija ne postoji ili pukne — vraća prazno, ručni unos radi.
        """
        if not callable(list_users_for_assignment):
            return []

        try:
            # Ne pretpostavljamo potpis funkcije — zovemo bez argumenata da bude najkompatibilnije.
            rr = list_users_for_assignment()  # type: ignore[misc]
            if isinstance(rr, list):
                # očekujemo dict-ove {username, display_name, sector...}
                return [x for x in rr if isinstance(x, dict)]
            return []
        except Exception:
            return []

    def new_assignment(self) -> None:
        if not _safe_can(PERM_ASSIGN_CREATE):
            self._set_status("Nemaš pravo za novo zaduženje (assignments.create).", kind="warn")
            _warn(self, "RBAC", "Nemaš pravo za novo zaduženje (assignments.create).")
            return

        assets = list_assets_brief(limit=2000) or []
        if not assets:
            self._set_status("Nema sredstava u bazi. Dodaj sredstvo ili ubaci demo.", kind="warn")
            _warn(
                self,
                "Baza je prazna",
                "Nema nijednog sredstva u bazi.\n\n"
                "Prvo dodaj sredstvo u 'Sredstva' (dugme Novo),\n"
                "ili klikni 'Ubaci demo sredstva' za test.",
            )
            return

        users_brief = self._load_users_brief_best_effort()
        dlg = NewAssignmentDialog(assets, users_brief=users_brief, parent=self)

        if dlg.exec() != QDialog.Accepted:
            return

        v = dlg.values()

        try:
            assignment_id = create_assignment(
                actor=_actor(),
                asset_uid=v["asset_uid"],
                action=v["action"],
                to_holder=v["to_holder"],
                to_location=v["to_location"],
                note=v["note"],
                source="ui_new_assignment",
            )
            self._set_status(f"Upisano zaduženje ID: {assignment_id}", kind="info")
            _info(self, "OK", f"Upisano zaduženje ID: {assignment_id}")

            self.load_assignments()
            try:
                self.assets_page.load_assets()
            except Exception:
                pass

        except Exception as e:
            self._set_status(f"Ne mogu da upišem zaduženje: {e}", kind="error")
            _err(self, "Greška", f"Ne mogu da upišem zaduženje.\n\n{e}")


# (FILENAME: ui/assignments_page.py - END)