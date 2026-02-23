# FILENAME: ui/metrology_page.py
# (FILENAME: ui/metrology_page.py - START PART 1/3)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/metrology_page.py

Hardening + usklađivanje sa novim pravilima (bez menjanja izgleda i postojećih UX elemenata):
- ✅ Prikazujemo samo metrologija sredstva (assets.is_metrology=1) KAD GOD možemo da potvrdimo preko assets map-a.
- ✅ Status: "NEPOZNATO" ako nije unet datum etaloniranja (calib_date je prazan),
  čak i ako valid_until postoji. (UI pravilo kao na dashboard-u)
- ✅ Debounce + cache i dalje rade, bez dodatnog “opterećenja”.
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Tuple

from PySide6.QtCore import Qt, QTimer  # type: ignore
from PySide6.QtGui import QColor, QBrush  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QTableWidget, QTableWidgetItem, QMessageBox, QDialog,
    QFormLayout, QDialogButtonBox, QPlainTextEdit, QMenu, QApplication,
    QAbstractItemView, QGroupBox
)

from services.metrology_service import (
    CALIB_TYPES,
    list_metrology_records,
    create_metrology_record,
    update_metrology_record,
    delete_metrology_record,
    list_metrology_audit,
    get_metrology_record,
)

# ✅ MY list (ako postoji u servisu); fallback je list_metrology_records (scope i dalje radi)
try:
    from services.metrology_service import list_metrology_records_my  # type: ignore
except Exception:  # pragma: no cover
    list_metrology_records_my = None  # type: ignore

# ✅ status iz servisa (da UI i servis ne “driftuju”)
try:
    from services.metrology_service import status_for_valid_until as _svc_status_for_valid_until  # type: ignore
except Exception:  # pragma: no cover
    _svc_status_for_valid_until = None  # type: ignore

from services.assets_service import list_assets_brief, get_asset_by_uid

from ui.widgets.datetime_widgets import DateFieldSR
from ui.utils.datetime_fmt import fmt_date_sr, fmt_dt_sr
from ui.utils.table_columns import wire_columns
from ui.utils.table_copy import wire_table_selection_plus_copy, copy_selected_cells

# ✅ Users-style filter bar
try:
    from ui.utils.table_search_sort import TableToolsBar, TableToolsConfig  # type: ignore
except Exception:
    TableToolsBar = None  # type: ignore
    TableToolsConfig = None  # type: ignore


# -------------------- RBAC helpers (UI-level, fail-closed) --------------------
try:
    from core.rbac import (  # type: ignore
        PERM_METRO_VIEW,
        PERM_METRO_MANAGE,
        PERM_METRO_EDIT,
        PERM_ASSETS_VIEW,
        PERM_ASSETS_METRO_VIEW,
        PERM_ASSETS_MY_VIEW,
        effective_role,
    )
except Exception:  # pragma: no cover
    PERM_METRO_VIEW = "metrology.view"
    PERM_METRO_MANAGE = "metrology.manage"
    PERM_METRO_EDIT = "metrology.edit"
    PERM_ASSETS_VIEW = "assets.view"
    PERM_ASSETS_METRO_VIEW = "assets.metrology.view"
    PERM_ASSETS_MY_VIEW = "assets.my.view"

    def effective_role(_u: Optional[Dict[str, Any]] = None) -> str:  # type: ignore
        try:
            u = _u or {}
            ar = str(u.get("active_role") or "").strip()
            if ar:
                return ar.upper()
            r = str(u.get("role") or "").strip()
            return (r or "READONLY").upper()
        except Exception:
            return "READONLY"


def _can(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _get_current_user_dict() -> Dict[str, Any]:
    try:
        from core.session import get_current_user  # type: ignore
        u = get_current_user()
        if not u:
            return {}
        if isinstance(u, dict):
            return dict(u)
        try:
            return dict(vars(u))
        except Exception:
            return {}
    except Exception:
        return {}


def _effective_role_ui() -> str:
    try:
        u = _get_current_user_dict()
        r = effective_role(u)
        return str(r or "READONLY").strip().upper() or "READONLY"
    except Exception:
        u = _get_current_user_dict()
        return str(u.get("active_role") or u.get("role") or "READONLY").strip().upper() or "READONLY"


def _is_basic_user() -> bool:
    return _effective_role_ui() == "BASIC_USER"


def _can_metro_write() -> bool:
    return _can(PERM_METRO_MANAGE) or _can(PERM_METRO_EDIT)


def _can_asset_access_from_metrology() -> bool:
    # ✅ FULL / METRO / MY
    return _can(PERM_ASSETS_VIEW) or _can(PERM_ASSETS_METRO_VIEW) or _can(PERM_ASSETS_MY_VIEW)


def _actor_name() -> str:
    try:
        from core.session import actor_name as _an  # type: ignore
        return (_an() or "user").strip() or "user"
    except Exception:
        import os
        return (os.environ.get("USERNAME") or os.environ.get("USER") or "user").strip() or "user"


def _today_iso() -> str:
    return date.today().isoformat()


def _status_for_record_ui(calib_date_iso: str, valid_until_iso: str, warn_days: int = 30) -> str:
    """
    Pravilo (po zahtevu):
    - ako calib_date nije unet -> NEPOZNATO
    - inače status računamo po valid_until (prefer servisnu logiku)
    """
    cd = (calib_date_iso or "").strip()
    if not cd:
        return "NEPOZNATO"

    if callable(_svc_status_for_valid_until):
        try:
            st = str(_svc_status_for_valid_until(valid_until_iso, warn_days=warn_days) or "NEPOZNATO").strip().upper()
            # servis tipično vraća ISTICE/ISTEKLO/OK/NEPOZNATO
            return st or "NEPOZNATO"
        except Exception:
            pass

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
    if wd < 0:
        wd = 0

    if (vu_date - today).days <= wd:
        return "ISTICE"
    return "OK"


def _add_years_iso(base_iso: str, years: int) -> str:
    try:
        if base_iso and len(base_iso) == 10 and base_iso[4] == "-" and base_iso[7] == "-":
            y = int(base_iso[0:4])
            m = int(base_iso[5:7])
            d = int(base_iso[8:10])
            b = date(y, m, d)
        else:
            b = date.today()
    except Exception:
        b = date.today()

    target_y = b.year + int(years)
    try:
        return date(target_y, b.month, b.day).isoformat()
    except Exception:
        if b.month == 2 and b.day == 29:
            return date(target_y, 2, 28).isoformat()
        return date(target_y, b.month, min(b.day, 28)).isoformat()


def _copy_text_to_clipboard(text: str) -> None:
    try:
        cb = QApplication.clipboard()
        cb.setText(text or "")
    except Exception:
        pass


def _current_row_any(table: QTableWidget) -> int:
    r = table.currentRow()
    if r >= 0:
        return r
    try:
        sm = table.selectionModel()
        if sm:
            idx = sm.selectedIndexes()
            if idx:
                return idx[0].row()
    except Exception:
        pass
    return -1


# -------------------- Asset helpers (metrology flag) --------------------
def _asset_is_metrology(a: Optional[Dict[str, Any]]) -> bool:
    if not a or not isinstance(a, dict):
        return False
    for k in ("is_metrology", "is_metro", "metrology_flag", "metro_flag"):
        v = a.get(k)
        if v is None:
            continue
        try:
            if isinstance(v, bool):
                return bool(v)
            if isinstance(v, (int, float)):
                return int(v) == 1
            s = str(v).strip().lower()
            if s in ("1", "true", "yes", "da", "on"):
                return True
        except Exception:
            continue
    return False


def _list_assets_brief_safe(limit: int = 5000, *, metrology_only: bool = False) -> List[Dict[str, Any]]:
    """
    Best-effort wrapper zbog kompatibilnosti potpisa + RBAC.
    """
    try:
        return list_assets_brief(limit=limit, metrology_only=bool(metrology_only))  # type: ignore[call-arg]
    except TypeError:
        try:
            return list_assets_brief(limit=limit)  # type: ignore[misc]
        except Exception:
            return []
    except PermissionError:
        return []
    except Exception:
        return []


# -------------------- Sort helpers (critical: date sort) --------------------
class SortableItem(QTableWidgetItem):
    """
    QTableWidgetItem default sort je leksikografski.
    Mi guramo sort ključ u Qt.UserRole i poredimo po njemu kad postoji.
    """
    def __init__(self, text: str = "", sort_value: Any = None):
        super().__init__(text)
        if sort_value is not None:
            try:
                self.setData(Qt.UserRole, sort_value)
            except Exception:
                pass

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        try:
            a = self.data(Qt.UserRole)
            b = other.data(Qt.UserRole)
            if a is not None and b is not None:
                return a < b
        except Exception:
            pass
        return super().__lt__(other)


def _iso_date_sort_key(iso_yyyy_mm_dd: str) -> Optional[int]:
    s = (iso_yyyy_mm_dd or "").strip()
    if not s:
        return None
    try:
        y, m, d = [int(x) for x in s.split("-")]
        return y * 10000 + m * 100 + d
    except Exception:
        return None


def _dt_sort_key_any(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, datetime):
        try:
            return int(v.timestamp())
        except Exception:
            return None
    s = str(v or "").strip()
    if not s:
        return None
    try:
        s2 = s.replace("Z", "").replace("T", " ").strip()
        dt = datetime.fromisoformat(s2)
        return int(dt.timestamp())
    except Exception:
        return None


def _renumber_rows_visible(table: QTableWidget, rb_col: int = 0) -> None:
    """
    Standard: Rb (#) prati trenutni prikaz (posle sort + posle filtera).
    Numeriše samo vidljive redove. Ujedno postavlja NUMERIC sort key.
    """
    try:
        n = 0
        rc = table.rowCount()
        for r in range(rc):
            hidden = table.isRowHidden(r)
            if hidden:
                txt = ""
                sort_v = 0
            else:
                n += 1
                txt = str(n)
                sort_v = n

            it = table.item(r, rb_col)
            if it is None or not isinstance(it, SortableItem):
                it = SortableItem("", sort_v)
                it.setFlags(it.flags() & ~Qt.ItemIsEditable)
                table.setItem(r, rb_col, it)

            it.setText(txt)
            it.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            try:
                it.setData(Qt.UserRole, sort_v)
            except Exception:
                pass
    except Exception:
        pass


def _resolve_db_path_for_mtime() -> Path:
    """
    Mora da pokazuje na ISTI DB fajl kao core.db.connect_db.
    """
    try:
        from core.db import get_db_path  # type: ignore
        p = str(get_db_path() or "").strip()
        if p:
            return Path(p).resolve()
    except Exception:
        pass

    try:
        from core.paths import DB_PATH  # type: ignore
        if DB_PATH:
            return Path(DB_PATH).resolve()
    except Exception:
        pass

    try:
        from core.config import DB_FILE  # type: ignore
        p2 = Path(DB_FILE)
    except Exception:
        p2 = Path("data/db/bazas2.sqlite")

    if not p2.is_absolute():
        root = Path(__file__).resolve().parents[1]
        p2 = (root / p2).resolve()
    return p2


def _db_mtime_safe() -> float:
    try:
        p = _resolve_db_path_for_mtime()
        if p.exists():
            return float(p.stat().st_mtime)
    except Exception:
        pass
    return 0.0


def _asset_field(a: Optional[Dict[str, Any]], *keys: str) -> str:
    if not a or not isinstance(a, dict):
        return ""
    for k in keys:
        v = a.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def _apply_status_badge(table: QTableWidget, row: int, status_txt: str, col_status: int = 1) -> None:
    """
    Suptilan ali jasan “badge” u status koloni.
    (ne farbamo ceo red da ne bude “šareno”)
    """
    st = (status_txt or "").strip().upper()
    palette: Dict[str, Tuple[QBrush, QBrush]] = {
        "OK": (QBrush(QColor(46, 125, 50, 190)), QBrush(QColor(255, 255, 255))),
        "ISTICE": (QBrush(QColor(255, 193, 7, 185)), QBrush(QColor(30, 30, 30))),
        "ISTEKLO": (QBrush(QColor(211, 47, 47, 190)), QBrush(QColor(255, 255, 255))),
        "NEPOZNATO": (QBrush(QColor(120, 120, 120, 170)), QBrush(QColor(255, 255, 255))),
    }
    it = table.item(row, col_status)
    if not it:
        return
    if st in palette:
        bg, fg = palette[st]
        try:
            it.setBackground(bg)
            it.setForeground(fg)
            it.setTextAlignment(Qt.AlignCenter)
        except Exception:
            pass


def _has_active_modal_dialog() -> bool:
    """
    Ako je otvoren modal (edit/details/audit), ne radimo auto-refresh,
    da UI ne “krade” fokus/selekciju.
    """
    try:
        w = QApplication.activeModalWidget()
        return w is not None
    except Exception:
        return False


def _list_metrology_rows_safe(
    q: str,
    limit: int,
    warn_days: int,
    prefer_my: bool,
) -> List[Dict[str, Any]]:
    """
    Stabilan wrapper:
    - BASIC_USER → pokušaj MY endpoint (ako postoji)
    - U slučaju razlike potpisa (TypeError) → fallback sa manje argumenata
    - Finalni scope/RBAC u servisu (fail-closed)
    """
    if prefer_my and callable(list_metrology_records_my):
        try:
            return list_metrology_records_my(q=q, limit=limit, warn_days=warn_days)  # type: ignore[misc]
        except TypeError:
            try:
                return list_metrology_records_my(q=q, limit=limit)  # type: ignore[misc]
            except TypeError:
                return list_metrology_records_my(q=q)  # type: ignore[misc]
        except Exception:
            pass

    try:
        return list_metrology_records(q=q, limit=limit, warn_days=warn_days)
    except TypeError:
        try:
            return list_metrology_records(q=q, limit=limit)
        except TypeError:
            return list_metrology_records(q=q)
    except Exception:
        return []


def _get_metrology_record_safe(met_uid: str, warn_days: int = 30) -> Optional[Dict[str, Any]]:
    """
    Kompatibilnost: servis može imati get_metrology_record(met_uid) ili get_metrology_record(met_uid, warn_days=..).
    """
    try:
        return get_metrology_record(met_uid, warn_days=warn_days)  # type: ignore[call-arg]
    except TypeError:
        try:
            return get_metrology_record(met_uid)  # type: ignore[misc]
        except Exception:
            return None
    except Exception:
        return None


# -------------------- dialogs --------------------
class MetrologyEditDialog(QDialog):
    """
    Novi/izmena metrology zapisa.
    FIX: Ako assets_brief nije dostupan (nema prava / servis pukne),
    dozvoli ručni unos Asset UID (servis će svakako enforce-ovati RBAC/scope).
    + NOVO: assets list je (po mogućnosti) već filtriran na is_metrology=1.
    """
    def __init__(self, assets_brief: List[Dict[str, Any]], existing: Optional[Dict[str, Any]] = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Metrologija — Novi zapis" if not existing else "Metrologija — Izmena zapisa")
        self.resize(760, 480)

        # Defanzivno: ako nam neko prosledi “sve”, preseci na metrology-only kad imamo flag.
        self.assets = []
        for a in (assets_brief or []):
            if not isinstance(a, dict):
                continue
            # ako nema ključa, ne pretpostavljamo ništa; ali assets_brief_safe će već filtrirati kad može
            if ("is_metrology" in a) or ("is_metro" in a) or ("metrology_flag" in a) or ("metro_flag" in a):
                if not _asset_is_metrology(a):
                    continue
            self.assets.append(a)

        self.existing = existing

        self.cb_asset = QComboBox()
        self.ed_asset_uid = QLineEdit()
        self.ed_asset_uid.setPlaceholderText("Unesi Asset UID (npr. A-2026-0000123)")
        self.ed_asset_uid.setClearButtonEnabled(True)

        self._use_manual_asset = (len(self.assets) == 0)

        if not self._use_manual_asset:
            for a in self.assets:
                uid = a.get("asset_uid", "") or ""
                name = a.get("name", "") or ""
                cat = a.get("category", "") or ""
                toc = a.get("toc_number", "") or ""
                sn = a.get("serial_number", "") or ""
                nom = _asset_field(a, "nomenclature_number", "nomenklaturni_broj", "nomenclature_no", "nomen_number")
                label = f"{uid} | {name} | {cat}"
                extra = []
                if toc:
                    extra.append(f"TOC:{toc}")
                if nom:
                    extra.append(f"NOM:{nom}")
                if sn:
                    extra.append(f"SN:{sn}")
                if extra:
                    label += " | " + " ".join(extra)
                self.cb_asset.addItem(label, uid)

        self.cb_type = QComboBox()
        self.cb_type.addItems(CALIB_TYPES)

        self.df_calib_date = DateFieldSR("dd.MM.yyyy (opciono)")
        self.df_valid_until = DateFieldSR("dd.MM.yyyy (važan za alarme)")

        self.btn_today = QPushButton("Danas")
        self.btn_plus1y = QPushButton("+1 godina")
        self.btn_plus2y = QPushButton("+2 godine")

        quick = QHBoxLayout()
        quick.setContentsMargins(0, 0, 0, 0)
        quick.addWidget(self.btn_today)
        quick.addWidget(self.btn_plus1y)
        quick.addWidget(self.btn_plus2y)
        quick.addStretch(1)

        quick_wrap = QWidget()
        quick_wrap.setLayout(quick)

        self.ed_provider = QLineEdit()
        self.ed_provider.setPlaceholderText("Laboratorija / firma / interna jedinica")

        self.ed_cert = QLineEdit()
        self.ed_cert.setPlaceholderText("Broj sertifikata (opciono)")

        self.ed_notes = QPlainTextEdit()
        self.ed_notes.setPlaceholderText("Napomena (opciono)")

        form = QFormLayout()

        if self._use_manual_asset:
            form.addRow("Sredstvo (Asset UID) *", self.ed_asset_uid)
        else:
            form.addRow("Sredstvo (asset) *", self.cb_asset)

        form.addRow("Tip etaloniranja *", self.cb_type)
        form.addRow("Datum etaloniranja", self.df_calib_date)
        form.addRow("Važi do (expiry)", self.df_valid_until)
        form.addRow("Brze akcije (Važi do)", quick_wrap)
        form.addRow("Izvršilac / Lab", self.ed_provider)
        form.addRow("Sertifikat broj", self.ed_cert)
        form.addRow("Napomena", self.ed_notes)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._on_ok)
        btns.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(btns)

        self.btn_today.clicked.connect(self._set_valid_today)
        self.btn_plus1y.clicked.connect(lambda: self._set_valid_plus_years(1))
        self.btn_plus2y.clicked.connect(lambda: self._set_valid_plus_years(2))

        if existing:
            asset_uid = existing.get("asset_uid", "") or ""

            if self._use_manual_asset:
                self.ed_asset_uid.setText(asset_uid)
                self.ed_asset_uid.setEnabled(False)
            else:
                idx = self.cb_asset.findData(asset_uid)
                if idx >= 0:
                    self.cb_asset.setCurrentIndex(idx)
                else:
                    self.cb_asset.insertItem(0, asset_uid, asset_uid)
                    self.cb_asset.setCurrentIndex(0)
                self.cb_asset.setEnabled(False)

            t = existing.get("calib_type", "")
            if t in CALIB_TYPES:
                self.cb_type.setCurrentText(t)

            self.df_calib_date.set_value_iso(existing.get("calib_date", "") or "")
            self.df_valid_until.set_value_iso(existing.get("valid_until", "") or "")
            self.ed_provider.setText(existing.get("provider_name", "") or "")
            self.ed_cert.setText(existing.get("cert_no", "") or "")
            self.ed_notes.setPlainText(existing.get("notes", "") or "")

    def _set_valid_today(self):
        self.df_valid_until.set_value_iso(_today_iso())

    def _set_valid_plus_years(self, years: int):
        base = self.df_calib_date.value_iso() or _today_iso()
        self.df_valid_until.set_value_iso(_add_years_iso(base, years))

    def _asset_uid_value(self) -> str:
        if self._use_manual_asset:
            return (self.ed_asset_uid.text() or "").strip()
        return (self.cb_asset.currentData() or "").strip()

    def _best_effort_validate_metrology_flag(self, asset_uid: str) -> bool:
        """
        Ako imamo pristup assets-u: blokiraj upis metrologije na sredstvo koje nije metrology-flag.
        Ako nemamo pristup: ne možemo da proverimo, ne blokiramo (servis je krajnji gate).
        """
        if not asset_uid:
            return True
        if not _can_asset_access_from_metrology():
            return True
        try:
            a = get_asset_by_uid(asset_uid=asset_uid)
            if not a or not isinstance(a, dict):
                return True
            # ako nemamo polje, ne pretpostavljamo
            if ("is_metrology" not in a) and ("is_metro" not in a) and ("metrology_flag" not in a) and ("metro_flag" not in a):
                return True
            return bool(_asset_is_metrology(a))
        except PermissionError:
            return True
        except Exception:
            return True

    def _on_ok(self):
        asset_uid = self._asset_uid_value()
        if not asset_uid:
            QMessageBox.warning(self, "Validacija", "Asset UID je obavezan.")
            return

        if any(ch.isspace() for ch in asset_uid) or len(asset_uid) > 64:
            QMessageBox.warning(self, "Validacija", "Asset UID nije validan (razmaci ili predugačak).")
            return

        # ✅ metrology flag check (best-effort)
        if not self._best_effort_validate_metrology_flag(asset_uid):
            QMessageBox.warning(self, "Validacija", "Ovo sredstvo nije označeno kao METROLOGIJA (is_metrology=0).")
            return

        calib_type = self.cb_type.currentText().strip()
        if calib_type not in CALIB_TYPES:
            QMessageBox.warning(self, "Validacija", "Tip etaloniranja nije validan.")
            return

        if self.df_calib_date.ed.text().strip().replace("_", "") and not self.df_calib_date.value_iso():
            QMessageBox.warning(self, "Validacija", "Datum etaloniranja nije validan. Koristi dd.MM.yyyy ili obriši.")
            return

        if self.df_valid_until.ed.text().strip().replace("_", "") and not self.df_valid_until.value_iso():
            QMessageBox.warning(self, "Validacija", "Važi do nije validan. Koristi dd.MM.yyyy ili obriši.")
            return

        self.accept()

    def values(self) -> Dict[str, Any]:
        return {
            "asset_uid": self._asset_uid_value(),
            "calib_type": self.cb_type.currentText().strip(),
            "calib_date": self.df_calib_date.value_iso(),
            "valid_until": self.df_valid_until.value_iso(),
            "provider_name": self.ed_provider.text().strip(),
            "cert_no": self.ed_cert.text().strip(),
            "notes": self.ed_notes.toPlainText().strip(),
        }


class MetrologyDetailsDialog(QDialog):
    """
    Read-only detalji zapisa (V1).
    + prikaz osnovnih podataka o sredstvu (ako user ima asset pristup)
    """
    def __init__(self, met_uid: str, parent=None, on_changed: Optional[Callable[[], None]] = None, warn_days: int = 30):
        super().__init__(parent)
        self.met_uid = (met_uid or "").strip()
        self.on_changed = on_changed
        try:
            self.warn_days = int(warn_days or 30)
        except Exception:
            self.warn_days = 30

        self.setWindowTitle(f"Metrologija — Detalji: {self.met_uid}")
        self.resize(920, 580)

        self.lbl_status = QLabel("")
        self.lbl_met_uid = QLabel(self.met_uid)
        self.lbl_asset_uid = QLabel("")
        self.lbl_type = QLabel("")
        self.lbl_calib_date = QLabel("")
        self.lbl_valid_until = QLabel("")
        self.lbl_provider = QLabel("")
        self.lbl_cert = QLabel("")
        self.txt_notes = QPlainTextEdit()
        self.txt_notes.setReadOnly(True)

        self.lbl_asset_name = QLabel("")
        self.lbl_asset_cat = QLabel("")
        self.lbl_asset_toc = QLabel("")
        self.lbl_asset_nomen = QLabel("")
        self.lbl_asset_sn = QLabel("")
        self.lbl_asset_holder = QLabel("")
        self.lbl_asset_loc = QLabel("")

        for lab in [
            self.lbl_status, self.lbl_met_uid, self.lbl_asset_uid, self.lbl_type,
            self.lbl_calib_date, self.lbl_valid_until, self.lbl_provider, self.lbl_cert,
            self.lbl_asset_name, self.lbl_asset_cat, self.lbl_asset_toc, self.lbl_asset_nomen,
            self.lbl_asset_sn, self.lbl_asset_holder, self.lbl_asset_loc,
        ]:
            lab.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)

        self.btn_copy_asset = QPushButton("Kopiraj Asset UID")
        self.btn_copy_met = QPushButton("Kopiraj Met UID")
        self.btn_open_asset = QPushButton("Otvori detalje sredstva")
        self.btn_edit = QPushButton("Izmeni…")
        self.btn_close = QPushButton("Zatvori")

        top = QHBoxLayout()
        top.addWidget(self.btn_copy_met)
        top.addWidget(self.btn_copy_asset)
        top.addStretch(1)
        top.addWidget(self.btn_open_asset)
        top.addWidget(self.btn_edit)
        top.addWidget(self.btn_close)

        box = QGroupBox("Podaci")
        form = QFormLayout(box)
        form.addRow("Status", self.lbl_status)
        form.addRow("Met UID", self.lbl_met_uid)
        form.addRow("Asset UID", self.lbl_asset_uid)

        asset_box = QGroupBox("Sredstvo (sažetak)")
        aform = QFormLayout(asset_box)
        aform.addRow("Naziv", self.lbl_asset_name)
        aform.addRow("Kategorija", self.lbl_asset_cat)
        aform.addRow("TOC", self.lbl_asset_toc)
        aform.addRow("Nomenklaturni br.", self.lbl_asset_nomen)
        aform.addRow("Serijski broj", self.lbl_asset_sn)
        aform.addRow("Duži", self.lbl_asset_holder)
        aform.addRow("Lokacija", self.lbl_asset_loc)

        mbox = QGroupBox("Metrologija")
        mform = QFormLayout(mbox)
        mform.addRow("Tip", self.lbl_type)
        mform.addRow("Datum etaloniranja", self.lbl_calib_date)
        mform.addRow("Važi do", self.lbl_valid_until)
        mform.addRow("Izvršilac / Lab", self.lbl_provider)
        mform.addRow("Sertifikat", self.lbl_cert)

        notes_box = QGroupBox("Napomena")
        notes_lay = QVBoxLayout(notes_box)
        notes_lay.addWidget(self.txt_notes, 1)

        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(box)
        lay.addWidget(asset_box)
        lay.addWidget(mbox)
        lay.addWidget(notes_box, 1)

        self.btn_close.clicked.connect(self.reject)
        self.btn_copy_met.clicked.connect(lambda: _copy_text_to_clipboard(self.met_uid))
        self.btn_copy_asset.clicked.connect(self._copy_asset_uid)
        self.btn_open_asset.clicked.connect(self._open_asset_detail)
        self.btn_edit.clicked.connect(self._edit)

        self.btn_open_asset.setEnabled(_can_asset_access_from_metrology())
        self.btn_edit.setEnabled(_can_metro_write())

        self._load()

    def _load_asset_summary(self, asset_uid: str) -> None:
        self.lbl_asset_name.setText("")
        self.lbl_asset_cat.setText("")
        self.lbl_asset_toc.setText("")
        self.lbl_asset_nomen.setText("")
        self.lbl_asset_sn.setText("")
        self.lbl_asset_holder.setText("")
        self.lbl_asset_loc.setText("")

        if not _can_asset_access_from_metrology():
            return
        try:
            a = get_asset_by_uid(asset_uid=asset_uid)
            if not a or not isinstance(a, dict):
                return
            self.lbl_asset_name.setText(_asset_field(a, "name"))
            self.lbl_asset_cat.setText(_asset_field(a, "category"))
            self.lbl_asset_toc.setText(_asset_field(a, "toc_number", "toc"))
            self.lbl_asset_nomen.setText(_asset_field(a, "nomenclature_number", "nomenklaturni_broj", "nomenclature_no", "nomen_number"))
            self.lbl_asset_sn.setText(_asset_field(a, "serial_number", "serial", "sn"))
            self.lbl_asset_holder.setText(_asset_field(a, "current_holder", "assigned_to"))
            self.lbl_asset_loc.setText(_asset_field(a, "location"))
        except PermissionError:
            return
        except Exception:
            return

    def _load(self) -> None:
        try:
            rec = _get_metrology_record_safe(self.met_uid, warn_days=self.warn_days)
            if not rec:
                QMessageBox.warning(self, "Nije nađeno", "Zapis ne postoji.")
                self.reject()
                return

            calib_date_iso = str(rec.get("calib_date", "") or "")
            valid_until_iso = str(rec.get("valid_until", "") or "")
            st = _status_for_record_ui(calib_date_iso, valid_until_iso, warn_days=self.warn_days)
            self.lbl_status.setText(st)

            asset_uid = str(rec.get("asset_uid", "") or "")
            self.lbl_asset_uid.setText(asset_uid)
            self.lbl_type.setText(str(rec.get("calib_type", "") or ""))

            self.lbl_calib_date.setText(fmt_date_sr(calib_date_iso))
            self.lbl_valid_until.setText(fmt_date_sr(valid_until_iso))

            self.lbl_provider.setText(str(rec.get("provider_name", "") or ""))
            self.lbl_cert.setText(str(rec.get("cert_no", "") or ""))
            self.txt_notes.setPlainText(str(rec.get("notes", "") or ""))

            if asset_uid:
                self._load_asset_summary(asset_uid)

        except PermissionError as e:
            QMessageBox.warning(self, "RBAC", f"Nemaš pravo da vidiš detalje.\n\n{e}")
            self.reject()
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da učitam detalje.\n\n{e}")
            self.reject()

    def _copy_asset_uid(self) -> None:
        uid = (self.lbl_asset_uid.text() or "").strip()
        if uid:
            _copy_text_to_clipboard(uid)

    def _open_asset_detail(self) -> None:
        if not _can_asset_access_from_metrology():
            QMessageBox.information(self, "RBAC", "Nemaš pravo da otvoriš detalje sredstva.")
            return
        uid = (self.lbl_asset_uid.text() or "").strip()
        if not uid:
            QMessageBox.information(self, "Info", "Nema Asset UID u zapisu.")
            return
        try:
            from ui.asset_detail_dialog import AssetDetailDialog  # type: ignore
            dlg = AssetDetailDialog(uid, self)
            dlg.exec()
        except PermissionError as e:
            QMessageBox.information(self, "RBAC", f"Nemaš pravo da vidiš detalje sredstva.\n\n{e}")
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da otvorim detalje sredstva.\n\n{e}")

    def _edit(self) -> None:
        if not _can_metro_write():
            QMessageBox.information(self, "RBAC", "Nemaš pravo za izmenu metrologije.")
            return
        try:
            existing = _get_metrology_record_safe(self.met_uid, warn_days=self.warn_days)
            if not existing:
                QMessageBox.warning(self, "Nije nađeno", "Zapis ne postoji.")
                return

            assets: List[Dict[str, Any]] = []
            if _can_asset_access_from_metrology():
                # ✅ metrology-only assets u picker-u
                assets = _list_assets_brief_safe(limit=5000, metrology_only=True)

            dlg = MetrologyEditDialog(assets, existing=existing, parent=self)
            if dlg.exec() != QDialog.Accepted:
                return

            v = dlg.values()
            okk = update_metrology_record(
                actor=_actor_name(),
                met_uid=self.met_uid,
                calib_type=v["calib_type"],
                calib_date=v["calib_date"],
                valid_until=v["valid_until"],
                provider_name=v["provider_name"],
                cert_no=v["cert_no"],
                notes=v["notes"],
            )
            if okk:
                QMessageBox.information(self, "OK", "Zapis je ažuriran.")
                self._load()
                if callable(self.on_changed):
                    self.on_changed()
            else:
                QMessageBox.warning(self, "Nije uspelo", "Ne mogu da ažuriram (zapis ne postoji).")
        except PermissionError as e:
            QMessageBox.warning(self, "RBAC", f"Nemaš pravo za izmenu.\n\n{e}")
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da izmenim zapis.\n\n{e}")

# (FILENAME: ui/metrology_page.py - END PART 1/3)

# FILENAME: ui/metrology_page.py
# (FILENAME: ui/metrology_page.py - START PART 2/3)

class MetrologyAuditDialog(QDialog):
    def __init__(self, met_uid: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Metrologija — Audit: {met_uid}")
        self.resize(900, 520)

        from ui.columns_dialog import ColSpec  # lokalno

        self._col_specs = [
            ColSpec(key="rb", label="#", default_visible=True, default_width=60),
            ColSpec(key="time", label="Vreme", default_visible=True, default_width=170),
            ColSpec(key="actor", label="Korisnik", default_visible=True, default_width=160),
            ColSpec(key="action", label="Akcija", default_visible=True, default_width=120),
            ColSpec(key="note", label="Napomena", default_visible=True, default_width=280),
            ColSpec(key="asset_uid", label="Asset UID", default_visible=True, default_width=180),
        ]
        self._table_key = "metrology_audit_table_v4"

        self.btn_columns = QPushButton("Kolone")
        self.btn_columns.setToolTip("Prikaži/sakrij kolone, sačuvaj raspored i širine")

        top = QHBoxLayout()
        top.addStretch(1)
        top.addWidget(self.btn_columns)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["#", "Vreme", "Korisnik", "Akcija", "Napomena", "Asset UID"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        try:
            self.table.setUniformRowHeights(True)
        except Exception:
            pass

        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(True)

        self.table.setSortingEnabled(True)
        hdr.setSectionsClickable(True)
        hdr.setSectionsMovable(True)
        try:
            hdr.setDragEnabled(True)  # type: ignore[attr-defined]
        except Exception:
            pass

        self.table.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        wire_table_selection_plus_copy(self.table)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_context_menu)

        lay = QVBoxLayout(self)
        lay.addLayout(top)

        self.tools = None
        if TableToolsBar is not None and TableToolsConfig is not None:
            cfg = TableToolsConfig(
                placeholder="Filter… (vreme/korisnik/akcija/napomena/asset uid)",
                show_sort_toggle=False,
                default_sort_enabled=True,
                filter_columns=None,
            )
            self.tools = TableToolsBar(self.table, cfg, parent=self)
            lay.addWidget(self.tools)
            try:
                self.tools.ed.textChanged.connect(lambda _t: _renumber_rows_visible(self.table, rb_col=0))
            except Exception:
                pass

        lay.addWidget(self.table, 1)

        self._apply_cols = wire_columns(self, self.table, self.btn_columns, self._table_key, self._col_specs)

        try:
            hdr.sortIndicatorChanged.connect(lambda _i, _o: _renumber_rows_visible(self.table, rb_col=0))
        except Exception:
            pass

        self.load(met_uid)

    def _selected_asset_uid(self) -> str:
        row = _current_row_any(self.table)
        if row < 0:
            return ""
        it = self.table.item(row, 5)
        return it.text().strip() if it else ""

    def _on_context_menu(self, pos):
        try:
            it = self.table.itemAt(pos)
            if it is not None:
                self.table.setCurrentCell(it.row(), it.column())

            cur = self.table.currentItem()
            cell_text = cur.text() if cur else ""

            menu = QMenu(self)
            act_copy_cell = menu.addAction("Kopiraj ćeliju")
            act_copy_sel = menu.addAction("Kopiraj selekciju (TSV)")
            menu.addSeparator()

            uid = self._selected_asset_uid()
            act_copy_uid = menu.addAction("Kopiraj Asset UID") if uid else None

            chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
            if chosen == act_copy_cell:
                _copy_text_to_clipboard(cell_text)
            elif chosen == act_copy_sel:
                copy_selected_cells(self.table)
            elif act_copy_uid is not None and chosen == act_copy_uid:
                _copy_text_to_clipboard(uid)
        except Exception:
            pass

    def load(self, met_uid: str):
        try:
            rows = list_metrology_audit(met_uid, limit=200)
        except PermissionError as e:
            rows = []
            QMessageBox.information(self, "RBAC", f"Nemaš pravo da vidiš audit.\n\n{e}")
        except Exception:
            rows = []

        was_sorting = True
        try:
            was_sorting = self.table.isSortingEnabled()
            self.table.setSortingEnabled(False)
        except Exception:
            pass

        try:
            self.table.setUpdatesEnabled(False)
            self.table.clearContents()
            self.table.setRowCount(len(rows or []))

            for idx, r in enumerate(rows or []):
                ts = r.get("ts", "") or r.get("event_time", "") or r.get("created_at", "") or ""
                disp_ts = fmt_dt_sr(str(ts))
                sort_ts = _dt_sort_key_any(ts)

                vals = [
                    ("#", str(idx + 1), idx + 1),
                    ("time", disp_ts, sort_ts),
                    ("actor", r.get("actor", ""), None),
                    ("action", r.get("action", ""), None),
                    ("note", r.get("note", ""), None),
                    ("asset_uid", r.get("asset_uid", ""), None),
                ]

                for c, (_k, v, sort_v) in enumerate(vals):
                    if c in (0, 1):
                        it = SortableItem(str(v), sort_v if sort_v is not None else None)
                    else:
                        it = QTableWidgetItem(str(v))
                    if c == 0:
                        it.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                    self.table.setItem(idx, c, it)

        finally:
            try:
                self.table.setUpdatesEnabled(True)
            except Exception:
                pass
            try:
                self.table.setSortingEnabled(was_sorting)
            except Exception:
                pass

        try:
            self._apply_cols()
        except Exception:
            pass

        _renumber_rows_visible(self.table, rb_col=0)

# (FILENAME: ui/metrology_page.py - END PART 2/3)

# FILENAME: ui/metrology_page.py
# (FILENAME: ui/metrology_page.py - START PART 3/3)

class MetrologyPage(QWidget):
    # ✅ Dodata kolona: Nomenklaturni br.
    COLS = [
        "#",
        "Status",
        "Met UID",
        "Asset UID",
        "Naziv", "Kategorija", "TOC", "Nomenklaturni br.", "Serijski", "Duži", "Lokacija",
        "Tip", "Datum", "Važi do",
        "Izvršilac/Lab", "Sertifikat", "Ažurirano"
    ]

    def __init__(self, logger: logging.Logger, parent=None):
        super().__init__(parent)
        self.logger = logger

        self._col_idx: Dict[str, int] = {name: i for i, name in enumerate(self.COLS)}
        self._IDX_RB = self._col_idx["#"]
        self._IDX_STATUS = self._col_idx["Status"]
        self._IDX_MET_UID = self._col_idx["Met UID"]
        self._IDX_ASSET_UID = self._col_idx["Asset UID"]
        self._IDX_CALIB_DATE = self._col_idx["Datum"]
        self._IDX_VALID_UNTIL = self._col_idx["Važi do"]
        self._IDX_UPDATED_AT = self._col_idx["Ažurirano"]

        from ui.columns_dialog import ColSpec
        self._col_specs = [
            ColSpec(key="rb", label="#", default_visible=True, default_width=60),

            ColSpec(key="status", label="Status", default_visible=True, default_width=110),
            ColSpec(key="met_uid", label="Met UID", default_visible=True, default_width=150),
            ColSpec(key="asset_uid", label="Asset UID", default_visible=True, default_width=170),

            ColSpec(key="asset_name", label="Naziv", default_visible=True, default_width=260),
            ColSpec(key="asset_category", label="Kategorija", default_visible=True, default_width=150),
            ColSpec(key="asset_toc", label="TOC", default_visible=True, default_width=110),
            ColSpec(key="asset_nomen", label="Nomenklaturni br.", default_visible=True, default_width=150),
            ColSpec(key="asset_sn", label="Serijski", default_visible=True, default_width=150),
            ColSpec(key="asset_holder", label="Duži", default_visible=True, default_width=160),
            ColSpec(key="asset_loc", label="Lokacija", default_visible=True, default_width=170),

            ColSpec(key="calib_type", label="Tip", default_visible=True, default_width=140),
            ColSpec(key="calib_date", label="Datum", default_visible=True, default_width=120),
            ColSpec(key="valid_until", label="Važi do", default_visible=True, default_width=120),
            ColSpec(key="provider_name", label="Izvršilac/Lab", default_visible=True, default_width=200),
            ColSpec(key="cert_no", label="Sertifikat", default_visible=True, default_width=160),
            ColSpec(key="updated_at", label="Ažurirano", default_visible=True, default_width=150),
        ]
        self._table_key = "metrology_table_v6"

        self.lb_rbac = QLabel("")
        self.lb_rbac.setWordWrap(True)
        self.lb_rbac.hide()

        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText(
            "Pretraga: asset_uid / naziv / nomenklaturni / TOC / SN / duži / lab / sertifikat / napomena"
        )
        self.ed_search.setClearButtonEnabled(True)

        self.cb_status = QComboBox()
        self.cb_status.addItems(["SVE", "OK", "ISTICE", "ISTEKLO", "NEPOZNATO"])

        self.cb_warn = QComboBox()
        self.cb_warn.addItems(["7", "14", "30", "60", "90"])
        self.cb_warn.setCurrentText("30")

        self.btn_search = QPushButton("Pretraži")
        self.btn_refresh = QPushButton("Osveži")
        self.btn_columns = QPushButton("Kolone")

        self.btn_new = QPushButton("Novi zapis")
        self.btn_details = QPushButton("Detalji")
        self.btn_del = QPushButton("Obriši")
        self.btn_audit = QPushButton("Audit")
        self.btn_asset = QPushButton("Detalji sredstva")

        self.btn_search.setToolTip("Primeni server-side pretragu i osveži listu")
        self.btn_refresh.setToolTip("Osveži (bez popup-a na grešku)")
        self.btn_columns.setToolTip("Prikaži/sakrij kolone, sačuvaj raspored i širine")
        self.btn_asset.setToolTip("Otvori AssetDetailDialog (ako imaš pravo)")

        top = QHBoxLayout()
        top.addWidget(self.ed_search, 3)
        top.addWidget(QLabel("Status:"))
        top.addWidget(self.cb_status, 1)
        top.addWidget(QLabel("Alarm prag (dana):"))
        top.addWidget(self.cb_warn, 1)
        top.addWidget(self.btn_search)
        top.addWidget(self.btn_refresh)
        top.addWidget(self.btn_columns)
        top.addWidget(self.btn_new)
        top.addWidget(self.btn_details)
        top.addWidget(self.btn_del)
        top.addWidget(self.btn_audit)
        top.addWidget(self.btn_asset)

        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        try:
            self.table.setUniformRowHeights(True)
        except Exception:
            pass

        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(True)

        self.table.setSortingEnabled(True)
        hdr.setSectionsClickable(True)
        hdr.setSectionsMovable(True)
        try:
            hdr.setDragEnabled(True)  # type: ignore[attr-defined]
        except Exception:
            pass

        self.table.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        wire_table_selection_plus_copy(self.table)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_context_menu)

        lay = QVBoxLayout(self)
        lay.addLayout(top)

        self.tools = None
        if TableToolsBar is not None and TableToolsConfig is not None:
            cfg = TableToolsConfig(
                placeholder="Filter… (status/met uid/asset uid/naziv/nomen/toc/sn/duži/lokacija/lab/sertifikat)",
                show_sort_toggle=False,
                default_sort_enabled=True,
                filter_columns=None,
            )
            self.tools = TableToolsBar(self.table, cfg, parent=self)
            lay.addWidget(self.tools)
            try:
                self.tools.ed.textChanged.connect(lambda _t: _renumber_rows_visible(self.table, rb_col=self._IDX_RB))
            except Exception:
                pass

        lay.addWidget(self.lb_rbac)
        lay.addWidget(self.table, 1)

        self._load_debounce = QTimer(self)
        self._load_debounce.setSingleShot(True)
        self._load_debounce.setInterval(180)
        self._pending_show_errors = False
        self._load_debounce.timeout.connect(self._do_load_debounced)

        self.btn_search.clicked.connect(lambda: self._schedule_load(show_errors=True))
        self.btn_refresh.clicked.connect(lambda: self._schedule_load(show_errors=False))

        self.btn_new.clicked.connect(self.new_record)
        self.btn_details.clicked.connect(self.open_details)
        self.btn_del.clicked.connect(self.delete_record)
        self.btn_audit.clicked.connect(self.open_audit)
        self.btn_asset.clicked.connect(self.open_asset_detail)

        self.ed_search.returnPressed.connect(lambda: self._schedule_load(show_errors=True))
        self.cb_status.currentIndexChanged.connect(lambda: self._schedule_load(show_errors=False))
        self.cb_warn.currentIndexChanged.connect(lambda: self._schedule_load(show_errors=False))

        self.table.cellDoubleClicked.connect(lambda _r, _c: self.open_details())
        self.table.itemSelectionChanged.connect(self._sync_buttons)

        self._apply_cols = wire_columns(self, self.table, self.btn_columns, self._table_key, self._col_specs)

        try:
            hdr.sortIndicatorChanged.connect(lambda _i, _o: _renumber_rows_visible(self.table, rb_col=self._IDX_RB))
        except Exception:
            pass

        self._assets_cache_mtime: float = 0.0
        self._assets_cache: Dict[str, Dict[str, Any]] = {}

        self._last_db_mtime = _db_mtime_safe()
        self._loading = False
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self._tick_auto_refresh)

        self._apply_rbac()
        self._sync_buttons()
        self.load(show_errors=False)

        if _can(PERM_METRO_VIEW):
            self._timer.start()

    def _apply_rbac(self) -> None:
        can_view = _can(PERM_METRO_VIEW)
        can_write = _can_metro_write()
        can_asset = _can_asset_access_from_metrology()

        for w in [self.table, self.ed_search, self.cb_status, self.cb_warn, self.btn_search, self.btn_refresh, self.btn_columns]:
            try:
                w.setEnabled(can_view)
            except Exception:
                pass

        self.btn_new.setEnabled(can_view and can_write)
        self.btn_del.setEnabled(can_view and can_write)

        self.btn_details.setEnabled(can_view)
        self.btn_audit.setEnabled(can_view)
        self.btn_asset.setEnabled(can_view and can_asset)

        if not can_view:
            self.lb_rbac.setText("Nemaš pravo da vidiš metrologiju (potrebno: metrology.view).")
            self.lb_rbac.show()
            try:
                self.table.setRowCount(0)
            except Exception:
                pass
        else:
            self.lb_rbac.hide()

    def _warn_days(self) -> int:
        try:
            return int(self.cb_warn.currentText().strip())
        except Exception:
            return 30

    def _tick_auto_refresh(self) -> None:
        if self._loading:
            return
        if not self.isVisible():
            return
        if _has_active_modal_dialog():
            return
        m = _db_mtime_safe()
        if m and m != self._last_db_mtime:
            self._last_db_mtime = m
            self._schedule_load(show_errors=False, immediate=True)

    def _selected_met_uid(self) -> str:
        row = _current_row_any(self.table)
        if row < 0:
            return ""
        it = self.table.item(row, self._IDX_MET_UID)
        return it.text().strip() if it else ""

    def _selected_asset_uid(self) -> str:
        row = _current_row_any(self.table)
        if row < 0:
            return ""
        it = self.table.item(row, self._IDX_ASSET_UID)
        return it.text().strip() if it else ""

    def _sync_buttons(self) -> None:
        can_view = _can(PERM_METRO_VIEW)
        can_write = _can_metro_write()
        can_asset = _can_asset_access_from_metrology()

        met_uid = self._selected_met_uid()
        has_sel = bool(met_uid)

        self.btn_details.setEnabled(can_view and has_sel)
        self.btn_audit.setEnabled(can_view and has_sel)
        self.btn_del.setEnabled(can_view and can_write and has_sel)

        asset_uid = self._selected_asset_uid()
        self.btn_asset.setEnabled(can_view and can_asset and bool(asset_uid))

    def _on_context_menu(self, pos):
        try:
            it = self.table.itemAt(pos)
            if it is not None:
                self.table.setCurrentCell(it.row(), it.column())

            cur = self.table.currentItem()
            cell_text = cur.text() if cur else ""

            met_uid = self._selected_met_uid()
            asset_uid = self._selected_asset_uid()

            menu = QMenu(self)
            act_copy_cell = menu.addAction("Kopiraj ćeliju")
            act_copy_sel = menu.addAction("Kopiraj selekciju (TSV)")
            menu.addSeparator()

            act_copy_met = menu.addAction("Kopiraj Met UID") if met_uid else None
            act_copy_asset = menu.addAction("Kopiraj Asset UID") if asset_uid else None

            menu.addSeparator()
            act_open_details = menu.addAction("Otvori detalje") if met_uid else None
            act_open_asset = menu.addAction("Otvori detalje sredstva") if asset_uid else None

            chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
            if chosen == act_copy_cell:
                _copy_text_to_clipboard(cell_text)
            elif chosen == act_copy_sel:
                copy_selected_cells(self.table)
            elif act_copy_met is not None and chosen == act_copy_met:
                _copy_text_to_clipboard(met_uid)
            elif act_copy_asset is not None and chosen == act_copy_asset:
                _copy_text_to_clipboard(asset_uid)
            elif act_open_details is not None and chosen == act_open_details:
                self.open_details()
            elif act_open_asset is not None and chosen == act_open_asset:
                self.open_asset_detail()
        except Exception:
            pass

    def _safe_asset_map(self, assets: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        m: Dict[str, Dict[str, Any]] = {}
        for a in assets or []:
            if not isinstance(a, dict):
                continue
            uid = str(a.get("asset_uid", "") or "").strip()
            if uid:
                m[uid] = a
        return m

    def _get_assets_map_cached(self) -> Dict[str, Dict[str, Any]]:
        """
        ✅ Metrology-only cache:
        - Ako možemo da dohvatimo assets_brief, uzimamo samo metrologija sredstva (flag=1).
        - Ovo nam omogućava da u listi metrologije sakrijemo zapise koji su vezani za ne-metrologija sredstva.
        """
        if not _can_asset_access_from_metrology():
            return {}

        mtime = _db_mtime_safe()
        if mtime and mtime == self._assets_cache_mtime and self._assets_cache:
            return self._assets_cache

        assets = _list_assets_brief_safe(limit=5000, metrology_only=True)
        self._assets_cache = self._safe_asset_map(assets)
        self._assets_cache_mtime = mtime
        return self._assets_cache

    def _schedule_load(self, show_errors: bool = False, immediate: bool = False) -> None:
        self._pending_show_errors = bool(show_errors)
        if immediate:
            self._load_debounce.stop()
            self._do_load_debounced()
            return
        self._load_debounce.start()

    def _do_load_debounced(self) -> None:
        self.load(show_errors=self._pending_show_errors)

    def _reselect_by_met_uid(self, met_uid: str) -> None:
        if not met_uid:
            return
        try:
            rc = self.table.rowCount()
            for r in range(rc):
                it = self.table.item(r, self._IDX_MET_UID)
                if it and it.text().strip() == met_uid:
                    self.table.setCurrentCell(r, self._IDX_MET_UID)
                    return
        except Exception:
            pass

    def load(self, show_errors: bool = False) -> None:
        if not _can(PERM_METRO_VIEW):
            self._apply_rbac()
            return

        if self._loading:
            return

        self._loading = True
        prev_sel_met_uid = self._selected_met_uid()

        was_sorting = True
        try:
            was_sorting = self.table.isSortingEnabled()
            self.table.setSortingEnabled(False)
        except Exception:
            pass

        try:
            q = self.ed_search.text().strip()
            status_filter = self.cb_status.currentText().strip()
            warn_days = self._warn_days()

            rows = _list_metrology_rows_safe(
                q=q,
                limit=5000,
                warn_days=warn_days,
                prefer_my=_is_basic_user(),
            )

            assets_map: Dict[str, Dict[str, Any]] = self._get_assets_map_cached()

            filtered: List[Dict[str, Any]] = []
            for rr in rows or []:
                if not isinstance(rr, dict):
                    continue
                r = dict(rr)  # ne mutiramo “u mestu”

                asset_uid = str(r.get("asset_uid", "") or "").strip()
                is_orphan = int(r.get("is_orphan") or 0) == 1

                # ✅ Metrology-only enforcement (kada assets_map postoji):
                # - ako asset postoji u metrology-only map-u -> OK
                # - ako NIJE u map-u i nije orphan -> preskoči (nije metrology asset ili nema flag)
                if assets_map and asset_uid:
                    if (asset_uid not in assets_map) and (not is_orphan):
                        continue

                calib_date_iso = str(r.get("calib_date", "") or "")
                valid_until_iso = str(r.get("valid_until", "") or "")

                st = _status_for_record_ui(calib_date_iso, valid_until_iso, warn_days=warn_days)

                if status_filter != "SVE" and st != status_filter:
                    continue

                r["_status_ui"] = st
                filtered.append(r)

            self.table.setUpdatesEnabled(False)
            self.table.clearContents()
            self.table.setRowCount(len(filtered))

            sortable_cols = {self._IDX_RB, self._IDX_CALIB_DATE, self._IDX_VALID_UNTIL, self._IDX_UPDATED_AT}

            for idx, r in enumerate(filtered):
                met_uid = str(r.get("met_uid", "") or "").strip()
                asset_uid = str(r.get("asset_uid", "") or "").strip()

                a = assets_map.get(asset_uid) if (asset_uid and assets_map) else None
                status_txt = str(r.get("_status_ui", "") or "")

                asset_name = _asset_field(a, "name")
                asset_cat = _asset_field(a, "category")
                asset_toc = _asset_field(a, "toc_number", "toc")
                asset_nomen = _asset_field(a, "nomenclature_number", "nomenklaturni_broj", "nomenclature_no", "nomen_number", "nomenklatura")
                asset_sn = _asset_field(a, "serial_number", "serial", "sn")
                asset_holder = _asset_field(a, "current_holder", "assigned_to")
                asset_loc = _asset_field(a, "location")

                calib_date_iso = str(r.get("calib_date", "") or "")
                valid_until_iso = str(r.get("valid_until", "") or "")
                updated_raw = r.get("updated_at", "") or r.get("modified_at", "") or ""

                vals: List[str] = [
                    str(idx + 1),
                    status_txt,
                    met_uid,
                    asset_uid,

                    asset_name,
                    asset_cat,
                    asset_toc,
                    asset_nomen,
                    asset_sn,
                    asset_holder,
                    asset_loc,

                    str(r.get("calib_type", "") or ""),
                    fmt_date_sr(calib_date_iso),
                    fmt_date_sr(valid_until_iso),
                    str(r.get("provider_name", "") or ""),
                    str(r.get("cert_no", "") or ""),
                    fmt_dt_sr(str(updated_raw)),
                ]

                sort_key_map: Dict[int, Optional[Any]] = {
                    self._IDX_RB: idx + 1,
                    self._IDX_CALIB_DATE: _iso_date_sort_key(calib_date_iso),
                    self._IDX_VALID_UNTIL: _iso_date_sort_key(valid_until_iso),
                    self._IDX_UPDATED_AT: _dt_sort_key_any(updated_raw),
                }

                is_orphan = int(r.get("is_orphan") or 0) == 1

                for c, disp in enumerate(vals):
                    if c in sortable_cols:
                        it = SortableItem(str(disp), sort_key_map.get(c))
                    else:
                        it = QTableWidgetItem(str(disp))

                    if c == self._IDX_RB:
                        it.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

                    if is_orphan and c == self._IDX_ASSET_UID:
                        try:
                            it.setToolTip("ORPHAN: Metrologija postoji, ali sredstvo nije u assets tabeli.")
                        except Exception:
                            pass

                    self.table.setItem(idx, c, it)

                _apply_status_badge(self.table, idx, status_txt, col_status=self._IDX_STATUS)

        except PermissionError as e:
            if show_errors:
                QMessageBox.information(self, "RBAC", f"Nemaš pravo.\n\n{e}")
        except Exception as e:
            if show_errors:
                QMessageBox.critical(self, "Greška", f"Ne mogu da učitam listu.\n\n{e}")
            try:
                self.logger.exception("MetrologyPage.load failed: %s", e)
            except Exception:
                pass
        finally:
            try:
                self.table.setUpdatesEnabled(True)
            except Exception:
                pass
            try:
                self.table.setSortingEnabled(was_sorting)
            except Exception:
                pass
            self._loading = False

        try:
            self._apply_cols()
        except Exception:
            pass

        _renumber_rows_visible(self.table, rb_col=self._IDX_RB)
        self._reselect_by_met_uid(prev_sel_met_uid)
        self._sync_buttons()

    def new_record(self) -> None:
        if not _can(PERM_METRO_VIEW):
            QMessageBox.information(self, "RBAC", "Nemaš pravo da vidiš metrologiju.")
            return
        if not _can_metro_write():
            QMessageBox.information(self, "RBAC", "Nemaš pravo da upisuješ metrologiju.")
            return

        assets: List[Dict[str, Any]] = []
        if _can_asset_access_from_metrology():
            assets = _list_assets_brief_safe(limit=5000, metrology_only=True)

        dlg = MetrologyEditDialog(assets, existing=None, parent=self)
        if dlg.exec() != QDialog.Accepted:
            return

        v = dlg.values()
        try:
            met_uid = create_metrology_record(
                actor=_actor_name(),
                asset_uid=v["asset_uid"],
                calib_type=v["calib_type"],
                calib_date=v["calib_date"],
                valid_until=v["valid_until"],
                provider_name=v["provider_name"],
                cert_no=v["cert_no"],
                notes=v["notes"],
            )
            QMessageBox.information(self, "OK", f"Zapis je kreiran.\n\nMet UID: {met_uid}")
            self._last_db_mtime = _db_mtime_safe()
            self._schedule_load(show_errors=False, immediate=True)
        except PermissionError as e:
            QMessageBox.information(self, "RBAC", f"Nemaš pravo.\n\n{e}")
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da kreiram zapis.\n\n{e}")

    def open_details(self) -> None:
        met_uid = self._selected_met_uid()
        if not met_uid:
            return
        dlg = MetrologyDetailsDialog(
            met_uid,
            parent=self,
            on_changed=lambda: self._schedule_load(show_errors=False, immediate=True),
            warn_days=self._warn_days()
        )
        dlg.exec()

    def open_audit(self) -> None:
        met_uid = self._selected_met_uid()
        if not met_uid:
            return
        dlg = MetrologyAuditDialog(met_uid, parent=self)
        dlg.exec()

    def open_asset_detail(self) -> None:
        if not _can_asset_access_from_metrology():
            QMessageBox.information(self, "RBAC", "Nemaš pravo da otvoriš detalje sredstva.")
            return
        uid = self._selected_asset_uid()
        if not uid:
            return
        try:
            from ui.asset_detail_dialog import AssetDetailDialog  # type: ignore
            dlg = AssetDetailDialog(uid, self)
            dlg.exec()
        except PermissionError as e:
            QMessageBox.information(self, "RBAC", f"Nemaš pravo.\n\n{e}")
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da otvorim detalje sredstva.\n\n{e}")

    def delete_record(self) -> None:
        if not _can_metro_write():
            QMessageBox.information(self, "RBAC", "Nemaš pravo da brišeš metrologiju.")
            return
        met_uid = self._selected_met_uid()
        if not met_uid:
            return

        if QMessageBox.question(self, "Potvrda", f"Obrisati metrology zapis?\n\n{met_uid}") != QMessageBox.Yes:
            return

        try:
            okk = delete_metrology_record(actor=_actor_name(), met_uid=met_uid)
            if okk:
                QMessageBox.information(self, "OK", "Zapis je obrisan.")
                self._last_db_mtime = _db_mtime_safe()
                self._schedule_load(show_errors=False, immediate=True)
            else:
                QMessageBox.warning(self, "Nije uspelo", "Zapis ne postoji ili je već obrisan.")
        except PermissionError as e:
            QMessageBox.information(self, "RBAC", f"Nemaš pravo.\n\n{e}")
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da obrišem zapis.\n\n{e}")

# (FILENAME: ui/metrology_page.py - END PART 3/3)