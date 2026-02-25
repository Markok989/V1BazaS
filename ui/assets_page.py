# FILENAME: ui/assets_page.py
# (FILENAME: ui/assets_page.py - START PART 1/3)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/assets_page.py

AssetsPage (V1):
- Tabovi: Aktivna / Bez zaduženja / Rashodovana / Sva
- Filteri: DB pretraga (Enter/Pretraži) + lokalni backstop
- Scope: Sva / Moja oprema / Metrologija (RBAC driven)
- Preview panel (collapse/expand) + sort persist + splitter persist
- Context menu + Copy UID + shortcuts (Enter samo nad tabelom)

Senior patch (stabilnost/UX):
- FIX: textChanged u search NE radi DB reload (samo state+chips) — DB fetch ide na Enter/Pretraži/Osveži.
- FIX: “Reset layout” sada resetuje i KOLONE (čisti wire_columns state + runtime vrati default).
- FIX: Row tint accent traka prati prvu VIDLJIVU kolonu (posle reorder/hide).
- Stabilnost: fail-soft importi, guard-ovi, ne ruši UI ako helper nije tu.
- NEW (compat): priprema za "scope-aware" service call (ako list_assets podrži scope/actor/sector u potpisu).

Patch (2026-02-26):
- FIX: fatal crash kada metoda _on_reload_timeout nije vidljiva (indent/copy-paste) — safe-connect fallback na load_assets().
- UX: dodata kolona "Sektor" u tabeli + u preview panelu (bez promene postojećih indeksa).
- Compat: bump wire_columns key na v11 da se stari layout ne sudara sa novom kolonom.
"""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import (
    Qt,
    QTimer,
    QByteArray,
    QVariantAnimation,
    QEasingCurve,
    QEvent,
    QSettings,
    QRect,
)  # type: ignore
from PySide6.QtGui import (
    QColor,
    QBrush,
    QCursor,
    QPainter,
    QPalette,
    QKeySequence,
    QShortcut,
)  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QApplication,
    QWidget,
    QFrame,
    QLabel,
    QPushButton,
    QToolButton,
    QLineEdit,
    QComboBox,
    QTabWidget,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QAbstractItemView,
    QHeaderView,
    QHBoxLayout,
    QVBoxLayout,
    QFormLayout,
    QMessageBox,
    QMenu,
    QDialog,
    QStyle,
    QStyledItemDelegate,
)

# -------------------- optional helpers (safe import) --------------------
wire_columns = None
wire_table_selection_plus_copy = None
TableToolsBar = None
TableToolsConfig = None

try:
    from ui.utils.table_columns import wire_columns  # type: ignore
except Exception:
    wire_columns = None  # type: ignore

try:
    from ui.utils.table_copy import wire_table_selection_plus_copy  # type: ignore
except Exception:
    wire_table_selection_plus_copy = None  # type: ignore

try:
    from ui.utils.table_search_sort import TableToolsBar, TableToolsConfig  # type: ignore
except Exception:
    TableToolsBar = None  # type: ignore
    TableToolsConfig = None  # type: ignore

# -------------------- RBAC perms (prefer core.rbac constants) --------------------
try:
    from core.rbac import (  # type: ignore
        PERM_ASSETS_VIEW,
        PERM_ASSETS_CREATE,
        PERM_ASSETS_MY_VIEW,
        PERM_ASSETS_METRO_VIEW,
    )
except Exception:
    PERM_ASSETS_VIEW = "assets.view"
    PERM_ASSETS_CREATE = "assets.create"
    PERM_ASSETS_MY_VIEW = "assets.my.view"
    PERM_ASSETS_METRO_VIEW = "assets.metrology.view"

# -------------------- services/dialogs (safe import) --------------------
try:
    from services.assets_service import list_assets, create_asset  # type: ignore
except Exception:
    list_assets = None
    create_asset = None

try:
    from ui.asset_detail_dialog import AssetDetailDialog  # type: ignore
except Exception:
    AssetDetailDialog = None

try:
    from ui.new_asset_dialog import NewAssetDialog  # type: ignore
except Exception:
    NewAssetDialog = None


# -------------------- helpers --------------------
def _can(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _actor_name() -> str:
    try:
        from core.session import actor_name  # type: ignore
        return (actor_name() or "user").strip() or "user"
    except Exception:
        return "user"


def _actor_key() -> str:
    try:
        from core.session import actor_key  # type: ignore
        return (actor_key() or "").strip()
    except Exception:
        return ""


def _actor_sector_id() -> Optional[int]:
    """
    Best-effort: ako session ekspozuje sector_id/sector, koristi ga (za budući sector-scope).
    Ne ruši UI ako ne postoji.
    """
    try:
        from core import session as _s  # type: ignore
        for name in ("actor_sector_id", "sector_id", "actor_sector", "sector"):
            fn = getattr(_s, name, None)
            if callable(fn):
                v = fn()
                if v is None or v is False:
                    return None
                try:
                    return int(v)
                except Exception:
                    return None
    except Exception:
        return None
    return None


def _settings() -> QSettings:
    return QSettings("BazaS2", "BazaS2")


def _norm(x: Any) -> str:
    try:
        return str(x or "").strip()
    except Exception:
        return ""


def _cf(x: Any) -> str:
    return _norm(x).casefold()


def _is_dark_theme() -> bool:
    try:
        a = QApplication.instance()
        pal = a.palette() if a else QApplication.palette()
        return pal.color(QPalette.Window).value() < 128
    except Exception:
        return True


def _qss_banner(dark: bool) -> str:
    if dark:
        return (
            "padding:10px 12px; border-radius:14px;"
            "background: rgba(255,255,255,0.06); color: rgba(255,255,255,0.92);"
            "border:1px solid rgba(255,255,255,0.14);"
        )
    return (
        "padding:10px 12px; border-radius:14px;"
        "background: rgba(0,0,0,0.04); color: rgba(0,0,0,0.82);"
        "border:1px solid rgba(0,0,0,0.12);"
    )


def _qss_empty(dark: bool) -> str:
    if dark:
        return "padding: 10px; color: rgba(255,255,255,0.55); font-weight:600;"
    return "padding: 10px; color: rgba(0,0,0,0.45); font-weight:600;"


def fmt_dt_sr(x: Any) -> str:
    try:
        from ui.utils.datetime_fmt import fmt_dt_sr as _f  # type: ignore
        return str(_f(x))
    except Exception:
        return _norm(x)


def _status_key(raw: Any) -> str:
    s = _cf(raw)
    if not s:
        return "unknown"
    if any(x in s for x in ("rashod", "otpis", "retired", "disposed", "decommission", "archiv", "inactive", "scrap")):
        return "scrapped"
    if any(x in s for x in ("serv", "repair", "kalibr", "metrolog", "service")):
        return "service"
    if any(x in s for x in ("loan", "assign", "zadu", "duž", "duzi", "on_loan")):
        return "on_loan"
    if s in ("active", "in_use", "u_upotrebi", "aktivno", "aktivna"):
        return "active"
    return s


def _safe_int(v: Any) -> Optional[int]:
    try:
        if v is None or isinstance(v, bool):
            return None
        if isinstance(v, int):
            return v
        if isinstance(v, float):
            return int(v)
        s = _norm(v)
        digits = "".join(ch for ch in s if ch.isdigit())
        return int(digits) if digits else None
    except Exception:
        return None


def _safe_dt_sort_value(v: Any) -> Optional[int]:
    try:
        if v is None:
            return None
        if isinstance(v, datetime):
            return int(v.timestamp())
        s = _norm(v).replace("Z", "").replace("T", " ")
        if not s:
            return None
        return int(datetime.fromisoformat(s).timestamp())
    except Exception:
        return None


def _row_as_dict(r: Any) -> Dict[str, Any]:
    if isinstance(r, dict):
        return r
    try:
        return dict(r)
    except Exception:
        return {}


def _get_nomenclature(r: Dict[str, Any]) -> str:
    for k in ("nomenclature_no", "nomenclature_number", "nomenklaturni_broj", "nom_broj", "nom_no", "nomen"):
        v = _norm((r or {}).get(k, ""))
        if v:
            return v
    return ""


def _get_sector(r: Dict[str, Any]) -> str:
    for k in ("sector", "sektor", "org_unit", "unit", "department", "dept", "sector_code", "sector_id"):
        v = _norm((r or {}).get(k, ""))
        if v:
            return v
    return ""


def _is_scrapped(r: Dict[str, Any]) -> bool:
    return _status_key((r or {}).get("status", "")) == "scrapped"


def _is_unassigned(r: Dict[str, Any]) -> bool:
    return not _norm((r or {}).get("current_holder", "") or (r or {}).get("assigned_to", ""))


def _scope_candidates_lower() -> List[str]:
    cand: List[str] = []
    ak = _actor_key()
    if ak:
        cand.append(ak)
    an = _actor_name()
    if an:
        cand.append(an)

    out: List[str] = []
    seen = set()
    for c in cand:
        cc = _norm(c).casefold()
        if cc and cc not in seen:
            seen.add(cc)
            out.append(cc)
    return out


def _is_my_asset_ui(r: Dict[str, Any]) -> bool:
    """
    UI convenience filter (ne security filter):
    - koristi samo kao narrowing filter (za korisnike koji ionako imaju full view),
      jer heuristika može promašiti ako se holder string razlikuje od actor_name.
    """
    holder = _norm((r or {}).get("current_holder", "") or (r or {}).get("assigned_to", ""))
    if not holder:
        return False
    h = holder.casefold()
    return any(h == c for c in _scope_candidates_lower())


def _is_metro_asset_ui(r: Dict[str, Any]) -> bool:
    cat = _cf((r or {}).get("category", ""))
    if "metrolog" in cat:
        return True
    for k in ("is_metrology", "metrology_flag", "metro_flag", "needs_calibration", "calibration_required", "metrology_scope"):
        if k in (r or {}):
            try:
                if bool((r or {}).get(k)):
                    return True
            except Exception:
                pass
    return False


def _try_create_assignment_after_create(asset_uid: str, to_holder: str, to_location: str = "", note: str = "") -> None:
    uid = _norm(asset_uid)
    holder = _norm(to_holder)
    if not uid or not holder:
        return
    try:
        from services.assignments_service import create_assignment  # type: ignore
        create_assignment(
            actor=_actor_name(),
            asset_uid=uid,
            action="assign",
            to_holder=holder,
            to_location=_norm(to_location),
            note=_norm(note),
            source="ui_new_asset_autozad",
        )
        return
    except Exception:
        pass
    try:
        from core.db import create_assignment_db  # type: ignore
        create_assignment_db(
            actor=_actor_name(),
            asset_uid=uid,
            action="assign",
            to_holder=holder,
            to_location=_norm(to_location),
            note=_norm(note),
            source="ui_new_asset_autozad",
        )
    except Exception:
        return


# -------------------- Sortable item (numeric-friendly sorting) --------------------
class SortableItem(QTableWidgetItem):
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


# -------------------- Chips --------------------
@dataclass
class ChipSpec:
    text: str
    on_remove: Callable[[], None]
    tooltip: str = ""


class FilterChipsBar(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.NoFrame)
        self._clear: Optional[Callable[[], None]] = None

        self.btn_clear = QPushButton("Očisti sve")
        self.btn_clear.clicked.connect(lambda: self._clear and self._clear())

        self.host = QWidget(self)
        self.hlay = QHBoxLayout(self.host)
        self.hlay.setContentsMargins(0, 0, 0, 0)
        self.hlay.setSpacing(6)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        lay.addWidget(QLabel("Aktivni filteri:"), 0)
        lay.addWidget(self.host, 1)
        lay.addWidget(self.btn_clear, 0)

        self.refresh_theme()
        self.set_chips([])

    def set_clear_all_handler(self, fn: Callable[[], None]) -> None:
        self._clear = fn

    def refresh_theme(self) -> None:
        try:
            dark = _is_dark_theme()
            if dark:
                self.setStyleSheet(
                    "QLabel{ color: rgba(255,255,255,0.78); font-weight:700; }"
                    "QPushButton{ padding:6px 10px; border-radius:12px;"
                    " background: rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.16);"
                    " color: rgba(255,255,255,0.90); }"
                    "QPushButton:hover{ background: rgba(255,255,255,0.10); border-color: rgba(255,255,255,0.28); }"
                )
            else:
                self.setStyleSheet(
                    "QLabel{ color: rgba(0,0,0,0.68); font-weight:700; }"
                    "QPushButton{ padding:6px 10px; border-radius:12px;"
                    " background: rgba(0,0,0,0.04); border:1px solid rgba(0,0,0,0.12);"
                    " color: rgba(0,0,0,0.86); }"
                    "QPushButton:hover{ background: rgba(0,0,0,0.07); border-color: rgba(0,0,0,0.20); }"
                )
        except Exception:
            pass

    def set_chips(self, chips: List[ChipSpec]) -> None:
        try:
            while self.hlay.count():
                it = self.hlay.takeAt(0)
                w = it.widget()
                if w:
                    w.deleteLater()
        except Exception:
            pass

        for ch in chips:
            b = QPushButton(ch.text)
            b.setToolTip(ch.tooltip or ch.text)
            b.setCursor(QCursor(Qt.PointingHandCursor))
            b.clicked.connect(ch.on_remove)
            self.hlay.addWidget(b, 0)

        self.hlay.addStretch(1)
        self.btn_clear.setVisible(bool(chips))
        self.setVisible(bool(chips))


# -------------------- Row tint delegate --------------------
class _RowTintDelegate(QStyledItemDelegate):
    def __init__(self, table: QTableWidget, status_col: int, palette: Dict[str, Tuple[QColor, QColor]], accent_px: int = 3):
        super().__init__(table)
        self._tbl = table
        self._status_col = int(status_col)
        self._palette = dict(palette or {})
        self._accent_px = max(1, int(accent_px))

    def _is_first_visible_column(self, logical_col: int) -> bool:
        try:
            hdr = self._tbl.horizontalHeader()
            return hdr.visualIndex(int(logical_col)) == 0
        except Exception:
            return logical_col == 0

    def paint(self, painter: QPainter, option, index) -> None:  # type: ignore[override]
        try:
            row = int(index.row())
            col = int(index.column())
        except Exception:
            super().paint(painter, option, index)
            return

        try:
            is_selected = bool(option.state & QStyle.State_Selected)
        except Exception:
            is_selected = False

        st = "unknown"
        try:
            it = self._tbl.item(row, self._status_col)
            st = _status_key(it.text() if it else "")
        except Exception:
            st = "unknown"

        accent, tint = self._palette.get(st, self._palette.get("unknown", (QColor("#a0a6b6"), QColor(0, 0, 0, 0))))

        painter.save()
        if not is_selected:
            try:
                painter.fillRect(option.rect, tint)
            except Exception:
                pass

        if self._is_first_visible_column(col):
            try:
                r = QRect(option.rect)
                stripe = QRect(r.left(), r.top(), self._accent_px, r.height())
                painter.fillRect(stripe, accent)
            except Exception:
                pass

        painter.restore()
        super().paint(painter, option, index)


# -------------------- Preview panel --------------------
class AssetPreviewPanel(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)

        self._collapsed = False
        self._cw = 64
        self._ew = 360
        self._uid = ""

        self._open: Optional[Callable[[], None]] = None
        self._toggle: Optional[Callable[[], None]] = None

        self.title = QLabel("Pregled sredstva")

        self.btn_toggle = QToolButton(self)
        self.btn_toggle.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_toggle.clicked.connect(lambda: self._toggle and self._toggle())

        self.btn_open = QPushButton("Otvori detalje")
        self.btn_open.clicked.connect(lambda: self._open and self._open())

        self.btn_copy = QPushButton("Kopiraj UID")
        self.btn_copy.clicked.connect(self._copy_uid)

        self._fields: Dict[str, QLabel] = {}
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft)
        form.setFormAlignment(Qt.AlignTop)

        def _add(k: str, lbl: str) -> None:
            v = QLabel("—")
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            v.setWordWrap(True)
            self._fields[k] = v
            form.addRow(QLabel(lbl), v)

        for k, lbl in [
            ("asset_uid", "Asset UID:"),
            ("rb", "RB:"),
            ("toc_number", "TOC:"),
            ("nomenclature", "Nomenkl. broj:"),
            ("serial_number", "Serijski:"),
            ("name", "Naziv:"),
            ("category", "Kategorija:"),
            ("status", "Status:"),
            ("current_holder", "Zaduženo kod:"),
            ("location", "Lokacija:"),
            ("sector", "Sektor:"),
            ("updated_at", "Ažurirano:"),
        ]:
            _add(k, lbl)

        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(8)
        head.addWidget(self.title, 1)
        head.addWidget(self.btn_toggle, 0, Qt.AlignRight)

        btns = QHBoxLayout()
        btns.setContentsMargins(0, 0, 0, 0)
        btns.setSpacing(8)
        btns.addWidget(self.btn_open, 1)
        btns.addWidget(self.btn_copy, 1)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)
        lay.addLayout(head)
        lay.addLayout(form)
        lay.addStretch(1)
        lay.addLayout(btns)

        self.refresh_theme()
        self._refresh_toggle()

    def refresh_theme(self) -> None:
        try:
            dark = _is_dark_theme()
            base = (
                "QToolButton{ padding:6px 10px; border-radius:12px; }"
                "QPushButton{ padding:6px 10px; border-radius:12px; }"
            )
            if dark:
                self.setStyleSheet(
                    base
                    + "QToolButton{ border:1px solid rgba(255,255,255,0.22); background:rgba(255,255,255,0.06); color:rgba(255,255,255,0.90); }"
                      "QToolButton:hover{ border-color:rgba(255,255,255,0.40); background:rgba(255,255,255,0.10); }"
                      "QPushButton{ border:1px solid rgba(255,255,255,0.18); background:rgba(255,255,255,0.06); color:rgba(255,255,255,0.90); }"
                      "QPushButton:hover{ border-color:rgba(255,255,255,0.32); background:rgba(255,255,255,0.10); }"
                )
            else:
                self.setStyleSheet(
                    base
                    + "QToolButton{ border:1px solid rgba(0,0,0,0.18); background:rgba(0,0,0,0.04); color:rgba(0,0,0,0.86); }"
                      "QToolButton:hover{ border-color:rgba(0,0,0,0.28); background:rgba(0,0,0,0.07); }"
                      "QPushButton{ border:1px solid rgba(0,0,0,0.12); background:rgba(0,0,0,0.04); color:rgba(0,0,0,0.86); }"
                      "QPushButton:hover{ border-color:rgba(0,0,0,0.20); background:rgba(0,0,0,0.07); }"
                )
        except Exception:
            pass

    def set_open_handler(self, fn: Callable[[], None]) -> None:
        self._open = fn

    def set_toggle_handler(self, fn: Callable[[], None]) -> None:
        self._toggle = fn

    def set_toggle_enabled(self, en: bool) -> None:
        try:
            self.btn_toggle.setEnabled(bool(en))
        except Exception:
            pass

    def collapsed_width(self) -> int:
        return int(self._cw)

    def expanded_width_hint(self) -> int:
        return int(self._ew)

    def set_collapsed(self, collapsed: bool) -> None:
        self._collapsed = bool(collapsed)
        self._refresh_toggle()

        vis = not self._collapsed
        for w in [self.title, self.btn_open, self.btn_copy, *self._fields.values()]:
            try:
                w.setVisible(vis)
            except Exception:
                pass

        try:
            if self._collapsed:
                self.setMinimumWidth(self._cw)
                self.setMaximumWidth(self._cw)
            else:
                self.setMinimumWidth(self._ew)
                self.setMaximumWidth(16777215)
        except Exception:
            pass

    def _refresh_toggle(self) -> None:
        try:
            st = self.style()
            if not self._collapsed:
                self.btn_toggle.setIcon(st.standardIcon(QStyle.SP_ArrowRight))
                self.btn_toggle.setText("Sakrij")
                self.btn_toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            else:
                self.btn_toggle.setIcon(st.standardIcon(QStyle.SP_ArrowLeft))
                self.btn_toggle.setText("")
                self.btn_toggle.setToolButtonStyle(Qt.ToolButtonIconOnly)
        except Exception:
            pass

    def clear(self) -> None:
        self._uid = ""
        for lb in self._fields.values():
            lb.setText("—")
            try:
                lb.setStyleSheet("")
            except Exception:
                pass

    def set_asset(self, r: Dict[str, Any]) -> None:
        if not isinstance(r, dict) or not r:
            self.clear()
            return

        self._uid = _norm(r.get("asset_uid", ""))

        def _set(k: str, v: Any) -> None:
            lb = self._fields.get(k)
            if lb:
                lb.setText(_norm(v) or "—")

        _set("asset_uid", self._uid)
        _set("rb", r.get("rb", ""))
        _set("toc_number", r.get("toc_number", ""))

        nom = _get_nomenclature(r)
        _set("nomenclature", nom)

        for k in ("serial_number", "name", "category", "status", "current_holder", "location"):
            _set(k, r.get(k, ""))

        _set("sector", _get_sector(r))
        _set("updated_at", fmt_dt_sr(r.get("updated_at", "")))

        try:
            lb = self._fields.get("nomenclature")
            if lb:
                lb.setStyleSheet("" if nom else "color:#ff8a80;font-weight:700;")
                lb.setToolTip("" if nom else "Nomenklaturni broj nije unet.")
        except Exception:
            pass

    def _copy_uid(self) -> None:
        if not self._uid:
            return
        try:
            QApplication.clipboard().setText(self._uid)
        except Exception:
            pass


# -------------------- ColSpec (fallback) --------------------
@dataclass
class ColSpec:
    key: str
    label: str
    default_visible: bool = True
    default_width: int = 120


# -------------------- AssetsPage --------------------
class AssetsPage(QWidget):
    COLS = [
        "#",
        "Asset UID", "TOC", "Nomenkl. broj", "Serijski",
        "Naziv", "Kategorija", "Status",
        "Zaduženo kod", "Lokacija", "Ažurirano",
        "Sektor",
    ]

    COL_IDX_ROWNUM = 0
    COL_IDX_UID = 1
    COL_IDX_TOC = 2
    COL_IDX_NOM = 3
    COL_IDX_SN = 4
    COL_IDX_NAME = 5
    COL_IDX_CAT = 6
    COL_IDX_STATUS = 7
    COL_IDX_HOLDER = 8
    COL_IDX_LOC = 9
    COL_IDX_UPD = 10
    COL_IDX_SECTOR = 11

    TAB_ACTIVE = "Aktivna"
    TAB_UNASSIGNED = "Bez zaduženja"
    TAB_SCRAPPED = "Rashodovana"
    TAB_ALL = "Sva"

    SCOPE_ALL = "Sva sredstva"
    SCOPE_MY = "Moja oprema"
    SCOPE_METRO = "Metrologija (scope)"

    _SET_GROUP = "ui/assets_page"
    _K_TAB = "tab_index"
    _K_SCOPE = "scope_text"
    _K_CAT = "category"
    _K_STATUS = "status"
    _K_SEARCH = "search"
    _K_QUICK = "quick_filter"
    _K_PREV_COLL = "preview_collapsed"
    _K_PREV_W = "preview_width"
    _K_SPLITTER = "splitter_state"
    _K_SORT_COL = "sort_col"
    _K_SORT_ORDER = "sort_order"
    _K_HDR_STATE = "header_state_fallback"

    _HARD_LIMIT = 5000

    def __init__(self, logger: Optional[logging.Logger] = None, parent=None):
        super().__init__(parent)
        self.setObjectName("AssetsPage")
        self.logger = logger or logging.getLogger(__name__)

        # wire_columns storage key (bitno za reset kolona)
        self._cols_key = "assets_table_v11"

        # RBAC flags
        self._has_any_view = False
        self._has_full_view = False
        self._has_my_view = False
        self._has_metro_view = False

        # state
        self._loading = False
        self._hidden_cache: List[bool] = []
        self._sort_col = -1
        self._sort_order = Qt.AscendingOrder

        # service signature cache (performance + stability)
        self._list_assets_param_names: Optional[set] = None

        # pending restore
        self._pending_splitter_state: Optional[QByteArray] = None
        self._pending_preview_collapsed: Optional[bool] = None
        self._pending_preview_width: Optional[int] = None
        self._pending_sort: Optional[Tuple[int, Qt.SortOrder]] = None
        self._pending_header_state: Optional[QByteArray] = None
        self._layout_restored_once = False

        # preview anim
        self._preview_collapsed = False
        self._preview_last_w: Optional[int] = None
        self._preview_anim: Optional[QVariantAnimation] = None
        self._preview_animating = False
        self._anim_last_right: Optional[int] = None
        self._anim_saved_stretch_last: Optional[bool] = None
        self._anim_saved_vp_mode: Optional[QAbstractItemView.ViewportUpdateMode] = None

        # palette
        self._row_paint_palette: Dict[str, Tuple[QColor, QColor]] = {}
        self._status_text_color: Dict[str, QColor] = {}
        self._init_status_palette()

        # timers
        self._reload_timer = QTimer(self)
        self._reload_timer.setSingleShot(True)
        self._reload_timer.setInterval(180)

        # ✅ CRASH-PROOF: safe-connect (fallback na load_assets)
        try:
            _handler = getattr(self, "_on_reload_timeout", None)
            self._reload_timer.timeout.connect(_handler if callable(_handler) else self.load_assets)
        except Exception:
            try:
                self._reload_timer.timeout.connect(self.load_assets)
            except Exception:
                pass

        self._persist_timer = QTimer(self)
        self._persist_timer.setSingleShot(True)
        self._persist_timer.setInterval(350)
        self._persist_timer.timeout.connect(self._persist_ui_state)

        self._sync_timer = QTimer(self)
        self._sync_timer.setInterval(250)
        self._sync_timer.timeout.connect(self._poll_hidden_for_renumber)

        # col specs for wire_columns
        self._col_specs = [
            ColSpec("rownum", "#", True, 60),
            ColSpec("asset_uid", "Asset UID", True, 160),
            ColSpec("toc_number", "TOC", True, 120),
            ColSpec("nomenclature_no", "Nomenkl. broj", True, 150),
            ColSpec("serial_number", "Serijski", True, 140),
            ColSpec("name", "Naziv", True, 260),
            ColSpec("category", "Kategorija", True, 140),
            ColSpec("status", "Status", True, 120),
            ColSpec("current_holder", "Zaduženo kod", True, 160),
            ColSpec("location", "Lokacija", True, 160),
            ColSpec("updated_at", "Ažurirano", True, 150),
            ColSpec("sector", "Sektor", True, 120),
        ]

        # ---- UI ----
        self.tabs = QTabWidget()
        self.tabs.addTab(QWidget(), self.TAB_ACTIVE)
        self.tabs.addTab(QWidget(), self.TAB_UNASSIGNED)
        self.tabs.addTab(QWidget(), self.TAB_SCRAPPED)
        self.tabs.addTab(QWidget(), self.TAB_ALL)

        self.cb_scope = QComboBox()
        self.cb_scope.setToolTip("Opseg prikaza (RBAC + scope)")

        self.ed_search = QLineEdit()
        self.ed_search.setClearButtonEnabled(True)
        self.ed_search.setPlaceholderText("DB pretraga: RB / UID / TOC / NOM / serijski / naziv / lokacija / zaduženo")

        self.cb_category = QComboBox()
        self.cb_category.addItems(["SVE", "IT", "Metrologija", "OS", "SI", "Zalihe", "Ostalo"])

        self.cb_status = QComboBox()
        self.cb_status.addItems(["SVE", "active", "on_loan", "service", "scrapped"])

        self.btn_search = QPushButton("Pretraži")
        self.btn_refresh = QPushButton("Osveži")
        self.btn_columns = QPushButton("Kolone")
        self.btn_reset = QPushButton("Reset layout")
        self.btn_detail = QPushButton("Detalji")
        self.btn_new = QPushButton("Novo")

        self.btn_detail.setEnabled(False)

        self.lb_rbac = QLabel("")
        self.lb_rbac.setWordWrap(True)
        self.lb_rbac.hide()

        self.lb_info = QLabel("")
        self.lb_info.setWordWrap(True)
        self.lb_info.hide()

        self.lb_empty = QLabel("Nema rezultata za izabrane filtere.")
        self.lb_empty.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.lb_empty.hide()

        self.chips = FilterChipsBar(self)
        self.chips.set_clear_all_handler(self._clear_all_filters)

        top = QHBoxLayout()
        top.addWidget(QLabel("Opseg:"))
        top.addWidget(self.cb_scope, 1)
        top.addWidget(self.ed_search, 3)
        top.addWidget(self.btn_search)
        top.addWidget(QLabel("Kategorija:"))
        top.addWidget(self.cb_category, 1)
        top.addWidget(QLabel("Status:"))
        top.addWidget(self.cb_status, 1)
        top.addWidget(self.btn_refresh)
        top.addWidget(self.btn_columns)
        top.addWidget(self.btn_reset)
        top.addWidget(self.btn_detail)
        top.addWidget(self.btn_new)

        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(True)

        vh = self.table.verticalHeader()
        vh.setVisible(True)
        vh.setDefaultAlignment(Qt.AlignRight | Qt.AlignVCenter)
        vh.setHighlightSections(False)
        try:
            vh.setSectionResizeMode(QHeaderView.Fixed)
            vh.setFixedWidth(46)
            self.table.verticalHeader().setDefaultSectionSize(30)
        except Exception:
            pass

        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionsClickable(True)
        hdr.setSectionsMovable(True)
        hdr.setDefaultAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        hdr.setHighlightSections(False)
        try:
            hdr.setSectionResizeMode(QHeaderView.Interactive)
            hdr.setFixedHeight(36)
        except Exception:
            pass

        # optional copy helper
        try:
            if wire_table_selection_plus_copy is not None:
                wire_table_selection_plus_copy(self.table)
        except Exception:
            pass

        # tint delegate
        self._row_tint_delegate = _RowTintDelegate(
            self.table,
            status_col=self.COL_IDX_STATUS,
            palette=self._row_paint_palette,
            accent_px=3,
        )
        self.table.setItemDelegate(self._row_tint_delegate)
        self._apply_table_visual_polish()

        # quick tools (optional)
        if TableToolsBar is not None and TableToolsConfig is not None:
            self.quick_tools = TableToolsBar(
                self.table,
                TableToolsConfig(
                    placeholder="Brzi filter (instant): npr. fluke 1234 nom-55 pera",
                    show_sort_toggle=True,
                    default_sort_enabled=True,
                    filter_columns=[
                        self.COL_IDX_UID, self.COL_IDX_TOC, self.COL_IDX_NOM, self.COL_IDX_SN,
                        self.COL_IDX_NAME, self.COL_IDX_CAT, self.COL_IDX_STATUS, self.COL_IDX_HOLDER,
                        self.COL_IDX_LOC, self.COL_IDX_SECTOR,
                    ],
                ),
                parent=self,
            )
        else:
            self.quick_tools = QLabel("")
            self.quick_tools.setVisible(False)

        # best-effort quick filter edit detection (persist + chip)
        self._quick_filter_edit: Optional[QLineEdit] = None
        try:
            for attr in ("ed_filter", "filter_edit", "search_edit", "edit", "line_edit", "le_filter"):
                w = getattr(self.quick_tools, attr, None)
                if isinstance(w, QLineEdit):
                    self._quick_filter_edit = w
                    break
        except Exception:
            self._quick_filter_edit = None

        if self._quick_filter_edit is not None:
            try:
                self._quick_filter_edit.textChanged.connect(lambda _t: (self._state_dirty(), self._rebuild_chips()))
            except Exception:
                pass

        self.preview = AssetPreviewPanel(self)
        self.preview.set_open_handler(self.open_selected_detail)
        self.preview.set_toggle_handler(self._toggle_preview)

        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.preview)
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 1)
        try:
            self.splitter.splitterMoved.connect(lambda *_a: self._state_dirty())
        except Exception:
            pass

        # layout
        lay = QVBoxLayout(self)
        lay.addWidget(self.tabs)
        lay.addLayout(top)
        lay.addWidget(self.quick_tools)
        lay.addWidget(self.chips)
        lay.addWidget(self.lb_info)
        lay.addWidget(self.lb_rbac)
        lay.addWidget(self.lb_empty)
        lay.addWidget(self.splitter, 1)

        # defaults snapshot (for Reset layout)
        try:
            self._default_splitter_state = self.splitter.saveState()
        except Exception:
            self._default_splitter_state = None
        try:
            self._default_header_state = self.table.horizontalHeader().saveState()
        except Exception:
            self._default_header_state = None
        try:
            self._default_col_widths = [int(self.table.columnWidth(i)) for i in range(self.table.columnCount())]
        except Exception:
            self._default_col_widths = None

        # signals
        self.btn_refresh.clicked.connect(self.request_reload)
        self.btn_search.clicked.connect(self.request_reload)
        self.btn_new.clicked.connect(self.new_asset)
        self.btn_detail.clicked.connect(self.open_selected_detail)
        self.btn_reset.clicked.connect(self.reset_layout)

        self.tabs.currentChanged.connect(lambda _i: (self._state_dirty(), self.request_reload()))
        self.cb_scope.currentIndexChanged.connect(lambda _i: (self._state_dirty(), self.request_reload()))
        self.cb_category.currentIndexChanged.connect(lambda _i: (self._state_dirty(), self.request_reload()))
        self.cb_status.currentIndexChanged.connect(lambda _i: (self._state_dirty(), self.request_reload()))

        # KEY FIX: search typing does NOT reload DB
        self.ed_search.textChanged.connect(self._on_search_typing)
        self.ed_search.returnPressed.connect(self.request_reload)

        self.table.cellDoubleClicked.connect(self.open_detail)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        try:
            self.table.horizontalHeader().sortIndicatorChanged.connect(self._on_sort_changed)
        except Exception:
            pass

        # header move/resize persist fallback (when no wire_columns)
        if wire_columns is None:
            try:
                hdr.sectionMoved.connect(lambda *_a: self._state_dirty())
                hdr.sectionResized.connect(lambda *_a: self._state_dirty())
            except Exception:
                pass

        # context menu + shortcuts
        self._install_context_menu()
        self._install_shortcuts()

        # columns dialog hook
        if wire_columns is not None:
            try:
                self._apply_cols_assets = wire_columns(self, self.table, self.btn_columns, self._cols_key, self._col_specs)
            except Exception:
                self._apply_cols_assets = lambda: None
        else:
            self._apply_cols_assets = lambda: None
            try:
                self.btn_columns.clicked.connect(
                    lambda: QMessageBox.information(self, "Info", "Podešavanje kolona nije dostupno u ovom buildu.")
                )
            except Exception:
                pass

        # theme + RBAC + restore
        self._refresh_theme()
        self._apply_rbac()
        self._restore_ui_state()

        if self._has_any_view:
            self._sync_timer.start()
            self.request_reload()

# (FILENAME: ui/assets_page.py - END PART 1/3)
# FILENAME: ui/assets_page.py

# FILENAME: ui/assets_page.py
# (FILENAME: ui/assets_page.py - START PART 2/3)

    # -------------------- Qt events --------------------
    def closeEvent(self, e) -> None:
        self._stop_timers()
        try:
            if self._preview_anim is not None:
                self._preview_anim.stop()
        except Exception:
            pass
        try:
            self._persist_ui_state()
        except Exception:
            pass
        try:
            super().closeEvent(e)
        except Exception:
            pass

    def showEvent(self, e) -> None:
        try:
            super().showEvent(e)
        except Exception:
            pass
        if not self._layout_restored_once:
            self._layout_restored_once = True
            QTimer.singleShot(0, self._apply_pending_layout_restore)

    def changeEvent(self, e) -> None:
        try:
            if e and e.type() == QEvent.PaletteChange:
                self._refresh_theme()
        except Exception:
            pass
        try:
            super().changeEvent(e)
        except Exception:
            pass

    def event(self, ev) -> bool:
        try:
            if ev and ev.type() == QEvent.Destroy:
                self._stop_timers()
        except Exception:
            pass
        try:
            return super().event(ev)
        except Exception:
            return False

    # -------------------- timers --------------------
    def _stop_timers(self) -> None:
        for name in ("_reload_timer", "_persist_timer", "_sync_timer"):
            try:
                t = getattr(self, name, None)
                if t is not None:
                    t.stop()
            except Exception:
                pass

    # -------------------- theme/visuals --------------------
    def _refresh_theme(self) -> None:
        dark = _is_dark_theme()
        try:
            self.lb_info.setStyleSheet(_qss_banner(dark))
        except Exception:
            pass
        try:
            self.lb_empty.setStyleSheet(_qss_empty(dark))
        except Exception:
            pass
        try:
            self.chips.refresh_theme()
        except Exception:
            pass
        try:
            self.preview.refresh_theme()
        except Exception:
            pass

    def _init_status_palette(self) -> None:
        self._row_paint_palette = {
            "active": (QColor("#22c55e"), QColor(34, 197, 94, 28)),
            "on_loan": (QColor("#3b82f6"), QColor(59, 130, 246, 26)),
            "service": (QColor("#ffcc00"), QColor(255, 204, 0, 24)),
            "scrapped": (QColor("#a0a6b6"), QColor(160, 166, 182, 22)),
            "unknown": (QColor("#a0a6b6"), QColor(0, 0, 0, 0)),
        }
        self._status_text_color = {
            "active": QColor("#22c55e"),
            "on_loan": QColor("#3b82f6"),
            "service": QColor("#ffcc00"),
            "scrapped": QColor("#a0a6b6"),
            "unknown": QColor("#b9beca"),
        }

    def _apply_table_visual_polish(self) -> None:
        try:
            self.table.setShowGrid(True)
            self.table.setGridStyle(Qt.SolidLine)
            self.table.setStyleSheet(
                "QTableWidget{ gridline-color: rgba(140,140,140,0.35); }"
                "QHeaderView::section{ padding: 6px 8px; border-right: 1px solid rgba(140,140,140,0.28);"
                " border-bottom: 1px solid rgba(140,140,140,0.45); }"
                "QTableCornerButton::section{ border-right: 1px solid rgba(140,140,140,0.28);"
                " border-bottom: 1px solid rgba(140,140,140,0.45); }"
            )
        except Exception:
            pass

    # -------------------- persistence --------------------
    def _state_dirty(self) -> None:
        try:
            self._persist_timer.start()
        except Exception:
            pass

    def _persist_ui_state(self) -> None:
        try:
            s = _settings()
            s.beginGroup(self._SET_GROUP)
            try:
                s.setValue(self._K_TAB, int(self.tabs.currentIndex()))
                s.setValue(self._K_SCOPE, str(self.cb_scope.currentText() or ""))
                s.setValue(self._K_CAT, str(self.cb_category.currentText() or "SVE"))
                s.setValue(self._K_STATUS, str(self.cb_status.currentText() or "SVE"))
                s.setValue(self._K_SEARCH, str(self.ed_search.text() or ""))

                if self._quick_filter_edit is not None:
                    try:
                        s.setValue(self._K_QUICK, str(self._quick_filter_edit.text() or ""))
                    except Exception:
                        pass

                s.setValue(self._K_PREV_COLL, bool(self._preview_collapsed))
                try:
                    sizes = self.splitter.sizes()
                    w = int(sizes[1]) if sizes and len(sizes) >= 2 else int(self.preview.width())
                except Exception:
                    w = int(self.preview.width())
                s.setValue(self._K_PREV_W, int(max(w, self.preview.collapsed_width())))

                try:
                    s.setValue(self._K_SPLITTER, self.splitter.saveState())
                except Exception:
                    pass

                try:
                    hdr = self.table.horizontalHeader()
                    s.setValue(self._K_SORT_COL, int(hdr.sortIndicatorSection()))
                    s.setValue(self._K_SORT_ORDER, int(hdr.sortIndicatorOrder()))
                except Exception:
                    pass

                if wire_columns is None:
                    try:
                        s.setValue(self._K_HDR_STATE, self.table.horizontalHeader().saveState())
                    except Exception:
                        pass
            finally:
                s.endGroup()
        except Exception:
            pass

    def _restore_ui_state(self) -> None:
        try:
            s = _settings()
            s.beginGroup(self._SET_GROUP)
            try:
                tab_idx = s.value(self._K_TAB, 0)
                scope_txt = str(s.value(self._K_SCOPE, "") or "")
                cat_txt = str(s.value(self._K_CAT, "SVE") or "SVE")
                st_txt = str(s.value(self._K_STATUS, "SVE") or "SVE")
                search_txt = str(s.value(self._K_SEARCH, "") or "")
                quick_txt = str(s.value(self._K_QUICK, "") or "")

                prev_coll = bool(s.value(self._K_PREV_COLL, False))
                prev_w = s.value(self._K_PREV_W, self.preview.expanded_width_hint())
                splitter_state = s.value(self._K_SPLITTER, None)

                sort_col = s.value(self._K_SORT_COL, -1)
                sort_order = s.value(self._K_SORT_ORDER, int(Qt.AscendingOrder))

                hdr_state = s.value(self._K_HDR_STATE, None)
            finally:
                s.endGroup()
        except Exception:
            return

        def _to_int(x: Any, default: int) -> int:
            try:
                return int(x)
            except Exception:
                return int(default)

        tab_idx_i = max(0, min(_to_int(tab_idx, 0), self.tabs.count() - 1))
        prev_w_i = max(self.preview.collapsed_width(), _to_int(prev_w, self.preview.expanded_width_hint()))
        sort_col_i = _to_int(sort_col, -1)
        sort_order_i = _to_int(sort_order, int(Qt.AscendingOrder))

        try:
            self.tabs.blockSignals(True)
            self.cb_scope.blockSignals(True)
            self.cb_category.blockSignals(True)
            self.cb_status.blockSignals(True)
            self.ed_search.blockSignals(True)

            self.tabs.setCurrentIndex(tab_idx_i)

            if scope_txt:
                i = self.cb_scope.findText(scope_txt, Qt.MatchFixedString)
                if i >= 0:
                    self.cb_scope.setCurrentIndex(i)

            i = self.cb_category.findText(cat_txt, Qt.MatchFixedString)
            if i >= 0:
                self.cb_category.setCurrentIndex(i)

            i2 = self.cb_status.findText(st_txt, Qt.MatchFixedString)
            if i2 >= 0:
                self.cb_status.setCurrentIndex(i2)

            self.ed_search.setText(search_txt)
        except Exception:
            pass
        finally:
            try:
                self.tabs.blockSignals(False)
                self.cb_scope.blockSignals(False)
                self.cb_category.blockSignals(False)
                self.cb_status.blockSignals(False)
                self.ed_search.blockSignals(False)
            except Exception:
                pass

        if self._quick_filter_edit is not None:
            try:
                self._quick_filter_edit.setText(quick_txt)
            except Exception:
                pass

        self._pending_preview_collapsed = bool(prev_coll)
        self._pending_preview_width = int(prev_w_i)

        if isinstance(splitter_state, (QByteArray, bytes)):
            self._pending_splitter_state = splitter_state if isinstance(splitter_state, QByteArray) else QByteArray(splitter_state)

        if wire_columns is None and isinstance(hdr_state, (QByteArray, bytes)):
            self._pending_header_state = hdr_state if isinstance(hdr_state, QByteArray) else QByteArray(hdr_state)

        try:
            order_enum = Qt.SortOrder(sort_order_i)
        except Exception:
            order_enum = Qt.AscendingOrder
        self._pending_sort = (sort_col_i, order_enum)

        try:
            self._rebuild_chips()
        except Exception:
            pass

    def _apply_pending_layout_restore(self) -> None:
        try:
            if self._pending_splitter_state is not None:
                self.splitter.restoreState(self._pending_splitter_state)
        except Exception:
            pass
        self._pending_splitter_state = None

        try:
            if self._pending_header_state is not None and wire_columns is None:
                self.table.horizontalHeader().restoreState(self._pending_header_state)
        except Exception:
            pass
        self._pending_header_state = None

        try:
            total = max(1, int(self.splitter.width()))
            if self._pending_preview_collapsed is True:
                self._preview_collapsed = True
                self.preview.set_collapsed(True)
                right = self.preview.collapsed_width()
                self.splitter.setSizes([max(1, total - right), right])
            else:
                self._preview_collapsed = False
                self.preview.set_collapsed(False)
                right = int(self._pending_preview_width or self.preview.expanded_width_hint())
                right = min(max(self.preview.collapsed_width(), right), max(1, total - 1))
                self.splitter.setSizes([max(1, total - right), right])
        except Exception:
            pass
        self._pending_preview_collapsed = None
        self._pending_preview_width = None

    # -------------------- RBAC --------------------
    def _default_scope(self) -> str:
        try:
            return str(self.cb_scope.itemText(0) or "")
        except Exception:
            return ""

    def _apply_rbac(self) -> None:
        self._has_full_view = _can(PERM_ASSETS_VIEW)
        self._has_my_view = _can(PERM_ASSETS_MY_VIEW)
        self._has_metro_view = _can(PERM_ASSETS_METRO_VIEW)
        self._has_any_view = self._has_full_view or self._has_my_view or self._has_metro_view

        try:
            self.cb_scope.blockSignals(True)
            self.cb_scope.clear()
            if self._has_full_view:
                self.cb_scope.addItem(self.SCOPE_ALL)
            if self._has_my_view:
                self.cb_scope.addItem(self.SCOPE_MY)
            if self._has_metro_view:
                self.cb_scope.addItem(self.SCOPE_METRO)
            if self.cb_scope.count() == 0:
                self.cb_scope.addItem(self.SCOPE_MY)
        finally:
            try:
                self.cb_scope.blockSignals(False)
            except Exception:
                pass

        if not self._has_any_view:
            self.lb_rbac.setText(
                "Nemaš pravo da vidiš stranu 'Sredstva' "
                "(potrebno je assets.view ili assets.my.view ili assets.metrology.view)."
            )
            self.lb_rbac.show()
            for w in (
                self.tabs, self.cb_scope, self.ed_search, self.cb_category, self.cb_status,
                self.btn_search, self.btn_refresh, self.btn_columns, self.btn_reset, self.btn_detail, self.btn_new,
                self.table, self.quick_tools, self.preview, self.splitter, self.chips
            ):
                try:
                    w.setEnabled(False)
                except Exception:
                    pass
            return

        self.lb_rbac.hide()
        ok_create = _can(PERM_ASSETS_CREATE)
        self.btn_new.setEnabled(bool(ok_create))
        self.btn_new.setToolTip("" if ok_create else "Novo sredstvo traži: assets.create.")

    # -------------------- search typing --------------------
    def _on_search_typing(self, _t: str) -> None:
        self._state_dirty()
        self._rebuild_chips()
        try:
            q = (self.ed_search.text() or "").strip()
            if q:
                self.lb_info.setText("Uneta je pretraga. Pritisni Enter ili klikni „Pretraži” da se primeni DB pretraga.")
                self.lb_info.show()
            else:
                if not self._loading:
                    self.lb_info.hide()
        except Exception:
            pass

    # -------------------- chips --------------------
    def _rebuild_chips(self) -> None:
        chips: List[ChipSpec] = []

        try:
            tab_txt = self.tabs.tabText(self.tabs.currentIndex())
            if tab_txt and tab_txt != self.TAB_ACTIVE:
                chips.append(ChipSpec(text=f"Tab: {tab_txt}", on_remove=lambda: self.tabs.setCurrentIndex(0)))
        except Exception:
            pass

        try:
            sc = str(self.cb_scope.currentText() or "")
            if sc and sc != self._default_scope():
                chips.append(ChipSpec(text=f"Opseg: {sc}", on_remove=lambda: self.cb_scope.setCurrentIndex(0)))
        except Exception:
            pass

        try:
            cat = str(self.cb_category.currentText() or "SVE")
            if cat.upper() != "SVE":
                def _rm_cat() -> None:
                    i = self.cb_category.findText("SVE", Qt.MatchFixedString)
                    self.cb_category.setCurrentIndex(i if i >= 0 else 0)
                chips.append(ChipSpec(text=f"Kategorija: {cat}", on_remove=_rm_cat))
        except Exception:
            pass

        try:
            st = str(self.cb_status.currentText() or "SVE")
            if st.upper() != "SVE":
                def _rm_st() -> None:
                    i = self.cb_status.findText("SVE", Qt.MatchFixedString)
                    self.cb_status.setCurrentIndex(i if i >= 0 else 0)
                chips.append(ChipSpec(text=f"Status: {st}", on_remove=_rm_st))
        except Exception:
            pass

        try:
            q = str(self.ed_search.text() or "").strip()
            if q:
                chips.append(ChipSpec(text=f"Pretraga: {q}", on_remove=lambda: self.ed_search.setText(""), tooltip="DB pretraga"))
        except Exception:
            pass

        if self._quick_filter_edit is not None:
            try:
                qq = str(self._quick_filter_edit.text() or "").strip()
                if qq:
                    chips.append(ChipSpec(text=f"Brzi filter: {qq}", on_remove=lambda: self._quick_filter_edit.setText(""), tooltip="Instant filter"))
            except Exception:
                pass

        self.chips.set_chips(chips)

    def _clear_all_filters(self) -> None:
        try:
            self.tabs.setCurrentIndex(0)
            self.cb_scope.setCurrentIndex(0)
            i = self.cb_category.findText("SVE", Qt.MatchFixedString)
            self.cb_category.setCurrentIndex(i if i >= 0 else 0)
            i2 = self.cb_status.findText("SVE", Qt.MatchFixedString)
            self.cb_status.setCurrentIndex(i2 if i2 >= 0 else 0)
            self.ed_search.setText("")
            if self._quick_filter_edit is not None:
                self._quick_filter_edit.setText("")
        except Exception:
            pass
        self._state_dirty()
        self.request_reload()

    # -------------------- selection / preview --------------------
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

    def _selected_uid(self) -> str:
        row = self._current_row_any()
        if row < 0:
            return ""
        it = self.table.item(row, self.COL_IDX_UID)
        return it.text().strip() if it else ""

    def _sync_buttons(self) -> None:
        try:
            self.btn_detail.setEnabled(self._has_any_view and (self._current_row_any() >= 0))
        except Exception:
            pass

    def _rowdata_from_row(self, row: int) -> Dict[str, Any]:
        it_uid = self.table.item(row, self.COL_IDX_UID)
        if it_uid:
            try:
                d = it_uid.data(Qt.UserRole)
                if isinstance(d, dict):
                    return d
            except Exception:
                pass

        def _txt(c: int) -> str:
            it = self.table.item(row, c)
            return it.text().strip() if it else ""

        return {
            "asset_uid": _txt(self.COL_IDX_UID),
            "rb": _txt(self.COL_IDX_ROWNUM),
            "toc_number": _txt(self.COL_IDX_TOC),
            "nomenclature_number": _txt(self.COL_IDX_NOM),
            "serial_number": _txt(self.COL_IDX_SN),
            "name": _txt(self.COL_IDX_NAME),
            "category": _txt(self.COL_IDX_CAT),
            "status": _txt(self.COL_IDX_STATUS),
            "current_holder": _txt(self.COL_IDX_HOLDER),
            "location": _txt(self.COL_IDX_LOC),
            "updated_at": _txt(self.COL_IDX_UPD),
            "sector": _txt(self.COL_IDX_SECTOR),
        }

    def _on_selection_changed(self) -> None:
        if self._loading:
            return
        row = self._current_row_any()
        if row >= 0:
            self.preview.set_asset(self._rowdata_from_row(row))
        else:
            self.preview.clear()
        self._sync_buttons()

    # -------------------- cell styles --------------------
    def _apply_status_cell_style(self, item: QTableWidgetItem, status_raw: Any) -> None:
        try:
            key = _status_key(status_raw)
            col = self._status_text_color.get(key, self._status_text_color.get("unknown", QColor("#b9beca")))
            item.setTextAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
            item.setForeground(QBrush(col))
            f = item.font()
            f.setBold(True)
            item.setFont(f)
        except Exception:
            pass

    def _apply_nomenclature_cell_style(self, item: QTableWidgetItem, nom: str) -> None:
        try:
            if nom:
                item.setToolTip("")
                return
            item.setToolTip("Nomenklaturni broj nije unet.")
            f = item.font()
            f.setBold(True)
            item.setFont(f)
            item.setForeground(QBrush(QColor("#ff8a80")))
            item.setText("—")
            item.setTextAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        except Exception:
            pass

    # -------------------- tab filter --------------------
    def _active_tab_name(self) -> str:
        try:
            return self.tabs.tabText(self.tabs.currentIndex())
        except Exception:
            return self.TAB_ACTIVE

    def _apply_tab_filter(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        tab = self._active_tab_name()
        if tab == self.TAB_ACTIVE:
            return [r for r in rows if not _is_scrapped(r)]
        if tab == self.TAB_UNASSIGNED:
            return [r for r in rows if (not _is_scrapped(r)) and _is_unassigned(r)]
        if tab == self.TAB_SCRAPPED:
            return [r for r in rows if _is_scrapped(r)]
        return rows

    def _scope_name(self) -> str:
        try:
            return (self.cb_scope.currentText() or "").strip()
        except Exception:
            return self.SCOPE_ALL

    def _cat_match(self, selected_cat: str, value_cat: Any) -> bool:
        sc = (selected_cat or "").strip().casefold()
        vc = _norm(value_cat).casefold()
        if sc in ("", "sve"):
            return True
        if sc == "it":
            return ("it" in vc) or (vc == "it")
        if sc == "metrologija":
            return "metrolog" in vc
        if sc == "os":
            return vc == "os" or "osnov" in vc
        if sc == "si":
            return vc == "si" or "sitan" in vc
        if sc == "zalihe":
            return "zaliha" in vc
        if sc == "ostalo":
            return True
        return vc == sc

    def _apply_local_filters(self, rows: List[Dict[str, Any]], *, apply_search: bool = True) -> List[Dict[str, Any]]:
        if not rows:
            return []

        cat = _norm(self.cb_category.currentText() or "SVE")
        st = _norm(self.cb_status.currentText() or "SVE")
        q = _cf(self.ed_search.text()) if apply_search else ""

        out = rows

        # category backstop
        try:
            if cat and cat.upper() != "SVE":
                out = [r for r in out if self._cat_match(cat, (r or {}).get("category", ""))]
        except Exception:
            pass

        # status backstop
        try:
            if st and st.upper() != "SVE":
                ss = st.casefold()
                if ss == "scrapped":
                    out = [r for r in out if _is_scrapped(r)]
                else:
                    out = [r for r in out if _norm((r or {}).get("status", "")).casefold() == ss]
        except Exception:
            pass

        # optional local search
        if q:
            def _row_text(rr: Dict[str, Any]) -> str:
                parts = [
                    rr.get("rb", ""),
                    rr.get("asset_uid", ""),
                    rr.get("toc_number", ""),
                    _get_nomenclature(rr),
                    rr.get("serial_number", ""),
                    rr.get("name", ""),
                    rr.get("category", ""),
                    rr.get("status", ""),
                    rr.get("current_holder", ""),
                    rr.get("location", ""),
                    _get_sector(rr),
                ]
                return " ".join(str(x or "") for x in parts).casefold()

            try:
                out = [r for r in out if q in _row_text(r)]
            except Exception:
                return rows

        return out

    # -------------------- renumber helpers --------------------
    def _rownum_sort_key(self, row: int) -> Optional[int]:
        it = self.table.item(row, self.COL_IDX_ROWNUM)
        if not it:
            return None
        try:
            v = it.data(Qt.UserRole)
            if isinstance(v, int):
                return v
            if isinstance(v, float):
                return int(v)
        except Exception:
            pass
        try:
            t = (it.text() or "").strip()
            return int(t) if t.isdigit() else None
        except Exception:
            return None

    def _sync_vertical_header_numbers(self, mode: str = "view") -> None:
        try:
            vh = self.table.verticalHeader()
            if not vh.isVisible():
                return
        except Exception:
            return

        rc = self.table.rowCount()
        visible = 0
        for r in range(rc):
            if self.table.isRowHidden(r):
                txt = ""
            else:
                if mode == "stable":
                    key = self._rownum_sort_key(r)
                    txt = str(int(key)) if key is not None else ""
                else:
                    visible += 1
                    txt = str(visible)
            try:
                it = self.table.verticalHeaderItem(r)
                if it is None:
                    it = QTableWidgetItem(txt)
                    self.table.setVerticalHeaderItem(r, it)
                else:
                    it.setText(txt)
            except Exception:
                pass

    def _apply_rownum_text_from_userrole(self) -> None:
        try:
            rc = self.table.rowCount()
            for r in range(rc):
                it = self.table.item(r, self.COL_IDX_ROWNUM)
                if it is None:
                    continue
                key = self._rownum_sort_key(r)
                if key is None:
                    continue
                it.setText(str(int(key)))
                it.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        except Exception:
            return
        self._sync_vertical_header_numbers(mode="stable")

    def _renumber_view_rows(self) -> None:
        try:
            if self._sort_col == self.COL_IDX_ROWNUM:
                return

            visible = 0
            rc = self.table.rowCount()
            for r in range(rc):
                if self.table.isRowHidden(r):
                    txt = ""
                else:
                    visible += 1
                    txt = str(visible)

                it = self.table.item(r, self.COL_IDX_ROWNUM)
                if it is None or not isinstance(it, SortableItem):
                    it = SortableItem("", 0)
                    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(r, self.COL_IDX_ROWNUM, it)

                it.setText(txt)
                it.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        except Exception:
            pass
        self._sync_vertical_header_numbers(mode="view")

    def _on_sort_changed(self, col: int, order: Qt.SortOrder) -> None:
        self._sort_col = int(col)
        self._sort_order = order
        self._state_dirty()
        if self._sort_col == self.COL_IDX_ROWNUM:
            QTimer.singleShot(0, self._apply_rownum_text_from_userrole)
        else:
            QTimer.singleShot(0, self._renumber_view_rows)

    def _poll_hidden_for_renumber(self) -> None:
        try:
            rc = self.table.rowCount()
            if rc <= 0:
                return
            if len(self._hidden_cache) != rc:
                self._hidden_cache = [False] * rc

            changed = False
            for r in range(rc):
                h = self.table.isRowHidden(r)
                if self._hidden_cache[r] != h:
                    self._hidden_cache[r] = h
                    changed = True

            if not changed:
                return

            if self._sort_col == self.COL_IDX_ROWNUM:
                return

            self._renumber_view_rows()
        except Exception:
            return

    # -------------------- preview animation --------------------
    def _anim_optimize_begin(self) -> None:
        try:
            hdr = self.table.horizontalHeader()
            self._anim_saved_stretch_last = bool(hdr.stretchLastSection())
            hdr.setStretchLastSection(False)
        except Exception:
            self._anim_saved_stretch_last = None

        try:
            self._anim_saved_vp_mode = self.table.viewportUpdateMode()
            self.table.setViewportUpdateMode(QAbstractItemView.MinimalViewportUpdate)
        except Exception:
            self._anim_saved_vp_mode = None

    def _anim_optimize_end(self) -> None:
        try:
            hdr = self.table.horizontalHeader()
            if self._anim_saved_stretch_last is not None:
                hdr.setStretchLastSection(bool(self._anim_saved_stretch_last))
        except Exception:
            pass

        try:
            if self._anim_saved_vp_mode is not None:
                self.table.setViewportUpdateMode(self._anim_saved_vp_mode)
        except Exception:
            pass

        self._anim_saved_stretch_last = None
        self._anim_saved_vp_mode = None
        self._anim_last_right = None

    def _animate_splitter_right(self, start_right: int, end_right: int, duration_ms: int) -> None:
        try:
            if self._preview_anim is not None:
                try:
                    self._preview_anim.stop()
                except Exception:
                    pass
                self._preview_anim = None

            self._anim_last_right = None
            self._anim_optimize_begin()

            anim = QVariantAnimation(self)
            anim.setStartValue(int(start_right))
            anim.setEndValue(int(end_right))
            anim.setDuration(int(duration_ms))
            anim.setEasingCurve(QEasingCurve.InOutSine)

            def _tick(val) -> None:
                try:
                    right = int(val)
                    if self._anim_last_right is not None and abs(right - self._anim_last_right) < 3:
                        return
                    self._anim_last_right = right
                    total = max(1, int(self.splitter.width()))
                    left = max(1, total - right)
                    self.splitter.setSizes([left, right])
                except Exception:
                    pass

            def _done() -> None:
                try:
                    self._preview_animating = False
                    self.preview.set_toggle_enabled(True)
                except Exception:
                    pass
                self._anim_optimize_end()
                self._state_dirty()

            anim.valueChanged.connect(_tick)
            anim.finished.connect(_done)
            self._preview_anim = anim

            self._preview_animating = True
            self.preview.set_toggle_enabled(False)
            anim.start()
        except Exception:
            try:
                self._preview_animating = False
                self.preview.set_toggle_enabled(True)
            except Exception:
                pass
            self._anim_optimize_end()
            self._state_dirty()

    def _toggle_preview(self) -> None:
        if self._preview_animating:
            return

        sizes = self.splitter.sizes()
        current_right = int(sizes[1] if sizes and len(sizes) >= 2 else self.preview.width())

        if not self._preview_collapsed:
            self._preview_last_w = max(current_right, self.preview.expanded_width_hint())
            self._preview_collapsed = True
            self.preview.set_collapsed(True)
            self._animate_splitter_right(current_right, self.preview.collapsed_width(), 260)
        else:
            self._preview_collapsed = False
            target = int(self._preview_last_w or self.preview.expanded_width_hint())
            target = max(target, self.preview.expanded_width_hint())
            self.preview.set_collapsed(False)
            self._animate_splitter_right(current_right, target, 290)

    # -------------------- context menu + shortcuts --------------------
    def _install_context_menu(self) -> None:
        try:
            self.table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._on_table_context_menu)
        except Exception:
            pass

    def _on_table_context_menu(self, pos) -> None:
        try:
            idx = self.table.indexAt(pos)
            if idx.isValid():
                self.table.setCurrentCell(idx.row(), max(0, idx.column()))
        except Exception:
            pass

        row = self._current_row_any()
        uid = self._selected_uid()

        m = QMenu(self.table)
        a_open = m.addAction("Otvori detalje")
        a_copy_uid = m.addAction("Kopiraj UID")
        m.addSeparator()
        a_reset_cols = m.addAction("Reset kolone (default)")
        a_reset_ui = m.addAction("Reset layout (sve)")
        m.addSeparator()
        a_refresh = m.addAction("Osveži")

        if row < 0:
            a_open.setEnabled(False)
            a_copy_uid.setEnabled(False)
        if not uid:
            a_copy_uid.setEnabled(False)

        act = m.exec(self.table.viewport().mapToGlobal(pos))
        if act == a_open:
            self.open_selected_detail()
        elif act == a_copy_uid:
            try:
                QApplication.clipboard().setText(uid)
            except Exception:
                pass
        elif act == a_reset_cols:
            self.reset_columns_to_default()
        elif act == a_reset_ui:
            self.reset_layout()
        elif act == a_refresh:
            self.request_reload()

    def _install_shortcuts(self) -> None:
        def _mk(seq: str, parent: QWidget, fn, ctx: Qt.ShortcutContext) -> None:
            try:
                sc = QShortcut(QKeySequence(seq), parent)
                sc.setContext(ctx)
                sc.activated.connect(fn)
            except Exception:
                pass

        _mk("Ctrl+R", self, self.request_reload, Qt.WindowShortcut)
        _mk("Ctrl+F", self, lambda: self.ed_search.setFocus(), Qt.WindowShortcut)
        _mk("Ctrl+Shift+C", self, self._copy_selected_uid, Qt.WindowShortcut)

        # Enter/Return only on table
        _mk("Return", self.table, self.open_selected_detail, Qt.WidgetShortcut)
        _mk("Enter", self.table, self.open_selected_detail, Qt.WidgetShortcut)

    def _copy_selected_uid(self) -> None:
        uid = self._selected_uid()
        if not uid:
            return
        try:
            QApplication.clipboard().setText(uid)
        except Exception:
            pass

    # -------------------- reload debounce --------------------
    def _on_reload_timeout(self) -> None:
        """
        Centralni handler za timer timeout.
        Postoji zbog starijih app.py connect-a i radi kao stabilna "jedna istina".
        """
        try:
            self.load_assets()
        except Exception:
            try:
                self.logger.exception("AssetsPage: reload failed")
            except Exception:
                pass

    def request_reload(self) -> None:
        if not self._has_any_view:
            return
        try:
            self._rebuild_chips()
        except Exception:
            pass
        try:
            self._reload_timer.start()
        except Exception:
            self._on_reload_timeout()

    # -------------------- columns reset (NEW) --------------------
    def _clear_wire_columns_state(self) -> None:
        """
        Best-effort uklanjanje wire_columns persisted state-a za ovaj table key.
        Ne pretpostavljamo strukturu helpera — brišemo sve QSettings ključeve koji sadrže self._cols_key.
        """
        key = _norm(getattr(self, "_cols_key", ""))
        if not key:
            return
        try:
            s = _settings()
            try:
                for k in list(s.allKeys()):
                    if key in k:
                        s.remove(k)
            except Exception:
                pass

            for grp in ("ui/table_columns", "table_columns", "ui/columns", "columns"):
                try:
                    s.beginGroup(grp)
                    try:
                        s.beginGroup(key)
                        s.remove("")
                    finally:
                        s.endGroup()
                except Exception:
                    pass
                finally:
                    try:
                        s.endGroup()
                    except Exception:
                        pass

            try:
                s.sync()
            except Exception:
                pass
        except Exception:
            return

    def _reset_columns_runtime_default(self) -> None:
        """
        Runtime reset kolona:
        - show all
        - restore default header order (snapshot) ili fallback na logički redosled
        - default širine iz ColSpec / snapshot
        """
        try:
            for i in range(self.table.columnCount()):
                self.table.setColumnHidden(i, False)
        except Exception:
            pass

        hdr = self.table.horizontalHeader()

        restored = False
        try:
            if getattr(self, "_default_header_state", None) is not None:
                hdr.restoreState(self._default_header_state)  # type: ignore[arg-type]
                restored = True
        except Exception:
            restored = False

        if not restored:
            try:
                for logical in range(self.table.columnCount()):
                    v = hdr.visualIndex(logical)
                    if v != logical:
                        hdr.moveSection(v, logical)
            except Exception:
                pass

        try:
            for i, spec in enumerate(self._col_specs):
                if 0 <= i < self.table.columnCount():
                    hdr.resizeSection(i, int(spec.default_width))
        except Exception:
            try:
                if getattr(self, "_default_col_widths", None):
                    for i, w in enumerate(self._default_col_widths):
                        if 0 <= i < self.table.columnCount():
                            hdr.resizeSection(i, int(w))
            except Exception:
                pass

        try:
            hdr.setStretchLastSection(True)
        except Exception:
            pass

    def reset_columns_to_default(self) -> None:
        """
        Public action: resetuje SAMO kolone (i njihovu persistenciju).
        """
        try:
            if QMessageBox.question(self, "Potvrda", "Resetovati kolone na podrazumevano?") != QMessageBox.Yes:
                return
        except Exception:
            pass

        self._clear_wire_columns_state()
        self._reset_columns_runtime_default()
        self._state_dirty()

# (FILENAME: ui/assets_page.py - END PART 2/3)

# FILENAME: ui/assets_page.py
# (FILENAME: ui/assets_page.py - START PART 3/3)

    # -------------------- data load --------------------
    def _list_assets_supported_params(self) -> set:
        """
        Kešira imena parametara koje list_assets prihvata.
        Time izbegavamo TypeError kad servis ne podržava nove parametre (scope/actor/sector...).
        """
        if self._list_assets_param_names is not None:
            return self._list_assets_param_names
        names: set = set()
        try:
            if callable(list_assets):
                sig = inspect.signature(list_assets)
                for p in sig.parameters.values():
                    # *args/**kwargs -> tretiramo kao "podržava sve"
                    if p.kind in (p.VAR_KEYWORD, p.VAR_POSITIONAL):
                        names.add("__any__")
                    else:
                        names.add(p.name)
        except Exception:
            names = set()
        self._list_assets_param_names = names
        return names

    def _call_list_assets(self, **kwargs) -> List[Any]:
        """
        Poziva list_assets fail-soft:
        - ako servis ima **kwargs ili param, prosledi ga
        - ako nema, izbaci ga iz kwargs (nema TypeError)
        """
        if not callable(list_assets):
            raise RuntimeError("Servis list_assets nije dostupan.")

        supported = self._list_assets_supported_params()
        if "__any__" in supported:
            try:
                return list_assets(**kwargs) or []
            except Exception:
                pass

        filtered: Dict[str, Any] = {}
        for k, v in (kwargs or {}).items():
            if k in supported:
                filtered[k] = v

        return list_assets(**filtered) or []

    def load_assets(self) -> None:
        if not self._has_any_view or self._loading:
            return

        if not callable(list_assets):
            QMessageBox.critical(self, "Greška", "Servis list_assets nije dostupan.")
            return

        self._loading = True
        selected_uid_before = self._selected_uid()

        try:
            scroll_before = int(self.table.verticalScrollBar().value())
        except Exception:
            scroll_before = None

        # capture sort intent BEFORE disabling sorting
        try:
            hdr = self.table.horizontalHeader()
            desired_col = int(hdr.sortIndicatorSection())
            desired_order = hdr.sortIndicatorOrder()
        except Exception:
            desired_col = -1
            desired_order = Qt.AscendingOrder

        if self._pending_sort is not None:
            desired_col, desired_order = self._pending_sort

        scope = self._scope_name()
        if scope == self.SCOPE_ALL and not self._has_full_view:
            scope = self._default_scope() or self.SCOPE_MY

        limit = int(getattr(self, "MAX_ROWS", self._HARD_LIMIT) or self._HARD_LIMIT)
        limit = max(100, min(limit, 50000))

        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
        except Exception:
            pass

        was_sorting = False
        try:
            was_sorting = bool(self.table.isSortingEnabled())
            self.table.setSortingEnabled(False)
        except Exception:
            pass

        try:
            actor_name = _actor_name()
            actor_key = _actor_key()
            sector_id = _actor_sector_id()

            rows_any = self._call_list_assets(
                search=self.ed_search.text(),
                category=self.cb_category.currentText(),
                status=self.cb_status.currentText(),
                limit=limit,
                scope=scope,
                actor=actor_name,
                actor_key=actor_key,
                sector_id=sector_id,
            ) or []

            # hard-cap banner
            try:
                if isinstance(rows_any, list) and len(rows_any) >= limit:
                    self.lb_info.setText(f"Prikazano je prvih {limit} rezultata. Suzi filtere za precizniji prikaz.")
                    self.lb_info.show()
                else:
                    q = (self.ed_search.text() or "").strip()
                    if not q:
                        self.lb_info.hide()
            except Exception:
                pass

            rows = [_row_as_dict(r) for r in (rows_any or [])]
            rows = [r for r in rows if isinstance(r, dict) and r]

            rows = self._apply_tab_filter(rows)

            # UI scope only for FULL (narrowing convenience)
            if self._has_full_view:
                if scope == self.SCOPE_MY:
                    rows = [r for r in rows if _is_my_asset_ui(r)]
                elif scope == self.SCOPE_METRO:
                    rows = [r for r in rows if _is_metro_asset_ui(r)]

            # local filters apply_search=False because DB search already done in service layer
            rows = self._apply_local_filters(rows, apply_search=False)

            try:
                self.lb_empty.setVisible(len(rows) == 0)
            except Exception:
                pass

            # render
            self.table.setUpdatesEnabled(False)
            self.table.blockSignals(True)
            try:
                self.table.clearContents()
                self.table.setRowCount(len(rows))
                self._hidden_cache = [False] * len(rows)

                self._sort_col = -1
                self._sort_order = Qt.AscendingOrder

                for i, r in enumerate(rows):
                    stable_key = i + 1

                    it0 = SortableItem(str(stable_key), stable_key)
                    it0.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                    it0.setFlags(it0.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(i, self.COL_IDX_ROWNUM, it0)
                    try:
                        self.table.setVerticalHeaderItem(i, QTableWidgetItem(str(stable_key)))
                    except Exception:
                        pass

                    uid = _norm(r.get("asset_uid", ""))
                    it_uid = QTableWidgetItem(uid)
                    it_uid.setFlags(it_uid.flags() & ~Qt.ItemIsEditable)
                    try:
                        it_uid.setData(Qt.UserRole, r)
                    except Exception:
                        pass
                    self.table.setItem(i, self.COL_IDX_UID, it_uid)

                    toc = _norm(r.get("toc_number", ""))
                    it_toc = SortableItem(toc, _safe_int(toc))
                    it_toc.setFlags(it_toc.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(i, self.COL_IDX_TOC, it_toc)

                    nom = _get_nomenclature(r)
                    it_nom = SortableItem(nom, _safe_int(nom))
                    it_nom.setFlags(it_nom.flags() & ~Qt.ItemIsEditable)
                    self._apply_nomenclature_cell_style(it_nom, nom)
                    self.table.setItem(i, self.COL_IDX_NOM, it_nom)

                    it_sn = QTableWidgetItem(_norm(r.get("serial_number", "")))
                    it_sn.setFlags(it_sn.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(i, self.COL_IDX_SN, it_sn)

                    it_name = QTableWidgetItem(_norm(r.get("name", "")))
                    it_name.setFlags(it_name.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(i, self.COL_IDX_NAME, it_name)

                    it_cat = QTableWidgetItem(_norm(r.get("category", "")))
                    it_cat.setFlags(it_cat.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(i, self.COL_IDX_CAT, it_cat)

                    st_raw = _norm(r.get("status", ""))
                    it_status = QTableWidgetItem(st_raw)
                    it_status.setFlags(it_status.flags() & ~Qt.ItemIsEditable)
                    self._apply_status_cell_style(it_status, st_raw)
                    self.table.setItem(i, self.COL_IDX_STATUS, it_status)

                    it_holder = QTableWidgetItem(_norm(r.get("current_holder", "")))
                    it_holder.setFlags(it_holder.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(i, self.COL_IDX_HOLDER, it_holder)

                    it_loc = QTableWidgetItem(_norm(r.get("location", "")))
                    it_loc.setFlags(it_loc.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(i, self.COL_IDX_LOC, it_loc)

                    # ✅ NOVO: sektor kolona (ako je Part 1 patch primenjen)
                    sec = _get_sector(r)  # helper je u Part 1 patch-u
                    it_sec = QTableWidgetItem(_norm(sec))
                    it_sec.setFlags(it_sec.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(i, self.COL_IDX_SECTOR, it_sec)

                    raw_upd = r.get("updated_at", "") or ""
                    disp_upd = fmt_dt_sr(raw_upd)
                    it_upd = SortableItem(str(disp_upd), _safe_dt_sort_value(raw_upd))
                    it_upd.setFlags(it_upd.flags() & ~Qt.ItemIsEditable)
                    if raw_upd:
                        it_upd.setToolTip(_norm(raw_upd))
                    self.table.setItem(i, self.COL_IDX_UPD, it_upd)

            finally:
                self.table.blockSignals(False)
                self.table.setUpdatesEnabled(True)

        except Exception as e:
            try:
                self.logger.exception("AssetsPage.load_assets failed: %s", e)
            except Exception:
                pass
            QMessageBox.critical(self, "Greška", f"Ne mogu da učitam sredstva.\n\n{e}")
            return
        finally:
            try:
                self.table.setSortingEnabled(bool(was_sorting))
            except Exception:
                pass
            try:
                QApplication.restoreOverrideCursor()
            except Exception:
                pass
            self._loading = False

        # apply column prefs (wire_columns)
        try:
            self._apply_cols_assets()
        except Exception:
            pass

        # apply desired sort every reload
        try:
            if was_sorting and 0 <= int(desired_col) < self.table.columnCount():
                try:
                    self.table.horizontalHeader().setSortIndicator(int(desired_col), desired_order)
                except Exception:
                    pass
                try:
                    self.table.sortItems(int(desired_col), desired_order)
                except Exception:
                    pass
                self._sort_col = int(desired_col)
                self._sort_order = desired_order
        except Exception:
            pass
        finally:
            self._pending_sort = None

        # renumber
        if self._sort_col == self.COL_IDX_ROWNUM:
            self._apply_rownum_text_from_userrole()
        else:
            self._renumber_view_rows()

        # restore selection by UID
        restored = False
        if selected_uid_before:
            for r in range(self.table.rowCount()):
                it = self.table.item(r, self.COL_IDX_UID)
                if it and it.text().strip() == selected_uid_before:
                    self.table.setCurrentCell(r, self.COL_IDX_UID)
                    try:
                        self.table.scrollToItem(it, QAbstractItemView.PositionAtCenter)
                    except Exception:
                        pass
                    restored = True
                    break

        if not restored and scroll_before is not None:
            try:
                self.table.verticalScrollBar().setValue(int(scroll_before))
            except Exception:
                pass

        self._sync_buttons()
        self._on_selection_changed()
        self._state_dirty()

    # -------------------- actions --------------------
    def new_asset(self) -> None:
        if not _can(PERM_ASSETS_CREATE):
            QMessageBox.warning(self, "Zabranjeno", "Nemaš pravo: assets.create.")
            return

        if NewAssetDialog is None or not callable(create_asset):
            QMessageBox.critical(self, "Greška", "Nedostaje NewAssetDialog ili create_asset servis.")
            return

        dlg = NewAssetDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return

        payload: Dict[str, Any] = {}
        try:
            if hasattr(dlg, "get_payload") and callable(getattr(dlg, "get_payload")):
                payload = dict(dlg.get_payload() or {})
            elif hasattr(dlg, "values") and callable(getattr(dlg, "values")):
                payload = dict(dlg.values() or {})
            elif hasattr(dlg, "payload"):
                payload = dict(getattr(dlg, "payload") or {})
        except Exception:
            payload = {}

        name = _norm(payload.get("name", ""))
        if not name:
            QMessageBox.warning(self, "Greška", "Naziv je obavezan.")
            return

        created = None
        try:
            try:
                created = create_asset(actor=_actor_name(), **payload)
            except TypeError:
                created = create_asset(**payload)
        except Exception as e:
            try:
                self.logger.exception("AssetsPage.new_asset failed: %s", e)
            except Exception:
                pass
            QMessageBox.critical(self, "Greška", f"Ne mogu da kreiram sredstvo.\n\n{e}")
            return

        uid = _norm(created.get("asset_uid", "")) if isinstance(created, dict) else _norm(created)

        # auto assignment (best-effort)
        try:
            assignee = _norm(payload.get("assignee", "") or payload.get("auto_assign_to", "") or payload.get("current_holder", ""))
            location = _norm(payload.get("location", "") or payload.get("auto_location", ""))
            note_extra = _norm(payload.get("assign_note", "") or payload.get("note", ""))
            if uid and assignee:
                note = "Auto-zaduženje pri kreiranju sredstva"
                if note_extra:
                    note = f"{note} — {note_extra}"
                _try_create_assignment_after_create(asset_uid=uid, to_holder=assignee, to_location=location, note=note)
        except Exception:
            pass

        QMessageBox.information(self, "OK", f"Kreirano sredstvo:\n{uid or '(UID nije vraćen)'}")
        self._state_dirty()
        self.request_reload()

    def open_selected_detail(self) -> None:
        if not self._has_any_view:
            QMessageBox.warning(self, "Zabranjeno", "Nemaš pravo da vidiš detalje sredstva.")
            return
        row = self._current_row_any()
        if row < 0:
            QMessageBox.information(self, "Info", "Prvo izaberi red/ćeliju u tabeli.")
            return
        self.open_detail(row, 0)

    def open_detail(self, row: int, col: int) -> None:
        _ = col
        if not self._has_any_view:
            return
        if AssetDetailDialog is None:
            QMessageBox.critical(self, "Greška", "AssetDetailDialog nije dostupan.")
            return

        uid_item = self.table.item(int(row), self.COL_IDX_UID)
        asset_uid = uid_item.text().strip() if uid_item else ""
        if not asset_uid:
            return

        try:
            try:
                dlg = AssetDetailDialog(asset_uid=asset_uid, parent=self)  # newer signature
            except TypeError:
                dlg = AssetDetailDialog(asset_uid, self)  # legacy signature
            dlg.exec()
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da otvorim detalje.\n\n{e}")
            return

        self.request_reload()

    # -------------------- Reset layout --------------------
    def reset_layout(self) -> None:
        """
        Resetuje UI layout za ovu stranu:
        - filtere (tab/scope/category/status/search + quick filter)
        - preview state
        - splitter/header state (factory snapshot)
        - čisti QSettings group ui/assets_page
        - čisti wire_columns state za assets_table_v10 (ako postoji)
        """
        try:
            if QMessageBox.question(self, "Potvrda", "Resetovati layout i filtere na podrazumevano?") != QMessageBox.Yes:
                return
        except Exception:
            pass

        # 1) clear our page state
        try:
            s = _settings()
            s.beginGroup(self._SET_GROUP)
            try:
                s.remove("")
            finally:
                s.endGroup()
        except Exception:
            pass

        # 2) clear persisted columns state (wire_columns)
        self._clear_wire_columns_state()

        # 3) reset widgets
        try:
            self.tabs.setCurrentIndex(0)
            self.cb_scope.setCurrentIndex(0)
            self.cb_category.setCurrentIndex(max(0, self.cb_category.findText("SVE", Qt.MatchFixedString)))
            self.cb_status.setCurrentIndex(max(0, self.cb_status.findText("SVE", Qt.MatchFixedString)))
            self.ed_search.setText("")
            if self._quick_filter_edit is not None:
                self._quick_filter_edit.setText("")
        except Exception:
            pass

        # 4) reset columns runtime to defaults
        self._reset_columns_runtime_default()

        # 5) restore splitter defaults
        try:
            if getattr(self, "_default_splitter_state", None) is not None:
                self.splitter.restoreState(self._default_splitter_state)  # type: ignore[arg-type]
        except Exception:
            pass

        # preview default: expanded
        try:
            self._preview_collapsed = False
            self.preview.set_collapsed(False)
        except Exception:
            pass

        self._state_dirty()
        self.request_reload()

# (FILENAME: ui/assets_page.py - END PART 3/3)
# END FILENAME: ui/assets_page.py