# FILENAME: ui/assets_page.py
# (FILENAME: ui/assets_page.py - START PART 1/3)
# -*- coding: utf-8 -*-
"""BazaS2 — AssetsPage (offline)."""
from __future__ import annotations
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QTimer, QByteArray, QVariantAnimation, QEasingCurve, QEvent  # type: ignore
from PySide6.QtGui import QColor, QBrush, QCursor, QPainter, QKeySequence, QShortcut  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QApplication, QWidget, QFrame, QLabel, QPushButton, QToolButton, QLineEdit, QComboBox, QTabWidget,
    QSplitter, QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QHBoxLayout, QVBoxLayout,
    QFormLayout, QMessageBox, QMenu, QDialog, QStyle, QStyledItemDelegate
)

# ---- optional helpers (safe import) ----
wire_columns = None
wire_table_selection_plus_copy = None
TableToolsBar = None
TableToolsConfig = None
try:
    from ui.utils.table_columns import wire_columns  # type: ignore
except Exception:
    pass
try:
    from ui.utils.table_copy import wire_table_selection_plus_copy  # type: ignore
except Exception:
    pass
try:
    from ui.utils.table_search_sort import TableToolsBar, TableToolsConfig  # type: ignore
except Exception:
    pass

# ---- RBAC perms (prefer core.rbac constants) ----
try:
    from core.rbac import PERM_ASSETS_VIEW, PERM_ASSETS_CREATE, PERM_ASSETS_MY_VIEW, PERM_ASSETS_METRO_VIEW  # type: ignore
except Exception:
    PERM_ASSETS_VIEW = "assets.view"
    PERM_ASSETS_CREATE = "assets.create"
    PERM_ASSETS_MY_VIEW = "assets.my.view"
    PERM_ASSETS_METRO_VIEW = "assets.metrology.view"

# ---- services/dialogs ----
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

# ---- helpers ----
def _can(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        try:
            from core.rbac import can  # type: ignore
            return bool(can(perm))
        except Exception:
            return False

def _actor_name() -> str:
    for fn in ("get_actor_display_name", "actor_name"):
        try:
            from core import session as s  # type: ignore
            f = getattr(s, fn, None)
            if callable(f):
                return str(f() or "").strip()
        except Exception:
            pass
    return "user"

def _actor_key() -> str:
    for fn in ("get_actor_username", "actor_key"):
        try:
            from core import session as s  # type: ignore
            f = getattr(s, fn, None)
            if callable(f):
                return str(f() or "").strip()
        except Exception:
            pass
    return ""

def _settings():
    try:
        from PySide6.QtCore import QSettings  # type: ignore
        return QSettings("BazaS2", "BazaS2")
    except Exception:
        from PySide6.QtCore import QSettings  # type: ignore
        return QSettings()

def _is_dark() -> bool:
    try:
        c = QApplication.palette().window().color()
        return (0.2126*c.red()+0.7152*c.green()+0.0722*c.blue()) < 128
    except Exception:
        return True

def fmt_dt_sr(x: Any) -> str:
    try:
        from ui.utils.datetime_fmt import fmt_dt_sr as _f  # type: ignore
        return str(_f(x))
    except Exception:
        return str(x or "").strip()

def _norm(x: Any) -> str:
    try:
        return str(x or "").strip()
    except Exception:
        return ""

def _cf(x: Any) -> str:
    return _norm(x).casefold()

def _status_key(raw: Any) -> str:
    s = _cf(raw)
    if not s:
        return "unknown"
    if "rashod" in s or "otpis" in s or "scrap" in s:
        return "scrapped"
    if "serv" in s or "kalibr" in s:
        return "service"
    if "loan" in s or "zadu" in s or "duž" in s:
        return "on_loan"
    if s in ("active", "aktivno", "aktivna"):
        return "active"
    return s

def _safe_int(v: Any) -> int:
    try:
        digits = "".join(ch for ch in _norm(v) if ch.isdigit())
        return int(digits) if digits else 0
    except Exception:
        return 0

def _safe_dt_sort_value(v: Any) -> int:
    try:
        if isinstance(v, datetime):
            return int(v.timestamp())
        s = _norm(v).replace("Z","").replace("T"," ")
        if not s:
            return 0
        return int(datetime.fromisoformat(s).timestamp())
    except Exception:
        return 0

def _row_as_dict(r: Any) -> Dict[str, Any]:
    if isinstance(r, dict):
        return r
    try:
        return dict(r)
    except Exception:
        return {}

def _get_nomenclature(r: Dict[str, Any]) -> str:
    for k in ("nomenclature_number","nomenclature_no","nomenklaturni_broj","nomenclature"):
        v = _norm(r.get(k,""))
        if v:
            return v
    return ""

def _is_scrapped(r: Dict[str, Any]) -> bool:
    return _status_key(r.get("status","")) == "scrapped"

def _is_unassigned(r: Dict[str, Any]) -> bool:
    return not _norm(r.get("current_holder","") or r.get("assigned_to",""))

def _is_metro_asset_ui(r: Dict[str, Any]) -> bool:
    if "metrolog" in _cf(r.get("category","")):
        return True
    try:
        return bool(int(r.get("is_metrology",0) or 0))
    except Exception:
        return False

def _is_my_asset_ui(r: Dict[str, Any]) -> bool:
    holder = _cf(r.get("current_holder","") or r.get("assigned_to",""))
    me_u, me_n = _cf(_actor_key()), _cf(_actor_name())
    return bool(holder and ((me_u and me_u in holder) or (me_n and me_n in holder)))

class SortableItem(QTableWidgetItem):
    def __init__(self, text: str, sort_value: Any = None):
        super().__init__(text)
        try: self.setData(Qt.UserRole, text if sort_value is None else sort_value)
        except Exception: pass
    def __lt__(self, other: "QTableWidgetItem") -> bool:
        try:
            a,b = self.data(Qt.UserRole), other.data(Qt.UserRole)
            if isinstance(a,(int,float)) and isinstance(b,(int,float)): return float(a)<float(b)
            return str(a)<str(b)
        except Exception:
            return super().__lt__(other)

class _RowTintDelegate(QStyledItemDelegate):
    def __init__(self, parent: QWidget, status_col: int, palette: Dict[str, Tuple[QColor,QColor]], accent_px: int = 3):
        super().__init__(parent); self._c=int(status_col); self._p=dict(palette or {}); self._a=max(1,int(accent_px))
    def paint(self, painter: QPainter, option, index) -> None:  # type: ignore[override]
        try: selected = bool(option.state & QStyle.State_Selected)
        except Exception: selected = False
        if not selected:
            try:
                st = index.model().index(index.row(), self._c).data()
                key = _status_key(st)
                accent,tint = self._p.get(key, self._p.get("unknown",(QColor("#a0a6b6"), QColor(0,0,0,0))))
                r = option.rect; painter.save()
                if tint.alpha()>0: painter.fillRect(r,tint)
                if index.column()==0: painter.fillRect(r.adjusted(0,0,-r.width()+self._a,0), accent)
                painter.restore()
            except Exception:
                try: painter.restore()
                except Exception: pass
        super().paint(painter, option, index)

@dataclass
class ChipSpec:
    text: str
    on_remove: Callable[[], None]
    tooltip: str = ""

class FilterChipsBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent); self._clear: Optional[Callable[[],None]] = None
        lay=QHBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(8)
        self.btn_clear=QPushButton("Obriši sve"); self.btn_clear.clicked.connect(lambda: self._clear and self._clear()); lay.addWidget(self.btn_clear,0)
        self.host=QWidget(self); self.hlay=QHBoxLayout(self.host); self.hlay.setContentsMargins(0,0,0,0); self.hlay.setSpacing(6); lay.addWidget(self.host,1)
        self.refresh_theme(); self.set_chips([])
    def set_clear_all_handler(self, fn: Callable[[],None]) -> None: self._clear = fn
    def refresh_theme(self) -> None:
        dark=_is_dark()
        try:
            self.setStyleSheet(
                "QPushButton{padding:6px 10px;border-radius:12px;}"
                + ("QPushButton{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.16);color:rgba(255,255,255,0.86);}" if dark
                   else "QPushButton{background:rgba(0,0,0,0.04);border:1px solid rgba(0,0,0,0.12);color:rgba(0,0,0,0.82);}")
            )
        except Exception: pass
    def set_chips(self, chips: List[ChipSpec]) -> None:
        try:
            while self.hlay.count():
                it=self.hlay.takeAt(0); w=it.widget()
                if w: w.deleteLater()
        except Exception: pass
        for ch in chips:
            b=QPushButton(ch.text); b.setToolTip(ch.tooltip or ch.text); b.clicked.connect(ch.on_remove); self.hlay.addWidget(b,0)
        self.hlay.addStretch(1); self.btn_clear.setVisible(bool(chips))

class AssetPreviewPanel(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent); self.setFrameShape(QFrame.StyledPanel)
        self._collapsed=False; self._cw=64; self._ew=340; self._uid=""
        self._open: Optional[Callable[[],None]] = None; self._toggle: Optional[Callable[[],None]] = None
        self.title=QLabel("Pregled sredstva")
        self.btn_toggle=QToolButton(self); self.btn_toggle.setCursor(QCursor(Qt.PointingHandCursor)); self.btn_toggle.clicked.connect(lambda: self._toggle and self._toggle())
        self.btn_open=QPushButton("Otvori detalje"); self.btn_open.clicked.connect(lambda: self._open and self._open())
        self.btn_copy=QPushButton("Kopiraj UID"); self.btn_copy.clicked.connect(self._copy_uid)
        self._fields: Dict[str,QLabel] = {}
        form=QFormLayout(); form.setLabelAlignment(Qt.AlignLeft); form.setFormAlignment(Qt.AlignTop)
        def add(k,lbl):
            v=QLabel("—"); v.setTextInteractionFlags(Qt.TextSelectableByMouse); v.setWordWrap(True); self._fields[k]=v; form.addRow(QLabel(lbl), v)
        for k,lbl in [("asset_uid","Asset UID:"),("rb","RB:"),("toc_number","TOC:"),("nomenclature","Nomenkl. broj:"),("serial_number","Serijski:"),("name","Naziv:"),("category","Kategorija:"),("status","Status:"),("current_holder","Zaduženo kod:"),("location","Lokacija:"),("updated_at","Ažurirano:")]:
            add(k,lbl)
        head=QHBoxLayout(); head.setContentsMargins(0,0,0,0); head.setSpacing(8); head.addWidget(self.title,1); head.addWidget(self.btn_toggle,0,Qt.AlignRight)
        btns=QHBoxLayout(); btns.setContentsMargins(0,0,0,0); btns.setSpacing(8); btns.addWidget(self.btn_open,1); btns.addWidget(self.btn_copy,1)
        lay=QVBoxLayout(self); lay.setContentsMargins(10,10,10,10); lay.setSpacing(10); lay.addLayout(head); lay.addLayout(form); lay.addStretch(1); lay.addLayout(btns)
        self.refresh_theme(); self._refresh_toggle()
    def refresh_theme(self) -> None:
        try: self.btn_toggle.setStyleSheet("QToolButton{padding:6px 10px;border-radius:12px;}"+("QToolButton{border:1px solid rgba(255,255,255,0.22);background:rgba(255,255,255,0.06);color:rgba(255,255,255,0.90);}QToolButton:hover{border-color:rgba(255,255,255,0.40);background:rgba(255,255,255,0.10);}" if _is_dark() else "QToolButton{border:1px solid rgba(0,0,0,0.18);background:rgba(0,0,0,0.04);color:rgba(0,0,0,0.86);}QToolButton:hover{border-color:rgba(0,0,0,0.28);background:rgba(0,0,0,0.07);}"))
        except Exception: pass
    def set_open_handler(self, fn: Callable[[],None]) -> None: self._open = fn
    def set_toggle_handler(self, fn: Callable[[],None]) -> None: self._toggle = fn
    def set_toggle_enabled(self, en: bool) -> None:
        try: self.btn_toggle.setEnabled(bool(en))
        except Exception: pass
    def collapsed_width(self) -> int: return int(self._cw)
    def expanded_width_hint(self) -> int: return int(self._ew)
    def set_collapsed(self, collapsed: bool) -> None:
        self._collapsed=bool(collapsed); self._refresh_toggle()
        vis=not self._collapsed
        for w in [self.title,self.btn_open,self.btn_copy,*self._fields.values()]:
            try: w.setVisible(vis)
            except Exception: pass
        try:
            if self._collapsed: self.setMinimumWidth(self._cw); self.setMaximumWidth(self._cw)
            else: self.setMinimumWidth(self._ew); self.setMaximumWidth(16777215)
        except Exception: pass
    def _refresh_toggle(self) -> None:
        try:
            st=self.style()
            if not self._collapsed:
                self.btn_toggle.setIcon(st.standardIcon(QStyle.SP_ArrowRight)); self.btn_toggle.setText("Sakrij"); self.btn_toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            else:
                self.btn_toggle.setIcon(st.standardIcon(QStyle.SP_ArrowLeft)); self.btn_toggle.setText("")
        except Exception: pass
    def clear(self) -> None:
        self._uid="";
        for lb in self._fields.values(): lb.setText("—")
    def set_asset(self, r: Dict[str,Any]) -> None:
        if not isinstance(r,dict) or not r: self.clear(); return
        self._uid=_norm(r.get("asset_uid",""))
        def setv(k,v):
            lb=self._fields.get(k);
            if lb: lb.setText(_norm(v) or "—")
        setv("asset_uid",self._uid); setv("rb",r.get("rb","")); setv("toc_number",r.get("toc_number",""))
        nom=_get_nomenclature(r); setv("nomenclature",nom)
        for k in ("serial_number","name","category","status","current_holder","location"): setv(k,r.get(k,""))
        setv("updated_at",fmt_dt_sr(r.get("updated_at","")))
        try:
            lb=self._fields.get("nomenclature")
            if lb: lb.setStyleSheet("" if nom else "color:#ff8a80;font-weight:700;"); lb.setToolTip("" if nom else "Nomenklaturni broj nije unet.")
        except Exception: pass
    def _copy_uid(self) -> None:
        if not self._uid: return
        try: QApplication.clipboard().setText(self._uid)
        except Exception: pass

# (FILENAME: ui/assets_page.py - END PART 1/3)

# FILENAME: ui/assets_page.py
# (FILENAME: ui/assets_page.py - START PART 2/3)

@dataclass
class ColSpec:
    key: str
    label: str
    default_visible: bool = True
    default_width: int = 120


class AssetsPage(QWidget):
    # Columns (11)
    COLS = [
        "#",
        "Asset UID", "TOC", "Nomenkl. broj", "Serijski",
        "Naziv", "Kategorija", "Status",
        "Zaduženo kod", "Lokacija", "Ažurirano",
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

    TAB_ACTIVE = "Aktivna"
    TAB_UNASSIGNED = "Bez zaduženja"
    TAB_SCRAPPED = "Rashodovana"
    TAB_ALL = "Sva"

    SCOPE_ALL = "Sva sredstva"
    SCOPE_MY = "Moja oprema"
    SCOPE_METRO = "Metrologija (scope)"

    # settings
    _SET_GROUP = "ui/assets_page"
    _K_TAB = "tab_index"
    _K_SCOPE = "scope_text"
    _K_CAT = "category"
    _K_STATUS = "status"
    _K_SEARCH = "search"
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

        # pending restores
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
        self._reload_timer.timeout.connect(self._on_reload_timeout)

        self._persist_timer = QTimer(self)
        self._persist_timer.setSingleShot(True)
        self._persist_timer.setInterval(350)
        self._persist_timer.timeout.connect(self._persist_ui_state)

        self._sync_timer = QTimer(self)
        self._sync_timer.setInterval(250)
        self._sync_timer.timeout.connect(self._poll_hidden_for_renumber)

        # columns spec for wire_columns
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
        top.addWidget(self.btn_detail)
        top.addWidget(self.btn_new)

        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        vh = self.table.verticalHeader()
        vh.setVisible(True)
        vh.setDefaultAlignment(Qt.AlignRight | Qt.AlignVCenter)
        vh.setHighlightSections(False)
        try:
            vh.setSectionResizeMode(QHeaderView.Fixed)
            vh.setFixedWidth(46)
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

        try:
            self.table.verticalHeader().setDefaultSectionSize(30)
        except Exception:
            pass

        self.table.setSortingEnabled(True)

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
                        self.COL_IDX_NAME, self.COL_IDX_CAT, self.COL_IDX_STATUS, self.COL_IDX_HOLDER, self.COL_IDX_LOC,
                    ],
                ),
                parent=self,
            )
        else:
            self.quick_tools = QLabel("")
            self.quick_tools.setVisible(False)

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

        lay = QVBoxLayout(self)
        lay.addWidget(self.tabs)
        lay.addLayout(top)
        lay.addWidget(self.quick_tools)
        lay.addWidget(self.chips)
        lay.addWidget(self.lb_info)
        lay.addWidget(self.lb_rbac)
        lay.addWidget(self.lb_empty)
        lay.addWidget(self.splitter, 1)

        # ---- signals (KEY FIX: search textChanged does NOT reload DB) ----
        self.btn_refresh.clicked.connect(self.request_reload)
        self.btn_search.clicked.connect(self.request_reload)
        self.btn_new.clicked.connect(self.new_asset)
        self.btn_detail.clicked.connect(self.open_selected_detail)

        self.tabs.currentChanged.connect(lambda _i: (self._state_dirty(), self.request_reload()))
        self.cb_scope.currentIndexChanged.connect(lambda _i: (self._state_dirty(), self.request_reload()))
        self.cb_category.currentIndexChanged.connect(lambda _i: (self._state_dirty(), self.request_reload()))
        self.cb_status.currentIndexChanged.connect(lambda _i: (self._state_dirty(), self.request_reload()))

        # ✅ only persist + chips on typing; fetch happens on Enter or button
        self.ed_search.textChanged.connect(lambda _t: (self._state_dirty(), self._rebuild_chips()))
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

        self._install_context_menu()
        self._install_shortcuts()

        # columns dialog hook
        if wire_columns is not None:
            try:
                self._apply_cols_assets = wire_columns(self, self.table, self.btn_columns, "assets_table_v10", self._col_specs)
            except Exception:
                self._apply_cols_assets = lambda: None
        else:
            self._apply_cols_assets = lambda: None
            # don't leave dead button
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
        dark = _is_dark()
        try:
            self.lb_info.setStyleSheet(
                "QLabel{ padding:10px 12px; border-radius:14px; "
                + ("background: rgba(255,255,255,0.06); color: rgba(255,255,255,0.92); border:1px solid rgba(255,255,255,0.14); }"
                   if dark else
                   "background: rgba(0,0,0,0.04); color: rgba(0,0,0,0.82); border:1px solid rgba(0,0,0,0.12); }")
            )
        except Exception:
            pass
        try:
            self.lb_empty.setStyleSheet(
                "QLabel{ padding: 10px; "
                + ("color: rgba(255,255,255,0.55); }" if dark else "color: rgba(0,0,0,0.45); }")
            )
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

        def to_int(x: Any, d: int) -> int:
            try:
                return int(x)
            except Exception:
                return int(d)

        tab_i = max(0, min(to_int(tab_idx, 0), self.tabs.count() - 1))
        prev_w_i = max(self.preview.collapsed_width(), to_int(prev_w, self.preview.expanded_width_hint()))
        sort_col_i = to_int(sort_col, -1)
        sort_ord_i = to_int(sort_order, int(Qt.AscendingOrder))

        try:
            self.tabs.blockSignals(True)
            self.cb_scope.blockSignals(True)
            self.cb_category.blockSignals(True)
            self.cb_status.blockSignals(True)
            self.ed_search.blockSignals(True)

            self.tabs.setCurrentIndex(tab_i)

            if scope_txt:
                i = self.cb_scope.findText(scope_txt, Qt.MatchFixedString)
                if i >= 0:
                    self.cb_scope.setCurrentIndex(i)

            i = self.cb_category.findText(cat_txt, Qt.MatchFixedString)
            if i >= 0:
                self.cb_category.setCurrentIndex(i)

            i = self.cb_status.findText(st_txt, Qt.MatchFixedString)
            if i >= 0:
                self.cb_status.setCurrentIndex(i)

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

        self._pending_preview_collapsed = bool(prev_coll)
        self._pending_preview_width = int(prev_w_i)

        if isinstance(splitter_state, (QByteArray, bytes)):
            self._pending_splitter_state = splitter_state if isinstance(splitter_state, QByteArray) else QByteArray(splitter_state)

        if wire_columns is None and isinstance(hdr_state, (QByteArray, bytes)):
            self._pending_header_state = hdr_state if isinstance(hdr_state, QByteArray) else QByteArray(hdr_state)

        try:
            order_enum = Qt.SortOrder(sort_ord_i)
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

    # -------------------- RBAC / chips / selection / menu / shortcuts --------------------
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
            for w in (self.tabs, self.cb_scope, self.ed_search, self.cb_category, self.cb_status,
                      self.btn_search, self.btn_refresh, self.btn_columns, self.btn_detail, self.btn_new,
                      self.table, self.quick_tools, self.preview, self.splitter, self.chips):
                try:
                    w.setEnabled(False)
                except Exception:
                    pass
            return

        ok_create = _can(PERM_ASSETS_CREATE)
        self.btn_new.setEnabled(bool(ok_create))
        self.lb_rbac.hide()

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
                chips.append(ChipSpec(
                    text=f"Kategorija: {cat}",
                    on_remove=lambda: self.cb_category.setCurrentIndex(max(0, self.cb_category.findText("SVE", Qt.MatchFixedString))),
                ))
        except Exception:
            pass

        try:
            st = str(self.cb_status.currentText() or "SVE")
            if st.upper() != "SVE":
                chips.append(ChipSpec(
                    text=f"Status: {st}",
                    on_remove=lambda: self.cb_status.setCurrentIndex(max(0, self.cb_status.findText("SVE", Qt.MatchFixedString))),
                ))
        except Exception:
            pass

        try:
            q = str(self.ed_search.text() or "").strip()
            if q:
                chips.append(ChipSpec(text=f"Pretraga: {q}", on_remove=lambda: self.ed_search.setText(""), tooltip="DB pretraga"))
        except Exception:
            pass

        self.chips.set_chips(chips)

    def _clear_all_filters(self) -> None:
        try:
            self.tabs.setCurrentIndex(0)
            self.cb_scope.setCurrentIndex(0)
            self.cb_category.setCurrentIndex(max(0, self.cb_category.findText("SVE", Qt.MatchFixedString)))
            self.cb_status.setCurrentIndex(max(0, self.cb_status.findText("SVE", Qt.MatchFixedString)))
            self.ed_search.setText("")
        except Exception:
            pass
        self._state_dirty()
        self.request_reload()

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

        def txt(c: int) -> str:
            it = self.table.item(row, c)
            return it.text().strip() if it else ""

        return {
            "asset_uid": txt(self.COL_IDX_UID),
            "rb": txt(self.COL_IDX_ROWNUM),
            "toc_number": txt(self.COL_IDX_TOC),
            "nomenclature_number": txt(self.COL_IDX_NOM),
            "serial_number": txt(self.COL_IDX_SN),
            "name": txt(self.COL_IDX_NAME),
            "category": txt(self.COL_IDX_CAT),
            "status": txt(self.COL_IDX_STATUS),
            "current_holder": txt(self.COL_IDX_HOLDER),
            "location": txt(self.COL_IDX_LOC),
            "updated_at": txt(self.COL_IDX_UPD),
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

    def _install_context_menu(self) -> None:
        try:
            self.table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._on_table_context_menu)
        except Exception:
            pass

    def _on_table_context_menu(self, pos) -> None:
        # context menu should act on clicked cell
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
        elif act == a_refresh:
            self.request_reload()

    def _install_shortcuts(self) -> None:
        # Global shortcuts
        def mk(seq: str, fn, parent: QWidget, ctx: Qt.ShortcutContext) -> None:
            try:
                sc = QShortcut(QKeySequence(seq), parent)
                sc.setContext(ctx)
                sc.activated.connect(fn)
            except Exception:
                pass

        mk("Ctrl+R", self.request_reload, parent=self, ctx=Qt.WindowShortcut)
        mk("Ctrl+F", lambda: self.ed_search.setFocus(), parent=self, ctx=Qt.WindowShortcut)
        mk("Ctrl+Shift+C", self._copy_selected_uid, parent=self, ctx=Qt.WindowShortcut)

        # ✅ Enter/Return only on TABLE (won't steal search field Enter)
        mk("Return", self.open_selected_detail, parent=self.table, ctx=Qt.WidgetShortcut)
        mk("Enter", self.open_selected_detail, parent=self.table, ctx=Qt.WidgetShortcut)

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

# (FILENAME: ui/assets_page.py - END PART 2/3)

# FILENAME: ui/assets_page.py
# (FILENAME: ui/assets_page.py - START PART 3/3)

    # -------------------- tab/scope/filter helpers --------------------
    def _active_tab_name(self) -> str:
        try:
            return self.tabs.tabText(self.tabs.currentIndex())
        except Exception:
            return self.TAB_ACTIVE

    def _apply_tab_filter(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        tab = self._active_tab_name()
        if tab == self.TAB_ACTIVE:
            return [r for r in rows if _status_key(r.get("status")) != "scrapped"]
        if tab == self.TAB_UNASSIGNED:
            out: List[Dict[str, Any]] = []
            for r in rows:
                if _status_key(r.get("status")) == "scrapped":
                    continue
                holder = _norm(r.get("current_holder") or r.get("assigned_to") or "")
                if not holder:
                    out.append(r)
            return out
        if tab == self.TAB_SCRAPPED:
            return [r for r in rows if _status_key(r.get("status")) == "scrapped"]
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
        """
        UI backstop filteri:
        - category/status uvek (brzo i stabilno)
        - search opciono (kad je DB već filtrirao)
        """
        if not rows:
            return []

        try:
            cat = _norm(self.cb_category.currentText() or "SVE")
        except Exception:
            cat = "SVE"

        try:
            st = _norm(self.cb_status.currentText() or "SVE")
        except Exception:
            st = "SVE"

        q = ""
        if apply_search:
            try:
                q = _cf(self.ed_search.text())
            except Exception:
                q = ""

        out = rows

        # category
        try:
            if cat and cat.upper() != "SVE":
                out = [r for r in out if self._cat_match(cat, (r or {}).get("category", ""))]
        except Exception:
            pass

        # status
        try:
            if st and st.upper() != "SVE":
                ss = st.casefold()
                if ss == "scrapped":
                    out = [r for r in out if _status_key((r or {}).get("status", "")) == "scrapped"]
                else:
                    out = [r for r in out if _norm((r or {}).get("status", "")).casefold() == ss]
        except Exception:
            pass

        # search (optional)
        if q:
            def row_text(rr: Dict[str, Any]) -> str:
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
                ]
                return " ".join(str(x or "") for x in parts).casefold()

            try:
                out = [r for r in out if q in row_text(r)]
            except Exception:
                return rows

        return out

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

    def _animate_splitter_right(
        self,
        start_right: int,
        end_right: int,
        duration_ms: int,
        on_finished: Optional[Callable[[], None]] = None,
    ) -> None:
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

            def tick(val) -> None:
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

            def done() -> None:
                try:
                    self._preview_animating = False
                    self.preview.set_toggle_enabled(True)
                except Exception:
                    pass
                self._anim_optimize_end()
                if on_finished:
                    try:
                        on_finished()
                    except Exception:
                        pass
                self._state_dirty()

            anim.valueChanged.connect(tick)
            anim.finished.connect(done)
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
            if on_finished:
                try:
                    on_finished()
                except Exception:
                    pass
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
            self._animate_splitter_right(
                start_right=current_right,
                end_right=self.preview.collapsed_width(),
                duration_ms=260,
            )
        else:
            self._preview_collapsed = False
            target = int(self._preview_last_w or self.preview.expanded_width_hint())
            target = max(target, self.preview.expanded_width_hint())

            self.preview.set_collapsed(False)
            self._animate_splitter_right(
                start_right=current_right,
                end_right=target,
                duration_ms=290,
            )

    # -------------------- data load --------------------
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
        # fail-closed: if user doesn't have full view, ALL is not allowed even if UI restored it
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
            # ---- fetch (robust signature; optional service-level scope if supported) ----
            rows_any: List[Any] = []
            used_service_scope = False

            # map UI scope to service-friendly values (best-effort)
            service_scope = None
            if scope == self.SCOPE_MY:
                service_scope = "my"
            elif scope == self.SCOPE_METRO:
                service_scope = "metro"

            # prefer keyword signature
            try:
                if service_scope:
                    rows_any = list_assets(
                        search=self.ed_search.text(),
                        category=self.cb_category.currentText(),
                        status=self.cb_status.currentText(),
                        limit=limit,
                        scope=service_scope,
                    ) or []
                    used_service_scope = True
                else:
                    rows_any = list_assets(
                        search=self.ed_search.text(),
                        category=self.cb_category.currentText(),
                        status=self.cb_status.currentText(),
                        limit=limit,
                    ) or []
            except TypeError:
                # fallback legacy signature
                try:
                    rows_any = list_assets(
                        self.ed_search.text(),
                        self.cb_category.currentText(),
                        self.cb_status.currentText(),
                        limit,
                    ) or []
                except Exception:
                    rows_any = list_assets(limit=limit) or []

            # banner cap
            try:
                if isinstance(rows_any, list) and len(rows_any) >= limit:
                    self.lb_info.setText(f"Prikazano je prvih {limit} rezultata. Suzi filtere za precizniji prikaz.")
                    self.lb_info.show()
                else:
                    self.lb_info.hide()
            except Exception:
                pass

            rows = [_row_as_dict(r) for r in (rows_any or [])]
            rows = [r for r in rows if isinstance(r, dict) and r]

            # tab filter
            rows = self._apply_tab_filter(rows)

            # ---- scope backstop (ALWAYS) ----
            # if service didn't apply scope, we must apply here
            if not used_service_scope:
                if scope == self.SCOPE_MY:
                    rows = [r for r in rows if _is_my_asset_ui(r)]
                elif scope == self.SCOPE_METRO:
                    rows = [r for r in rows if _is_metro_asset_ui(r)]

            # ---- local backstop filters ----
            # if we used keyword list_assets(search/category/status), DB likely already filtered;
            # but keep local category/status as safety; avoid double search where possible
            apply_search_local = not (
                # DB-level filter is assumed when we used keyword path above
                True
            )
            # practical: do NOT double-search; but keep local category/status always
            rows = self._apply_local_filters(rows, apply_search=False)

            try:
                self.lb_empty.setVisible(len(rows) == 0)
            except Exception:
                pass

            # ---- render ----
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
                    it_toc = SortableItem(toc, _safe_int(toc) or 0)
                    it_toc.setFlags(it_toc.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(i, self.COL_IDX_TOC, it_toc)

                    nom = _get_nomenclature(r)
                    it_nom = SortableItem(nom, _safe_int(nom) or 0)
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

                    raw_upd = r.get("updated_at", "") or ""
                    disp_upd = ""
                    try:
                        disp_upd = fmt_dt_sr(raw_upd)
                    except Exception:
                        disp_upd = _norm(raw_upd)
                    it_upd = SortableItem(str(disp_upd), _safe_dt_sort_value(raw_upd) or 0)
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

        # apply column prefs
        try:
            self._apply_cols_assets()
        except Exception:
            pass

        # apply sort every reload
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
            fn = globals().get("_try_create_assignment_after_create")
            if callable(fn):
                assignee = _norm(payload.get("assignee", "") or payload.get("auto_assign_to", "") or payload.get("current_holder", ""))
                location = _norm(payload.get("location", "") or payload.get("auto_location", ""))
                note_extra = _norm(payload.get("assign_note", "") or payload.get("note", ""))
                if uid and assignee:
                    note = "Auto-zaduženje pri kreiranju sredstva"
                    if note_extra:
                        note = f"{note} — {note_extra}"
                    fn(asset_uid=uid, to_holder=assignee, to_location=location, note=note)
        except Exception:
            pass

        QMessageBox.information(self, "OK", f"Kreirano sredstvo:\n{uid or '(UID nije vraćen)'}")
        self._state_dirty()
        self.request_reload()

        if uid:
            def _sel() -> None:
                try:
                    for r in range(self.table.rowCount()):
                        it = self.table.item(r, self.COL_IDX_UID)
                        if it and it.text().strip() == uid:
                            self.table.setCurrentCell(r, self.COL_IDX_UID)
                            try:
                                self.table.scrollToItem(it, QAbstractItemView.PositionAtCenter)
                            except Exception:
                                pass
                            return
                except Exception:
                    return
            QTimer.singleShot(260, _sel)

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

# (FILENAME: ui/assets_page.py - END PART 3/3)
# FILENAME: ui/assets_page.py