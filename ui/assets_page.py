# -*- coding: utf-8 -*-
# FILENAME: ui/assets_page.py
# (FILENAME: ui/assets_page.py - START PART 1)
"""
BazaS2 (offline) — ui/assets_page.py

Sredstva — UI (V1):
- Tabovi: Aktivna / Bez zaduženja / Rashodovana / Sva
- Filteri (DB) + Brzi filter (instant) (ako postoji helper)
- Kreiraj novo sredstvo
- Detalji sredstva (AssetDetailDialog)
- Desni Preview panel (collapse/expand)

UX/Perf polish (bez menjanja osnovne logike):
- Persist: tab/scope/category/status/search + preview + splitter state
- Persist: sort indikator (kolona + smer) + (fallback) header state ako nema wire_columns
- Empty-state poruka kad nema rezultata
- Hard-cap info (npr. “prikazano prvih 5000”)
- Stabilniji restore selekcije + scroll posle reload-a
- Theme-aware stilovi za info/empty/preview/chips
- CloseEvent: forsira persist (da se ne izgubi ako user odmah zatvori)

Napomena:
- Aplikacija je 100% offline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import (  # type: ignore
    Qt,
    QTimer,
    QSize,
    QVariantAnimation,
    QEasingCurve,
    QRect,
    QPoint,
    QSettings,
    QByteArray,
    QEvent,
)
from PySide6.QtGui import (  # type: ignore
    QColor,
    QBrush,
    QPainter,
    QPalette,
    QCursor,
)
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
    QAbstractItemView,
    QTabWidget,
    QDialog,
    QSplitter,
    QFrame,
    QFormLayout,
    QApplication,
    QToolButton,
    QStyle,
    QHeaderView,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QLayout,
    QLayoutItem,
    QMenu,
)

from core.rbac import PERM_ASSETS_VIEW, PERM_ASSETS_CREATE, PERM_ASSETS_MY_VIEW, PERM_ASSETS_METRO_VIEW
from services.assets_service import create_asset, list_assets, list_assets_brief
from ui.asset_detail_dialog import AssetDetailDialog
from ui.columns_dialog import ColSpec
from ui.new_asset_dialog import NewAssetDialog


# ---- fmt_dt_sr (fail-safe) ----
try:
    from ui.utils.datetime_fmt import fmt_dt_sr  # type: ignore
except Exception:  # pragma: no cover
    def fmt_dt_sr(x: Any) -> str:
        return str(x or "").strip()


# ---- wire_columns (fail-safe) ----
try:
    from ui.utils.table_columns import wire_columns  # type: ignore
except Exception:  # pragma: no cover
    wire_columns = None  # type: ignore


# ---- copy helper (fail-safe) ----
try:
    from ui.utils.table_copy import wire_table_selection_plus_copy  # type: ignore
except Exception:  # pragma: no cover
    wire_table_selection_plus_copy = None  # type: ignore


# ---- quick tools (fail-safe) ----
try:
    from ui.utils.table_search_sort import TableToolsBar, TableToolsConfig  # type: ignore
except Exception:  # pragma: no cover
    TableToolsBar = None  # type: ignore
    TableToolsConfig = None  # type: ignore


# -------------------- helpers --------------------
def _can(perm: str) -> bool:
    """Fail-closed RBAC check (ako session/can ne postoji => False)."""
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


def _norm(x: Any) -> str:
    try:
        return str(x or "").strip()
    except Exception:
        return ""


def _cf(x: Any) -> str:
    return _norm(x).casefold()


def _status_key(raw: Any) -> str:
    """
    Normalizuje status u stabilne ključne vrednosti.
    Ne oslanjamo se da DB/service uvek vraća iste stringove.
    """
    s = _cf(raw)
    if not s:
        return "unknown"
    if any(x in s for x in ("rashod", "otpis", "retired", "disposed", "decommission", "archiv", "inactive")):
        return "scrapped"
    if s in ("active", "in_use", "u_upotrebi", "upotrebi", "aktivno", "aktivna"):
        return "active"
    if any(x in s for x in ("on_loan", "loan", "assign", "zaduzen", "zaduž", "duzi", "duži")):
        return "on_loan"
    if any(x in s for x in ("service", "repair", "servis", "kalibr", "kalibracij", "metrolog")):
        return "service"
    return s


def _safe_int(v: Any) -> Optional[int]:
    """Ekstrakcija int-a iz raznih formata (TOC, NOM) – za sortiranje."""
    try:
        if v is None or isinstance(v, bool):
            return None
        if isinstance(v, int):
            return v
        if isinstance(v, float):
            return int(v)
        s = str(v).strip()
        digits = "".join(ch for ch in s if ch.isdigit())
        return int(digits) if digits else None
    except Exception:
        return None


def _safe_dt_sort_value(v: Any) -> Optional[int]:
    """Sort value za datetime; tolerantno na ISO-ish stringove."""
    try:
        if v is None:
            return None
        if isinstance(v, datetime):
            return int(v.timestamp())
        s = str(v or "").strip().replace("Z", "").replace("T", " ")
        if not s:
            return None
        return int(datetime.fromisoformat(s).timestamp())
    except Exception:
        return None


def _row_as_dict(r: Any) -> Dict[str, Any]:
    if r is None:
        return {}
    if isinstance(r, dict):
        return r
    try:
        return dict(r)
    except Exception:
        return {}


def _get_nomenclature(r: Dict[str, Any]) -> str:
    for k in ("nomenclature_number", "nomenclature_no", "nomenklaturni_broj", "nom_broj", "nom_no", "nomen"):
        try:
            v = str(r.get(k, "") or "").strip()
            if v:
                return v
        except Exception:
            pass
    return ""


def _is_unassigned(r: Dict[str, Any]) -> bool:
    return not _norm(r.get("current_holder", "") or r.get("assigned_to", ""))


def _is_scrapped(r: Dict[str, Any]) -> bool:
    return _status_key(r.get("status", "")) == "scrapped"


def _scope_candidates_lower() -> List[str]:
    """Kandidati koji mogu biti upisani kao holder (ključ/ime) – sve casefold."""
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
        cc = str(c or "").strip().casefold()
        if cc and cc not in seen:
            seen.add(cc)
            out.append(cc)
    return out


def _is_my_asset_ui(r: Dict[str, Any]) -> bool:
    holder = _norm(r.get("current_holder", "") or r.get("assigned_to", ""))
    h = holder.casefold()
    return bool(holder) and any(h == c for c in _scope_candidates_lower())


def _is_metro_asset_ui(r: Dict[str, Any]) -> bool:
    cat = _cf(r.get("category", ""))
    if "metrolog" in cat:
        return True
    for k in ("is_metrology", "is_metro", "metrology_flag", "metro_flag", "calibration_required", "needs_calibration"):
        if k in r:
            try:
                if bool(r.get(k)):
                    return True
            except Exception:
                pass
    return False


def _try_create_assignment_after_create(asset_uid: str, to_holder: str, to_location: str = "", note: str = "") -> None:
    """
    Best-effort auto-zaduženje nakon kreiranja sredstva.
    FAIL-SAFE: ako servis/helper ne postoji => tiho preskoči (ne ruši UI).
    """
    holder = (to_holder or "").strip()
    if not asset_uid or not holder:
        return
    try:
        from services.assignments_service import create_assignment  # type: ignore
        create_assignment(
            actor=_actor_name(),
            asset_uid=asset_uid,
            action="assign",
            to_holder=holder,
            to_location=(to_location or "").strip(),
            note=(note or "").strip(),
            source="ui_new_asset_autozad",
        )
    except Exception:
        # fallback ako postoji DB helper (ne mora postojati)
        try:
            from core.db import create_assignment_db  # type: ignore
            create_assignment_db(
                actor=_actor_name(),
                asset_uid=asset_uid,
                action="assign",
                to_holder=holder,
                to_location=(to_location or "").strip(),
                note=(note or "").strip(),
                source="ui_new_asset_autozad",
            )
        except Exception:
            return


def _is_dark_theme() -> bool:
    try:
        a = QApplication.instance()
        pal = a.palette() if a else QApplication.palette()
        return pal.color(QPalette.Window).value() < 128
    except Exception:
        return True


def _settings() -> QSettings:
    return QSettings("BazaS2", "BazaS2")


def _qss_banner(dark: bool) -> str:
    if dark:
        return "padding:6px 10px; border-radius:10px; background: rgba(255,255,255,0.06); color: rgba(255,255,255,0.88);"
    return "padding:6px 10px; border-radius:10px; background: rgba(0,0,0,0.04); color: rgba(0,0,0,0.78);"


def _qss_empty(dark: bool) -> str:
    if dark:
        return "padding:14px; color: rgba(255,255,255,0.75); font-weight:600;"
    return "padding:14px; color: rgba(0,0,0,0.55); font-weight:600;"


def _qss_btn_soft(dark: bool) -> str:
    """Soft dugme stil (dark/light aware) – koristi se za preview toggle."""
    if dark:
        return (
            "QToolButton{ border:1px solid rgba(255,255,255,0.22); background: rgba(255,255,255,0.06); color: rgba(255,255,255,0.90); }"
            "QToolButton:hover{ border-color: rgba(255,255,255,0.40); background: rgba(255,255,255,0.10); }"
            "QToolButton:pressed{ background: rgba(255,255,255,0.14); }"
            "QToolButton:focus{ border-color: rgba(90,170,255,0.75); }"
        )
    return (
        "QToolButton{ border:1px solid rgba(0,0,0,0.20); background: rgba(0,0,0,0.03); color: rgba(0,0,0,0.88); }"
        "QToolButton:hover{ border-color: rgba(0,0,0,0.35); background: rgba(0,0,0,0.06); }"
        "QToolButton:pressed{ background: rgba(0,0,0,0.08); }"
        "QToolButton:focus{ border-color: rgba(60,130,255,0.75); }"
    )


class _SignalBlock:
    """Minimal helper: blockSignals(True) na entry, restore na exit."""
    def __init__(self, *objs: Any):
        self._objs = [o for o in objs if o is not None]
        self._prev: List[bool] = []

    def __enter__(self):
        self._prev = []
        for o in self._objs:
            try:
                self._prev.append(bool(o.blockSignals(True)))
            except Exception:
                self._prev.append(False)
        return self

    def __exit__(self, exc_type, exc, tb):
        for o, prev in zip(self._objs, self._prev):
            try:
                o.blockSignals(bool(prev))
            except Exception:
                pass
        return False


# -------------------- Sortable item (numeričko sortiranje) --------------------
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


# -------------------- FlowLayout (chip bar) --------------------
class FlowLayout(QLayout):
    def __init__(self, parent=None, margin: int = 0, hspacing: int = 6, vspacing: int = 6):
        super().__init__(parent)
        self._items: List[QLayoutItem] = []
        self.setContentsMargins(margin, margin, margin, margin)
        self._h, self._v = int(hspacing), int(vspacing)

    def addItem(self, item: QLayoutItem) -> None:
        self._items.append(item)

    def addWidget(self, w: QWidget) -> None:
        from PySide6.QtWidgets import QWidgetItem  # type: ignore
        self.addItem(QWidgetItem(w))

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int) -> Optional[QLayoutItem]:
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index: int) -> Optional[QLayoutItem]:
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self) -> Qt.Orientations:
        return Qt.Orientations(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._do_layout(QRect(0, 0, width, 0), True)

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        self._do_layout(rect, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for it in self._items:
            size = size.expandedTo(it.minimumSize())
        l, t, r, b = self.getContentsMargins()
        return size + QSize(l + r, t + b)

    def _do_layout(self, rect: QRect, test_only: bool) -> int:
        l, t, r, b = self.getContentsMargins()
        effective = QRect(rect.x() + l, rect.y() + t, rect.width() - (l + r), rect.height() - (t + b))

        x, y, line_h = effective.x(), effective.y(), 0

        for it in self._items:
            w = it.widget()
            if w and not w.isVisible():
                continue
            hint = it.sizeHint()
            next_x = x + hint.width() + self._h
            if next_x - self._h > effective.right() and line_h > 0:
                x = effective.x()
                y = y + line_h + self._v
                next_x = x + hint.width() + self._h
                line_h = 0
            if not test_only:
                it.setGeometry(QRect(QPoint(x, y), hint))
            x = next_x
            line_h = max(line_h, hint.height())

        return y + line_h - rect.y() + b


# -------------------- Filter chips (chip bar) --------------------
@dataclass
class ChipSpec:
    text: str
    on_remove: Callable[[], None]
    tooltip: str = ""


class FilterChipsBar(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.NoFrame)
        self._clear_all: Optional[Callable[[], None]] = None

        title = QLabel("Aktivni filteri:")
        title.setObjectName("FilterChipsTitle")

        self.btn_clear = QToolButton(self)
        self.btn_clear.setText("Očisti sve")
        self.btn_clear.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_clear.setAutoRaise(True)
        self.btn_clear.clicked.connect(lambda: self._clear_all and self._clear_all())

        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(8)
        head.addWidget(title, 0)
        head.addStretch(1)
        head.addWidget(self.btn_clear, 0)

        self.host = QWidget(self)
        self.flow = FlowLayout(self.host, margin=0, hspacing=6, vspacing=6)
        self.host.setLayout(self.flow)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        lay.addLayout(head)
        lay.addWidget(self.host, 1)

        self._apply_qss()
        self.setVisible(False)

    def _apply_qss(self) -> None:
        try:
            dark = _is_dark_theme()
            chip_bg, chip_bg_h, chip_bd, title = (
                ("rgba(255,255,255,0.08)", "rgba(255,255,255,0.12)", "rgba(255,255,255,0.18)", "rgba(255,255,255,0.82)")
                if dark else
                ("rgba(0,0,0,0.05)", "rgba(0,0,0,0.08)", "rgba(0,0,0,0.15)", "rgba(0,0,0,0.70)")
            )
            self.setStyleSheet(
                "QLabel#FilterChipsTitle{ font-weight:700; color:%s; }"
                "QToolButton#ChipBtn{ border:1px solid %s; border-radius:12px; background:%s; padding:5px 10px; }"
                "QToolButton#ChipBtn:hover{ background:%s; }"
                % (title, chip_bd, chip_bg, chip_bg_h)
            )
        except Exception:
            pass

    def set_clear_all_handler(self, fn: Callable[[], None]) -> None:
        self._clear_all = fn

    def set_chips(self, chips: List[ChipSpec]) -> None:
        # clear
        try:
            while self.flow.count():
                it = self.flow.takeAt(0)
                if it and it.widget():
                    it.widget().deleteLater()
        except Exception:
            pass

        for spec in (chips or []):
            btn = QToolButton(self.host)
            btn.setObjectName("ChipBtn")
            btn.setText(f"{spec.text}  ✕")
            btn.setCursor(QCursor(Qt.PointingHandCursor))
            if spec.tooltip:
                btn.setToolTip(spec.tooltip)
            btn.clicked.connect(spec.on_remove)
            self.flow.addWidget(btn)

        self.setVisible(bool(chips))

    def refresh_theme(self) -> None:
        self._apply_qss()


# -------------------- Row tint delegate --------------------
class _AssetsRowTintDelegate(QStyledItemDelegate):
    def __init__(
        self,
        table: QTableWidget,
        status_col: int,
        palette: Dict[str, Tuple[QColor, QColor]],
        accent_px: int = 3,
    ):
        super().__init__(table)
        self._tbl = table
        self._status_col = int(status_col)
        self._accent_px = max(1, int(accent_px))
        self._palette = dict(palette or {})

    def _status_for_row(self, row: int) -> str:
        try:
            it = self._tbl.item(row, self._status_col)
            return _status_key(it.text() if it else "")
        except Exception:
            return "unknown"

    def _is_first_visible_column(self, logical_col: int) -> bool:
        try:
            hdr = self._tbl.horizontalHeader()
            return hdr.visualIndex(int(logical_col)) == 0
        except Exception:
            return logical_col == 0

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        try:
            row = int(index.row())
            logical_col = int(index.column())
        except Exception:
            super().paint(painter, option, index)
            return

        st = self._status_for_row(row)
        accent, tint = self._palette.get(
            st,
            self._palette.get("unknown", (QColor("#a0a6b6"), QColor(0, 0, 0, 0))),
        )
        is_selected = bool(option.state & QStyle.State_Selected)

        painter.save()
        try:
            if not is_selected:
                painter.fillRect(option.rect, tint)
            if self._is_first_visible_column(logical_col):
                r = QRect(option.rect)
                stripe = QRect(r.left(), r.top(), self._accent_px, r.height())
                painter.fillRect(stripe, accent)
        finally:
            painter.restore()

        super().paint(painter, option, index)


# -------------------- Preview panel --------------------
class AssetPreviewPanel(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setObjectName("assetPreviewPanel")

        self._collapsed = False
        self._expanded_min_w = 320
        self._collapsed_w = 64

        self._open_handler: Optional[Callable[[], None]] = None
        self._open_slot: Optional[Callable[..., None]] = None

        self._toggle_handler: Optional[Callable[[], None]] = None
        self._toggle_slot: Optional[Callable[..., None]] = None

        self.title = QLabel("Pregled sredstva")
        try:
            self.title.setStyleSheet("font-weight: 700; font-size: 14px;")
        except Exception:
            pass

        self.btn_toggle_close = QToolButton(self)
        self.btn_toggle_close.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_toggle_close.setIconSize(QSize(16, 16))
        self.btn_toggle_close.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.btn_toggle_close.setText("Sakrij pregled")
        self.btn_toggle_close.setToolTip("Sakrij panel pregleda")

        self.btn_toggle_open = QToolButton(self)
        self.btn_toggle_open.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_toggle_open.setIconSize(QSize(18, 18))
        self.btn_toggle_open.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        self.btn_toggle_open.setText("P\nR\nE\nG\nL\nE\nD")
        self.btn_toggle_open.setToolTip("Prikaži pregled")
        self.btn_toggle_open.hide()

        self._refresh_toggle_icons()
        self._apply_button_qss()

        self._header_expanded = QWidget(self)
        header_lay = QHBoxLayout(self._header_expanded)
        header_lay.setContentsMargins(0, 0, 0, 0)
        header_lay.setSpacing(8)
        header_lay.addWidget(self.title, 1)
        header_lay.addWidget(self.btn_toggle_close, 0, Qt.AlignRight)

        self._header_collapsed = QWidget(self)
        collapsed_lay = QVBoxLayout(self._header_collapsed)
        collapsed_lay.setContentsMargins(0, 0, 0, 0)
        collapsed_lay.setSpacing(0)
        collapsed_lay.addStretch(1)
        collapsed_lay.addWidget(self.btn_toggle_open, 0, Qt.AlignHCenter)
        collapsed_lay.addStretch(1)
        self._header_collapsed.hide()

        self._fields: Dict[str, QLabel] = {}
        self.form = QFormLayout()
        self.form.setLabelAlignment(Qt.AlignLeft)
        self.form.setFormAlignment(Qt.AlignTop)

        def _add(key: str, label: str) -> None:
            v = QLabel("—")
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            v.setWordWrap(True)
            self._fields[key] = v
            self.form.addRow(QLabel(label), v)

        _add("asset_uid", "Asset UID:")
        _add("rb", "RB:")
        _add("toc_number", "TOC:")
        _add("nomenclature", "Nomenkl. broj:")
        _add("serial_number", "Serijski:")
        _add("name", "Naziv:")
        _add("category", "Kategorija:")
        _add("status", "Status:")
        _add("current_holder", "Zaduženo kod:")
        _add("location", "Lokacija:")
        _add("updated_at", "Ažurirano:")

        self.btn_open = QPushButton("Otvori detalje")
        self.btn_copy_uid = QPushButton("Kopiraj UID")

        self._current_uid = ""
        self.btn_copy_uid.clicked.connect(self._copy_uid)

        btns = QHBoxLayout()
        btns.addWidget(self.btn_open, 1)
        btns.addWidget(self.btn_copy_uid, 1)

        self._content = QWidget(self)
        content_lay = QVBoxLayout(self._content)
        content_lay.addLayout(self.form)
        content_lay.addStretch(1)
        content_lay.addLayout(btns)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(8)
        lay.addWidget(self._header_expanded)
        lay.addWidget(self._header_collapsed, 1)
        lay.addWidget(self._content, 1)

        self.setMinimumWidth(self._expanded_min_w)

    def _apply_button_qss(self) -> None:
        try:
            dark = _is_dark_theme()
            base = _qss_btn_soft(dark)
            self.btn_toggle_close.setStyleSheet(base + "QToolButton{ padding: 6px 10px; border-radius: 12px; }")
            self.btn_toggle_open.setStyleSheet(base + "QToolButton{ padding: 10px 8px; border-radius: 16px; }")
        except Exception:
            pass

    def refresh_theme(self) -> None:
        self._apply_button_qss()

    def collapsed_width(self) -> int:
        return int(self._collapsed_w)

    def expanded_width_hint(self) -> int:
        return int(self._expanded_min_w)

    def set_toggle_enabled(self, enabled: bool) -> None:
        try:
            self.btn_toggle_close.setEnabled(enabled)
            self.btn_toggle_open.setEnabled(enabled)
        except Exception:
            pass

    def set_open_handler(self, fn: Callable[[], None]) -> None:
        if self._open_slot is not None:
            try:
                self.btn_open.clicked.disconnect(self._open_slot)
            except Exception:
                pass

        self._open_handler = fn

        def _slot(*_args: Any, **_kwargs: Any) -> None:
            try:
                if self._open_handler:
                    self._open_handler()
            except Exception:
                return

        self._open_slot = _slot
        try:
            self.btn_open.clicked.connect(self._open_slot)
        except Exception:
            pass

    def set_toggle_handler(self, fn: Callable[[], None]) -> None:
        if self._toggle_slot is not None:
            for btn in (self.btn_toggle_close, self.btn_toggle_open):
                try:
                    btn.clicked.disconnect(self._toggle_slot)
                except Exception:
                    pass

        self._toggle_handler = fn

        def _slot(*_args: Any, **_kwargs: Any) -> None:
            try:
                if self._toggle_handler:
                    self._toggle_handler()
            except Exception:
                return

        self._toggle_slot = _slot
        for btn in (self.btn_toggle_close, self.btn_toggle_open):
            try:
                btn.clicked.connect(self._toggle_slot)
            except Exception:
                pass

    def set_collapsed(self, collapsed: bool) -> None:
        self._collapsed = bool(collapsed)
        self._refresh_toggle_icons()

        if self._collapsed:
            self._content.hide()
            self._header_expanded.hide()
            self.btn_toggle_open.show()
            self._header_collapsed.show()
            self.setMinimumWidth(self._collapsed_w)
            self.setMaximumWidth(self._collapsed_w)
        else:
            self._header_collapsed.hide()
            self.btn_toggle_open.hide()
            self._header_expanded.show()
            self._content.show()
            self.setMinimumWidth(self._expanded_min_w)
            self.setMaximumWidth(16777215)

    def _refresh_toggle_icons(self) -> None:
        try:
            style = self.style()
            self.btn_toggle_close.setIcon(style.standardIcon(QStyle.SP_ArrowRight))
            self.btn_toggle_open.setIcon(style.standardIcon(QStyle.SP_ArrowLeft))
        except Exception:
            pass

    def clear(self) -> None:
        self._current_uid = ""
        for v in self._fields.values():
            v.setText("—")
            try:
                v.setStyleSheet("")
                v.setToolTip("")
            except Exception:
                pass

    def set_asset(self, r: Dict[str, Any]) -> None:
        if not isinstance(r, dict) or not r:
            self.clear()
            return

        uid = _norm(r.get("asset_uid", ""))
        self._current_uid = uid

        def _set(key: str, text: str) -> None:
            lb = self._fields.get(key)
            if lb:
                lb.setText(text if text else "—")

        _set("asset_uid", uid)
        _set("rb", _norm(r.get("rb", "")))
        _set("toc_number", _norm(r.get("toc_number", "")))

        nom = _get_nomenclature(r)
        _set("nomenclature", nom)

        _set("serial_number", _norm(r.get("serial_number", "")))
        _set("name", _norm(r.get("name", "")))
        _set("category", _norm(r.get("category", "")))
        _set("status", _norm(r.get("status", "")))
        _set("current_holder", _norm(r.get("current_holder", "")))
        _set("location", _norm(r.get("location", "")))

        raw_upd = r.get("updated_at", "") or ""
        try:
            disp = fmt_dt_sr(raw_upd)
        except Exception:
            disp = _norm(raw_upd)
        _set("updated_at", disp)

        # vizuelni hint za nedostajući NOM (UX)
        try:
            lb_nom = self._fields.get("nomenclature")
            if lb_nom:
                if nom:
                    lb_nom.setStyleSheet("")
                    lb_nom.setToolTip("")
                else:
                    lb_nom.setStyleSheet("color: #ff8a80; font-weight: 600;")
                    lb_nom.setToolTip("Nomenklaturni broj nije unet.")
        except Exception:
            pass

    def _copy_uid(self) -> None:
        uid = (self._current_uid or "").strip()
        if not uid:
            return
        try:
            QApplication.clipboard().setText(uid)
        except Exception:
            pass

# (FILENAME: ui/assets_page.py - END PART 1)
# FILENAME: ui/assets_page.py

# -*- coding: utf-8 -*-
# FILENAME: ui/assets_page.py
# (FILENAME: ui/assets_page.py - START PART 2)

# -------------------- AssetsPage --------------------
class AssetsPage(QWidget):
    """
    Sredstva — glavna stranica (FULL UI).
    - RBAC fail-closed: ako nema view permisije, ne učitava podatke.
    - Scope: ALL / MY / METRO (ako user ima relevantne permisije).
    - Tabovi: Aktivna / Bez zaduženja / Rashodovana / Sva (lokalna logika filtera)
    - Desni preview panel + “Otvori detalje”.
    - Persist stanja preko QSettings.
    """

    MAX_ROWS = 5000

    def __init__(self, parent=None):
        super().__init__(parent)
        self.log = logging.getLogger("ui.assets_page")
        self._dark = _is_dark_theme()

        # data
        self._rows: List[Dict[str, Any]] = []
        self._view_rows: List[Dict[str, Any]] = []
        self._selected_uid: str = ""

        # flags
        self._loading = False
        self._header_state_applied = False

        # RBAC
        self._can_view_all = _can(PERM_ASSETS_VIEW)
        self._can_view_my = _can(PERM_ASSETS_MY_VIEW)
        self._can_view_metro = _can(PERM_ASSETS_METRO_VIEW)
        self._can_create = _can(PERM_ASSETS_CREATE)

        # UI
        self._build_ui()
        self._wire_events()

        # restore + initial load
        QTimer.singleShot(0, self._restore_state)
        QTimer.singleShot(0, self.reload)

    # -------------------- settings --------------------
    def _profile_key(self) -> str:
        """
        Multi-role support: probaj da uzmeš aktivni profil/rolu iz session-a,
        pa kombinuješ sa actor_key da state bude stabilan per user+role.
        """
        ak = _actor_key() or _actor_name()
        rk = ""
        try:
            from core.session import active_role_key  # type: ignore
            rk = (active_role_key() or "").strip()
        except Exception:
            rk = ""
        if not rk:
            try:
                from core.session import active_role_name  # type: ignore
                rk = (active_role_name() or "").strip()
            except Exception:
                rk = ""
        rk = rk or "default"
        return f"{ak}__{rk}"

    def _sprefix(self) -> str:
        return f"assets_page/{self._profile_key()}"

    def _persist_state(self) -> None:
        try:
            s = _settings()
            p = self._sprefix()

            s.setValue(f"{p}/tab_index", int(self.tabs.currentIndex()))
            s.setValue(f"{p}/scope", int(self.cmb_scope.currentIndex()))
            s.setValue(f"{p}/category", int(self.cmb_category.currentIndex()))
            s.setValue(f"{p}/status", int(self.cmb_status.currentIndex()))
            s.setValue(f"{p}/search", self.ed_search.text().strip())

            s.setValue(f"{p}/preview_collapsed", bool(self.preview_is_collapsed()))
            try:
                s.setValue(f"{p}/splitter", self.splitter.saveState())
            except Exception:
                pass

            # sort
            try:
                hdr = self.table.horizontalHeader()
                s.setValue(f"{p}/sort_col", int(hdr.sortIndicatorSection()))
                s.setValue(f"{p}/sort_ord", int(hdr.sortIndicatorOrder()))
            except Exception:
                pass

            # header columns state (width/order)
            try:
                s.setValue(f"{p}/header_state", self.table.horizontalHeader().saveState())
            except Exception:
                pass

            s.sync()
        except Exception:
            return

    def _restore_state(self) -> None:
        try:
            s = _settings()
            p = self._sprefix()

            with _SignalBlock(self.tabs, self.cmb_scope, self.cmb_category, self.cmb_status, self.ed_search):
                self.tabs.setCurrentIndex(int(s.value(f"{p}/tab_index", 0)))
                self.cmb_scope.setCurrentIndex(int(s.value(f"{p}/scope", 0)))
                self.cmb_category.setCurrentIndex(int(s.value(f"{p}/category", 0)))
                self.cmb_status.setCurrentIndex(int(s.value(f"{p}/status", 0)))
                self.ed_search.setText(str(s.value(f"{p}/search", "")) or "")

            # preview collapsed
            try:
                collapsed = bool(s.value(f"{p}/preview_collapsed", False))
                self._set_preview_collapsed(collapsed, animate=False)
            except Exception:
                pass

            # splitter
            try:
                st = s.value(f"{p}/splitter", None)
                if isinstance(st, (QByteArray, bytes, bytearray)):
                    self.splitter.restoreState(QByteArray(st))
            except Exception:
                pass

            # sort
            try:
                col = int(s.value(f"{p}/sort_col", 0))
                ordv = int(s.value(f"{p}/sort_ord", int(Qt.AscendingOrder)))
                self.table.horizontalHeader().setSortIndicator(col, Qt.SortOrder(ordv))
            except Exception:
                pass

            # header state (apply later, posle wire_columns ako postoji)
            try:
                self._saved_header_state = s.value(f"{p}/header_state", None)
            except Exception:
                self._saved_header_state = None

        except Exception:
            self._saved_header_state = None

    def closeEvent(self, event) -> None:
        self._persist_state()
        super().closeEvent(event)

    # -------------------- UI --------------------
    def _build_ui(self) -> None:
        self.banner = QLabel()
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet(_qss_banner(self._dark))

        # scope options (RBAC-driven)
        self.cmb_scope = QComboBox()
        self._scope_items: List[Tuple[str, str]] = []  # (key, label)

        # default scope order: ALL -> MY -> METRO
        if self._can_view_all:
            self._scope_items.append(("ALL", "Sva sredstva"))
        if self._can_view_my:
            self._scope_items.append(("MY", "Moja sredstva"))
        if self._can_view_metro:
            self._scope_items.append(("METRO", "Metrologija"))
        if not self._scope_items:
            # fail-closed: nema scope opcija, ali UI mora da živi
            self._scope_items.append(("NONE", "Nema pristup"))

        for _, label in self._scope_items:
            self.cmb_scope.addItem(label)

        self.cmb_category = QComboBox()
        self.cmb_category.addItem("Sve kategorije")

        self.cmb_status = QComboBox()
        self.cmb_status.addItem("Svi statusi")

        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("Pretraga (UID, RB, TOC, naziv, serijski, zaduženje...)")

        self.btn_refresh = QPushButton("Osveži")
        self.btn_new = QPushButton("Novo sredstvo")
        self.btn_new.setEnabled(bool(self._can_create))

        # tabs (filter mode)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        for t in ("Aktivna", "Bez zaduženja", "Rashodovana", "Sva"):
            self.tabs.addTab(QWidget(), t)

        # chips
        self.chips = FilterChipsBar(self)
        self.chips.set_clear_all_handler(self._clear_all_filters)

        # table
        self.table = QTableWidget(0, 10)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)

        headers = [
            "UID",
            "RB",
            "TOC",
            "NOM",
            "Naziv",
            "Kategorija",
            "Status",
            "Zaduženo kod",
            "Lokacija",
            "Ažurirano",
        ]
        self.table.setHorizontalHeaderLabels(headers)

        # row tint delegate (status col index = 6)
        self._install_row_tint()

        # empty state label
        self.lbl_empty = QLabel("Nema rezultata za izabrane filtere.")
        self.lbl_empty.setAlignment(Qt.AlignCenter)
        self.lbl_empty.setStyleSheet(_qss_empty(self._dark))
        self.lbl_empty.hide()

        # preview
        self.preview = AssetPreviewPanel(self)
        self.preview.set_toggle_handler(self.toggle_preview)
        self.preview.set_open_handler(self.open_selected_asset)

        # splitter
        self.splitter = QSplitter(Qt.Horizontal, self)
        left = QWidget(self)
        left_lay = QVBoxLayout(left)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(8)

        # top controls row
        row1 = QHBoxLayout()
        row1.setContentsMargins(0, 0, 0, 0)
        row1.setSpacing(8)
        row1.addWidget(QLabel("Scope:"), 0)
        row1.addWidget(self.cmb_scope, 0)
        row1.addWidget(QLabel("Kategorija:"), 0)
        row1.addWidget(self.cmb_category, 0)
        row1.addWidget(QLabel("Status:"), 0)
        row1.addWidget(self.cmb_status, 0)
        row1.addStretch(1)
        row1.addWidget(self.btn_refresh, 0)
        row1.addWidget(self.btn_new, 0)

        row2 = QHBoxLayout()
        row2.setContentsMargins(0, 0, 0, 0)
        row2.setSpacing(8)
        row2.addWidget(self.ed_search, 1)

        left_lay.addWidget(self.banner, 0)
        left_lay.addWidget(self.tabs, 0)
        left_lay.addLayout(row1, 0)
        left_lay.addLayout(row2, 0)
        left_lay.addWidget(self.chips, 0)
        left_lay.addWidget(self.table, 1)
        left_lay.addWidget(self.lbl_empty, 0)

        self.splitter.addWidget(left)
        self.splitter.addWidget(self.preview)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 0)

        # main layout
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)
        root.addWidget(self.splitter, 1)

        # optional helpers
        if wire_table_selection_plus_copy:
            try:
                wire_table_selection_plus_copy(self.table)
            except Exception:
                pass

        self._apply_banner()

    def _apply_banner(self) -> None:
        if not (self._can_view_all or self._can_view_my or self._can_view_metro):
            self.banner.setText("⛔ Nemaš pravo pristupa listi sredstava (RBAC).")
            self.table.setEnabled(False)
            self.btn_refresh.setEnabled(False)
            self.btn_new.setEnabled(False)
        else:
            # friendly info + cap note
            cap = self.MAX_ROWS
            self.banner.setText(f"📦 Prikaz liste sredstava (limit: prvih {cap}). Filteri su lokalni + bezbedni (offline).")
            self.table.setEnabled(True)
            self.btn_refresh.setEnabled(True)
            self.btn_new.setEnabled(bool(self._can_create))

    def _install_row_tint(self) -> None:
        dark = self._dark
        # status palette (accent, tint)
        palette: Dict[str, Tuple[QColor, QColor]] = {
            "active": (QColor("#2dd4bf"), QColor(45, 212, 191, 18) if dark else QColor(45, 212, 191, 28)),
            "on_loan": (QColor("#60a5fa"), QColor(96, 165, 250, 16) if dark else QColor(96, 165, 250, 26)),
            "service": (QColor("#fbbf24"), QColor(251, 191, 36, 18) if dark else QColor(251, 191, 36, 28)),
            "scrapped": (QColor("#fb7185"), QColor(251, 113, 133, 16) if dark else QColor(251, 113, 133, 26)),
            "unknown": (QColor("#a0a6b6"), QColor(160, 166, 182, 10) if dark else QColor(160, 166, 182, 18)),
        }
        try:
            self._tint_delegate = _AssetsRowTintDelegate(self.table, status_col=6, palette=palette, accent_px=3)
            self.table.setItemDelegate(self._tint_delegate)
        except Exception:
            self._tint_delegate = None

    # -------------------- events --------------------
    def _wire_events(self) -> None:
        self.btn_refresh.clicked.connect(self.reload)
        self.btn_new.clicked.connect(self.create_new_asset)

        self.tabs.currentChanged.connect(lambda _i: self._on_filters_changed())
        self.cmb_scope.currentIndexChanged.connect(lambda _i: self._on_scope_changed())
        self.cmb_category.currentIndexChanged.connect(lambda _i: self._on_filters_changed())
        self.cmb_status.currentIndexChanged.connect(lambda _i: self._on_filters_changed())

        self.ed_search.textChanged.connect(lambda _t: self._on_filters_changed(debounce=True))

        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.table.customContextMenuRequested.connect(self._on_context_menu)

        # debounce timer for search (UX)
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(180)
        self._debounce.timeout.connect(self.apply_filters)

    # -------------------- scope/filter --------------------
    def current_scope_key(self) -> str:
        idx = max(0, int(self.cmb_scope.currentIndex()))
        try:
            return self._scope_items[idx][0]
        except Exception:
            return "NONE"

    def current_tab_key(self) -> str:
        idx = int(self.tabs.currentIndex())
        if idx == 0:
            return "ACTIVE"
        if idx == 1:
            return "UNASSIGNED"
        if idx == 2:
            return "SCRAPPED"
        return "ALL"

    def _clear_all_filters(self) -> None:
        with _SignalBlock(self.cmb_category, self.cmb_status, self.ed_search, self.tabs):
            self.tabs.setCurrentIndex(0)
            self.cmb_category.setCurrentIndex(0)
            self.cmb_status.setCurrentIndex(0)
            self.ed_search.setText("")
        self.apply_filters()

    def _on_scope_changed(self) -> None:
        # scope change -> reload from service (different dataset)
        self.reload()

    def _on_filters_changed(self, debounce: bool = False) -> None:
        if debounce:
            self._debounce.start()
        else:
            self.apply_filters()

    def _build_chips(self) -> List[ChipSpec]:
        chips: List[ChipSpec] = []

        # tab
        tab = self.current_tab_key()
        tab_label = {0: "Aktivna", 1: "Bez zaduženja", 2: "Rashodovana", 3: "Sva"}.get(self.tabs.currentIndex(), "Sva")
        if tab != "ACTIVE":
            chips.append(ChipSpec(
                text=f"Tab: {tab_label}",
                on_remove=lambda: self.tabs.setCurrentIndex(0),
                tooltip="Klik na X vraća tab na Aktivna",
            ))

        # category
        if self.cmb_category.currentIndex() > 0:
            chips.append(ChipSpec(
                text=f"Kategorija: {self.cmb_category.currentText()}",
                on_remove=lambda: self.cmb_category.setCurrentIndex(0),
            ))

        # status
        if self.cmb_status.currentIndex() > 0:
            chips.append(ChipSpec(
                text=f"Status: {self.cmb_status.currentText()}",
                on_remove=lambda: self.cmb_status.setCurrentIndex(0),
            ))

        # search
        q = self.ed_search.text().strip()
        if q:
            chips.append(ChipSpec(
                text=f"Pretraga: {q}",
                on_remove=lambda: self.ed_search.setText(""),
            ))

        return chips

    # -------------------- service calls --------------------
    def _svc_list(self, scope_key: str) -> List[Dict[str, Any]]:
        """
        Best-effort wrapper — podrži različite potpise list_assets_brief/list_assets.
        Vraća listu dict-ova.
        """
        limit = int(self.MAX_ROWS)
        # prefer brief
        try:
            # najčešći slučaj: list_assets_brief(scope="MY"/"ALL"/"METRO", limit=N)
            return [ _row_as_dict(x) for x in (list_assets_brief(scope=scope_key, limit=limit) or []) ]
        except Exception:
            pass

        try:
            # varijanta: list_assets_brief(limit=N, scope=...)
            return [ _row_as_dict(x) for x in (list_assets_brief(limit=limit, scope=scope_key) or []) ]
        except Exception:
            pass

        try:
            # fallback: list_assets(scope, limit)
            return [ _row_as_dict(x) for x in (list_assets(scope=scope_key, limit=limit) or []) ]
        except Exception:
            pass

        try:
            # fallback: list_assets(limit)
            return [ _row_as_dict(x) for x in (list_assets(limit=limit) or []) ]
        except Exception:
            pass

        try:
            # last resort: list_assets()
            return [ _row_as_dict(x) for x in (list_assets() or []) ]
        except Exception:
            return []

    # -------------------- load + apply --------------------
    def reload(self) -> None:
        if self._loading:
            return
        if not (self._can_view_all or self._can_view_my or self._can_view_metro):
            self._rows = []
            self._view_rows = []
            self._render_table([])
            return

        self._loading = True
        self.banner.setText("⏳ Učitavam listu sredstava...")

        try:
            scope_key = self.current_scope_key()
            if scope_key == "NONE":
                data = []
            else:
                data = self._svc_list(scope_key)

            # enforce RBAC locally as backstop
            if scope_key == "MY":
                data = [r for r in data if _is_my_asset_ui(r)]
            elif scope_key == "METRO":
                data = [r for r in data if _is_metro_asset_ui(r)]

            self._rows = data[: self.MAX_ROWS]
            self._hydrate_filter_sources()
            self.apply_filters(keep_selection=True)

            cap_note = ""
            if len(data) > self.MAX_ROWS:
                cap_note = f" (prikazano {self.MAX_ROWS} / {len(data)})"

            self.banner.setText(f"✅ Učitano: {len(self._rows)} redova{cap_note}.")
        except Exception as e:
            self._rows = []
            self._view_rows = []
            self._render_table([])
            self.banner.setText(f"⚠️ Greška pri učitavanju: {e}")
        finally:
            self._loading = False

    def _hydrate_filter_sources(self) -> None:
        """
        Popuni kategorije/status iz podataka — ali ne ruši postojeći izbor.
        """
        cats = sorted({ _norm(r.get("category", "")) for r in self._rows if _norm(r.get("category", "")) })
        stats = sorted({ _norm(r.get("status", "")) for r in self._rows if _norm(r.get("status", "")) })

        # preserve current selections
        cur_cat = self.cmb_category.currentText()
        cur_stat = self.cmb_status.currentText()

        with _SignalBlock(self.cmb_category, self.cmb_status):
            self.cmb_category.clear()
            self.cmb_category.addItem("Sve kategorije")
            for c in cats:
                self.cmb_category.addItem(c)

            self.cmb_status.clear()
            self.cmb_status.addItem("Svi statusi")
            for st in stats:
                self.cmb_status.addItem(st)

            # restore if possible
            if cur_cat and cur_cat != "Sve kategorije":
                i = self.cmb_category.findText(cur_cat)
                if i >= 0:
                    self.cmb_category.setCurrentIndex(i)

            if cur_stat and cur_stat != "Svi statusi":
                i = self.cmb_status.findText(cur_stat)
                if i >= 0:
                    self.cmb_status.setCurrentIndex(i)

    def apply_filters(self, keep_selection: bool = True) -> None:
        if self._loading:
            return

        tab = self.current_tab_key()
        cat = self.cmb_category.currentText().strip()
        st = self.cmb_status.currentText().strip()
        q = self.ed_search.text().strip().casefold()

        prev_uid = self._selected_uid if keep_selection else ""

        def _match(r: Dict[str, Any]) -> bool:
            if tab == "ACTIVE":
                if _is_scrapped(r):
                    return False
            elif tab == "UNASSIGNED":
                if _is_scrapped(r) or not _is_unassigned(r):
                    return False
            elif tab == "SCRAPPED":
                if not _is_scrapped(r):
                    return False

            if self.cmb_category.currentIndex() > 0 and _norm(r.get("category", "")) != cat:
                return False
            if self.cmb_status.currentIndex() > 0 and _norm(r.get("status", "")) != st:
                return False

            if q:
                hay = " | ".join([
                    _norm(r.get("asset_uid", "")),
                    _norm(r.get("rb", "")),
                    _norm(r.get("toc_number", "")),
                    _get_nomenclature(r),
                    _norm(r.get("name", "")),
                    _norm(r.get("serial_number", "")),
                    _norm(r.get("current_holder", "")),
                    _norm(r.get("location", "")),
                    _norm(r.get("category", "")),
                    _norm(r.get("status", "")),
                ]).casefold()
                return q in hay

            return True

        self._view_rows = [r for r in self._rows if _match(r)]
        self._render_table(self._view_rows)

        # chips
        self.chips.set_chips(self._build_chips())

        # restore selection if possible
        if prev_uid:
            self._select_uid(prev_uid)

        self.lbl_empty.setVisible(len(self._view_rows) == 0)

    # -------------------- table render --------------------
    def _render_table(self, rows: List[Dict[str, Any]]) -> None:
        self.table.setSortingEnabled(False)
        try:
            self.table.setRowCount(0)
            self.preview.clear()
        except Exception:
            pass

        for r in (rows or []):
            row_idx = self.table.rowCount()
            self.table.insertRow(row_idx)

            uid = _norm(r.get("asset_uid", ""))
            rb = _norm(r.get("rb", ""))
            toc = _norm(r.get("toc_number", ""))
            nom = _get_nomenclature(r)
            name = _norm(r.get("name", ""))
            cat = _norm(r.get("category", ""))
            status = _norm(r.get("status", ""))
            holder = _norm(r.get("current_holder", ""))
            loc = _norm(r.get("location", ""))
            upd = fmt_dt_sr(r.get("updated_at", ""))

            items: List[QTableWidgetItem] = [
                SortableItem(uid, sort_value=uid),
                SortableItem(rb, sort_value=rb),
                SortableItem(toc, sort_value=_safe_int(toc) if _safe_int(toc) is not None else toc),
                SortableItem(nom, sort_value=_safe_int(nom) if _safe_int(nom) is not None else nom),
                SortableItem(name, sort_value=name.casefold()),
                SortableItem(cat, sort_value=cat.casefold()),
                SortableItem(status, sort_value=_status_key(status)),
                SortableItem(holder, sort_value=holder.casefold()),
                SortableItem(loc, sort_value=loc.casefold()),
                SortableItem(upd, sort_value=_safe_dt_sort_value(r.get("updated_at", "")) or 0),
            ]

            for c, it in enumerate(items):
                it.setData(Qt.UserRole + 1, uid)  # stash uid for quick access
                self.table.setItem(row_idx, c, it)

        # restore header state once
        if not self._header_state_applied:
            self._header_state_applied = True
            self._apply_saved_header_state_once()

        self.table.setSortingEnabled(True)
        self._auto_select_first_if_needed()

    def _apply_saved_header_state_once(self) -> None:
        try:
            st = getattr(self, "_saved_header_state", None)
            if isinstance(st, (QByteArray, bytes, bytearray)):
                self.table.horizontalHeader().restoreState(QByteArray(st))
            elif isinstance(st, str) and st:
                # some Qt versions serialize to str
                self.table.horizontalHeader().restoreState(QByteArray(st.encode("utf-8")))
        except Exception:
            pass

    def _auto_select_first_if_needed(self) -> None:
        if self.table.rowCount() <= 0:
            self._selected_uid = ""
            self.preview.clear()
            return
        if self.table.currentRow() < 0:
            self.table.selectRow(0)

    def _selected_uid_from_table(self) -> str:
        row = self.table.currentRow()
        if row < 0:
            return ""
        try:
            it = self.table.item(row, 0)
            return _norm(it.text() if it else "")
        except Exception:
            return ""

    def _select_uid(self, uid: str) -> None:
        uid = (uid or "").strip()
        if not uid:
            return
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 0)
            if it and _norm(it.text()) == uid:
                self.table.selectRow(r)
                try:
                    self.table.scrollToItem(it, QAbstractItemView.PositionAtCenter)
                except Exception:
                    pass
                return

    def _on_selection_changed(self) -> None:
        uid = self._selected_uid_from_table()
        self._selected_uid = uid
        if not uid:
            self.preview.clear()
            return

        # find row data
        rec = None
        for r in self._view_rows:
            if _norm(r.get("asset_uid", "")) == uid:
                rec = r
                break

        if rec:
            self.preview.set_asset(rec)
        else:
            self.preview.clear()

    # -------------------- preview toggle --------------------
    def preview_is_collapsed(self) -> bool:
        try:
            return bool(getattr(self.preview, "_collapsed", False))
        except Exception:
            return False

    def toggle_preview(self) -> None:
        self._set_preview_collapsed(not self.preview_is_collapsed(), animate=True)

    def _set_preview_collapsed(self, collapsed: bool, animate: bool = True) -> None:
        collapsed = bool(collapsed)
        if not animate:
            self.preview.set_collapsed(collapsed)
            self._persist_state()
            return

        # animation: smooth width change (simple)
        start = self.preview.width()
        end = self.preview.collapsed_width() if collapsed else self.preview.expanded_width_hint()

        self._anim = QVariantAnimation(self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.InOutQuad)
        self._anim.setStartValue(start)
        self._anim.setEndValue(end)

        def _step(v: Any) -> None:
            try:
                w = int(v)
                self.preview.setMinimumWidth(w)
                if collapsed:
                    self.preview.setMaximumWidth(w)
                else:
                    self.preview.setMaximumWidth(16777215)
            except Exception:
                pass

        def _done() -> None:
            self.preview.set_collapsed(collapsed)
            self._persist_state()

        self._anim.valueChanged.connect(_step)
        self._anim.finished.connect(_done)
        self._anim.start()

    # -------------------- context menu --------------------
    def _on_context_menu(self, pos: QPoint) -> None:
        if self.table.rowCount() <= 0:
            return
        row = self.table.currentRow()
        if row < 0:
            return
        uid = self._selected_uid_from_table()
        if not uid:
            return

        m = QMenu(self)
        act_open = m.addAction("Otvori detalje")
        act_copy = m.addAction("Kopiraj UID")
        m.addSeparator()
        act_refresh = m.addAction("Osveži listu")

        act = m.exec(self.table.viewport().mapToGlobal(pos))
        if act == act_open:
            self.open_selected_asset()
        elif act == act_copy:
            try:
                QApplication.clipboard().setText(uid)
            except Exception:
                pass
        elif act == act_refresh:
            self.reload()

    # -------------------- actions --------------------
    def open_selected_asset(self) -> None:
        uid = self._selected_uid or self._selected_uid_from_table()
        uid = (uid or "").strip()
        if not uid:
            return
        try:
            dlg = AssetDetailDialog(asset_uid=uid, parent=self)
            dlg.exec()
        except Exception as e:
            QMessageBox.warning(self, "Greška", f"Ne mogu da otvorim detalje sredstva.\n\n{e}")
            return
        # posle zatvaranja detalja — osveži (podrazumevano)
        self.reload()

    def create_new_asset(self) -> None:
        if not self._can_create:
            QMessageBox.information(self, "RBAC", "Nemaš pravo da kreiraš novo sredstvo.")
            return

        dlg = NewAssetDialog(parent=self)
        if dlg.exec() != QDialog.Accepted:
            return

        # Best-effort izvlačenje podataka iz dialoga (razni API-ji kroz verzije)
        payload: Dict[str, Any] = {}
        try:
            if hasattr(dlg, "get_payload"):
                payload = dict(dlg.get_payload() or {})
            elif hasattr(dlg, "payload"):
                payload = dict(getattr(dlg, "payload") or {})
        except Exception:
            payload = {}

        try:
            created = create_asset(actor=_actor_name(), **payload)
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Kreiranje sredstva nije uspelo.\n\n{e}")
            return

        # created može biti dict ili uid
        new_uid = ""
        if isinstance(created, dict):
            new_uid = _norm(created.get("asset_uid", ""))
        else:
            new_uid = _norm(created)

        # auto-zaduženje ako dialog daje info
        try:
            auto_holder = _norm(payload.get("auto_assign_to", "")) or _norm(payload.get("current_holder", ""))
            auto_loc = _norm(payload.get("auto_location", "")) or _norm(payload.get("location", ""))
            auto_note = _norm(payload.get("note", "")) or "Auto-zaduženje pri kreiranju sredstva"
            if new_uid and auto_holder:
                _try_create_assignment_after_create(new_uid, auto_holder, auto_loc, auto_note)
        except Exception:
            pass

        self.reload()
        if new_uid:
            self._select_uid(new_uid)

# (FILENAME: ui/assets_page.py - END PART 2)
# FILENAME: ui/assets_page.py

# -*- coding: utf-8 -*-
# FILENAME: ui/assets_page.py
# (FILENAME: ui/assets_page.py - START PART 3)

# -------------------- AssetsPage: post-init wiring (non-invasive) --------------------
def _assets_try_wire_columns(page: "AssetsPage") -> None:
    """
    Best-effort integracija 'wire_columns' ako postoji u projektu.
    Ne ruši aplikaciju ako funkcija/modul ne postoje.
    """
    # 1) global function by convention
    for fn_name in ("wire_assets_columns", "wire_columns", "wire_assets_table_columns"):
        fn = globals().get(fn_name, None)
        if callable(fn):
            try:
                fn(page.table)
                return
            except Exception:
                pass

    # 2) module-based (optional)
    try:
        # primer: ui/columns.py može imati wire_assets_columns(table)
        from ui.columns import wire_assets_columns  # type: ignore
        try:
            wire_assets_columns(page.table)
            return
        except Exception:
            pass
    except Exception:
        pass

    # 3) nothing found → ok
    return


def _assets_post_wire_once(page: "AssetsPage") -> None:
    """
    Hook koji se poziva jednom kad je widget realno prikazan.
    Ovde kačimo signale i event filtere bez menjanja ranijih delova.
    """
    if getattr(page, "_post_wired", False):
        return
    page._post_wired = True  # type: ignore

    # wire_columns (ako postoji)
    _assets_try_wire_columns(page)

    # Double-click otvara detalje
    try:
        page.table.itemDoubleClicked.connect(lambda _it: page.open_selected_asset())
    except Exception:
        pass

    # Sort change → reselect po UID (da ne “pobegne” selekcija)
    try:
        hdr = page.table.horizontalHeader()

        def _on_sort_changed(_col: int, _order) -> None:
            try:
                uid = getattr(page, "_selected_uid", "") or page._selected_uid_from_table()
                if uid:
                    # mali defer da Qt završi re-order
                    from PySide6.QtCore import QTimer  # type: ignore
                    QTimer.singleShot(0, lambda: page._select_uid(uid))
            except Exception:
                pass
            try:
                page._persist_state()
            except Exception:
                pass

        hdr.sortIndicatorChanged.connect(_on_sort_changed)  # type: ignore
    except Exception:
        pass

    # Keyboard shortcuts / UX: eventFilter na table viewport
    try:
        vp = page.table.viewport()
        vp.installEventFilter(page)
    except Exception:
        pass

    # (bonus) Enter/Return otvara detalje i iz preview dugmeta logike i iz table
    try:
        page.table.installEventFilter(page)
    except Exception:
        pass


def _assets_show_event(self: "AssetsPage", event) -> None:
    # pozovi originalni showEvent (ako postoji)
    try:
        super(AssetsPage, self).showEvent(event)  # type: ignore
    except Exception:
        pass

    # post-wire (once)
    try:
        _assets_post_wire_once(self)
    except Exception:
        pass


def _assets_event_filter(self: "AssetsPage", obj, ev) -> bool:
    """
    Prečice:
    - Ctrl+F: fokus na pretragu
    - Enter: otvori detalje selektovanog sredstva
    - Esc: očisti pretragu (ako je fokus u search)
    """
    try:
        from PySide6.QtCore import QEvent, Qt  # type: ignore
    except Exception:
        return False

    try:
        if ev.type() == QEvent.KeyPress:
            key = ev.key()
            mods = ev.modifiers()

            # Ctrl+F → fokus na search
            if (mods & Qt.ControlModifier) and key in (Qt.Key_F,):
                try:
                    self.ed_search.setFocus()
                    self.ed_search.selectAll()
                    return True
                except Exception:
                    return False

            # Enter/Return → open detail (kad fokus na tabeli/viewportu)
            if key in (Qt.Key_Return, Qt.Key_Enter):
                try:
                    # ako je fokus u search, ne otvaraj odmah (ne prekidaj kucanje)
                    if self.ed_search.hasFocus():
                        return False
                except Exception:
                    pass
                try:
                    self.open_selected_asset()
                    return True
                except Exception:
                    return False

            # Esc → clear search (ako je fokus na search)
            if key == Qt.Key_Escape:
                try:
                    if self.ed_search.hasFocus() and self.ed_search.text().strip():
                        self.ed_search.setText("")
                        return True
                except Exception:
                    return False

        return False
    except Exception:
        return False


# Monkey-patch: dodaj showEvent + eventFilter bez regeneracije ranijih delova
try:
    AssetsPage.showEvent = _assets_show_event  # type: ignore
except Exception:
    pass

try:
    AssetsPage.eventFilter = _assets_event_filter  # type: ignore
except Exception:
    pass

# (FILENAME: ui/assets_page.py - END PART 3)
# FILENAME: ui/assets_page.py


