# FILENAME: ui/utils/table_copy.py
# -*- coding: utf-8 -*-
"""
table_copy — univerzalno kopiranje selekcije + header persist (Ctrl+C)

STANDARD:
- klik ćelija = selektuje ćeliju (NE ceo red)
- klik header kolone = selektuje celu kolonu (persist)
- klik header reda = selektuje ceo red (persist)
- Ctrl+C kopira selekciju (TSV)
- Ctrl/Shift + klik na header = dodaje još redova/kolona
"""
from __future__ import annotations

from typing import Dict, List, Tuple, Any

from PySide6.QtCore import Qt, QModelIndex, QItemSelection, QTimer  # type: ignore
from PySide6.QtGui import QAction, QKeySequence  # type: ignore
from PySide6.QtWidgets import QApplication, QTableWidget, QTableView, QAbstractItemView  # type: ignore
from PySide6.QtCore import QItemSelectionModel  # type: ignore

_FLAG_COPY_PROP = "_bazas2_copy_wired"
_FLAG_HDR_PROP = "_bazas2_hdrplus_wired"


def _copy_text(text: str) -> None:
    try:
        QApplication.clipboard().setText(text or "")
    except Exception:
        pass


# ----------------------------
# COPY: QTableWidget
# ----------------------------
def _copy_selected_cells_qtablewidget(table: QTableWidget) -> None:
    try:
        ranges = table.selectedRanges()
        if not ranges:
            it = table.currentItem()
            if it:
                _copy_text(it.text())
            return

        lines: List[str] = []
        for r in ranges:
            for row in range(r.topRow(), r.bottomRow() + 1):
                cols: List[str] = []
                for col in range(r.leftColumn(), r.rightColumn() + 1):
                    it = table.item(row, col)
                    cols.append(it.text() if it else "")
                lines.append("\t".join(cols))
        _copy_text("\n".join(lines).strip("\n"))
    except Exception:
        pass


# ----------------------------
# COPY: QTableView
# ----------------------------
def _index_text(idx: QModelIndex) -> str:
    try:
        v = idx.data(Qt.DisplayRole)
        return "" if v is None else str(v)
    except Exception:
        return ""


def _copy_selected_cells_qtableview(view: QTableView) -> None:
    try:
        sm = view.selectionModel()
        model = view.model()
        if sm is None or model is None:
            return

        indexes = sm.selectedIndexes()
        if not indexes:
            cur = view.currentIndex()
            if cur.isValid():
                _copy_text(_index_text(cur))
            return

        rows = sorted({i.row() for i in indexes})
        cols = sorted({i.column() for i in indexes})

        m: Dict[Tuple[int, int], str] = {}
        for i in indexes:
            m[(i.row(), i.column())] = _index_text(i)

        lines: List[str] = []
        for r in rows:
            parts: List[str] = []
            for c in cols:
                parts.append(m.get((r, c), ""))
            lines.append("\t".join(parts))

        _copy_text("\n".join(lines).strip("\n"))
    except Exception:
        pass


def copy_selected_cells(table_or_view: Any) -> None:
    if table_or_view is None:
        return
    try:
        if isinstance(table_or_view, QTableWidget):
            _copy_selected_cells_qtablewidget(table_or_view)
        elif isinstance(table_or_view, QTableView):
            _copy_selected_cells_qtableview(table_or_view)
        else:
            sm = getattr(table_or_view, "selectionModel", None)
            model = getattr(table_or_view, "model", None)
            if callable(sm) and callable(model):
                _copy_selected_cells_qtableview(table_or_view)  # type: ignore
    except Exception:
        pass


def wire_table_copy(table_or_view: Any) -> None:
    if table_or_view is None:
        return
    try:
        if bool(table_or_view.property(_FLAG_COPY_PROP)):
            return
        act_copy = QAction("Kopiraj", table_or_view)
        act_copy.setShortcut(QKeySequence.Copy)
        act_copy.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        act_copy.triggered.connect(lambda: copy_selected_cells(table_or_view))
        table_or_view.addAction(act_copy)
        table_or_view.setProperty(_FLAG_COPY_PROP, True)
    except Exception:
        pass


# ----------------------------
# Selection helpers
# ----------------------------
def _mods_extend() -> bool:
    try:
        mods = QApplication.keyboardModifiers()
        return bool(mods & (Qt.ControlModifier | Qt.ShiftModifier))
    except Exception:
        return False


def _enforce_full_control_behavior(widget: Any) -> None:
    try:
        if isinstance(widget, (QTableWidget, QTableView)):
            widget.setSelectionBehavior(QAbstractItemView.SelectItems)
            widget.setSelectionMode(QAbstractItemView.ExtendedSelection)
    except Exception:
        pass


def _force_headers_clickable(widget: Any) -> None:
    try:
        hh = widget.horizontalHeader()
        hh.setSectionsClickable(True)
        hh.setHighlightSections(True)
    except Exception:
        pass
    try:
        vh = widget.verticalHeader()
        vh.setSectionsClickable(True)
        vh.setHighlightSections(True)
    except Exception:
        pass


def _sel_flags_columns(extend: bool) -> QItemSelectionModel.SelectionFlags:
    # Columns/Rows flagovi + ClearAndSelect/Select
    if extend:
        return QItemSelectionModel.Select | QItemSelectionModel.Columns
    return QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Columns


def _sel_flags_rows(extend: bool) -> QItemSelectionModel.SelectionFlags:
    if extend:
        return QItemSelectionModel.Select | QItemSelectionModel.Rows
    return QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows


# ✅ KLJUČNI FIX: setCurrentIndex sa NoUpdate (da ne razbije selekciju)
def _set_current_no_update(sm: QItemSelectionModel, idx: QModelIndex) -> None:
    try:
        sm.setCurrentIndex(idx, QItemSelectionModel.NoUpdate)
    except Exception:
        try:
            # fallback, ali ovo može da utiče na selekciju na nekim Qt buildovima
            sm.setCurrentIndex(idx, QItemSelectionModel.Current)
        except Exception:
            pass


def _select_column_widget(table: QTableWidget, col: int) -> None:
    try:
        if col < 0:
            return
        model = table.model()
        sm = table.selectionModel()
        if model is None or sm is None or model.rowCount() <= 0:
            return

        table.setFocus(Qt.OtherFocusReason)

        top = model.index(0, col)
        bottom = model.index(model.rowCount() - 1, col)
        sel = QItemSelection(top, bottom)

        sm.select(sel, _sel_flags_columns(_mods_extend()))
        _set_current_no_update(sm, top)  # ✅ ne dira selekciju
    except Exception:
        pass


def _select_row_widget(table: QTableWidget, row: int) -> None:
    try:
        if row < 0:
            return
        model = table.model()
        sm = table.selectionModel()
        if model is None or sm is None or model.columnCount() <= 0:
            return

        table.setFocus(Qt.OtherFocusReason)

        left = model.index(row, 0)
        right = model.index(row, model.columnCount() - 1)
        sel = QItemSelection(left, right)

        sm.select(sel, _sel_flags_rows(_mods_extend()))
        _set_current_no_update(sm, left)  # ✅ ne dira selekciju
    except Exception:
        pass


def _select_column_view(view: QTableView, col: int) -> None:
    try:
        model = view.model()
        sm = view.selectionModel()
        if model is None or sm is None or col < 0 or model.rowCount() <= 0:
            return

        view.setFocus(Qt.OtherFocusReason)

        top = model.index(0, col)
        bottom = model.index(model.rowCount() - 1, col)
        sel = QItemSelection(top, bottom)

        sm.select(sel, _sel_flags_columns(_mods_extend()))
        _set_current_no_update(sm, top)  # ✅ ne dira selekciju
    except Exception:
        pass


def _select_row_view(view: QTableView, row: int) -> None:
    try:
        model = view.model()
        sm = view.selectionModel()
        if model is None or sm is None or row < 0 or model.columnCount() <= 0:
            return

        view.setFocus(Qt.OtherFocusReason)

        left = model.index(row, 0)
        right = model.index(row, model.columnCount() - 1)
        sel = QItemSelection(left, right)

        sm.select(sel, _sel_flags_rows(_mods_extend()))
        _set_current_no_update(sm, left)  # ✅ ne dira selekciju
    except Exception:
        pass


def wire_table_header_plus_copy(table_or_view: Any) -> None:
    if table_or_view is None:
        return

    try:
        _enforce_full_control_behavior(table_or_view)
        wire_table_copy(table_or_view)
        _force_headers_clickable(table_or_view)

        if bool(table_or_view.property(_FLAG_HDR_PROP)):
            return

        if isinstance(table_or_view, QTableWidget):

            def _h(c: int) -> None:
                QTimer.singleShot(0, lambda: _select_column_widget(table_or_view, c))

            def _v(r: int) -> None:
                QTimer.singleShot(0, lambda: _select_row_widget(table_or_view, r))

            table_or_view.horizontalHeader().sectionClicked.connect(_h)
            table_or_view.verticalHeader().sectionClicked.connect(_v)

        elif isinstance(table_or_view, QTableView):

            def _h(c: int) -> None:
                QTimer.singleShot(0, lambda: _select_column_view(table_or_view, c))

            def _v(r: int) -> None:
                QTimer.singleShot(0, lambda: _select_row_view(table_or_view, r))

            table_or_view.horizontalHeader().sectionClicked.connect(_h)
            table_or_view.verticalHeader().sectionClicked.connect(_v)

        table_or_view.setProperty(_FLAG_HDR_PROP, True)

    except Exception:
        pass


def wire_table_selection_plus_copy(table_or_view: Any) -> None:
    wire_table_header_plus_copy(table_or_view)
# END FILENAME: ui/utils/table_copy.py