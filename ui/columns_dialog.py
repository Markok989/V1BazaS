# =========================
# [START] FILENAME: ui/columns_dialog.py
# =========================
# -*- coding: utf-8 -*-
"""
ColumnsDialog — univerzalni dijalog za podešavanje kolona:
- redosled (drag&drop + Move Up/Down kao fallback)
- vidljivost (checkbox)
- širine (uzima trenutne širine iz tabele)
- reset na default

Helperi:
- normalize_state_to_specs(saved, specs)
- apply_state_to_table(table, state, specs)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QLabel,
    QDialogButtonBox,
    QMessageBox,
    QAbstractItemView,
)

from ui.utils.columns_prefs import get_table_state, set_table_state


@dataclass(frozen=True)
class ColSpec:
    key: str
    label: str
    default_visible: bool = True
    default_width: int = 140


def _spec_map(specs: List[ColSpec]) -> Dict[str, ColSpec]:
    return {s.key: s for s in (specs or []) if s and s.key}


def default_state_from_specs(specs: List[ColSpec]) -> Dict[str, Any]:
    return {
        "order": [s.key for s in specs],
        "visible": {s.key: bool(s.default_visible) for s in specs},
        "widths": {s.key: int(s.default_width) for s in specs},
    }


def normalize_state_to_specs(saved: Optional[Dict[str, Any]], specs: List[ColSpec]) -> Dict[str, Any]:
    """
    Osigura da state uvek sadrži sve kolone iz specs:
    - dopuni nove kolone
    - izbaci nepostojeće
    - garantuje order/visible/widths
    """
    base = default_state_from_specs(specs)
    if not saved or not isinstance(saved, dict):
        return base

    smap = _spec_map(specs)

    # order
    order_in = saved.get("order")
    order: List[str] = []
    if isinstance(order_in, list):
        for k in order_in:
            if isinstance(k, str) and k in smap and k not in order:
                order.append(k)
    for s in specs:
        if s.key not in order:
            order.append(s.key)

    # visible
    vis_in = saved.get("visible", {})
    visible: Dict[str, bool] = {}
    if isinstance(vis_in, dict):
        for k, v in vis_in.items():
            if k in smap:
                visible[k] = bool(v)
    for s in specs:
        if s.key not in visible:
            visible[s.key] = bool(s.default_visible)

    # widths
    w_in = saved.get("widths", {})
    widths: Dict[str, int] = {}
    if isinstance(w_in, dict):
        for k, v in w_in.items():
            if k in smap:
                try:
                    widths[k] = max(30, int(v))
                except Exception:
                    pass
    for s in specs:
        if s.key not in widths:
            widths[s.key] = int(s.default_width)

    return {"order": order, "visible": visible, "widths": widths}


def apply_state_to_table(table, state: Dict[str, Any], specs: Optional[List[ColSpec]] = None) -> None:
    """
    Primeni state na QTableWidget:
    - vidljivost
    - širine
    - redosled (header.moveSection)
    """
    if table is None or not state or not isinstance(state, dict):
        return

    order = state.get("order", [])
    visible = state.get("visible", {})
    widths = state.get("widths", {})

    if not isinstance(order, list) or not isinstance(visible, dict) or not isinstance(widths, dict):
        return

    # key -> logical index (po specs redosledu)
    if specs:
        key_to_logical = {s.key: i for i, s in enumerate(specs)}
    else:
        key_to_logical = {}
        for i in range(table.columnCount()):
            try:
                hdr = table.horizontalHeaderItem(i).text()
            except Exception:
                hdr = str(i)
            key_to_logical[hdr] = i

    # widths + visibility
    for k, logical in key_to_logical.items():
        try:
            is_vis = bool(visible.get(k, True))
            table.setColumnHidden(logical, not is_vis)
        except Exception:
            pass
        try:
            w = widths.get(k, None)
            if w is not None:
                table.setColumnWidth(logical, max(30, int(w)))
        except Exception:
            pass

    # order (visual)
    header = table.horizontalHeader()

    desired_logical: List[int] = []
    for k in order:
        if k in key_to_logical:
            desired_logical.append(key_to_logical[k])

    for i in range(table.columnCount()):
        if i not in desired_logical:
            desired_logical.append(i)

    for target_visual, logical in enumerate(desired_logical):
        try:
            current_visual = header.visualIndex(logical)
            if current_visual != target_visual:
                header.moveSection(current_visual, target_visual)
        except Exception:
            pass


class ColumnsDialog(QDialog):
    def __init__(self, parent, table, table_key: str, specs: List[ColSpec]):
        super().__init__(parent)
        self.setWindowTitle("Podešavanje kolona")
        self.resize(520, 420)

        self.table = table
        self.table_key = (table_key or "").strip()
        self.specs = specs or []
        self._smap = _spec_map(self.specs)

        info = QLabel("Izaberi koje kolone su vidljive i promeni redosled (prevuci mišem ili Up/Down).")
        info.setWordWrap(True)

        self.listw = QListWidget()
        self.listw.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        # ✅ Drag&Drop reorder u listi
        self.listw.setDragEnabled(True)
        self.listw.setAcceptDrops(True)
        self.listw.setDropIndicatorShown(True)
        self.listw.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.listw.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.listw.setDragDropOverwriteMode(False)

        self.btn_up = QPushButton("▲ Gore")
        self.btn_down = QPushButton("▼ Dole")
        self.btn_reset = QPushButton("Reset (default)")

        # init from saved/current
        saved = get_table_state(self.table_key)
        st = normalize_state_to_specs(saved, self.specs)

        # punjenje liste po state order
        for k in st["order"]:
            s = self._smap.get(k)
            if not s:
                continue

            it = QListWidgetItem(s.label)
            it.setData(Qt.ItemDataRole.UserRole, k)

            # ✅ KRITIČNO: flagovi za drag/drop + checkable + selectable
            flags = it.flags()
            flags |= Qt.ItemFlag.ItemIsEnabled
            flags |= Qt.ItemFlag.ItemIsSelectable
            flags |= Qt.ItemFlag.ItemIsUserCheckable
            flags |= Qt.ItemFlag.ItemIsDragEnabled
            flags |= Qt.ItemFlag.ItemIsDropEnabled
            it.setFlags(flags)

            it.setCheckState(
                Qt.CheckState.Checked if st["visible"].get(k, True) else Qt.CheckState.Unchecked
            )
            self.listw.addItem(it)

        # layout
        btn_col = QVBoxLayout()
        btn_col.addWidget(self.btn_up)
        btn_col.addWidget(self.btn_down)
        btn_col.addStretch(1)
        btn_col.addWidget(self.btn_reset)

        mid = QHBoxLayout()
        mid.addWidget(self.listw, 1)
        mid.addLayout(btn_col)

        self.btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)

        lay = QVBoxLayout(self)
        lay.addWidget(info)
        lay.addLayout(mid, 1)
        lay.addWidget(self.btns)

        # signals
        self.btn_up.clicked.connect(self._move_up)
        self.btn_down.clicked.connect(self._move_down)
        self.btn_reset.clicked.connect(self._reset_defaults)

        self.btns.accepted.connect(self._on_ok)
        self.btns.rejected.connect(self.reject)

    def _move_up(self):
        r = self.listw.currentRow()
        if r <= 0:
            return
        it = self.listw.takeItem(r)
        self.listw.insertItem(r - 1, it)
        self.listw.setCurrentRow(r - 1)

    def _move_down(self):
        r = self.listw.currentRow()
        if r < 0 or r >= self.listw.count() - 1:
            return
        it = self.listw.takeItem(r)
        self.listw.insertItem(r + 1, it)
        self.listw.setCurrentRow(r + 1)

    def _reset_defaults(self):
        self.listw.clear()
        st = default_state_from_specs(self.specs)
        for k in st["order"]:
            s = self._smap.get(k)
            if not s:
                continue

            it = QListWidgetItem(s.label)
            it.setData(Qt.ItemDataRole.UserRole, k)

            flags = it.flags()
            flags |= Qt.ItemFlag.ItemIsEnabled
            flags |= Qt.ItemFlag.ItemIsSelectable
            flags |= Qt.ItemFlag.ItemIsUserCheckable
            flags |= Qt.ItemFlag.ItemIsDragEnabled
            flags |= Qt.ItemFlag.ItemIsDropEnabled
            it.setFlags(flags)

            it.setCheckState(
                Qt.CheckState.Checked if st["visible"].get(k, True) else Qt.CheckState.Unchecked
            )
            self.listw.addItem(it)

    def _on_ok(self):
        try:
            if not self.table_key:
                QMessageBox.warning(self, "Greška", "Nedostaje table_key (ne mogu da sačuvam prikaz).")
                return

            order: List[str] = []
            visible: Dict[str, bool] = {}
            widths: Dict[str, int] = {}

            # ✅ order + visible: uzmi STVARNO stanje iz liste (posle drag&drop)
            for i in range(self.listw.count()):
                it = self.listw.item(i)
                k = it.data(Qt.ItemDataRole.UserRole)
                if isinstance(k, str) and k in self._smap:
                    order.append(k)
                    visible[k] = (it.checkState() == Qt.CheckState.Checked)

            # widths uzmi iz trenutne tabele (po spec logičkom indeksu)
            for idx, s in enumerate(self.specs):
                try:
                    widths[s.key] = max(30, int(self.table.columnWidth(idx)))
                except Exception:
                    widths[s.key] = int(s.default_width)

            st = {"order": order, "visible": visible, "widths": widths}
            st = normalize_state_to_specs(st, self.specs)

            set_table_state(self.table_key, st)

            # ✅ apply odmah (da se vidi)
            apply_state_to_table(self.table, st, self.specs)

            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da sačuvam kolone.\n\n{e}")

# =========================
# [END] FILENAME: ui/columns_dialog.py
# =========================