# [START] FILENAME: ui/column_manager_dialog.py
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/column_manager_dialog.py
Dialog za kolone (V1):
- vidljivost (checkbox)
- redosled (gore/dole)
- širina (px, 0=auto)
- ✅ dugme "Vrati na početno" (reset na stanje pri otvaranju dijaloga)
FIX:
- Uklonjen QSpinBox kao cellWidget (Qt ownership/GC može da napravi hard-crash pri swap-u).
- Širina je editable cell (int, 0..2000), stabilno i bez pucanja.
- ✅ FULL CONTROL selekcija + header persist + Ctrl+C (TSV) preko ui/utils/table_copy.py
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QDialogButtonBox, QMessageBox,
    QAbstractItemView,
)

# ✅ FULL CONTROL: header persist + Ctrl+C TSV (ne dira edit width ćelije)
from ui.utils.table_copy import wire_table_header_plus_copy


class ColumnManagerDialog(QDialog):
    def __init__(self, title: str, cols_in: List[Dict[str, Any]], parent=None):
        super().__init__(parent)
        self.setWindowTitle(title or "Kolone")
        self.resize(820, 560)

        # stanje pri otvaranju (default za reset)
        self._cols_default = copy.deepcopy(cols_in or [])
        # trenutno stanje koje uređujemo
        self._cols_in = copy.deepcopy(cols_in or [])

        top = QHBoxLayout()
        top.addWidget(QLabel("Podešavanje prikaza kolona (ne menja sadržaj baze)."))
        top.addStretch(1)

        self.btn_reset = QPushButton("Vrati na početno")
        self.btn_up = QPushButton("▲ Gore")
        self.btn_dn = QPushButton("▼ Dole")
        self.btn_up.setEnabled(False)
        self.btn_dn.setEnabled(False)

        top.addWidget(self.btn_reset)
        top.addWidget(self.btn_up)
        top.addWidget(self.btn_dn)

        self.tbl = QTableWidget(0, 4)
        self.tbl.setHorizontalHeaderLabels(["Vidljivo", "Kolona", "Ključ", "Širina (px)"])
        self.tbl.setAlternatingRowColors(True)
        self.tbl.horizontalHeader().setStretchLastSection(True)

        # ✅ FULL CONTROL: klik ćelije = ćelija (ne ceo red), multi-select radi
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.tbl.setSelectionMode(QAbstractItemView.ExtendedSelection)

        # edit samo za "Širina"
        self.tbl.setEditTriggers(QTableWidget.DoubleClicked | QTableWidget.EditKeyPressed)

        # ✅ header persist selekcija + Ctrl+C
        wire_table_header_plus_copy(self.tbl)

        self.btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        okb = self.btns.button(QDialogButtonBox.Ok)
        if okb:
            okb.setText("Sačuvaj")
        cb = self.btns.button(QDialogButtonBox.Cancel)
        if cb:
            cb.setText("Otkaži")

        self.btns.accepted.connect(self._on_save)
        self.btns.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.tbl, 1)
        lay.addWidget(self.btns)

        self._load(self._cols_in)

        # signals
        self.tbl.itemSelectionChanged.connect(self._sync_move_buttons)
        self.btn_up.clicked.connect(lambda: self._move_selected(-1))
        self.btn_dn.clicked.connect(lambda: self._move_selected(+1))
        self.btn_reset.clicked.connect(self._reset_to_default)

    def _load(self, cols: List[Dict[str, Any]]):
        self.tbl.setRowCount(0)
        for i, c in enumerate(cols):
            self.tbl.insertRow(i)

            # 0) visible checkbox
            it_vis = QTableWidgetItem("")
            it_vis.setFlags(it_vis.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            it_vis.setCheckState(Qt.Checked if int(c.get("visible", 1) or 0) != 0 else Qt.Unchecked)
            self.tbl.setItem(i, 0, it_vis)

            # 1) title (read-only)
            title = str(c.get("title", "") or c.get("col_key", "") or "")
            it_title = QTableWidgetItem(title)
            it_title.setFlags(it_title.flags() & ~Qt.ItemIsEditable)
            self.tbl.setItem(i, 1, it_title)

            # 2) key (read-only)
            key = str(c.get("col_key", "") or "")
            it_key = QTableWidgetItem(key)
            it_key.setFlags(it_key.flags() & ~Qt.ItemIsEditable)
            self.tbl.setItem(i, 2, it_key)

            # 3) width (editable int text)
            width = int(c.get("width", 0) or 0)
            it_w = QTableWidgetItem(str(width))
            it_w.setFlags((it_w.flags() | Qt.ItemIsEditable) & ~Qt.ItemIsUserCheckable)
            it_w.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.tbl.setItem(i, 3, it_w)

        # UX: selektuj prvi red/ćeliju (da odmah rade up/down + copy)
        if self.tbl.rowCount() > 0 and self.tbl.currentRow() < 0:
            self.tbl.setCurrentCell(0, 1)

        self._sync_move_buttons()

    def _sync_move_buttons(self):
        row = self.tbl.currentRow()
        has = row >= 0
        self.btn_up.setEnabled(has and row > 0)
        self.btn_dn.setEnabled(has and row < self.tbl.rowCount() - 1)

    def _swap_rows(self, r1: int, r2: int):
        for col in range(self.tbl.columnCount()):
            a = self.tbl.takeItem(r1, col)
            b = self.tbl.takeItem(r2, col)
            self.tbl.setItem(r1, col, b)
            self.tbl.setItem(r2, col, a)

    def _move_selected(self, delta: int):
        row = self.tbl.currentRow()
        if row < 0:
            return
        new_row = row + int(delta)
        if new_row < 0 or new_row >= self.tbl.rowCount():
            return

        self.tbl.setUpdatesEnabled(False)
        try:
            self._swap_rows(row, new_row)
            self.tbl.setCurrentCell(new_row, 1)
            self.tbl.setFocus(Qt.OtherFocusReason)
        finally:
            self.tbl.setUpdatesEnabled(True)

        self._sync_move_buttons()

    def _parse_width(self, s: str) -> int:
        try:
            v = int((s or "").strip())
        except Exception:
            return 0
        if v < 0:
            v = 0
        if v > 2000:
            v = 2000
        return v

    def _reset_to_default(self):
        reply = QMessageBox.question(
            self,
            "Vrati na početno",
            "Vrati kolone na početno stanje (kako je bilo pri otvaranju prozora)?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        self.tbl.setUpdatesEnabled(False)
        try:
            self._load(copy.deepcopy(self._cols_default))
            if self.tbl.rowCount() > 0:
                self.tbl.setCurrentCell(0, 1)
                self.tbl.setFocus(Qt.OtherFocusReason)
        finally:
            self.tbl.setUpdatesEnabled(True)

        self._sync_move_buttons()

    def _on_save(self):
        # Validacija širina
        for i in range(self.tbl.rowCount()):
            it_w = self.tbl.item(i, 3)
            raw = it_w.text() if it_w else "0"
            w = self._parse_width(raw)
            if it_w:
                it_w.setText(str(w))
        self.accept()

    def result_cols(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for i in range(self.tbl.rowCount()):
            it_vis = self.tbl.item(i, 0)
            it_title = self.tbl.item(i, 1)
            it_key = self.tbl.item(i, 2)
            it_w = self.tbl.item(i, 3)

            key = it_key.text().strip() if it_key else ""
            title = it_title.text().strip() if it_title else key
            visible = 1 if (it_vis and it_vis.checkState() == Qt.Checked) else 0

            width_raw = it_w.text() if it_w else "0"
            width = self._parse_width(width_raw)

            out.append({
                "col_key": key,
                "title": title,
                "visible": int(visible),
                "order_index": int(i),
                "width": int(width),
            })
        return out

# [END] FILENAME: ui/column_manager_dialog.py