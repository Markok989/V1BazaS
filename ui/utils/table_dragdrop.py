# ui/utils/table_dragdrop.py
# -*- coding: utf-8 -*-
# FILENAME: ui/utils/table_dragdrop.py
"""
Helper: Drag&Drop (prevlačenje) kolona na QTableWidget + autosave u columns_prefs.

Kako radi:
- uključi QHeaderView.setSectionsMovable(True)
- sluša header.sectionMoved i snimi novi "order" u prefs
- sluša header.sectionResized i snimi širine (throttle)
- kompatibilno sa ui.columns_dialog state formatom: {"order":[], "visible":{}, "widths":{}}
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from PySide6.QtCore import QObject, QTimer  # type: ignore

from ui.utils.columns_prefs import get_table_state, set_table_state
from ui.columns_dialog import normalize_state_to_specs


class _DragDropColumnsBinder(QObject):
    """
    Drži konekcije i throttle za resize snimanje.
    Čuva se kao atribut na tabeli da ne bude GC-ovan.
    """
    def __init__(self, table, table_key: str, specs: list, parent=None):
        super().__init__(parent)
        self.table = table
        self.table_key = (table_key or "").strip()
        self.specs = specs or []

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(250)
        self._timer.timeout.connect(self._save_widths_only)

    def _spec_keys(self) -> List[str]:
        return [s.key for s in self.specs]

    def _save_state(self, patch: Dict[str, Any]) -> None:
        if not self.table_key:
            return
        saved = get_table_state(self.table_key)
        st = normalize_state_to_specs(saved, self.specs)
        for k, v in (patch or {}).items():
            st[k] = v
        st = normalize_state_to_specs(st, self.specs)
        set_table_state(self.table_key, st)

    def _save_order_from_header(self) -> None:
        header = self.table.horizontalHeader()
        keys = self._spec_keys()
        order: List[str] = []
        # prođi po vizuelnim pozicijama i mapiraj na logical index
        for visual in range(self.table.columnCount()):
            logical = header.logicalIndex(visual)
            if 0 <= logical < len(keys):
                order.append(keys[logical])
        if order:
            self._save_state({"order": order})

    def _save_widths_only(self) -> None:
        keys = self._spec_keys()
        widths: Dict[str, int] = {}
        for logical, k in enumerate(keys):
            try:
                widths[k] = max(30, int(self.table.columnWidth(logical)))
            except Exception:
                widths[k] = 140
        self._save_state({"widths": widths})

    def on_section_moved(self, *_args) -> None:
        # čim user prevuče kolonu -> snimi redosled
        self._save_order_from_header()

    def on_section_resized(self, *_args) -> None:
        # resize može da spamuje signal -> throttle
        self._timer.start()


def enable_column_dragdrop(table, table_key: str, specs: list) -> None:
    """
    Pozovi posle setHorizontalHeaderLabels() i posle apply_state_to_table().
    """
    if table is None:
        return
    header = table.horizontalHeader()
    header.setSectionsMovable(True)
    header.setDragEnabled(True)
    header.setDragDropMode(header.InternalMove)

    binder = _DragDropColumnsBinder(table, table_key, specs, parent=table)
    # da ne bude GC:
    setattr(table, "_col_dragdrop_binder", binder)

    # connect
    header.sectionMoved.connect(binder.on_section_moved)
    header.sectionResized.connect(binder.on_section_resized)

# END FILENAME: ui/utils/table_dragdrop.py