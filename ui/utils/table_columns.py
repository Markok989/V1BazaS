# FILENAME: ui/utils/table_columns.py
# (FILENAME: ui/utils/table_columns.py - START)
# -*- coding: utf-8 -*-
"""
wire_columns — integracija "Kolone" dugmeta + auto-apply prefs.
- odmah primeni saved prikaz (ako postoji)
- na klik dugmeta otvori ColumnsDialog i sačuvaj
- debounce re-apply kad se tabela menja
Dodatno:
- Drag&Drop kolona mišem (header)
- Auto-save redosleda (order) kad user prevuče kolonu
- Auto-save širina (widths) kad user menja širinu (throttle)
Fix:
- Apply-state (programatsko pomeranje kolona/širina) emituje sectionMoved/sectionResized.
  To pravi feedback loop i ubija DnD + Kolone dialog.
  Rešenje: apply-guard (lock) — autosave ignoriše signale dok se primenjuje state.

KOMPAT:
- Podržava novi poziv: wire_columns(owner, table, button, table_key, specs)
- Podržava legacy poziv: wire_columns(table, key="...")  -> samo apply + header DnD/autosave (bez dijaloga)
"""

from __future__ import annotations

from typing import Callable, List, Any, Dict, Optional

from PySide6.QtCore import QTimer  # type: ignore
from PySide6.QtWidgets import QMessageBox  # type: ignore

from ui.columns_dialog import ColSpec, normalize_state_to_specs, apply_state_to_table
from ui.utils.columns_prefs import get_table_state, set_table_state


# -------------------- internal guard helpers --------------------
def _guard_inc(table) -> None:
    try:
        n = int(getattr(table, "_cols_apply_guard", 0) or 0)
        setattr(table, "_cols_apply_guard", n + 1)
    except Exception:
        pass


def _guard_dec(table) -> None:
    try:
        n = int(getattr(table, "_cols_apply_guard", 0) or 0)
        setattr(table, "_cols_apply_guard", max(0, n - 1))
    except Exception:
        pass


def _guard_active(table) -> bool:
    try:
        return int(getattr(table, "_cols_apply_guard", 0) or 0) > 0
    except Exception:
        return False


class _ApplyGuard:
    def __init__(self, table):
        self.table = table
        self._hdr = None

    def __enter__(self):
        _guard_inc(self.table)
        try:
            self._hdr = self.table.horizontalHeader()
            # blokiramo signale header-a tokom apply
            self._hdr.blockSignals(True)
        except Exception:
            self._hdr = None
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._hdr is not None:
                self._hdr.blockSignals(False)
        except Exception:
            pass
        _guard_dec(self.table)
        return False


# -------------------- snapshot / autosave --------------------
def _save_state_snapshot(table, table_key: str, specs: List[ColSpec]) -> None:
    """
    Snimi kompletno trenutno stanje tabele:
    - order: po vizuelnom redosledu u header-u
    - widths: po logičkim kolonama (specs redosled)
    - visible: po logičkim kolonama (specs redosled)
    """
    try:
        if table is None:
            return
        tk = (table_key or "").strip()
        if not tk:
            return

        header = table.horizontalHeader()
        spec_keys = [s.key for s in (specs or [])]

        # order: visual -> logical -> key
        order: List[str] = []
        for visual in range(table.columnCount()):
            logical = header.logicalIndex(visual)
            if 0 <= logical < len(spec_keys):
                order.append(spec_keys[logical])

        widths: Dict[str, int] = {}
        visible: Dict[str, bool] = {}

        for logical, key in enumerate(spec_keys):
            try:
                widths[key] = max(30, int(table.columnWidth(logical)))
            except Exception:
                widths[key] = int(specs[logical].default_width) if logical < len(specs) else 140

            try:
                visible[key] = not bool(table.isColumnHidden(logical))
            except Exception:
                visible[key] = True

        saved = get_table_state(tk)
        st = normalize_state_to_specs(saved, specs)
        st["order"] = order or st.get("order", [])
        st["widths"] = widths or st.get("widths", {})
        st["visible"] = visible or st.get("visible", {})
        st = normalize_state_to_specs(st, specs)
        set_table_state(tk, st)
    except Exception:
        pass


def _ensure_dragdrop_wired(table, table_key: str, specs: List[ColSpec]) -> None:
    """
    Uključi drag&drop kolona + autosave (order/widths).
    Bezbedno je pozvati više puta (ne pravi duple konekcije).
    """
    if table is None:
        return
    if bool(getattr(table, "_cols_dragdrop_wired", False)):
        return

    tk = (table_key or "").strip()
    header = table.horizontalHeader()
    spec_keys = [s.key for s in (specs or [])]

    # Enable DnD on header (kolone)
    try:
        header.setSectionsMovable(True)
    except Exception:
        pass

    # Throttle za width snimanje (resize spam)
    width_timer = QTimer(table)
    width_timer.setSingleShot(True)
    width_timer.setInterval(250)

    def _save_patch(patch: Dict[str, Any]) -> None:
        try:
            if not tk:
                return
            saved = get_table_state(tk)
            st = normalize_state_to_specs(saved, specs)
            for k, v in (patch or {}).items():
                st[k] = v
            st = normalize_state_to_specs(st, specs)
            set_table_state(tk, st)
        except Exception:
            pass

    def _order_from_header() -> List[str]:
        order: List[str] = []
        try:
            for visual in range(table.columnCount()):
                logical = header.logicalIndex(visual)
                if 0 <= logical < len(spec_keys):
                    order.append(spec_keys[logical])
        except Exception:
            pass
        return order

    def _widths_from_table() -> Dict[str, int]:
        widths: Dict[str, int] = {}
        for logical, key in enumerate(spec_keys):
            try:
                widths[key] = max(30, int(table.columnWidth(logical)))
            except Exception:
                widths[key] = 140
        return widths

    def on_section_moved(*_args) -> None:
        # IGNORE dok apply radi (programatsko pomeranje)
        if _guard_active(table):
            return
        order = _order_from_header()
        if order:
            _save_patch({"order": order})

    def on_section_resized(*_args) -> None:
        # IGNORE dok apply radi
        if _guard_active(table):
            return
        width_timer.start()

    def _save_widths_only() -> None:
        if _guard_active(table):
            return
        w = _widths_from_table()
        if w:
            _save_patch({"widths": w})

    width_timer.timeout.connect(_save_widths_only)

    try:
        header.sectionMoved.connect(on_section_moved)
    except Exception:
        pass
    try:
        header.sectionResized.connect(on_section_resized)
    except Exception:
        pass

    setattr(table, "_cols_dragdrop_wired", True)


# -------------------- public API (NEW) --------------------
def wire_columns(
    owner,
    table=None,
    button=None,
    table_key: str = "",
    specs: Optional[List[ColSpec]] = None,
    **legacy_kwargs,
) -> Callable[[], None]:
    """
    Novi stil:
      wire_columns(owner, table, button, table_key, specs) -> apply()

    Legacy stil:
      wire_columns(table, key="users_page") -> apply()
      (bez dijaloga, samo apply + header DnD/autosave)
    """
    # ---- legacy adapter ----
    if table is None:
        # pozvan kao wire_columns(table, key="...")
        table = owner
        owner = None
        button = None
        table_key = str(legacy_kwargs.get("key") or legacy_kwargs.get("table_key") or table_key or "").strip()
        specs = specs or []  # bez specs ne možemo normalno; ali bolje i prazno nego crash

    specs = list(specs or [])
    tk = (table_key or "").strip()

    def apply() -> None:
        try:
            with _ApplyGuard(table):
                saved = get_table_state(tk)
                st = normalize_state_to_specs(saved, specs) if specs else (saved or {})
                if specs:
                    apply_state_to_table(table, st, specs)
        except Exception:
            pass
        finally:
            # DnD + autosave uvek pokušaj
            try:
                if specs and tk:
                    _ensure_dragdrop_wired(table, tk, specs)
            except Exception:
                pass

    def open_dialog() -> None:
        try:
            if owner is None:
                return
            if not specs or not tk:
                QMessageBox.warning(owner, "Greška", "Nedostaju specs/table_key za podešavanje kolona.")
                return
            from ui.columns_dialog import ColumnsDialog  # lokalni import (manje šanse za cikluse)

            dlg = ColumnsDialog(owner, table, table_key=tk, specs=specs)
            dlg.exec()
            # Posle dijaloga: primeni prefs (guarded), pa snapshot 1:1 sa UI
            apply()
            _save_state_snapshot(table, tk, specs)
        except Exception as e:
            if owner is not None:
                QMessageBox.critical(owner, "Greška", f"Ne mogu da otvorim podešavanje kolona.\n\n{e}")

    # init apply
    apply()

    # click -> dialog (samo novi stil gde imamo button)
    if button is not None:
        try:
            button.clicked.connect(open_dialog)
        except Exception:
            pass

    # debounce apply on model/table changes
    try:
        timer = QTimer(table)
        timer.setSingleShot(True)
        timer.timeout.connect(apply)

        def schedule() -> None:
            timer.start(80)

        m = table.model()
        if m is not None:
            m.modelReset.connect(schedule)
            m.layoutChanged.connect(schedule)
            m.rowsInserted.connect(schedule)
            m.columnsInserted.connect(schedule)
            m.columnsRemoved.connect(schedule)
    except Exception:
        pass

    return apply

# (FILENAME: ui/utils/table_columns.py - END)
# END FILENAME: ui/utils/table_columns.py