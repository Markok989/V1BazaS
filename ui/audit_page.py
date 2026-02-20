# FILENAME: ui/audit_page.py
# -*- coding: utf-8 -*-
"""
AuditPage — GLOBAL audit prikaz (V1)
MARKER: AUDIT_PAGE_V10b_MARKER_2026_02_03

V10b FIX/IMPROVE:
- Ctrl+C kopiranje selekcije: koristi ui/utils/table_copy.py
- Copy shortcut vezan direktno za tabelu (stabilnije)
- Context menu: kopiraj ćeliju/red/SELEKCIJU/PRE/POSLE (+ tihe opcije)
- ExtendedSelection ostaje (SelectItems + ExtendedSelection)
- Header klik (kolona/red) ostaje selektovan (persist)

UI standard:
- "Pretraži" + Enter u poljima
- Bez pop-up na startu, pop-up tek na "Pretraži"
"""

from __future__ import annotations

import re
import traceback
from typing import Any, Dict, List, Optional, Callable

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QComboBox, QMessageBox, QPlainTextEdit,
    QSplitter, QApplication, QMenu, QAbstractItemView
)

from ui.utils.datetime_fmt import fmt_dt_sr
from ui.utils.table_columns import wire_columns
from ui.utils.table_copy import (
    copy_selected_cells,
    wire_table_header_plus_copy,
)

_audit_mod = None
_audit_import_err: Optional[str] = None
try:
    import services.audit_service as _audit_mod  # type: ignore
except Exception:
    _audit_import_err = traceback.format_exc()
    _audit_mod = None


def _norm_name(s: str) -> str:
    s = (s or "").strip().lower()
    return re.sub(r"[^a-z0-9_]+", "", s)


def _resolve_fn_dict(mod, target: str) -> Optional[Callable]:
    if mod is None:
        return None
    d = getattr(mod, "__dict__", None)
    if not isinstance(d, dict):
        return None
    obj = d.get(target, None)
    if callable(obj):
        return obj
    for k, v in d.items():
        if isinstance(k, str) and k.strip() == target and callable(v):
            return v
    tnorm = _norm_name(target)
    for k, v in d.items():
        if isinstance(k, str) and _norm_name(k) == tnorm and callable(v):
            return v
    return None


def _list_list_keys(mod) -> List[str]:
    if mod is None:
        return []
    d = getattr(mod, "__dict__", {})
    if not isinstance(d, dict):
        return []
    return sorted([k for k in d.keys() if isinstance(k, str) and k.startswith("list_")])


def _diag_value(mod, key: str) -> str:
    if mod is None:
        return "mod=None"
    d = getattr(mod, "__dict__", None)
    if not isinstance(d, dict):
        return "mod.__dict__ nije dict"
    if key not in d:
        return f"ključ '{key}' ne postoji u __dict__"
    v = d.get(key)
    t = type(v).__name__
    try:
        r = repr(v)
    except Exception:
        r = "<repr failed>"
    if len(r) > 300:
        r = r[:300] + "...(truncated)"
    return f"type={t}, callable={callable(v)}, repr={r}"


class AuditPage(QWidget):
    COLS = ["Vreme", "Entitet", "Entitet ID", "Akcija", "Korisnik", "Izvor", "Pre", "Posle"]

    def __init__(self, logger, parent=None):
        super().__init__(parent)
        self.logger = logger

        from ui.columns_dialog import ColSpec
        self._col_specs = [
            ColSpec(key="time", label="Vreme", default_visible=True, default_width=170),
            ColSpec(key="entity", label="Entitet", default_visible=True, default_width=130),
            ColSpec(key="entity_id", label="Entitet ID", default_visible=True, default_width=150),
            ColSpec(key="action", label="Akcija", default_visible=True, default_width=110),
            ColSpec(key="actor", label="Korisnik", default_visible=True, default_width=150),
            ColSpec(key="source", label="Izvor", default_visible=True, default_width=180),
            ColSpec(key="before", label="Pre", default_visible=True, default_width=240),
            ColSpec(key="after", label="Posle", default_visible=True, default_width=240),
        ]
        self._table_key = "audit_table_v1"

        try:
            self.logger.info("AUDIT_PAGE_V10b_MARKER_2026_02_03: AuditPage učitan (ui/audit_page.py).")
        except Exception:
            pass

        # --- Filteri
        self.ed_q = QLineEdit()
        self.ed_q.setPlaceholderText("Pretraga (q): entity/entity_id/actor/source/json...")

        self.cb_entity = QComboBox()
        self.cb_entity.addItems(["SVE", "assets", "assignments", "attachments"])

        self.cb_action = QComboBox()
        self.cb_action.addItems(["SVE", "INSERT", "UPDATE", "DELETE"])

        self.ed_actor = QLineEdit()
        self.ed_actor.setPlaceholderText("Actor (deo imena)")

        self.ed_source = QLineEdit()
        self.ed_source.setPlaceholderText("Source (deo teksta)")

        self.btn_search = QPushButton("Pretraži")
        self.btn_refresh_silent = QPushButton("Osveži")
        self.btn_columns = QPushButton("Kolone")

        top1 = QHBoxLayout()
        top1.addWidget(QLabel("Pretraga:"))
        top1.addWidget(self.ed_q, 1)
        top1.addWidget(QLabel("Entitet:"))
        top1.addWidget(self.cb_entity)
        top1.addWidget(QLabel("Akcija:"))
        top1.addWidget(self.cb_action)
        top1.addWidget(self.btn_search)
        top1.addWidget(self.btn_refresh_silent)
        top1.addWidget(self.btn_columns)

        top2 = QHBoxLayout()
        top2.addWidget(QLabel("Actor:"))
        top2.addWidget(self.ed_actor, 1)
        top2.addWidget(QLabel("Source:"))
        top2.addWidget(self.ed_source, 1)

        # --- Tabela
        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        # FULL CONTROL: ćelije + multi-select
        self.table.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)

        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)

        # Context menu
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_context_menu)

        # --- Detalji
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)

        self.btn_copy_before = QPushButton("Kopiraj PRE")
        self.btn_copy_after = QPushButton("Kopiraj POSLE")
        self.btn_copy_before.setEnabled(False)
        self.btn_copy_after.setEnabled(False)

        det_top = QHBoxLayout()
        det_top.addStretch(1)
        det_top.addWidget(self.btn_copy_before)
        det_top.addWidget(self.btn_copy_after)

        det_wrap = QWidget()
        det_lay = QVBoxLayout(det_wrap)
        det_lay.setContentsMargins(0, 0, 0, 0)
        det_lay.addLayout(det_top)
        det_lay.addWidget(self.details, 1)

        split = QSplitter(Qt.Vertical)
        split.addWidget(self.table)
        split.addWidget(det_wrap)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)

        lay = QVBoxLayout(self)
        lay.addLayout(top1)
        lay.addLayout(top2)
        lay.addWidget(split, 1)

        # Signals
        self.btn_search.clicked.connect(lambda: self.load_rows(show_errors=True))
        self.btn_refresh_silent.clicked.connect(lambda: self.load_rows(show_errors=False))

        self.ed_q.returnPressed.connect(lambda: self.load_rows(show_errors=True))
        self.ed_actor.returnPressed.connect(lambda: self.load_rows(show_errors=True))
        self.ed_source.returnPressed.connect(lambda: self.load_rows(show_errors=True))

        self.cb_entity.currentIndexChanged.connect(lambda: self.load_rows(show_errors=False))
        self.cb_action.currentIndexChanged.connect(lambda: self.load_rows(show_errors=False))

        self.table.itemSelectionChanged.connect(self._on_select)

        self.btn_copy_before.clicked.connect(lambda: self.copy_before(show_popup=True))
        self.btn_copy_after.clicked.connect(lambda: self.copy_after(show_popup=True))

        # columns (DnD + autosave)
        self._apply_cols = wire_columns(self, self.table, self.btn_columns, self._table_key, self._col_specs)

        # ✅ KRITIČNO: header persist + Ctrl+C mora POSLE wire_columns (da ga wire_columns ne “pregazi”)
        wire_table_header_plus_copy(self.table)

        self._set_status_text()
        self.load_rows(show_errors=False)

    # -------------------- copy helpers --------------------

    def _copy_text(self, text: str) -> None:
        try:
            cb = QApplication.clipboard()
            cb.setText(text or "")
        except Exception:
            pass

    def copy_before(self, show_popup: bool = True):
        row = self.table.currentRow()
        if row < 0:
            return
        txt = self.table.item(row, 6).text() if self.table.item(row, 6) else ""
        if not txt:
            if show_popup:
                QMessageBox.information(self, "Info", "PRE je prazno.")
            return
        self._copy_text(txt)
        if show_popup:
            QMessageBox.information(self, "OK", "PRE kopirano u clipboard.")

    def copy_after(self, show_popup: bool = True):
        row = self.table.currentRow()
        if row < 0:
            return
        txt = self.table.item(row, 7).text() if self.table.item(row, 7) else ""
        if not txt:
            if show_popup:
                QMessageBox.information(self, "Info", "POSLE je prazno.")
            return
        self._copy_text(txt)
        if show_popup:
            QMessageBox.information(self, "OK", "POSLE kopirano u clipboard.")

    def copy_cell(self, row: int, col: int, show_popup: bool = True):
        it = self.table.item(row, col)
        txt = it.text() if it else ""
        self._copy_text(txt)
        if show_popup:
            QMessageBox.information(self, "OK", "Ćelija kopirana u clipboard.")

    def copy_row(self, row: int, show_popup: bool = True):
        parts = []
        for c in range(self.table.columnCount()):
            it = self.table.item(row, c)
            parts.append((it.text() if it else ""))
        txt = "\t".join(parts)
        self._copy_text(txt)
        if show_popup:
            QMessageBox.information(self, "OK", "Red kopiran u clipboard (TSV).")

    # -------------------- context menu --------------------

    def _on_context_menu(self, pos):
        try:
            item = self.table.itemAt(pos)
            if item is None:
                return

            # desni klik postavi current cell
            self.table.setCurrentCell(item.row(), item.column())

            row = item.row()
            col = item.column()

            menu = QMenu(self)

            act_copy_cell = menu.addAction("Kopiraj ćeliju")
            act_copy_cell_silent = menu.addAction("Kopiraj ćeliju (tiho)")
            act_copy_row = menu.addAction("Kopiraj red (TSV)")
            act_copy_row_silent = menu.addAction("Kopiraj red (TSV) (tiho)")
            menu.addSeparator()
            act_copy_sel = menu.addAction("Kopiraj selekciju (TSV)")
            menu.addSeparator()
            act_copy_before = menu.addAction("Kopiraj PRE")
            act_copy_before_silent = menu.addAction("Kopiraj PRE (tiho)")
            act_copy_after = menu.addAction("Kopiraj POSLE")
            act_copy_after_silent = menu.addAction("Kopiraj POSLE (tiho)")

            chosen = menu.exec(self.table.viewport().mapToGlobal(pos))

            if chosen == act_copy_cell:
                self.copy_cell(row, col, show_popup=True)
            elif chosen == act_copy_cell_silent:
                self.copy_cell(row, col, show_popup=False)
            elif chosen == act_copy_row:
                self.copy_row(row, show_popup=True)
            elif chosen == act_copy_row_silent:
                self.copy_row(row, show_popup=False)
            elif chosen == act_copy_sel:
                copy_selected_cells(self.table)
            elif chosen == act_copy_before:
                self.table.setCurrentCell(row, 0)
                self.copy_before(show_popup=True)
            elif chosen == act_copy_before_silent:
                self.table.setCurrentCell(row, 0)
                self.copy_before(show_popup=False)
            elif chosen == act_copy_after:
                self.table.setCurrentCell(row, 0)
                self.copy_after(show_popup=True)
            elif chosen == act_copy_after_silent:
                self.table.setCurrentCell(row, 0)
                self.copy_after(show_popup=False)
        except Exception:
            pass

    # -------------------- audit loading --------------------

    def _set_status_text(self) -> None:
        if _audit_mod is None:
            self.details.setPlainText(
                "Audit trenutno nije dostupan (audit_service import greška).\n"
                "Klikni 'Pretraži' da vidiš detalje."
            )
            return

        fn = _resolve_fn_dict(_audit_mod, "list_audit_global")
        if fn is None:
            avail = _list_list_keys(_audit_mod)
            self.details.setPlainText(
                "Audit trenutno nije dostupan (ne mogu da nađem funkciju list_audit_global).\n"
                f"Dostupno u audit_service.__dict__: {avail}\n"
                "Klikni 'Pretraži' da vidiš detalje."
            )
            return

        self.details.setPlainText("Audit spreman. Podesi filtere i klikni 'Pretraži'.")

    def _guard(self, show_errors: bool) -> bool:
        if _audit_mod is None:
            if show_errors:
                QMessageBox.critical(
                    self,
                    "Greška (Audit servis)",
                    "Ne mogu da učitam audit jer import services.audit_service puca.\n\n"
                    f"{_audit_import_err or 'N/A'}"
                )
            return False

        fn = _resolve_fn_dict(_audit_mod, "list_audit_global")
        if fn is None:
            avail = _list_list_keys(_audit_mod)
            diag = _diag_value(_audit_mod, "list_audit_global")
            if show_errors:
                QMessageBox.critical(
                    self,
                    "Greška (Audit API)",
                    "Ne mogu da učitam audit jer ne mogu da pronađem funkciju list_audit_global.\n\n"
                    f"Pronađeni list_* ključevi: {avail}\n"
                    f"Dijagnostika list_audit_global: {diag}\n\n"
                    "Ovo skoro uvek znači: circular import ili je neko pregazio ime (varijabla umesto funkcije)."
                )
            return False

        return True

    def load_rows(self, show_errors: bool = True) -> None:
        if not self._guard(show_errors=show_errors):
            self._set_status_text()
            self._sync_copy_buttons()
            return

        try:
            list_audit_global = _resolve_fn_dict(_audit_mod, "list_audit_global")  # type: ignore
            if list_audit_global is None:
                raise RuntimeError("list_audit_global resolve failed (neočekivano).")

            entity = self.cb_entity.currentText().strip()
            action = self.cb_action.currentText().strip()
            actor_like = (self.ed_actor.text() or "").strip()
            source_like = (self.ed_source.text() or "").strip()
            q = (self.ed_q.text() or "").strip()

            rows: List[Dict[str, Any]] = list_audit_global(  # type: ignore
                entity=entity,
                action=action,
                actor_like=actor_like,
                source_like=source_like,
                q=q,
                limit=5000
            )

            self.table.setRowCount(0)

            for r in (rows or []):
                i = self.table.rowCount()
                self.table.insertRow(i)

                ts = (
                    r.get("event_time", "")
                    or r.get("ts", "")
                    or r.get("created_at", "")
                    or r.get("time", "")
                    or ""
                )
                ent = r.get("entity", "") or ""
                ent_id = r.get("entity_id", "") or ""
                act = r.get("action", "") or ""
                actor = r.get("actor", "") or r.get("user", "") or ""
                src = r.get("source", "") or ""
                before = r.get("before_json", "") or r.get("before", "") or ""
                after = r.get("after_json", "") or r.get("after", "") or ""

                values = [
                    fmt_dt_sr(str(ts)),
                    str(ent),
                    str(ent_id),
                    str(act),
                    str(actor),
                    str(src),
                    str(before),
                    str(after),
                ]
                for c, v in enumerate(values):
                    self.table.setItem(i, c, QTableWidgetItem(v))

            try:
                self._apply_cols()
            except Exception:
                pass

            # ✅ POSLE apply_cols još jednom “zakucaj” header persist (wire_columns zna da dira header)
            wire_table_header_plus_copy(self.table)

            if self.table.rowCount() == 0:
                self.details.setPlainText("Nema audit zapisa za izabrane filtere.")
            else:
                self.details.setPlainText("Izaberi red/ćeliju da vidiš detalje (pre/posle).")

            self._sync_copy_buttons()

        except Exception as e:
            if show_errors:
                QMessageBox.critical(self, "Greška", f"Ne mogu da učitam audit.\n\n{e}")
            self.details.setPlainText(f"Ne mogu da učitam audit.\n\n{e}")
            self._sync_copy_buttons()

    def _sync_copy_buttons(self):
        has_row = self.table.currentRow() >= 0
        self.btn_copy_before.setEnabled(has_row)
        self.btn_copy_after.setEnabled(has_row)

    def _on_select(self) -> None:
        try:
            row = self.table.currentRow()
            if row < 0:
                self._sync_copy_buttons()
                return

            before = self.table.item(row, 6).text() if self.table.item(row, 6) else ""
            after = self.table.item(row, 7).text() if self.table.item(row, 7) else ""
            self.details.setPlainText(f"=== PRE ===\n{before}\n\n=== POSLE ===\n{after}\n")
            self._sync_copy_buttons()
        except Exception:
            self._sync_copy_buttons()
            pass


# END FILENAME: ui/audit_page.py