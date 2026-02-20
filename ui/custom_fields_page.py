# [START] FILENAME: ui/custom_fields_page.py
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/custom_fields_page.py
Admin ekran: definisanje prilagođenih polja (custom kolona).
V1:
- lista definicija
- dodaj/izmeni
- aktiviraj/deaktiviraj
UI standard (GLOBAL):
- FULL CONTROL selekcija + Ctrl+C TSV:
  - klik ćelije = ćelija (NE ceo red)
  - klik header kolone/red = selektuje kolonu/red i PERSIST
  - Ctrl+C kopira selekciju kao TSV
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from PySide6.QtWidgets import (  # type: ignore
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QMessageBox, QDialog, QFormLayout, QLineEdit, QComboBox, QPlainTextEdit, QCheckBox,
    QSpinBox, QDialogButtonBox, QAbstractItemView
)
from PySide6.QtCore import Qt  # type: ignore

from core.session import actor_name
from services.custom_fields_service import (
    list_field_defs,
    upsert_field_def,
    set_field_active,
)

# ✅ FULL CONTROL selekcija + header persist + Ctrl+C (TSV)
from ui.utils.table_copy import wire_table_header_plus_copy

_TYPES = ["TEXT", "NUMBER", "DATE", "BOOL", "CHOICE"]


class FieldDefDialog(QDialog):
    def __init__(self, existing: Optional[Dict[str, Any]] = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Prilagođeno polje")
        self.resize(520, 380)

        self.existing = existing or {}

        self.ed_key = QLineEdit()
        self.ed_label = QLineEdit()

        self.cb_type = QComboBox()
        self.cb_type.addItems(_TYPES)

        self.ed_choices = QPlainTextEdit()
        self.ed_choices.setPlaceholderText("Opcije za CHOICE (svaka u novom redu ili A|B|C).")
        self.ed_choices.setFixedHeight(110)

        self.chk_required = QCheckBox("Obavezno")
        self.chk_show = QCheckBox("Prikaži u tabeli sredstava")
        self.chk_active = QCheckBox("Aktivno")
        self.chk_active.setChecked(True)

        self.sp_pos = QSpinBox()
        self.sp_pos.setRange(-9999, 9999)
        self.sp_pos.setValue(0)

        form = QFormLayout()
        form.addRow("Ključ (field_key) *", self.ed_key)
        form.addRow("Naziv (label) *", self.ed_label)
        form.addRow("Tip", self.cb_type)
        form.addRow("Opcije (CHOICE)", self.ed_choices)
        form.addRow("Pozicija", self.sp_pos)
        form.addRow("", self.chk_required)
        form.addRow("", self.chk_show)
        form.addRow("", self.chk_active)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._ok)
        btns.rejected.connect(self.reject)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(btns)

        # fill existing
        if self.existing:
            self.ed_key.setText(str(self.existing.get("field_key", "") or ""))
            self.ed_key.setEnabled(False)  # ključ se ne menja
            self.ed_label.setText(str(self.existing.get("label", "") or ""))

            t = str(self.existing.get("field_type", "TEXT") or "TEXT").upper()
            if t in _TYPES:
                self.cb_type.setCurrentText(t)

            self.chk_required.setChecked(bool(int(self.existing.get("is_required", 0) or 0)))
            self.chk_show.setChecked(bool(int(self.existing.get("show_in_table", 0) or 0)))
            self.chk_active.setChecked(bool(int(self.existing.get("is_active", 1) or 1)))
            self.sp_pos.setValue(int(self.existing.get("position", 0) or 0))

            choices = self.existing.get("choices", [])
            if isinstance(choices, list) and choices:
                self.ed_choices.setPlainText("\n".join([str(x) for x in choices]))

        self.cb_type.currentTextChanged.connect(self._sync_ui)
        self._sync_ui()

    def _sync_ui(self):
        is_choice = self.cb_type.currentText().upper() == "CHOICE"
        self.ed_choices.setEnabled(is_choice)

    def _ok(self):
        k = self.ed_key.text().strip()
        lbl = self.ed_label.text().strip()
        if not k:
            QMessageBox.warning(self, "Validacija", "Ključ je obavezan (field_key).")
            return
        if not lbl:
            QMessageBox.warning(self, "Validacija", "Naziv je obavezan (label).")
            return
        self.accept()

    def values(self) -> Dict[str, Any]:
        t = self.cb_type.currentText().upper()
        choices_raw = self.ed_choices.toPlainText().strip()
        return {
            "field_key": self.ed_key.text().strip(),
            "label": self.ed_label.text().strip(),
            "field_type": t,
            "choices": choices_raw,
            "is_required": self.chk_required.isChecked(),
            "show_in_table": self.chk_show.isChecked(),
            "position": int(self.sp_pos.value()),
            "is_active": self.chk_active.isChecked(),
        }


class CustomFieldsPage(QWidget):
    """
    Stranica u app meniju: Prilagođena polja
    """
    COLS = ["Ključ", "Naziv", "Tip", "Obavezno", "U tabeli", "Aktivno", "Pozicija", "Opcije"]

    def __init__(self, logger=None, parent=None):
        super().__init__(parent)
        self.logger = logger

        top = QHBoxLayout()
        title = QLabel("Prilagođena polja (Admin)")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")

        self.btn_refresh = QPushButton("Osveži")
        self.btn_add = QPushButton("Dodaj")
        self.btn_edit = QPushButton("Izmeni")
        self.btn_toggle = QPushButton("Aktiviraj/Deaktiviraj")
        self.btn_edit.setEnabled(False)
        self.btn_toggle.setEnabled(False)

        top.addWidget(title)
        top.addStretch(1)
        top.addWidget(self.btn_refresh)
        top.addWidget(self.btn_add)
        top.addWidget(self.btn_edit)
        top.addWidget(self.btn_toggle)

        self.tbl = QTableWidget(0, len(self.COLS))
        self.tbl.setHorizontalHeaderLabels(self.COLS)

        # ✅ FULL CONTROL standard
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.tbl.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)  # ✅ fix (nema QTableWidget import problema)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.horizontalHeader().setStretchLastSection(True)

        # ✅ Header persist + Ctrl+C TSV
        wire_table_header_plus_copy(self.tbl)

        root = QVBoxLayout(self)
        root.addLayout(top)
        root.addWidget(self.tbl, 1)

        self.btn_refresh.clicked.connect(self.load)
        self.btn_add.clicked.connect(self.add_def)
        self.btn_edit.clicked.connect(self.edit_def)
        self.btn_toggle.clicked.connect(self.toggle_def)

        self.tbl.itemSelectionChanged.connect(self._sync_buttons)
        self.tbl.cellDoubleClicked.connect(lambda r, c: self.edit_def())

        self.load()

    def _sync_buttons(self):
        ok = self.tbl.currentRow() >= 0
        self.btn_edit.setEnabled(ok)
        self.btn_toggle.setEnabled(ok)

    def _selected_key(self) -> str:
        r = self.tbl.currentRow()
        if r < 0:
            return ""
        it = self.tbl.item(r, 0)
        return it.text().strip() if it else ""

    def load(self):
        selected = self._selected_key()
        try:
            rows = list_field_defs(active_only=False)
            self.tbl.setRowCount(0)

            for d in rows:
                i = self.tbl.rowCount()
                self.tbl.insertRow(i)

                key = d.get("field_key", "")
                lbl = d.get("label", "")
                t = d.get("field_type", "TEXT")
                req = "DA" if int(d.get("is_required", 0) or 0) == 1 else ""
                show = "DA" if int(d.get("show_in_table", 0) or 0) == 1 else ""
                act = "DA" if int(d.get("is_active", 0) or 0) == 1 else ""
                pos = str(int(d.get("position", 0) or 0))
                choices = d.get("choices", [])
                ch = ", ".join([str(x) for x in choices]) if choices else ""

                vals = [key, lbl, t, req, show, act, pos, ch]
                for c, v in enumerate(vals):
                    self.tbl.setItem(i, c, QTableWidgetItem(str(v)))

            # ✅ restore selection (UX)
            if selected:
                for r in range(self.tbl.rowCount()):
                    it = self.tbl.item(r, 0)
                    if it and it.text().strip() == selected:
                        self.tbl.setCurrentCell(r, 0)
                        break

            self._sync_buttons()

        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da učitam prilagođena polja.\n\n{e}")

    def add_def(self):
        dlg = FieldDefDialog(None, self)
        if dlg.exec() != QDialog.Accepted:
            return
        v = dlg.values()
        try:
            upsert_field_def(
                actor=actor_name(),
                field_key=v["field_key"],
                label=v["label"],
                field_type=v["field_type"],
                choices=v["choices"],
                is_required=bool(v["is_required"]),
                show_in_table=bool(v["show_in_table"]),
                position=int(v["position"]),
                is_active=bool(v["is_active"]),
            )
            QMessageBox.information(self, "OK", "Polje je sačuvano.")
            self.load()
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da sačuvam polje.\n\n{e}")

    def edit_def(self):
        key = self._selected_key()
        if not key:
            return

        rows = list_field_defs(active_only=False)
        existing = None
        for d in rows:
            if str(d.get("field_key", "")).strip() == key:
                existing = d
                break

        if not existing:
            QMessageBox.warning(self, "Nije nađeno", "Ne mogu da nađem definiciju polja.")
            return

        dlg = FieldDefDialog(existing, self)
        if dlg.exec() != QDialog.Accepted:
            return
        v = dlg.values()

        try:
            upsert_field_def(
                actor=actor_name(),
                field_key=key,
                label=v["label"],
                field_type=v["field_type"],
                choices=v["choices"],
                is_required=bool(v["is_required"]),
                show_in_table=bool(v["show_in_table"]),
                position=int(v["position"]),
                is_active=bool(v["is_active"]),
            )
            QMessageBox.information(self, "OK", "Izmene su sačuvane.")
            self.load()
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da sačuvam izmene.\n\n{e}")

    def toggle_def(self):
        key = self._selected_key()
        if not key:
            return

        r = self.tbl.currentRow()
        it_active = self.tbl.item(r, 5)
        active_now = (it_active.text().strip().upper() == "DA") if it_active else False

        try:
            set_field_active(key, (not active_now))
            self.load()
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da promenim status.\n\n{e}")

# [END] FILENAME: ui/custom_fields_page.py