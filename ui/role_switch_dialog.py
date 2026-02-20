# FILENAME: ui/role_switch_dialog.py
# (FILENAME: ui/role_switch_dialog.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/role_switch_dialog.py

Role switch dijalog (V1.2):
- Prikazuje listu dodeljenih rola (roles)
- Vraća izabranu rolu
- Ne radi ništa sa RBAC direktno; app.py poziva core.session.set_active_role(...)
"""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtWidgets import (  # type: ignore
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton
)
from PySide6.QtCore import Qt  # type: ignore


class RoleSwitchDialog(QDialog):
    def __init__(self, roles: List[str], active_role: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Promena uloge")
        self.resize(420, 160)

        self._roles = [str(r or "").strip() for r in (roles or []) if str(r or "").strip()]
        self._active = (active_role or "").strip()
        self._selected: Optional[str] = None

        lay = QVBoxLayout(self)

        info = QLabel("Izaberi aktivnu ulogu za ovu sesiju:")
        info.setWordWrap(True)
        lay.addWidget(info)

        row = QHBoxLayout()
        row.addWidget(QLabel("Uloga:"), 0)

        self.cb = QComboBox()
        for r in self._roles:
            self.cb.addItem(r, r)
        row.addWidget(self.cb, 1)
        lay.addLayout(row)

        # postavi aktivnu ako postoji
        if self._active:
            idx = self.cb.findText(self._active, Qt.MatchFixedString)
            if idx >= 0:
                self.cb.setCurrentIndex(idx)

        btns = QHBoxLayout()
        btns.addStretch(1)

        self.btn_ok = QPushButton("Primeni")
        self.btn_cancel = QPushButton("Otkaži")
        btns.addWidget(self.btn_ok)
        btns.addWidget(self.btn_cancel)
        lay.addStretch(1)
        lay.addLayout(btns)

        self.btn_cancel.clicked.connect(self.reject)
        self.btn_ok.clicked.connect(self._on_ok)

    def _on_ok(self) -> None:
        try:
            self._selected = (self.cb.currentData() or self.cb.currentText() or "").strip()
        except Exception:
            self._selected = (self.cb.currentText() or "").strip()
        self.accept()

    def selected_role(self) -> Optional[str]:
        return self._selected

# (FILENAME: ui/role_switch_dialog.py - END)