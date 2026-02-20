# FILENAME: ui/theme/theme_picker.py
# (FILENAME: ui/theme/theme_picker.py - START)
# -*- coding: utf-8 -*-
"""
UI widget za izbor teme (offline).
- Dropdown sa temama iz ui.theme.theme_manager.list_themes()
- Live primena teme
- Pamćenje izbora u data/settings/ui_settings.json
- Rollback: "Vrati prethodnu temu"

Fix (tvoj zahtev):
- Classic tema treba da izgleda "old school": ovaj widget NE SME da nameće moderni stil kad je Classic aktivan.
- Zato: lokalni style box-a je sada uslovan (Classic -> old school; ostalo -> lep/modern box).
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QApplication,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from ui.theme.theme_manager import (
    apply_theme,
    get_current_theme_id,
    get_theme_id_default,
    list_themes,
    load_ui_settings,
    save_ui_settings,
)

log = logging.getLogger(__name__)


class ThemePickerBox(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ThemePickerBox")

        self._themes: Dict[str, str] = dict(list_themes() or {})
        if not self._themes:
            self._themes = {"dark_blue": "Dark (Plava)"}

        self._app = QApplication.instance()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(10)

        self.title = QLabel("Tema aplikacije")
        lay.addWidget(self.title)

        self.desc = QLabel("Promena se primenjuje odmah. Ako ti se ne svidi – klikni „Vrati prethodnu temu“.")
        self.desc.setWordWrap(True)
        lay.addWidget(self.desc)

        row = QHBoxLayout()
        row.setSpacing(10)

        self.cb = QComboBox()
        self.cb.setMinimumWidth(260)

        # Popuni teme (stabilno: id je userData)
        for tid, label in self._themes.items():
            self.cb.addItem(str(label), str(tid))

        # Postavi trenutno aktivnu temu
        cur = (get_current_theme_id() or "").strip() or get_theme_id_default()
        self._set_combo_to_theme(cur)

        self.btn_revert = QPushButton("Vrati prethodnu temu")
        self.btn_revert.setToolTip("Vrati temu koju si imao pre poslednje promene.")

        self.btn_default = QPushButton("Default")
        self.btn_default.setToolTip("Vrati na podrazumevanu temu (Dark Plava).")

        row.addWidget(QLabel("Izaberi:"))
        row.addWidget(self.cb, 1)
        row.addWidget(self.btn_revert)
        row.addWidget(self.btn_default)
        lay.addLayout(row)

        self.lb_active = QLabel("")
        lay.addWidget(self.lb_active)

        self._refresh_active_label()
        self._apply_local_styles(cur)

        # Signals
        self.cb.currentIndexChanged.connect(self._on_theme_changed)
        self.btn_revert.clicked.connect(self._revert_last)
        self.btn_default.clicked.connect(self._set_default)

    # -------------------- local styling (critical for Classic) --------------------
    def _apply_local_styles(self, theme_id: str) -> None:
        """
        Classic = old school (bez modernog box stila).
        Ostale teme: zadrži lep “panel” box.
        """
        tid = (theme_id or "").strip().lower()

        # Base label styles (sigurno, bez prebijanja globalnog više nego što treba)
        if tid == "classic":
            # Old school: kvadratno, bez poluprovidnih “glass” fazona
            self.setStyleSheet("""
            QFrame#ThemePickerBox {
                border: 1px solid #3c3c3c;
                border-radius: 0px;
                background: #252526;
            }
            """)
            self.title.setStyleSheet("font-size: 13px; font-weight: 800;")
            self.desc.setStyleSheet("color: #a0a0a0; font-weight: 600;")
            self.lb_active.setStyleSheet("color: #a0a0a0; font-weight: 700;")
        else:
            # Modern (kao ranije): blago zaobljeno + light glass
            self.setStyleSheet("""
            QFrame#ThemePickerBox {
                border: 1px solid rgba(255,255,255,0.06);
                border-radius: 12px;
                background: rgba(255,255,255,0.02);
            }
            """)
            self.title.setStyleSheet("font-size: 14px; font-weight: 900;")
            self.desc.setStyleSheet("color: #aab2c5; font-weight: 600;")
            self.lb_active.setStyleSheet("color: #aab2c5; font-weight: 700;")

    # -------------------- helpers --------------------
    def _refresh_active_label(self) -> None:
        cur = (get_current_theme_id() or "").strip() or get_theme_id_default()
        label = self._themes.get(cur, cur)
        self.lb_active.setText(f"Aktivna tema: {label}")

    def _set_combo_to_theme(self, theme_id: str) -> None:
        tid = (theme_id or "").strip()
        idx = self.cb.findData(tid, role=Qt.UserRole)
        if idx >= 0:
            self.cb.blockSignals(True)
            self.cb.setCurrentIndex(idx)
            self.cb.blockSignals(False)

    def _save_last_theme(self, last_theme_id: str) -> None:
        s = load_ui_settings()
        s["last_theme_id"] = (last_theme_id or "").strip()
        save_ui_settings(s)

    def _get_last_theme(self) -> str:
        s = load_ui_settings()
        return str(s.get("last_theme_id") or "").strip()

    def _apply(self, theme_id: str) -> bool:
        if not self._app:
            self._app = QApplication.instance()
        if not self._app:
            return False
        try:
            ok = bool(apply_theme(self._app, theme_id))
            return ok
        except Exception as e:
            log.exception("Theme apply failed: %s", e)
            return False

    # -------------------- events --------------------
    def _on_theme_changed(self, _idx: int) -> None:
        new_id = str(self.cb.currentData() or "").strip()
        if not new_id:
            return

        old_id = (get_current_theme_id() or "").strip() or get_theme_id_default()
        if new_id == old_id:
            return

        # upamti prethodnu temu za rollback
        self._save_last_theme(old_id)

        ok = self._apply(new_id)
        if not ok:
            QMessageBox.warning(self, "Tema", "Ne mogu da primenim temu. Vraćam prethodnu.")
            self._apply(old_id)
            self._set_combo_to_theme(old_id)
            new_id = old_id

        # ✅ critical: Classic ne sme da “nasledi” moderni box stil
        self._apply_local_styles(new_id)
        self._refresh_active_label()

    def _revert_last(self) -> None:
        last_id = self._get_last_theme()
        cur_id = (get_current_theme_id() or "").strip() or get_theme_id_default()

        if not last_id or last_id == cur_id:
            QMessageBox.information(self, "Tema", "Nema prethodne teme za vraćanje.")
            return

        # pre revert-a, upamti trenutnu kao last (da revert može i “napred”)
        self._save_last_theme(cur_id)

        ok = self._apply(last_id)
        if not ok:
            QMessageBox.warning(self, "Tema", "Ne mogu da vratim prethodnu temu.")
            return

        self._set_combo_to_theme(last_id)
        self._apply_local_styles(last_id)
        self._refresh_active_label()

    def _set_default(self) -> None:
        default_id = get_theme_id_default()
        cur_id = (get_current_theme_id() or "").strip() or default_id
        if cur_id == default_id:
            return

        self._save_last_theme(cur_id)

        ok = self._apply(default_id)
        if not ok:
            QMessageBox.warning(self, "Tema", "Ne mogu da vratim default temu.")
            return

        self._set_combo_to_theme(default_id)
        self._apply_local_styles(default_id)
        self._refresh_active_label()

# (FILENAME: ui/theme/theme_picker.py - END)