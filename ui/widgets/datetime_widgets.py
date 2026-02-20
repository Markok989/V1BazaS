# [START] FILENAME: ui/widgets/datetime_widgets.py
# -*- coding: utf-8 -*-
"""
BazaS2 — reusable Date/DateTime widgets for Serbian locale.

- DateFieldSR:
    * QLineEdit sa maskom dd.MM.yyyy
    * 📅 mini kalendar
    * X clear
    * value_iso() vraća ISO "YYYY-MM-DD" (ili "")

- DateTimeFieldSR (spremno za upotrebu):
    * QDateTimeEdit sa calendar popup
    * display: dd.MM.yyyy HH:mm (24h)
    * value_iso() vraća "YYYY-MM-DD HH:MM:SS"
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PySide6.QtWidgets import QWidget, QHBoxLayout, QLineEdit, QToolButton, QDialog, QVBoxLayout, QDialogButtonBox, QCalendarWidget  # type: ignore
from PySide6.QtCore import QDate, QDateTime  # type: ignore
from PySide6.QtWidgets import QDateTimeEdit  # type: ignore

from ui.utils.datetime_fmt import sr_to_iso_date, iso_to_sr_masked


class CalendarPickDialog(QDialog):
    def __init__(self, initial_iso: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Izaberi datum")
        self.resize(360, 280)

        self.cal = QCalendarWidget()
        self.cal.setGridVisible(True)

        qd = QDate.currentDate()
        try:
            if initial_iso and len(initial_iso) == 10:
                y = int(initial_iso[0:4]); m = int(initial_iso[5:7]); d = int(initial_iso[8:10])
                qd = QDate(y, m, d)
        except Exception:
            pass
        self.cal.setSelectedDate(qd)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addWidget(self.cal, 1)
        lay.addWidget(btns)

    def selected_iso(self) -> str:
        qd = self.cal.selectedDate()
        return f"{qd.year():04d}-{qd.month():02d}-{qd.day():02d}"


class DateFieldSR(QWidget):
    """
    UI prikaz: dd.MM.yyyy
    DB vrednost: ISO yyyy-mm-dd
    """
    def __init__(self, placeholder: str = "dd.MM.yyyy", parent=None):
        super().__init__(parent)

        self.ed = QLineEdit()
        self.ed.setPlaceholderText(placeholder)
        self.ed.setMaxLength(10)
        self.ed.setInputMask("00.00.0000;_")

        self.btn_cal = QToolButton()
        self.btn_cal.setText("📅")
        self.btn_cal.setToolTip("Otvori kalendar")

        self.btn_clear = QToolButton()
        self.btn_clear.setText("X")
        self.btn_clear.setToolTip("Obriši datum")

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.ed, 1)
        lay.addWidget(self.btn_cal)
        lay.addWidget(self.btn_clear)

        self.btn_cal.clicked.connect(self._open_calendar)
        self.btn_clear.clicked.connect(self.clear)

    def _open_calendar(self):
        dlg = CalendarPickDialog(self.value_iso(), self)
        if dlg.exec() == QDialog.Accepted:
            self.set_value_iso(dlg.selected_iso())

    def clear(self):
        self.ed.setText("")

    def value_iso(self) -> str:
        # dd.MM.yyyy -> ISO
        txt = (self.ed.text() or "").strip()
        return sr_to_iso_date(txt)

    def set_value_iso(self, iso: str):
        self.ed.setText(iso_to_sr_masked(iso or ""))


class DateTimeFieldSR(QDateTimeEdit):
    """
    UI prikaz: dd.MM.yyyy HH:mm (24h)
    DB vrednost: YYYY-MM-DD HH:MM:SS
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCalendarPopup(True)
        self.setDisplayFormat("dd.MM.yyyy HH:mm")
        self.setDateTime(QDateTime.currentDateTime())

    def value_iso(self) -> str:
        dt = self.dateTime().toPython()
        if isinstance(dt, datetime):
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        # fallback
        qdt = self.dateTime()
        return f"{qdt.date().year():04d}-{qdt.date().month():02d}-{qdt.date().day():02d} {qdt.time().hour():02d}:{qdt.time().minute():02d}:00"
# [END] FILENAME: ui/widgets/datetime_widgets.py