# [START] FILENAME: ui/utils/search_ui.py
# -*- coding: utf-8 -*-
"""
UI helper za pretrage (Enter + dugme).

Korišćenje:
    from ui.utils.search_ui import wire_search

    self.btn_search = QPushButton("Pretraži")
    wire_search([self.ed_search, self.ed_actor], self.btn_search, self.load_rows)
"""

from __future__ import annotations

from typing import Callable, Iterable

from PySide6.QtWidgets import QLineEdit, QPushButton  # type: ignore


def wire_search(
    fields: Iterable[QLineEdit],
    button: QPushButton,
    callback: Callable[[], None],
    button_text: str = "Pretraži",
) -> None:
    """
    Povezuje:
    - Enter na svakom QLineEdit -> callback()
    - klik na dugme -> callback()
    """
    if button_text:
        button.setText(button_text)

    # Klik na dugme
    button.clicked.connect(callback)

    # Enter na svakom polju
    for f in fields:
        try:
            f.returnPressed.connect(callback)
        except Exception:
            # Ako nešto nije QLineEdit ili nema signal, preskoči
            pass

# [END] FILENAME: ui/utils/search_ui.py