# FILENAME: ui/theme/palettes.py
# (FILENAME: ui/theme/palettes.py - START)
# -*- coding: utf-8 -*-
"""
Palete boja (tokens) za teme.

Za sada radimo DARK BASE + accent varijante:
- dark_blue (default)
- dark_pink
- dark_yellow
- dark_soft_purple

Kasnije dodajemo light base na isti način, bez menjanja UI logike.
"""

from __future__ import annotations

from typing import Dict


def _dark_base() -> Dict[str, str]:
    return {
        "BG": "#12141a",
        "TEXT": "#e7e9f1",
        "TEXT_MUTED": "#aab2c5",

        "PANEL": "#171a22",
        "PANEL_2": "#161a24",
        "PANEL_3": "#121624",

        "BORDER": "#2a3040",
        "GRID": "#2b3346",

        "ALT_ROW": "#111a2a",

        "SELECTION_BG": "#223a66",
        "SELECTION_TEXT": "#ffffff",

        "CHIP_BAR_BG": "#131726",
        "CHIP_BAR_BORDER": "#232a3a",
        "CHIP_BG": "#141a2a",
        "CHIP_BORDER": "#232a3a",
        "CHIP_X_BG": "#1a1f2f",
        "CHIP_X_BORDER": "#2a3040",

        "SCROLL_BG": "#0f1116",
        "SCROLL_HANDLE": "#2a3040",
        "SCROLL_HANDLE_HOVER": "#3a4460",

        "DISABLED_TEXT": "#7b849c",
        "DISABLED_BG": "#141724",
        "DISABLED_BORDER": "#23283a",

        # defaults (override u accent packovima)
        "PRIMARY": "#2e6bff",
        "PRIMARY_HOVER": "#255df0",
        "PRIMARY_SOFT": "rgba(46,107,255,0.18)",
    }


def palette(theme_id: str) -> Dict[str, str]:
    tid = (theme_id or "").strip().lower()

    base = _dark_base()

    if tid in ("dark_blue", "blue", "dark"):
        # već je default
        return base

    if tid in ("dark_pink", "pink"):
        base.update({
            "PRIMARY": "#ff4da6",
            "PRIMARY_HOVER": "#e63f95",
            "PRIMARY_SOFT": "rgba(255,77,166,0.18)",
            # selection može da ostane plava (čitljivost), ali je lepše blago “accent-ovana”
            "SELECTION_BG": "rgba(255,77,166,0.22)",
        })
        return base

    if tid in ("dark_yellow", "yellow", "amber"):
        # žuta je tricky: držimo je kao accent, a selection bude amber-soft da ostane čitljivo
        base.update({
            "PRIMARY": "#ffcc00",
            "PRIMARY_HOVER": "#e6b800",
            "PRIMARY_SOFT": "rgba(255,204,0,0.18)",
            "SELECTION_BG": "rgba(255,204,0,0.22)",
            "SELECTION_TEXT": "#ffffff",
        })
        return base

    if tid in ("dark_soft_purple", "purple", "lavender"):
        base.update({
            "PRIMARY": "#a78bfa",
            "PRIMARY_HOVER": "#8b6cf6",
            "PRIMARY_SOFT": "rgba(167,139,250,0.18)",
            "SELECTION_BG": "rgba(167,139,250,0.22)",
        })
        return base

    # fallback
    return _dark_base()


def available_themes() -> Dict[str, str]:
    """
    ID -> lep naziv (za UI dropdown kasnije).
    """
    return {
        "dark_blue": "Dark (Plava)",
        "dark_pink": "Dark (Roza)",
        "dark_yellow": "Dark (Žuta)",
        "dark_soft_purple": "Dark (Blaga ljubičasta)",
    }

# (FILENAME: ui/theme/palettes.py - END)
# FILENAME: ui/theme/palettes.py