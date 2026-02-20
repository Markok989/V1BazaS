# FILENAME: ui/theme/theme_manager.py
# (FILENAME: ui/theme/theme_manager.py - START)  [PART 1/2]
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/theme/theme_manager.py

Token-based theme manager (minimal + fail-safe):
- Teme: dark_blue, light, classic, pink, yellow, lavender
- + NOVO: test, test_2 (dve potpuno custom PRO teme)

Bitno (tvoj zahtev):
- Classic je sada DARK + OLD SCHOOL (bez modernih dodataka):
  - kvadratni uglovi, tanke ivice, bez “glass/rounded” estetike

API:
- apply_theme(app, theme_id): primena app-wide QSS + pamćenje u data/settings/ui_settings.json
- Fallback: ako theme_id ne postoji ili primena failuje -> default tema
- apply_theme_from_settings(app) alias za apply_saved_theme(app)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple


# -------------------- paths (offline) --------------------
def _project_root_fallback() -> Path:
    # ui/theme/theme_manager.py -> ui/theme -> ui -> ROOT
    try:
        return Path(__file__).resolve().parents[2]
    except Exception:
        return Path(".").resolve()


def _app_root() -> Path:
    """
    Best-effort: koristi isti helper kao backup/settings ako postoji.
    Fallback: koren projekta izveden iz lokacije ovog fajla.
    """
    try:
        from core.backup import _app_root as _root_helper  # type: ignore
        p = _root_helper()
        return Path(p).resolve()
    except Exception:
        return _project_root_fallback()


def _settings_dir() -> Path:
    return _app_root() / "data" / "settings"


def _settings_file() -> Path:
    return _settings_dir() / "ui_settings.json"


def _ensure_settings_dir() -> None:
    try:
        _settings_dir().mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


# -------------------- theme tokens --------------------
_REQUIRED_TOKEN_KEYS = (
    "bg",
    "panel",
    "panel2",
    "border",
    "border2",
    "text",
    "muted",
    "muted2",
    "accent",
    "accent2",
    "ok",
    "warn",
    "danger",
    "select_bg",
    "hover_bg",
    "input_bg",
    "table_alt",
)

_THEMES: Dict[str, Dict[str, Any]] = {
    "dark_blue": {
        "label": "Dark (Plava)",
        "t": {
            "bg": "#12141a",
            "panel": "#161a24",
            "panel2": "#171a22",
            "border": "#2a3040",
            "border2": "#232a3a",
            "text": "#e7e9f1",
            "muted": "#aab2c5",
            "muted2": "#7b849c",
            "accent": "#2e6bff",
            "accent2": "#3a7bff",
            "ok": "#22c55e",
            "warn": "#ffcc00",
            "danger": "#ff4d57",
            "select_bg": "#223a66",
            "hover_bg": "#172544",
            "input_bg": "#171a22",
            "table_alt": "#111a2a",
        },
    },
    "light": {
        "label": "Light",
        "t": {
            "bg": "#f6f7fb",
            "panel": "#ffffff",
            "panel2": "#fbfcff",
            "border": "#d7dbe6",
            "border2": "#c8cedd",
            "text": "#111827",
            "muted": "#4b5563",
            "muted2": "#6b7280",
            "accent": "#2563eb",
            "accent2": "#1d4ed8",
            "ok": "#16a34a",
            "warn": "#ca8a04",
            "danger": "#dc2626",
            "select_bg": "#dbeafe",
            "hover_bg": "#eef2ff",
            "input_bg": "#ffffff",
            "table_alt": "#f2f4f9",
        },
    },

    # ✅ CLASSIC: sada je DARK + OLD SCHOOL (bez modernih dodataka)
    "classic": {
        "label": "Classic (Dark / Old School)",
        "t": {
            "bg": "#1e1e1e",
            "panel": "#252526",
            "panel2": "#2d2d2d",
            "border": "#3c3c3c",
            "border2": "#333333",
            "text": "#d4d4d4",
            "muted": "#a0a0a0",
            "muted2": "#7a7a7a",
            "accent": "#0e639c",
            "accent2": "#1177bb",
            "ok": "#16a34a",
            "warn": "#d7ba7d",
            "danger": "#f44747",
            "select_bg": "#094771",
            "hover_bg": "#2a2a2a",
            "input_bg": "#1b1b1b",
            "table_alt": "#232323",
        },
    },

    "pink": {
        "label": "Roza",
        "t": {
            "bg": "#131018",
            "panel": "#1a1422",
            "panel2": "#171123",
            "border": "#2f2940",
            "border2": "#2a2340",
            "text": "#f4eefb",
            "muted": "#c8b7df",
            "muted2": "#a392c2",
            "accent": "#ff4da6",
            "accent2": "#ff2f97",
            "ok": "#22c55e",
            "warn": "#ffcc00",
            "danger": "#ff4d57",
            "select_bg": "#3a2450",
            "hover_bg": "#231a35",
            "input_bg": "#171123",
            "table_alt": "#140f1f",
        },
    },
    "yellow": {
        "label": "Žuta (blaga)",
        "t": {
            "bg": "#111214",
            "panel": "#17181b",
            "panel2": "#15161a",
            "border": "#2a2c33",
            "border2": "#24262d",
            "text": "#f5f6f7",
            "muted": "#b8bcc6",
            "muted2": "#9096a3",
            "accent": "#facc15",
            "accent2": "#eab308",
            "ok": "#22c55e",
            "warn": "#f59e0b",
            "danger": "#ff4d57",
            "select_bg": "#2e2f33",
            "hover_bg": "#1d1f24",
            "input_bg": "#15161a",
            "table_alt": "#101114",
        },
    },
    "lavender": {
        "label": "Ljubičasta (blaga)",
        "t": {
            "bg": "#11121a",
            "panel": "#16172a",
            "panel2": "#141628",
            "border": "#2b2d4a",
            "border2": "#242644",
            "text": "#eef0ff",
            "muted": "#b8bde0",
            "muted2": "#8e95c7",
            "accent": "#a78bfa",
            "accent2": "#8b5cf6",
            "ok": "#22c55e",
            "warn": "#ffcc00",
            "danger": "#ff4d57",
            "select_bg": "#2a2d52",
            "hover_bg": "#1c1f3a",
            "input_bg": "#141628",
            "table_alt": "#0f1020",
        },
    },

    # -------------------- ADD: test (total freedom) --------------------
    "test": {
        "label": "Test (Neo Glass)",
        "t": {
            "bg": "#0a0f1a",
            "panel": "#101a2d",
            "panel2": "#12223a",
            "border": "#243656",
            "border2": "#1c2b46",
            "text": "#eef4ff",
            "muted": "#a7b5d6",
            "muted2": "#7f8fb4",
            "accent": "#7c3aed",     # purple
            "accent2": "#22d3ee",    # cyan
            "ok": "#22c55e",
            "warn": "#fbbf24",
            "danger": "#fb7185",
            "select_bg": "#1b3a5b",
            "hover_bg": "#0f2440",
            "input_bg": "#0c1426",
            "table_alt": "#0a1324",
        },
    },

    # -------------------- ADD: test_2 (PRO Studio) --------------------
    "test_2": {
        "label": "Test 2 (PRO Studio)",
        "t": {
            "bg": "#0b1020",
            "panel": "#0f1730",
            "panel2": "#121d3a",
            "border": "#223057",
            "border2": "#1b2747",
            "text": "#eaf0ff",
            "muted": "#a8b3d6",
            "muted2": "#7f8bb2",
            "accent": "#00d3a7",
            "accent2": "#00b894",
            "ok": "#22c55e",
            "warn": "#fbbf24",
            "danger": "#ff4d6d",
            "select_bg": "#163a55",
            "hover_bg": "#101f3e",
            "input_bg": "#0c142a",
            "table_alt": "#0a1326",
        },
    },
}


# -------------------- helpers --------------------
def _norm_theme_id(theme_id: str) -> str:
    return str(theme_id or "").strip().lower()


def list_themes() -> Dict[str, str]:
    return {k: v.get("label", k) for k, v in _THEMES.items()}


def get_theme_id_default() -> str:
    return "dark_blue"


def load_ui_settings() -> Dict[str, Any]:
    _ensure_settings_dir()
    fp = _settings_file()
    if not fp.exists():
        return {}
    try:
        raw = fp.read_text(encoding="utf-8", errors="ignore") or "{}"
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def save_ui_settings(settings: Dict[str, Any]) -> bool:
    """
    Best-effort atomic save:
    - pišemo u .tmp pa replace
    """
    _ensure_settings_dir()
    fp = _settings_file()
    try:
        s = settings if isinstance(settings, dict) else {}
        tmp = fp.with_suffix(".tmp")
        tmp.write_text(json.dumps(s, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(fp)
        return True
    except Exception:
        return False


def get_current_theme_id() -> str:
    s = load_ui_settings()
    return _norm_theme_id(s.get("theme_id") or "")


def _merge_tokens(base: Dict[str, str], override: Dict[str, Any]) -> Dict[str, str]:
    out = dict(base)
    for k, v in (override or {}).items():
        if v is None:
            continue
        out[str(k)] = str(v)
    return out


def _resolve_theme(theme_id: str) -> Tuple[str, Dict[str, str]]:
    tid = _norm_theme_id(theme_id)
    if tid not in _THEMES:
        tid = get_theme_id_default()

    base_tid = get_theme_id_default()
    base_tokens = dict(_THEMES[base_tid]["t"])
    tokens = _merge_tokens(base_tokens, _THEMES[tid].get("t", {}))

    for k in _REQUIRED_TOKEN_KEYS:
        if k not in tokens or not str(tokens[k]).strip():
            tokens[k] = base_tokens.get(k, "#000000")

    return tid, tokens


_QSS_CACHE: Dict[str, str] = {}


def _qss_for_tokens(t: Dict[str, str]) -> str:
    return f"""
/* ===== BazaS2 Theme (tokens) ===== */
QWidget {{
  background: {t["bg"]};
  color: {t["text"]};
  font-size: 12px;
}}
QMainWindow, QDialog, QMessageBox {{
  background: {t["bg"]};
  color: {t["text"]};
}}
QLabel {{ color: {t["text"]}; }}
QLabel#muted, QLabel[muted="true"] {{ color: {t["muted"]}; }}

QToolTip {{
  background: {t["panel2"]};
  color: {t["text"]};
  border: 1px solid {t["border"]};
  border-radius: 8px;
  padding: 6px 8px;
}}

QMenuBar {{
  background: {t["panel2"]};
  color: {t["text"]};
}}
QMenuBar::item:selected {{ background: {t["hover_bg"]}; }}

QMenu {{
  background: {t["panel2"]};
  color: {t["text"]};
  border: 1px solid {t["border"]};
}}
QMenu::item {{ padding: 6px 10px; }}
QMenu::item:selected {{ background: {t["select_bg"]}; }}

QGroupBox {{
  border: 1px solid {t["border"]};
  border-radius: 12px;
  margin-top: 10px;
  padding: 10px;
  background: {t["panel"]};
}}
QGroupBox::title {{
  subcontrol-origin: margin;
  left: 10px;
  padding: 0px 6px;
  color: {t["muted"]};
  font-weight: 800;
}}

QPushButton, QToolButton {{
  background: {t["panel2"]};
  border: 1px solid {t["border"]};
  border-radius: 10px;
  padding: 7px 12px;
}}
QPushButton:hover, QToolButton:hover {{ border: 1px solid {t["accent"]}; }}
QPushButton:pressed, QToolButton:pressed {{ background: {t["hover_bg"]}; }}
QPushButton:disabled, QToolButton:disabled {{
  color: {t["muted2"]};
  background: {t["panel"]};
  border: 1px solid {t["border2"]};
}}

QLineEdit, QPlainTextEdit, QTextEdit {{
  background: {t["input_bg"]};
  border: 1px solid {t["border"]};
  border-radius: 10px;
  padding: 7px 10px;
  selection-background-color: {t["select_bg"]};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border: 1px solid {t["accent"]}; }}

QComboBox {{
  background: {t["input_bg"]};
  border: 1px solid {t["border"]};
  border-radius: 10px;
  padding: 6px 10px;
}}
QComboBox:focus {{ border: 1px solid {t["accent"]}; }}
QComboBox::drop-down {{ border: 0px; width: 22px; }}
QComboBox QAbstractItemView {{
  background: {t["panel2"]};
  border: 1px solid {t["border"]};
  selection-background-color: {t["select_bg"]};
}}

QTableWidget {{
  background: {t["panel"]};
  border: 1px solid {t["border"]};
  border-radius: 12px;
  gridline-color: {t["border2"]};
  alternate-background-color: {t["table_alt"]};
  selection-background-color: {t["select_bg"]};
  selection-color: {t["text"]};
}}
QHeaderView::section {{
  background: {t["panel2"]};
  color: {t["text"]};
  border: 0px;
  border-bottom: 2px solid {t["border2"]};
  border-right: 1px solid {t["border2"]};
  padding: 9px 10px;
  font-weight: 900;
}}
"""

# FILENAME: ui/theme/theme_manager.py
# (FILENAME: ui/theme/theme_manager.py - START)  [PART 2/2]

def _qss_classic_oldschool(t: Dict[str, str]) -> str:
    """
    Classic: dark + old school.
    - Nema rounded corners
    - Nema modernih “glass” elemenata
    - Tanke ivice, pravougaoni look
    """
    return f"""
/* ===== CLASSIC OLD SCHOOL (dark) ===== */
QWidget {{
  background: {t["bg"]};
  color: {t["text"]};
  font-family: "Segoe UI", "Tahoma", "Arial";
  font-size: 12px;
}}
QMainWindow, QDialog, QMessageBox {{
  background: {t["bg"]};
  color: {t["text"]};
}}

QToolTip {{
  background: {t["panel2"]};
  color: {t["text"]};
  border: 1px solid {t["border"]};
  border-radius: 0px;
  padding: 6px 8px;
}}

QMenuBar {{
  background: {t["panel2"]};
  color: {t["text"]};
  border-bottom: 1px solid {t["border"]};
}}
QMenuBar::item {{
  padding: 4px 8px;
}}
QMenuBar::item:selected {{
  background: {t["hover_bg"]};
}}

QMenu {{
  background: {t["panel2"]};
  color: {t["text"]};
  border: 1px solid {t["border"]};
}}
QMenu::item {{
  padding: 6px 10px;
}}
QMenu::item:selected {{
  background: {t["select_bg"]};
}}

QGroupBox {{
  background: {t["panel"]};
  border: 1px solid {t["border"]};
  border-radius: 0px;
  margin-top: 10px;
  padding: 10px;
}}
QGroupBox::title {{
  subcontrol-origin: margin;
  left: 10px;
  padding: 0px 6px;
  color: {t["muted"]};
  font-weight: 700;
}}

QPushButton, QToolButton {{
  background: {t["panel2"]};
  border: 1px solid {t["border"]};
  border-radius: 0px;
  padding: 5px 10px;
}}
QPushButton:hover, QToolButton:hover {{
  border: 1px solid {t["accent"]};
}}
QPushButton:pressed, QToolButton:pressed {{
  background: {t["hover_bg"]};
}}
QPushButton#primary {{
  background: {t["accent"]};
  border: 1px solid {t["accent"]};
  color: #ffffff;
  font-weight: 800;
}}
QPushButton#primary:hover {{
  background: {t["accent2"]};
  border: 1px solid {t["accent2"]};
}}

QLineEdit, QPlainTextEdit, QTextEdit {{
  background: {t["input_bg"]};
  border: 1px solid {t["border"]};
  border-radius: 0px;
  padding: 5px 8px;
  selection-background-color: {t["select_bg"]};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{
  border: 1px solid {t["accent"]};
}}

QComboBox {{
  background: {t["input_bg"]};
  border: 1px solid {t["border"]};
  border-radius: 0px;
  padding: 4px 8px;
}}
QComboBox::drop-down {{
  border: 0px;
  width: 22px;
}}
QComboBox QAbstractItemView {{
  background: {t["panel2"]};
  border: 1px solid {t["border"]};
  selection-background-color: {t["select_bg"]};
}}

QTableWidget {{
  background: {t["panel"]};
  border: 1px solid {t["border"]};
  border-radius: 0px;
  gridline-color: {t["border2"]};
  alternate-background-color: {t["table_alt"]};
  selection-background-color: {t["select_bg"]};
  selection-color: {t["text"]};
}}
QTableWidget::item {{
  padding: 5px 8px;
  border-bottom: 1px solid {t["border2"]};
  border-right: 1px solid {t["border2"]};
}}
QHeaderView::section {{
  background: {t["panel2"]};
  color: {t["text"]};
  border: 1px solid {t["border2"]};
  padding: 7px 8px;
  font-weight: 800;
}}
"""


def _qss_test(t: Dict[str, str]) -> str:
    """
    TEST (Neo Glass): total freedom — pro, “glassy”, modern, sa drugačijim fontovima i oblicima.
    """
    base = _qss_for_tokens(t)
    override = f"""
/* ===== OVERRIDES: TEST (Neo Glass) ===== */
QWidget {{
  font-family: "Segoe UI Variable", "Inter", "Segoe UI", "Roboto", "Arial";
  font-size: 13px;
}}
QGroupBox {{
  border-radius: 18px;
  padding: 12px;
}}
QPushButton, QToolButton {{
  border-radius: 16px;
  padding: 9px 14px;
  font-weight: 850;
  background: rgba(255,255,255,0.04);
}}
QPushButton:hover, QToolButton:hover {{
  border: 1px solid {t["accent2"]};
}}
QPushButton#primary {{
  background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {t["accent"]}, stop:1 {t["accent2"]});
  border: 0px;
  color: #061018;
  font-weight: 950;
}}
QLineEdit, QTextEdit, QPlainTextEdit {{
  border-radius: 16px;
  padding: 10px 12px;
}}
QComboBox {{
  border-radius: 16px;
  padding: 9px 12px;
}}
QMenu {{
  border-radius: 14px;
  padding: 6px;
}}
QMenu::item {{
  border-radius: 12px;
  padding: 8px 12px;
}}
QTableWidget {{
  border-radius: 18px;
}}
QHeaderView::section {{
  padding: 11px 10px;
  font-weight: 950;
}}
"""
    return base + override


def _qss_test_2(t: Dict[str, str]) -> str:
    """
    TEST 2 — PRO Studio: premium, čist, “studio” feel.
    """
    base = _qss_for_tokens(t)
    override = f"""
/* ===== OVERRIDES: TEST 2 (PRO Studio) ===== */
QWidget {{
  font-family: "Segoe UI Variable", "Segoe UI", "Inter", "Roboto", "Arial";
  font-size: 13px;
}}
QToolTip {{
  border-radius: 10px;
  padding: 8px 10px;
}}
QGroupBox {{
  border-radius: 16px;
  padding: 12px;
}}
QPushButton, QToolButton {{
  border-radius: 14px;
  padding: 9px 14px;
  font-weight: 800;
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 {t["panel2"]}, stop:1 {t["panel"]});
}}
QPushButton#primary {{
  background: {t["accent"]};
  border: 1px solid {t["accent"]};
  color: #071014;
  font-weight: 950;
}}
QPushButton#primary:hover {{
  background: {t["accent2"]};
  border: 1px solid {t["accent2"]};
}}
QLineEdit, QTextEdit, QPlainTextEdit {{
  border-radius: 14px;
  padding: 9px 12px;
}}
QComboBox {{
  border-radius: 14px;
  padding: 8px 12px;
}}
QMenu {{
  border-radius: 12px;
  padding: 6px;
}}
QMenu::item {{
  border-radius: 10px;
  padding: 8px 12px;
}}
QTableWidget {{
  border-radius: 16px;
}}
QHeaderView::section {{
  padding: 11px 10px;
  font-weight: 950;
}}

/* ThemePickerBox lepši u test_2 */
QFrame#ThemePickerBox {{
  border: 1px solid rgba(255,255,255,0.10);
  border-radius: 16px;
  background: rgba(255,255,255,0.04);
}}
"""
    return base + override


def _qss_for_theme(tid: str, tokens: Dict[str, str]) -> str:
    tt = (tid or "").strip().lower()
    if tt == "classic":
        return _qss_classic_oldschool(tokens)
    if tt == "test":
        return _qss_test(tokens)
    if tt == "test_2":
        return _qss_test_2(tokens)
    return _qss_for_tokens(tokens)


# -------------------- API --------------------
def apply_theme(app, theme_id: str) -> bool:
    """
    Primeni temu na QApplication + upiši theme_id u ui_settings.json.
    Fail-safe: fallback na default ako tema ne postoji ili QSS baci grešku.
    """
    if app is None:
        return False

    tid, tokens = _resolve_theme(theme_id)

    qss = _QSS_CACHE.get(tid)
    if not qss:
        qss = _qss_for_theme(tid, tokens)
        _QSS_CACHE[tid] = qss

    try:
        app.setStyleSheet(qss)
    except Exception:
        try:
            tid2, tokens2 = _resolve_theme(get_theme_id_default())
            qss2 = _QSS_CACHE.get(tid2)
            if not qss2:
                qss2 = _qss_for_theme(tid2, tokens2)
                _QSS_CACHE[tid2] = qss2
            app.setStyleSheet(qss2)
            tid = tid2
        except Exception:
            return False

    try:
        s = load_ui_settings()
        cur = _norm_theme_id(s.get("theme_id") or "")
        if cur != tid:
            s["theme_id"] = tid
            save_ui_settings(s)
    except Exception:
        pass

    return True


def apply_saved_theme(app) -> bool:
    """Primeni sačuvanu temu (ili default)."""
    try:
        tid = get_current_theme_id() or get_theme_id_default()
    except Exception:
        tid = get_theme_id_default()
    return apply_theme(app, tid)


def apply_theme_from_settings(app) -> bool:
    """Backward/compat alias."""
    return apply_saved_theme(app)

# (FILENAME: ui/theme/theme_manager.py - END)  [PART 2/2]