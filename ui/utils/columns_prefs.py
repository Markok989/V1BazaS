# =========================
# [START] FILENAME: ui/utils/columns_prefs.py
# =========================
# -*- coding: utf-8 -*-
"""
columns_prefs — čuvanje/učitavanje prikaza kolona (redosled/vidljivost/širine)
- 100% offline: JSON fajl u data/ui/table_columns.json
- Namerno bez PySide6 import-a (da izbegnemo cikluse)

BITNO:
- Putanja je vezana za PROJECT ROOT (ne zavisi od trenutnog foldera pokretanja).
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, Optional


def _project_root() -> str:
    # ui/utils/columns_prefs.py -> ui/utils -> ui -> ROOT
    here = os.path.abspath(os.path.dirname(__file__))
    root = os.path.abspath(os.path.join(here, "..", ".."))
    return root


_PREFS_DIR = os.path.join(_project_root(), "data", "ui")
_PREFS_FILE = os.path.join(_PREFS_DIR, "table_columns.json")


def _ensure_dir() -> None:
    os.makedirs(_PREFS_DIR, exist_ok=True)


def _load_all() -> Dict[str, Any]:
    _ensure_dir()
    if not os.path.exists(_PREFS_FILE):
        return {}
    try:
        with open(_PREFS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _atomic_write_json(path: str, data: Dict[str, Any]) -> None:
    _ensure_dir()
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)

    fd, tmp = tempfile.mkstemp(prefix="tmp_cols_", suffix=".json", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def get_table_state(table_key: str) -> Optional[Dict[str, Any]]:
    """
    Vrati saved state ili None.

    State očekivano:
      {
        "order": ["key1", "key2", ...],
        "visible": {"key": true/false, ...},
        "widths":  {"key": 160, ...}
      }
    """
    tk = (table_key or "").strip()
    if not tk:
        return None
    all_data = _load_all()
    st = all_data.get(tk)
    return st if isinstance(st, dict) else None


def set_table_state(table_key: str, state: Dict[str, Any]) -> None:
    tk = (table_key or "").strip()
    if not tk:
        return
    all_data = _load_all()
    all_data[tk] = state if isinstance(state, dict) else {}
    _atomic_write_json(_PREFS_FILE, all_data)

# =========================
# [END] FILENAME: ui/utils/columns_prefs.py
# =========================