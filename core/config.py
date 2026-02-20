# FILENAME: core/config.py
# (FILENAME: core/config.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — core/config.py
Putanje i folderi (portabilno: sve u jednom folderu).

DOPUNA (DB override):
- Default: BASE_DIR/data/db/bazas2.sqlite (lokalno, portable)
- Shared opcija: promeni DB putanju bez menjanja koda:
  1) ENV: BAZAS2_DB_FILE ili BAZAS2_DB_PATH
  2) data/db_path.txt (prva linija = putanja)

Primer (Windows):
- Z:\\BazaS2_Shared\\bazas2.sqlite
- \\\\SERVER\\Share\\BazaS2\\bazas2.sqlite
"""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "BazaS2"
APP_VERSION = "0.2-v1"

BASE_DIR = Path(__file__).resolve().parent.parent  # root projekta

DATA_DIR = BASE_DIR / "data"
DB_DIR = DATA_DIR / "db"
BACKUPS_DIR = DATA_DIR / "backups"
IMPORTS_DIR = DATA_DIR / "imports"
EXPORTS_DIR = DATA_DIR / "exports"
ATTACHMENTS_DIR = DATA_DIR / "attachments"
LOGS_DIR = DATA_DIR / "logs"

# ✅ novo (ne remeti postojeće): gde držimo UI/podešavanja (tema, UI prefs...)
SETTINGS_DIR = DATA_DIR / "settings"

VENDOR_DIR = BASE_DIR / "vendor"
WHEELS_DIR = VENDOR_DIR / "wheels"


def _clean_path_str(s: str) -> str:
    """
    Normalizuj putanju (best-effort):
    - trim
    - ukloni BOM (ako db_path.txt ima BOM)
    - ukloni navodnike ako su oko cele putanje
    - expandvars (%VAR% / $VAR) i ~
    """
    s = (s or "").strip()
    if not s:
        return ""
    # BOM (u Windows editorima zna da se pojavi)
    s = s.lstrip("\ufeff").strip()

    # navodnici oko cele putanje: "C:\..." ili 'C:\...'
    if (len(s) >= 2) and ((s[0] == s[-1]) and s[0] in ("'", '"')):
        s = s[1:-1].strip()

    # expand env vars + user home
    try:
        s = os.path.expandvars(s)
    except Exception:
        pass
    return s


def _read_db_override() -> Path | None:
    # 1) ENV override
    env = (os.environ.get("BAZAS2_DB_FILE") or os.environ.get("BAZAS2_DB_PATH") or "")
    env = _clean_path_str(env)
    if env:
        try:
            return Path(env).expanduser()
        except Exception:
            # ako je baš nevalidan string
            return None

    # 2) file override: data/db_path.txt
    p = DATA_DIR / "db_path.txt"
    try:
        if p.exists():
            first = (p.read_text(encoding="utf-8", errors="ignore").splitlines() or [""])[0]
            line = _clean_path_str(first)
            if line:
                return Path(line).expanduser()
    except Exception:
        pass

    return None


_DEFAULT_DB_FILE = DB_DIR / "bazas2.sqlite"

_override = _read_db_override()
if _override is not None:
    # Ako je relativna putanja, vežemo je za BASE_DIR (postojeće ponašanje)
    try:
        if not _override.is_absolute():
            # strict=False da ne puca ako putanja trenutno ne postoji
            _override = (BASE_DIR / _override).resolve(strict=False)
        else:
            _override = _override.resolve(strict=False)
    except Exception:
        # fallback bez rušenja
        try:
            if not _override.is_absolute():
                _override = (BASE_DIR / _override).absolute()
        except Exception:
            pass

    DB_FILE = _override
else:
    DB_FILE = _DEFAULT_DB_FILE

LOG_FILE = LOGS_DIR / "app.log"
ERR_FILE = LOGS_DIR / "errors.log"


def _safe_mkdir(p: Path) -> None:
    """Best-effort mkdir: nikad ne ruši app."""
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def ensure_folders() -> None:
    """
    Kreira sve potrebne foldere (offline/portable).
    Best-effort: ne ruši app ako neki folder ne može da se napravi.
    """
    for p in [
        DATA_DIR,
        DB_DIR,
        BACKUPS_DIR,
        IMPORTS_DIR,
        EXPORTS_DIR,
        ATTACHMENTS_DIR,
        LOGS_DIR,
        SETTINGS_DIR,
        VENDOR_DIR,
        WHEELS_DIR,
    ]:
        _safe_mkdir(p)

    # DB parent (ako je override negde drugde, probaj; ako ne može — ne ruši app)
    try:
        _safe_mkdir(Path(DB_FILE).parent)
    except Exception:
        pass

# END FILENAME: core/config.py
# (FILENAME: core/config.py - END)