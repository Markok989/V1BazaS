# FILENAME: core/paths.py
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — core/paths.py
Centralizovane putanje (stabilno, bez zavisnosti od imena promenljive u core.config).
- APP_ROOT: root folder aplikacije (gde je app.py)
- DB_PATH: putanja do SQLite baze
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def _try_from_core_config_root() -> Optional[Path]:
    """
    Pokuša da pročita root putanju iz core.config bez pretpostavke kako se promenljiva zove.
    """
    try:
        import core.config as cfg  # type: ignore

        # najčešća imena
        for name in ("APP_ROOT", "ROOT_DIR", "ROOT", "BASE_DIR", "PROJECT_ROOT"):
            if hasattr(cfg, name):
                v = getattr(cfg, name)
                try:
                    return Path(v).expanduser().resolve()
                except Exception:
                    pass

        # ako postoji funkcija
        if hasattr(cfg, "get_app_root"):
            try:
                return Path(cfg.get_app_root()).expanduser().resolve()  # type: ignore
            except Exception:
                pass

    except Exception:
        return None

    return None


def get_app_root() -> Path:
    """
    Root folder aplikacije.
    Fallback: 2 nivoa iznad ovog fajla -> core/paths.py => root je parent od 'core'.
    """
    p = _try_from_core_config_root()
    if p:
        return p
    return Path(__file__).resolve().parents[1]


def _try_from_core_config_db(app_root: Path) -> Optional[Path]:
    """
    Pokuša da pročita DB putanju iz core.config (npr. DB_FILE), ali bez obavezne zavisnosti.
    """
    try:
        import core.config as cfg  # type: ignore

        if hasattr(cfg, "DB_FILE"):
            v = getattr(cfg, "DB_FILE")
            try:
                p = Path(v).expanduser()
                # Ako je relativna, veži je za APP_ROOT
                if not p.is_absolute():
                    p = (app_root / p).resolve()
                else:
                    p = p.resolve()
                return p
            except Exception:
                pass

    except Exception:
        return None

    return None


APP_ROOT: Path = get_app_root()

# Default (fallback) DB lokacija:
_default_db = (APP_ROOT / "data" / "db" / "bazas2.sqlite").resolve()

# Ako core.config ima DB_FILE, koristi njega:
DB_PATH: Path = _try_from_core_config_db(APP_ROOT) or _default_db

# ✅ Osiguraj da folderi postoje (da SQLite ne pukne na startu)
try:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
except Exception:
    # ne ruši aplikaciju ako nema prava, samo ostavi da init_db prijavi grešku lepo
    pass

# END FILENAME: core/paths.py