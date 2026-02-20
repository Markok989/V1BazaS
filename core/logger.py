# FILENAME: core/logger.py
# (FILENAME: core/logger.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — core/logger.py
Logging u fajlove + konzola (PRO, fail-safe).

Unapređeno (bez menjanja postojećih funkcija/poziva):
- Rotacija log fajlova (da ne narastu beskonačno)
- Kontekst u svakoj liniji: run_id + user + role (best-effort)
- logger.propagate=False (sprečava dupliranje logova)
- Fail-safe: ako ne može upis u fajl, radi bar konzola (app ne pada)
- Cache session getter-a (ne radi import na svaku log poruku)
- Warnings (py.warnings) idu u iste handlere (realno korisno)
"""

from __future__ import annotations

import os
import sys
import uuid
import logging
from logging.handlers import RotatingFileHandler

from .config import APP_NAME, APP_VERSION, BASE_DIR, LOG_FILE, ERR_FILE, LOGS_DIR


# ---------- RUN ID (jedan po startu procesa) ----------
# Možeš override preko env ako želiš: BAZAS2_RUN_ID
_RUN_ID = (os.environ.get("BAZAS2_RUN_ID") or "").strip() or uuid.uuid4().hex[:10]


def get_run_id() -> str:
    """Public helper (ne menja ništa postojeće) — koristan za log bundle."""
    return _RUN_ID


# ---------- Rotacija (offline-safe) ----------
def _env_int(name: str, default: int) -> int:
    raw = str(os.environ.get(name, "")).strip()
    if raw == "":
        return default
    try:
        v = int(raw)
        if v < 0:
            return default
        return v
    except Exception:
        return default


# Npr: set BAZAS2_LOG_MAX_MB=10 i BAZAS2_LOG_BACKUPS=10
_LOG_MAX_MB = _env_int("BAZAS2_LOG_MAX_MB", 10)
_LOG_BACKUPS = _env_int("BAZAS2_LOG_BACKUPS", 10)

_MAX_BYTES = max(int(_LOG_MAX_MB), 1) * 1024 * 1024
_BACKUP_COUNT = max(int(_LOG_BACKUPS), 0)


class SessionContextFilter(logging.Filter):
    """
    Ubaci run_id/user/role u svaki LogRecord (best-effort, ne sme da obori app).

    PRO detalj:
    - cache-ujemo funkcije actor_name/current_role posle prvog pokušaja
      da filter ne radi import na svaku log-liniju.
    """
    _cached = False
    _actor_fn = None
    _role_fn = None

    def _ensure_cached(self) -> None:
        if self.__class__._cached:
            return
        try:
            from core.session import actor_name, current_role  # type: ignore
            self.__class__._actor_fn = actor_name
            self.__class__._role_fn = current_role
        except Exception:
            self.__class__._actor_fn = None
            self.__class__._role_fn = None
        finally:
            self.__class__._cached = True

    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = _RUN_ID  # type: ignore[attr-defined]
        record.actor = "-"       # type: ignore[attr-defined]
        record.role = "-"        # type: ignore[attr-defined]

        try:
            self._ensure_cached()
            af = self.__class__._actor_fn
            rf = self.__class__._role_fn
            if callable(af):
                record.actor = str(af() or "-")  # type: ignore[attr-defined]
            if callable(rf):
                record.role = str(rf() or "-").strip().upper()  # type: ignore[attr-defined]
        except Exception:
            pass

        return True


def _make_rotating_file_handler(path, level: int, fmt: logging.Formatter) -> logging.Handler:
    h = RotatingFileHandler(
        filename=str(path),
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
        delay=True,  # fajl se otvara kad zatreba (manje šanse za lock/permission problem)
    )
    h.setLevel(level)
    h.setFormatter(fmt)
    h.addFilter(SessionContextFilter())
    return h


def _make_console_handler(level: int, fmt: logging.Formatter) -> logging.Handler:
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(fmt)
    ch.addFilter(SessionContextFilter())
    return ch


def _attach_handlers_safe(logger: logging.Logger, handlers: list[logging.Handler]) -> None:
    for h in handlers:
        try:
            logger.addHandler(h)
        except Exception:
            pass


def _configure_warnings_logger(handlers: list[logging.Handler]) -> None:
    """
    logging.captureWarnings(True) šalje warnings na logger 'py.warnings'.
    Ako mu ne dodaš handlere, često “nestanu” (zavisno od root loggera).
    """
    try:
        wl = logging.getLogger("py.warnings")
        wl.setLevel(logging.WARNING)
        wl.propagate = False
        try:
            wl.handlers.clear()
        except Exception:
            while wl.handlers:
                wl.removeHandler(wl.handlers[0])
        _attach_handlers_safe(wl, handlers)
    except Exception:
        pass


def setup_logging() -> logging.Logger:
    """
    Vraća app logger. Interfejs ostaje isti (da ne diraš ostatak koda).
    """
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    try:
        logger.handlers.clear()
    except Exception:
        while logger.handlers:
            try:
                logger.removeHandler(logger.handlers[0])
            except Exception:
                break

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | run=%(run_id)s | user=%(actor)s | role=%(role)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handlers: list[logging.Handler] = []

    # fajlovi (rotirajući) — best-effort
    try:
        fh = _make_rotating_file_handler(LOG_FILE, logging.INFO, fmt)
        eh = _make_rotating_file_handler(ERR_FILE, logging.ERROR, fmt)
        handlers.extend([fh, eh])
    except Exception as e:
        try:
            print(f"[LOGGING] Ne mogu da otvorim log fajlove (fallback na konzolu). Reason: {e}", file=sys.stderr)
        except Exception:
            pass

    # konzola (uvek)
    try:
        ch = _make_console_handler(logging.INFO, fmt)
        handlers.append(ch)
    except Exception:
        pass

    _attach_handlers_safe(logger, handlers)

    # warnings -> logging + 'py.warnings' na iste handlere
    try:
        logging.captureWarnings(True)
        _configure_warnings_logger(handlers)
    except Exception:
        pass

    # startup linije
    try:
        logger.info(f"=== {APP_NAME} start | version={APP_VERSION} ===")
        logger.info(f"RUN_ID={_RUN_ID}")
        logger.info(f"BASE_DIR={BASE_DIR}")
        logger.info(f"LOG_FILE={LOG_FILE}")
        logger.info(f"ERR_FILE={ERR_FILE}")
        logger.info(f"LOG_ROTATE maxMB={_LOG_MAX_MB} backups={_LOG_BACKUPS}")
    except Exception:
        pass

    return logger

# (FILENAME: core/logger.py - END)