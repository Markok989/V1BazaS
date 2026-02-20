# FILENAME: services/users_service.py
# (FILENAME: services/users_service.py - START / PART 1 of 3)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/users_service.py

HARDENED + CLEAN (single-source-of-truth, no duplicate defs)

Ciljevi (bez lomljenja postojeće logike):
- Stabilan DB konektor: pragme + commit/rollback + sigurno zatvaranje.
- Bezbednost: UI ne dobija salt/hash (secrets) — samo flagove.
- Multi-role: user_roles tabela + garantovan sync sa users.role.
- FAIL-CLOSED RBAC na servisnom nivou, uz kontrolisan pre-login izuzetak (LoginDialog).
- Sektor-scope: SECTOR_ADMIN radi samo unutar svog sektora (sektor “zakucan”).
- UX safety: prazno polje "" u UI edit formi NE sme da znači “obriši kredencijal”.
  Brisanje je eksplicitno: prosledi None ili pozovi clear_*.

Napomena:
- Login mora da radi pre RBAC-a, zato verify_login() ne koristi _must().
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from core.config import DB_FILE

# -------------------- logging (silent by default) --------------------

_log = logging.getLogger(__name__)
_log.addHandler(logging.NullHandler())

# -------------------- constants / limits --------------------

PBKDF2_ITER = 200_000
SALT_BYTES = 16
_MAX_ROLES = 64  # sanity limit

# password policy (V1) — minimalno; možeš pooštriti kasnije bez promene DB šeme
_MIN_PASSWORD_LEN = 6

# -------------------- optional core db connector --------------------
# Prefer centralizovani konektor (isti DB kao ostatak sistema).

try:
    from core.db import connect_db as _core_connect_db  # type: ignore
except Exception:  # pragma: no cover
    _core_connect_db = None  # type: ignore

# -------------------- RBAC perms (fallback-safe) --------------------

try:
    from core.rbac import PERM_USERS_VIEW, PERM_USERS_MANAGE  # type: ignore
except Exception:  # pragma: no cover
    PERM_USERS_VIEW = "users.view"
    PERM_USERS_MANAGE = "users.manage"

# Optional RBAC role normalizer (aliases)
try:
    from core.rbac import normalize_role as _rbac_normalize_role  # type: ignore
except Exception:  # pragma: no cover
    _rbac_normalize_role = None  # type: ignore

# -------------------- roles / scope rules --------------------

ROLE_ADMIN = "ADMIN"
ROLE_SECTOR_ADMIN = "SECTOR_ADMIN"

SECTOR_ADMIN_ASSIGNABLE = {
    "SECTOR_ADMIN",
    "REFERENT_IT",
    "REFERENT_METRO",
    "READONLY",
    "BASIC_USER",
}

# -------------------- credential policy --------------------
# Ako user ima bar jedan kredencijal (PIN ili lozinku) -> posle izmene mora ostati bar jedno.
# Izuzetak: legacy user sa 0 kredencijala (dozvoljeno “bez lozinke”) dok admin ne opremi.

_ALLOW_NO_CREDENTIALS_FOR_LEGACY = True

# -------------------- schema/migration lock --------------------

_SCHEMA_LOCK = RLock()

# -------------------- title choices (čin/status) --------------------

_TITLE_GROUP_CINOVI = ["Vojnik", "Razvodnik", "Desetar"]

_TITLE_GROUP_PODOFICIRI = [
    "Mlađi vodnik",
    "Vodnik",
    "Stariji vodnik",
    "Stariji vodnik I klase",
    "Zastavnik",
    "Zastavnik I klase",
]

_TITLE_GROUP_OFICIRI = [
    "Potporučnik",
    "Poručnik",
    "Kapetan",
    "Kapetan I klase",
    "Major",
    "Potpukovnik",
    "Pukovnik",
    "Brigadni general",
    "General-major",
    "General-potpukovnik",
    "General",
]

_TITLE_GROUP_STATUS = ["Civilno lice", "Vojni službenik"]

DEFAULT_TITLE_CHOICES: List[str] = (
    _TITLE_GROUP_CINOVI + _TITLE_GROUP_PODOFICIRI + _TITLE_GROUP_OFICIRI + _TITLE_GROUP_STATUS
)

_KNOWN_TITLES_SET = {x.strip().lower() for x in DEFAULT_TITLE_CHOICES if str(x).strip()}

# -------------------- RBAC helpers --------------------


def _safe_can(perm: str) -> bool:
    """FAIL-CLOSED: ako session/can ne radi -> deny."""
    try:
        from core.session import can  # type: ignore

        return bool(can(perm))
    except Exception:
        return False


def _is_logged_in() -> bool:
    """Prefer core.session.is_logged_in(); fallback best-effort."""
    try:
        from core.session import is_logged_in  # type: ignore

        return bool(is_logged_in())
    except Exception:
        pass

    try:
        import core.session as s  # type: ignore

        fn = getattr(s, "get_current_user", None)
        if callable(fn):
            return bool(fn())
    except Exception:
        pass
    return False


def _must(perm: str, *, allow_prelogin: bool = False) -> None:
    """
    Service-level RBAC “must”.
    - allow_prelogin=True: ako još nema ulogovanog user-a -> ne blokiramo (LoginDialog).
      (Ali pre-login output je sužen u list/get funkcijama.)
    - Inače FAIL-CLOSED.
    """
    if allow_prelogin and (not _is_logged_in()):
        return
    if not _safe_can(perm):
        raise PermissionError(f"RBAC: nemaš pravo za akciju ({perm}).")


# -------------------- time / actor helpers --------------------


def _now() -> str:
    """DB canonical: ISO (YYYY-MM-DD HH:MM:SS)."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ts_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _actor_username() -> str:
    """Ko izvršava akciju (best-effort)."""
    try:
        from core.session import get_current_user  # type: ignore

        u = get_current_user() or {}
        if isinstance(u, dict):
            return str(u.get("username") or u.get("user") or "").strip()
        return str(u or "").strip()
    except Exception:
        return ""


def _current_username() -> str:
    """Ulogovani username (best-effort)."""
    try:
        from core.session import get_current_user  # type: ignore

        u = get_current_user() or {}
        if isinstance(u, dict):
            return str(u.get("username") or u.get("user") or "").strip()
        return str(u or "").strip()
    except Exception:
        return ""


# -------------------- db helpers --------------------


def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _resolve_db_path() -> Path:
    p = Path(DB_FILE)
    if not p.is_absolute():
        p = (_app_root() / p).resolve()
    return p


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    """Pragme koje želimo konzistentno (best-effort)."""
    try:
        conn.execute("PRAGMA busy_timeout=2500;")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass
    # WAL poboljšava UX (manje lock-ovanja), ali ne forsiramo ako DB ne dozvoli
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass


@contextmanager
def _connect_db() -> Iterator[Any]:
    """
    Prefer core.db.connect_db() ako postoji.
    Podržava da connect_db vrati:
      A) sqlite3.Connection
      B) context manager (with connect_db() as conn)
      C) connection-like objekat

    HARDENING:
    - pragme u svim granama
    - rollback na exception (best-effort)
    - commit na uspešan izlaz (best-effort)
    - sigurno zatvaranje konekcije
    """
    if _core_connect_db is not None:
        obj: Any = None
        try:
            obj = _core_connect_db()

            # A) direct connection
            if isinstance(obj, sqlite3.Connection):
                conn = obj
                _apply_pragmas(conn)
                try:
                    yield conn
                    try:
                        conn.commit()
                    except Exception:
                        pass
                except Exception:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    raise
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
                return

            # B) context manager
            if hasattr(obj, "__enter__") and hasattr(obj, "__exit__"):
                with obj as conn:  # type: ignore[assignment]
                    try:
                        if isinstance(conn, sqlite3.Connection):
                            _apply_pragmas(conn)
                        yield conn
                        try:
                            if hasattr(conn, "commit"):
                                conn.commit()  # type: ignore[attr-defined]
                        except Exception:
                            pass
                    except Exception:
                        try:
                            if hasattr(conn, "rollback"):
                                conn.rollback()  # type: ignore[attr-defined]
                        except Exception:
                            pass
                        raise
                return

            # C) unknown object treated as connection-like
            conn = obj
            try:
                if isinstance(conn, sqlite3.Connection):
                    _apply_pragmas(conn)
                yield conn
                try:
                    if hasattr(conn, "commit"):
                        conn.commit()  # type: ignore[attr-defined]
                except Exception:
                    pass
            except Exception:
                try:
                    if hasattr(conn, "rollback"):
                        conn.rollback()  # type: ignore[attr-defined]
                except Exception:
                    pass
                raise
            finally:
                try:
                    if hasattr(conn, "close"):
                        conn.close()  # type: ignore[attr-defined]
                except Exception:
                    pass
            return

        except Exception:
            try:
                if obj is not None and hasattr(obj, "close"):
                    obj.close()  # type: ignore[attr-defined]
            except Exception:
                pass
            raise

    # fallback: direktno na DB_FILE
    db_path = _resolve_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path.as_posix(), timeout=2.5)
    _apply_pragmas(conn)
    try:
        yield conn
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


# -------------------- crypto helpers --------------------


def _new_salt_hex() -> str:
    return secrets.token_bytes(SALT_BYTES).hex()


def _pbkdf2_hash(secret_value: str, salt_hex: str, iters: int) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", (secret_value or "").encode("utf-8"), salt, int(iters))
    return dk.hex()


# Backward/compat alias (ako je negde importovano kao pbkdf2_hash)
def pbkdf2_hash(secret_value: str, salt_hex: str, iters: int) -> str:
    return _pbkdf2_hash(secret_value, salt_hex, iters)


# -------------------- normalize helpers --------------------


def _canon_role_value(role: Any) -> str:
    """
    Canonical role (alias-aware if core.rbac.normalize_role exists).
    """
    s = str(role or "").strip()
    if not s:
        return "READONLY"
    # allow CSV, take first
    if "," in s:
        s = (s.split(",", 1)[0] or "").strip()
    if callable(_rbac_normalize_role):
        try:
            rr = str(_rbac_normalize_role(s) or "").strip().upper()
            return rr or "READONLY"
        except Exception:
            pass
    return s.strip().upper() or "READONLY"


def _norm_username(u: Union[str, Dict[str, Any], None]) -> str:
    """Normalizuje username; prihvata string/dict/None."""
    if isinstance(u, dict):
        u = u.get("username") or u.get("user") or u.get("login") or u.get("name") or ""
    s: Any = (u or "")
    if not isinstance(s, str):
        s = str(s)
    s = s.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    s = s.strip().replace(" ", "_")
    return s[:50]


def _norm_sector(x: Any) -> str:
    s = ("" if x is None else str(x)).replace("\n", " ").replace("\r", " ").strip()
    return s[:80]


def _norm_location(x: Any) -> str:
    s = ("" if x is None else str(x)).replace("\n", " ").replace("\r", " ").strip()
    return s[:120]


def _norm_text(x: Any, max_len: int = 160) -> str:
    s = ("" if x is None else str(x))
    s = s.replace("\n", " ").replace("\r", " ").strip()
    return s[: max_len if max_len > 0 else 160]


# -------------------- sqlite schema helpers --------------------


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
        (str(name or "").strip(),),
    ).fetchone()
    return bool(r)


def _cols(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        # table names are internal constants, not user input
        return [r[1] for r in conn.execute(f"PRAGMA table_info({table});").fetchall()]
    except Exception:
        return []


def _pick_existing(cols: Sequence[str], *names: str) -> str:
    for n in names:
        if n in cols:
            return n
    return ""


# -------------------- session role/scope helpers --------------------


def _current_role() -> str:
    """Efektivna uloga iz sesije (active_role)."""
    try:
        from core.session import get_current_user  # type: ignore
        from core.rbac import effective_role  # type: ignore

        return str(effective_role(get_current_user() or {})).strip().upper()
    except Exception:
        # fallback: pokušaj da izvučeš role iz sesije direktno
        try:
            from core.session import get_current_user  # type: ignore

            u = get_current_user() or {}
            if isinstance(u, dict):
                return str(u.get("active_role") or u.get("role") or "").strip().upper()
        except Exception:
            pass
        return ""


def _current_sector() -> str:
    """Sektor iz sesije."""
    try:
        from core.session import current_sector  # type: ignore

        return str(current_sector() or "").strip()
    except Exception:
        # fallback: izvuci iz current_user dict
        try:
            from core.session import get_current_user  # type: ignore

            u = get_current_user() or {}
            if isinstance(u, dict):
                return str(u.get("sector") or u.get("org_unit") or "").strip()
        except Exception:
            pass
        return ""


def _is_sector_admin() -> bool:
    return _current_role().upper() == ROLE_SECTOR_ADMIN


def _is_admin() -> bool:
    return _current_role().upper() == ROLE_ADMIN


def _enforce_sector_scope(target_sector: str, *, action: str) -> None:
    """
    SECTOR_ADMIN: može samo u okviru svog sektora.
    ADMIN (global): bypass.
    """
    role = _current_role().upper()
    if role == ROLE_ADMIN:
        return
    if role == ROLE_SECTOR_ADMIN:
        my_sec = _current_sector().strip()
        if my_sec and (my_sec == (target_sector or "").strip()):
            return
        raise PermissionError(f"Sektor-scope: nije dozvoljeno ({action}).")
    raise PermissionError(f"Sektor-scope: nije dozvoljeno ({action}).")


def _normalize_roles_list(roles: List[str]) -> List[str]:
    """Dedup + canonicalize roles (alias-aware)."""
    seen = set()
    out: List[str] = []
    for r in roles or []:
        t = _canon_role_value(r)
        if t and t not in seen:
            seen.add(t)
            out.append(t)
        if len(out) >= _MAX_ROLES:
            break
    return out


def _enforce_role_assignment_rules(roles: List[str], *, action: str) -> None:
    """
    Global pravila dodele rola:
    - ADMIN može sve
    - SECTOR_ADMIN ne može dodeliti ADMIN i može dodeliti samo SECTOR_ADMIN_ASSIGNABLE
    """
    rr = _normalize_roles_list(roles or [])
    if not rr:
        return

    if _is_admin():
        return

    if _is_sector_admin():
        if ROLE_ADMIN in rr:
            raise PermissionError(
                f"Role-scope: SECTOR_ADMIN ne može dodeliti {ROLE_ADMIN} ({action})."
            )
        for r in rr:
            if r not in SECTOR_ADMIN_ASSIGNABLE:
                raise PermissionError(
                    f"Role-scope: SECTOR_ADMIN ne može dodeliti rolu '{r}' ({action})."
                )
        return

    raise PermissionError(f"Role-scope: nije dozvoljeno dodeljivanje rola ({action}).")


# -------------------- credential validation --------------------

_WEAK_PINS = {
    "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
    "1234", "4321", "1212", "1122", "2211", "2580", "0852", "0101", "1010",
    "000000", "111111", "123456", "654321",
}


def validate_pin(pin: str) -> Optional[str]:
    p = (pin or "").strip()
    if not p:
        return "PIN je prazan."
    if not re.fullmatch(r"\d{4,8}", p):
        return "PIN mora imati 4 do 8 cifara."
    if p in _WEAK_PINS:
        return "PIN je previše slab (npr. 0000/1234)."
    if len(set(p)) == 1:
        return "PIN je previše slab (sve iste cifre)."
    return None


def validate_password(pw: str) -> Optional[str]:
    s = (pw or "")
    if not s.strip():
        return "Lozinka je prazna."
    if len(s) < _MIN_PASSWORD_LEN:
        return f"Lozinka mora imati najmanje {_MIN_PASSWORD_LEN} karaktera."
    return None


def list_available_roles() -> List[str]:
    """
    UI helper: koje role smeju da se dodeljuju iz trenutnog konteksta.
    - pre-login: sve (da LoginDialog može da prikaže izbor posle logina)
    - ADMIN: sve
    - SECTOR_ADMIN: samo subset
    - ostali: minimalno
    """
    all_roles = ["ADMIN", "SECTOR_ADMIN", "REFERENT_IT", "REFERENT_METRO", "BASIC_USER", "READONLY"]
    if not _is_logged_in():
        return all_roles

    role = _current_role().upper()
    if role == ROLE_ADMIN:
        return all_roles
    if role == ROLE_SECTOR_ADMIN:
        return ["SECTOR_ADMIN", "REFERENT_IT", "REFERENT_METRO", "BASIC_USER", "READONLY"]
    return ["BASIC_USER", "READONLY"]

# (FILENAME: services/users_service.py - END / PART 1 of 3)

# FILENAME: services/users_service.py
# (FILENAME: services/users_service.py - START / PART 2 of 3)

# -------------------- schema creation / migration --------------------


def _create_users_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,      -- legacy/compat
            display_name TEXT NOT NULL,
            role TEXT NOT NULL,

            -- name parts (V1.3.3)
            last_name TEXT NOT NULL DEFAULT '',
            father_name TEXT NOT NULL DEFAULT '',
            first_name TEXT NOT NULL DEFAULT '',
            jmbg TEXT NOT NULL DEFAULT '',

            -- org scope
            sector TEXT NOT NULL DEFAULT '',
            location TEXT NOT NULL DEFAULT '',

            -- extra info
            email TEXT NOT NULL DEFAULT '',
            phone TEXT NOT NULL DEFAULT '',
            employee_no TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',

            created_by TEXT NOT NULL DEFAULT '',
            updated_by TEXT NOT NULL DEFAULT '',

            -- PIN
            pin_salt TEXT,
            pin_hash TEXT,

            -- PASSWORD
            pass_salt TEXT,
            pass_hash TEXT,

            -- credential policy flag (V1.3.4)
            must_change_creds INTEGER NOT NULL DEFAULT 0,

            -- meta
            iters INTEGER NOT NULL DEFAULT 200000,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )

    # indices (best-effort, idempotent)
    for sql in (
        "CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);",
        "CREATE INDEX IF NOT EXISTS idx_users_sector ON users(sector);",
        "CREATE INDEX IF NOT EXISTS idx_users_location ON users(location);",
        "CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);",
        "CREATE INDEX IF NOT EXISTS idx_users_last_name ON users(last_name);",
        "CREATE INDEX IF NOT EXISTS idx_users_jmbg ON users(jmbg);",
        "CREATE INDEX IF NOT EXISTS idx_users_must_change_creds ON users(must_change_creds);",
    ):
        try:
            conn.execute(sql)
        except Exception:
            pass


def _create_user_roles_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            created_by TEXT,
            UNIQUE(user_id, role),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    for sql in (
        "CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);",
        "CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role);",
        "CREATE INDEX IF NOT EXISTS idx_user_roles_active ON user_roles(is_active);",
    ):
        try:
            conn.execute(sql)
        except Exception:
            pass


def _ensure_primary_roles_present(conn: sqlite3.Connection) -> None:
    """
    Multi-role hardening:
    - Za svakog korisnika obezbedi da primary role iz users.role postoji u user_roles (is_active=1).
    """
    if not (_table_exists(conn, "users") and _table_exists(conn, "user_roles")):
        return

    try:
        rows = conn.execute("SELECT id, role FROM users;").fetchall()
    except Exception:
        rows = []

    for uid, role in rows:
        try:
            user_id = int(uid or 0)
        except Exception:
            user_id = 0
        if user_id <= 0:
            continue

        rl = _canon_role_value(role) or "READONLY"
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO user_roles(user_id, role, is_active, created_at, created_by)
                VALUES(?,?,?,?,?);
                """,
                (user_id, rl, 1, _now(), "migration"),
            )
            conn.execute(
                "UPDATE user_roles SET is_active=1 WHERE user_id=? AND role=?;",
                (user_id, rl),
            )
        except Exception:
            continue


def _seed_admin_if_empty(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT COUNT(1) FROM users;").fetchone()
    cnt = int(row[0] if row else 0)
    if cnt != 0:
        return

    iters = PBKDF2_ITER
    admin_user = "admin"
    admin_display = "Administrator"
    admin_role = ROLE_ADMIN

    # Default admin PIN je slab (0000) -> forsiramo promenu posle prvog logina
    pin = "0000"
    pin_salt = _new_salt_hex()
    pin_hash = _pbkdf2_hash(pin, pin_salt, iters)

    conn.execute(
        """
        INSERT INTO users(
            username, display_name, role,
            last_name, father_name, first_name, jmbg,
            sector, location,
            email, phone, employee_no, title, note,
            created_by, updated_by,
            pin_salt, pin_hash, pass_salt, pass_hash,
            must_change_creds,
            iters, is_active, created_at, updated_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
        """,
        (
            admin_user,
            admin_display,
            admin_role,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "Vojni službenik",
            "",
            "seed",
            "seed",
            pin_salt,
            pin_hash,
            "",
            "",
            1,  # must_change_creds=1 (default PIN)
            int(iters),
            1,
            _now(),
            _now(),
        ),
    )


def _ensure_admin_has_credential(conn: sqlite3.Connection) -> None:
    r = conn.execute(
        "SELECT iters, COALESCE(pin_hash,''), COALESCE(pass_hash,'') "
        "FROM users WHERE username='admin' LIMIT 1;"
    ).fetchone()
    if not r:
        return

    iters = int(r[0] or PBKDF2_ITER)
    pin_hash = (r[1] or "").strip()
    pass_hash = (r[2] or "").strip()

    if pin_hash or pass_hash:
        return

    # Legacy admin bez kredencijala -> dodeli default PIN i forsiraj promenu
    pin = "0000"
    pin_salt = _new_salt_hex()
    pin_hash2 = _pbkdf2_hash(pin, pin_salt, iters)

    conn.execute(
        "UPDATE users SET pin_salt=?, pin_hash=?, must_change_creds=1, updated_at=?, updated_by=? "
        "WHERE username='admin';",
        (pin_salt, pin_hash2, _now(), "seed"),
    )


def _ensure_users_extra_columns(conn: sqlite3.Connection) -> None:
    """
    Dodaje nove kolone u users bez “velike migracije”.
    Bezbedno za postojeće baze.
    """
    if not _table_exists(conn, "users"):
        return

    cols = _cols(conn, "users")
    wanted: List[Tuple[str, str]] = [
        ("email", "TEXT NOT NULL DEFAULT ''"),
        ("phone", "TEXT NOT NULL DEFAULT ''"),
        ("employee_no", "TEXT NOT NULL DEFAULT ''"),
        ("title", "TEXT NOT NULL DEFAULT ''"),
        ("note", "TEXT NOT NULL DEFAULT ''"),
        ("created_by", "TEXT NOT NULL DEFAULT ''"),
        ("updated_by", "TEXT NOT NULL DEFAULT ''"),
        ("location", "TEXT NOT NULL DEFAULT ''"),
        ("sector", "TEXT NOT NULL DEFAULT ''"),
        # V1.3.3
        ("last_name", "TEXT NOT NULL DEFAULT ''"),
        ("father_name", "TEXT NOT NULL DEFAULT ''"),
        ("first_name", "TEXT NOT NULL DEFAULT ''"),
        ("jmbg", "TEXT NOT NULL DEFAULT ''"),
        # meta
        ("created_at", "TEXT NOT NULL DEFAULT ''"),
        ("updated_at", "TEXT NOT NULL DEFAULT ''"),
        # V1.3.4
        ("must_change_creds", "INTEGER NOT NULL DEFAULT 0"),
    ]

    for name, ddl in wanted:
        if name in cols:
            continue
        try:
            conn.execute(f"ALTER TABLE users ADD COLUMN {name} {ddl};")
        except Exception:
            pass

    # indeksi (best-effort)
    for idx_sql in (
        "CREATE INDEX IF NOT EXISTS idx_users_last_name ON users(last_name);",
        "CREATE INDEX IF NOT EXISTS idx_users_jmbg ON users(jmbg);",
        "CREATE INDEX IF NOT EXISTS idx_users_must_change_creds ON users(must_change_creds);",
    ):
        try:
            conn.execute(idx_sql)
        except Exception:
            pass


def _backfill_created_updated(conn: sqlite3.Connection) -> None:
    """
    Ako su created_at/updated_at prazni (ili NULL), popuni ih.
    Pravilo:
    - created_at: ako prazno -> sada
    - updated_at: ako prazno -> created_at (ako postoji), inače sada
    """
    if not _table_exists(conn, "users"):
        return

    cols = set(_cols(conn, "users"))
    if "created_at" not in cols or "updated_at" not in cols:
        return

    now = _now()
    try:
        conn.execute(
            """
            UPDATE users
               SET created_at = CASE
                                WHEN TRIM(COALESCE(created_at,'')) = '' THEN ?
                                ELSE created_at
                              END
            """,
            (now,),
        )
    except Exception:
        pass

    try:
        conn.execute(
            """
            UPDATE users
               SET updated_at = CASE
                                WHEN TRIM(COALESCE(updated_at,'')) = '' THEN
                                     CASE
                                       WHEN TRIM(COALESCE(created_at,'')) <> '' THEN created_at
                                       ELSE ?
                                     END
                                ELSE updated_at
                              END
            """,
            (now,),
        )
    except Exception:
        pass


def _needs_migration(existing_cols: List[str]) -> bool:
    """
    Full migration samo kad fali osnova.
    created_at/updated_at se više ne tretiraju kao razlog za full-migraciju.
    """
    if "id" not in existing_cols:
        return True
    must_have = {"username", "display_name", "role", "iters", "is_active"}
    return not must_have.issubset(set(existing_cols))


def _migrate_legacy_users(conn: sqlite3.Connection) -> None:
    """
    Safe-ish legacy migracija:
    - rename users -> users_legacy_backup_YYYYMMDD_HHMMSS
    - create fresh users
    - best-effort prekopiraj polja koja postoje
    """
    legacy = f"users_legacy_backup_{_ts_tag()}"
    conn.execute(f"ALTER TABLE users RENAME TO {legacy};")

    _create_users_table(conn)
    legacy_cols = _cols(conn, legacy)

    c_username = _pick_existing(legacy_cols, "username", "user", "login", "name")
    c_display = _pick_existing(legacy_cols, "display_name", "display", "full_name")
    c_role = _pick_existing(legacy_cols, "role", "user_role")
    c_sector = _pick_existing(
        legacy_cols, "sector", "sektor", "org_unit", "orgunit", "department", "unit", "org"
    )
    c_location = _pick_existing(legacy_cols, "location", "lokacija", "place", "site")

    c_email = _pick_existing(legacy_cols, "email", "mail", "e_mail")
    c_phone = _pick_existing(legacy_cols, "phone", "telefon", "tel")
    c_empno = _pick_existing(
        legacy_cols, "employee_no", "emp_no", "personal_no", "personnel_no", "broj", "id_no"
    )
    c_title = _pick_existing(legacy_cols, "title", "cin", "čin", "status", "pozicija", "position", "rank")
    c_note = _pick_existing(legacy_cols, "note", "notes", "napomena", "beleška", "beleshka")

    # V1.3.3 (ako je neko već imao)
    c_last = _pick_existing(legacy_cols, "last_name", "prezime", "surname")
    c_father = _pick_existing(legacy_cols, "father_name", "ime_oca", "middle_name")
    c_first = _pick_existing(legacy_cols, "first_name", "ime", "firstname", "given_name")
    c_jmbg = _pick_existing(legacy_cols, "jmbg", "jmbg13", "personal_id")

    c_created_by = _pick_existing(legacy_cols, "created_by", "creator")
    c_updated_by = _pick_existing(legacy_cols, "updated_by", "modifier", "modified_by")

    c_pin_salt = _pick_existing(legacy_cols, "pin_salt")
    c_pin_hash = _pick_existing(legacy_cols, "pin_hash", "pin")

    c_pass_salt = _pick_existing(legacy_cols, "pass_salt")
    c_pass_hash = _pick_existing(legacy_cols, "pass_hash", "password_hash", "pwd_hash", "pass", "password")

    c_iters = _pick_existing(legacy_cols, "iters", "iterations")
    c_active = _pick_existing(legacy_cols, "is_active", "active", "enabled")
    c_created = _pick_existing(legacy_cols, "created_at", "created")
    c_updated = _pick_existing(legacy_cols, "updated_at", "updated", "modified_at")
    c_must_change = _pick_existing(legacy_cols, "must_change_creds", "must_change", "force_change")

    if not c_username:
        _seed_admin_if_empty(conn)
        _ensure_admin_has_credential(conn)
        return

    sel_cols: List[str] = [c_username]
    for c in [
        c_display,
        c_role,
        c_sector,
        c_location,
        c_email,
        c_phone,
        c_empno,
        c_title,
        c_note,
        c_last,
        c_father,
        c_first,
        c_jmbg,
        c_created_by,
        c_updated_by,
        c_pin_salt,
        c_pin_hash,
        c_pass_salt,
        c_pass_hash,
        c_must_change,
        c_iters,
        c_active,
        c_created,
        c_updated,
    ]:
        if c:
            sel_cols.append(c)

    q = f"SELECT {', '.join(sel_cols)} FROM {legacy};"
    rows = conn.execute(q).fetchall()

    for r in rows:
        data: Dict[str, Any] = {sel_cols[i]: r[i] for i in range(len(sel_cols))}
        un = _norm_username(str(data.get(c_username, "") or ""))
        if not un:
            continue

        dn = (str(data.get(c_display, "") or "") if c_display else "").strip() or un
        rl = _canon_role_value((str(data.get(c_role, "") or "") if c_role else "") or "READONLY")
        sec = _norm_sector(data.get(c_sector, "") or "") if c_sector else ""
        loc = _norm_location(data.get(c_location, "") or "") if c_location else ""

        email = _norm_text(data.get(c_email, "") or "", 160) if c_email else ""
        phone = _norm_text(data.get(c_phone, "") or "", 80) if c_phone else ""
        empno = _norm_text(data.get(c_empno, "") or "", 80) if c_empno else ""
        title = _norm_text(data.get(c_title, "") or "", 120) if c_title else ""
        note = _norm_text(data.get(c_note, "") or "", 500) if c_note else ""

        last_name = _norm_text(data.get(c_last, "") or "", 80) if c_last else ""
        father_name = _norm_text(data.get(c_father, "") or "", 80) if c_father else ""
        first_name = _norm_text(data.get(c_first, "") or "", 80) if c_first else ""
        jmbg = _norm_text(data.get(c_jmbg, "") or "", 13) if c_jmbg else ""

        created_by = _norm_text(data.get(c_created_by, "") or "", 80) if c_created_by else "migration"
        updated_by = _norm_text(data.get(c_updated_by, "") or "", 80) if c_updated_by else created_by

        pin_salt = (str(data.get(c_pin_salt, "") or "") if c_pin_salt else "").strip()
        pin_hash = (str(data.get(c_pin_hash, "") or "") if c_pin_hash else "").strip()
        pass_salt = (str(data.get(c_pass_salt, "") or "") if c_pass_salt else "").strip()
        pass_hash = (str(data.get(c_pass_hash, "") or "") if c_pass_hash else "").strip()

        must_change = 0
        if c_must_change:
            try:
                must_change = 1 if int(data.get(c_must_change, 0) or 0) != 0 else 0
            except Exception:
                must_change = 0

        iters = int(data.get(c_iters, PBKDF2_ITER) or PBKDF2_ITER) if c_iters else PBKDF2_ITER

        is_active = 1
        if c_active:
            try:
                is_active = 1 if int(data.get(c_active, 1) or 1) != 0 else 0
            except Exception:
                is_active = 1

        created_at = (str(data.get(c_created, "") or "") if c_created else "").strip() or _now()
        updated_at = (str(data.get(c_updated, "") or "") if c_updated else "").strip() or created_at

        conn.execute(
            """
            INSERT OR IGNORE INTO users(
                username, display_name, role,
                last_name, father_name, first_name, jmbg,
                sector, location,
                email, phone, employee_no, title, note,
                created_by, updated_by,
                pin_salt, pin_hash,
                pass_salt, pass_hash,
                must_change_creds,
                iters, is_active, created_at, updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
            """,
            (
                un,
                _norm_text(dn, 120),
                rl,
                last_name,
                father_name,
                first_name,
                jmbg,
                sec,
                loc,
                email,
                phone,
                empno,
                title,
                note,
                created_by,
                updated_by,
                pin_salt,
                pin_hash,
                pass_salt,
                pass_hash,
                int(must_change),
                int(iters),
                int(is_active),
                created_at,
                updated_at,
            ),
        )

    _seed_admin_if_empty(conn)
    _ensure_admin_has_credential(conn)


def _backfill_name_parts_from_display(conn: sqlite3.Connection) -> None:
    """
    Best-effort:
    ako last_name i first_name prazni, a display_name postoji,
    pokuša: "Prezime Ime" (2+ reči) => last=prva, first=poslednja.

    Ne dira postojeće popunjene vrednosti.
    """
    if not _table_exists(conn, "users"):
        return
    cols = _cols(conn, "users")
    if not {"display_name", "last_name", "first_name"}.issubset(set(cols)):
        return

    rows = conn.execute(
        """
        SELECT id, display_name
        FROM users
        WHERE TRIM(COALESCE(display_name,'')) <> ''
          AND TRIM(COALESCE(last_name,'')) = ''
          AND TRIM(COALESCE(first_name,'')) = ''
        LIMIT 2000;
        """
    ).fetchall()

    for rid, dn in rows:
        try:
            uid = int(rid or 0)
        except Exception:
            continue
        name = str(dn or "").strip()
        parts = [p for p in name.split(" ") if p.strip()]
        if len(parts) < 2:
            continue
        last_name = _norm_text(parts[0], 80)
        first_name = _norm_text(parts[-1], 80)
        if not last_name or not first_name:
            continue
        try:
            conn.execute(
                "UPDATE users SET last_name=?, first_name=? WHERE id=?;",
                (last_name, first_name, uid),
            )
        except Exception:
            pass


def ensure_users_schema() -> None:
    """Kreira/migrira users i user_roles šemu. Thread-safe (lock)."""
    with _SCHEMA_LOCK:
        with _connect_db() as conn:
            if _table_exists(conn, "users"):
                existing_cols = _cols(conn, "users")
                if _needs_migration(existing_cols):
                    _migrate_legacy_users(conn)
                else:
                    _ensure_users_extra_columns(conn)
                    try:
                        _backfill_created_updated(conn)
                    except Exception:
                        pass
                    _seed_admin_if_empty(conn)
                    _ensure_admin_has_credential(conn)
            else:
                _create_users_table(conn)
                _seed_admin_if_empty(conn)
                _ensure_admin_has_credential(conn)
                try:
                    _backfill_created_updated(conn)
                except Exception:
                    pass

            _create_user_roles_table(conn)

            # Multi-role: uvek osiguraj da primary role postoji u user_roles
            try:
                _ensure_primary_roles_present(conn)
            except Exception:
                pass

            # V1.3.3 backfill (best-effort)
            try:
                _backfill_name_parts_from_display(conn)
            except Exception:
                pass


# -------------------- credential guards --------------------


def _get_user_cred_state(conn: sqlite3.Connection, user_id: int) -> Tuple[bool, bool]:
    """Vrati (has_pin, has_password) za user_id."""
    try:
        r = conn.execute(
            "SELECT COALESCE(pin_hash,''), COALESCE(pass_hash,'') FROM users WHERE id=? LIMIT 1;",
            (int(user_id),),
        ).fetchone()
        if not r:
            return False, False
        has_pin = bool(str(r[0] or "").strip())
        has_pw = bool(str(r[1] or "").strip())
        return has_pin, has_pw
    except Exception:
        return False, False


def _enforce_not_both_removed(
    before_has_pin: bool,
    before_has_pw: bool,
    after_has_pin: bool,
    after_has_pw: bool,
    *,
    action: str,
) -> None:
    """
    Pravilo:
    - ako je korisnik pre imao bar jedan kredencijal -> posle izmene mora imati bar jedan
    - ako pre nije imao nijedan -> dozvoljeno je i dalje 0 (legacy), dok admin ne postavi
    """
    if before_has_pin or before_has_pw:
        if (not after_has_pin) and (not after_has_pw):
            raise ValueError(
                f"Kredencijali: nije dozvoljeno obrisati i PIN i lozinku ({action}). Mora ostati bar jedno."
            )
    else:
        if (not after_has_pin) and (not after_has_pw):
            if _ALLOW_NO_CREDENTIALS_FOR_LEGACY:
                return
            raise ValueError(f"Kredencijali: korisnik mora imati PIN ili lozinku ({action}).")


# -------------------- list helpers (UI expects) --------------------


def get_sector_context() -> Dict[str, Any]:
    """
    UI helper:
    - koji je moj sektor (iz sesije)
    - da li je sektor "zakucan" (SECTOR_ADMIN)
    """
    my_sec = _current_sector().strip()
    locked = bool(_is_logged_in() and _is_sector_admin())
    return {"my_sector": my_sec, "sector_locked": locked}


def list_sectors() -> List[str]:
    """
    UX + bezbednost:
    - ADMIN: svi sektori iz baze
    - SECTOR_ADMIN: samo njegov sektor (da UI ne nudi pogrešne opcije)
    - pre-login: može sve (ako UI uopšte koristi)
    """
    _must(PERM_USERS_VIEW, allow_prelogin=True)
    ensure_users_schema()

    if _is_logged_in() and _is_sector_admin():
        my_sec = _current_sector().strip()
        return [my_sec] if my_sec else []

    with _connect_db() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT TRIM(COALESCE(sector,'')) AS s
            FROM users
            WHERE TRIM(COALESCE(sector,'')) <> ''
            ORDER BY s COLLATE NOCASE;
            """
        ).fetchall()
    return [str(r[0] or "").strip() for r in rows if str(r[0] or "").strip()]


def list_locations() -> List[str]:
    _must(PERM_USERS_VIEW, allow_prelogin=True)
    ensure_users_schema()

    with _connect_db() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT TRIM(COALESCE(location,'')) AS l
            FROM users
            WHERE TRIM(COALESCE(location,'')) <> ''
            ORDER BY l COLLATE NOCASE;
            """
        ).fetchall()
    return [str(r[0] or "").strip() for r in rows if str(r[0] or "").strip()]


def list_title_groups() -> List[Dict[str, Any]]:
    _must(PERM_USERS_VIEW, allow_prelogin=True)
    ensure_users_schema()

    base_groups: List[Tuple[str, List[str]]] = [
        ("Činovi", list(_TITLE_GROUP_CINOVI)),
        ("Podoficiri", list(_TITLE_GROUP_PODOFICIRI)),
        ("Oficiri", list(_TITLE_GROUP_OFICIRI)),
        ("Status", list(_TITLE_GROUP_STATUS)),
    ]

    db_vals: List[str] = []
    try:
        with _connect_db() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT TRIM(COALESCE(title,'')) AS t
                FROM users
                WHERE TRIM(COALESCE(title,'')) <> ''
                ORDER BY t COLLATE NOCASE;
                """
            ).fetchall()
        db_vals = [str(r[0] or "").strip() for r in rows if str(r[0] or "").strip()]
    except Exception:
        db_vals = []

    extras: List[str] = []
    seen: set = set()
    for x in db_vals:
        k = x.strip().lower()
        if not k or k in _KNOWN_TITLES_SET or k in seen:
            continue
        seen.add(k)
        extras.append(x.strip())
    extras = sorted(extras, key=lambda s: s.casefold())

    out: List[Dict[str, Any]] = []
    for g, items in base_groups:
        out.append({"group": g, "items": [str(i).strip() for i in items if str(i).strip()]})
    if extras:
        out.append({"group": "Ostalo", "items": extras})
    return out


def list_titles() -> List[str]:
    groups = list_title_groups()
    out: List[str] = []
    seen: set = set()
    for g in groups:
        items = g.get("items") or []
        if not isinstance(items, list):
            continue
        for x in items:
            t = str(x or "").strip()
            if not t:
                continue
            k = t.lower()
            if k in seen:
                continue
            seen.add(k)
            out.append(t)
    return out


# -------------------- roles helpers --------------------


def _roles_from_csv(s: str) -> List[str]:
    out: List[str] = []
    for p in (s or "").split(","):
        t = p.strip()
        if t:
            out.append(_canon_role_value(t))
    return _normalize_roles_list(out)


def _get_user_id_sector_role(conn: sqlite3.Connection, username_norm: str) -> Tuple[int, str, str]:
    r = conn.execute(
        "SELECT id, sector, role FROM users WHERE username=? LIMIT 1;",
        (username_norm,),
    ).fetchone()
    if not r:
        return 0, "", ""
    try:
        uid = int(r[0] or 0)
    except Exception:
        uid = 0
    return uid, str(r[1] or "").strip(), _canon_role_value(r[2] or "")


def _list_roles_for_user_id(conn: sqlite3.Connection, user_id: int) -> List[str]:
    if user_id <= 0 or (not _table_exists(conn, "user_roles")):
        return []
    try:
        rows = conn.execute(
            "SELECT role FROM user_roles WHERE user_id=? AND is_active=1 ORDER BY role COLLATE NOCASE;",
            (int(user_id),),
        ).fetchall()
        return _normalize_roles_list([str(x[0] or "") for x in rows])
    except Exception:
        return []


def _ensure_role_active(conn: sqlite3.Connection, user_id: int, role: str, created_by: str = "") -> None:
    if user_id <= 0 or (not _table_exists(conn, "user_roles")):
        return
    rl = _canon_role_value(role)
    if not rl:
        return
    conn.execute(
        """
        INSERT OR IGNORE INTO user_roles(user_id, role, is_active, created_at, created_by)
        VALUES(?,?,?,?,?);
        """,
        (int(user_id), rl, 1, _now(), (created_by or "").strip()),
    )
    conn.execute(
        "UPDATE user_roles SET is_active=1 WHERE user_id=? AND role=?;",
        (int(user_id), rl),
    )


def _target_has_admin_role(conn: sqlite3.Connection, user_id: int, primary_role: str = "") -> bool:
    pr = _canon_role_value(primary_role)
    if pr == ROLE_ADMIN:
        return True
    roles = _list_roles_for_user_id(conn, user_id)
    return ROLE_ADMIN in [r.strip().upper() for r in roles if r.strip()]


def _forbid_sector_admin_touching_admin(
    conn: sqlite3.Connection, user_id: int, primary_role: str, *, action: str
) -> None:
    if not _is_sector_admin():
        return
    if _target_has_admin_role(conn, user_id, primary_role=primary_role):
        raise PermissionError(f"Role-scope: SECTOR_ADMIN ne može menjati ADMIN korisnika ({action}).")


def _is_prelogin() -> bool:
    return not _is_logged_in()

# (FILENAME: services/users_service.py - END / PART 2 of 3)


# FILENAME: services/users_service.py
# (FILENAME: services/users_service.py - START / PART 3 of 3)

# -------------------- list/get users --------------------


def list_users(active_only: bool = True, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    UI koristi i pre login-a (LoginDialog).
    Pre-login vraćamo MINIMALNI profil (bez PII: email/phone/jmbg/employee_no/note...).
    """
    _must(PERM_USERS_VIEW, allow_prelogin=True)
    ensure_users_schema()

    lim: Optional[int] = None
    if limit is not None:
        try:
            lim = int(limit)
            if lim <= 0:
                lim = None
        except Exception:
            lim = None

    where_parts: List[str] = []
    args: List[Any] = []

    if active_only:
        where_parts.append("u.is_active=1")

    # SECTOR_ADMIN scope (samo ako je ulogovan)
    if _is_logged_in() and _is_sector_admin():
        my_sec = _current_sector().strip()
        if my_sec:
            where_parts.append("COALESCE(u.sector,'') = ?")
            args.append(my_sec)

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    prelogin = _is_prelogin()
    sector_locked = bool(_is_logged_in() and _is_sector_admin())

    if prelogin:
        q = (
            """
            SELECT
                u.id, u.username, u.display_name, u.role,
                u.sector, u.location,
                COALESCE(u.must_change_creds,0) AS must_change_creds,
                u.iters, u.is_active, u.created_at, u.updated_at,
                CASE WHEN TRIM(COALESCE(u.pin_hash,'')) <> '' THEN 1 ELSE 0 END AS has_pin,
                CASE WHEN TRIM(COALESCE(u.pass_hash,'')) <> '' THEN 1 ELSE 0 END AS has_password
            FROM users u
            """
            + where_sql
            + """
            ORDER BY u.display_name COLLATE NOCASE
            """
        )
        if lim is not None:
            q += " LIMIT ?"
            args.append(lim)
        q += ";"

        with _connect_db() as conn:
            rows = conn.execute(q, tuple(args)).fetchall()

        out: List[Dict[str, Any]] = []
        for r in rows:
            uid = int(r[0] or 0)
            username = (r[1] or "").strip()
            display = (r[2] or "").strip() or username
            role_primary = _canon_role_value(r[3] or "")

            must_change_creds = 1 if int(r[6] or 0) != 0 else 0
            has_pin = bool(int(r[11] or 0))
            has_password = bool(int(r[12] or 0))

            out.append(
                {
                    "id": uid,
                    "user_id": uid,
                    "username": username,
                    "user": username,
                    "name": username,
                    "display_name": display,
                    "last_name": "",
                    "father_name": "",
                    "first_name": "",
                    "jmbg": "",
                    "primary_role": role_primary,
                    "role": role_primary,
                    "user_role": role_primary,
                    "active_role": role_primary,
                    "roles": [role_primary] if role_primary else ["READONLY"],
                    "sector": (r[4] or "").strip(),
                    "org_unit": (r[4] or "").strip(),
                    "location": (r[5] or "").strip(),
                    # PII blank pre-login
                    "email": "",
                    "phone": "",
                    "employee_no": "",
                    "title": "",
                    "note": "",
                    "created_by": "",
                    "updated_by": "",
                    "must_change_creds": int(must_change_creds),
                    "iters": int(r[7] or PBKDF2_ITER),
                    "is_active": int(r[8] or 0),
                    "created_at": r[9] or "",
                    "updated_at": r[10] or "",
                    "has_pin": bool(has_pin),
                    "has_password": bool(has_password),
                    "sector_locked": False,
                    # secrets always blank
                    "pin_salt": "",
                    "pin_hash": "",
                    "pass_salt": "",
                    "pass_hash": "",
                }
            )
        return out

    # Authenticated: full listing (ali i dalje bez salt/hash)
    q_join = (
        """
        SELECT
            u.id, u.username, u.display_name, u.role,
            u.last_name, u.father_name, u.first_name, u.jmbg,
            u.sector, u.location,
            u.email, u.phone, u.employee_no, u.title, u.note,
            u.created_by, u.updated_by,
            COALESCE(u.must_change_creds,0) AS must_change_creds,
            u.iters, u.is_active, u.created_at, u.updated_at,
            CASE WHEN TRIM(COALESCE(u.pin_hash,'')) <> '' THEN 1 ELSE 0 END AS has_pin,
            CASE WHEN TRIM(COALESCE(u.pass_hash,'')) <> '' THEN 1 ELSE 0 END AS has_password,
            COALESCE(GROUP_CONCAT(CASE WHEN ur.is_active=1 THEN ur.role END, ','), '') AS roles_csv
        FROM users u
        LEFT JOIN user_roles ur ON ur.user_id = u.id
        """
        + where_sql
        + """
        GROUP BY u.id
        ORDER BY u.display_name COLLATE NOCASE
        """
    )
    if lim is not None:
        q_join += " LIMIT ?"
        args.append(lim)
    q_join += ";"

    rows2: List[Tuple[Any, ...]] = []
    with _connect_db() as conn:
        try:
            rows2 = conn.execute(q_join, tuple(args)).fetchall()
        except sqlite3.OperationalError:
            # ultra-safe fallback (ako user_roles nije dostupna iz bilo kog razloga)
            q_simple = (
                """
                SELECT
                    u.id, u.username, u.display_name, u.role,
                    u.last_name, u.father_name, u.first_name, u.jmbg,
                    u.sector, u.location,
                    u.email, u.phone, u.employee_no, u.title, u.note,
                    u.created_by, u.updated_by,
                    COALESCE(u.must_change_creds,0) AS must_change_creds,
                    u.iters, u.is_active, u.created_at, u.updated_at,
                    CASE WHEN TRIM(COALESCE(u.pin_hash,'')) <> '' THEN 1 ELSE 0 END AS has_pin,
                    CASE WHEN TRIM(COALESCE(u.pass_hash,'')) <> '' THEN 1 ELSE 0 END AS has_password
                FROM users u
                """
                + where_sql
                + """
                ORDER BY u.display_name COLLATE NOCASE
                """
            )
            args2 = list(args)
            if lim is not None:
                q_simple += " LIMIT ?"
                args2.append(lim)
            q_simple += ";"
            rows2 = conn.execute(q_simple, tuple(args2)).fetchall()

    out2: List[Dict[str, Any]] = []
    for r in rows2:
        uid = int(r[0] or 0)
        username = (r[1] or "").strip()
        display = (r[2] or "").strip() or username
        role_primary = _canon_role_value(r[3] or "")

        last_name = (r[4] or "").strip()
        father_name = (r[5] or "").strip()
        first_name = (r[6] or "").strip()
        jmbg = (r[7] or "").strip()

        sector = (r[8] or "").strip()
        location = (r[9] or "").strip()

        must_change_creds = 1 if int(r[17] or 0) != 0 else 0
        has_pin = bool(int(r[22] or 0))
        has_password = bool(int(r[23] or 0))

        roles: List[str] = []
        if len(r) >= 25:
            roles = _roles_from_csv(str(r[24] or ""))
        if not roles and role_primary:
            roles = [role_primary]

        out2.append(
            {
                "id": uid,
                "user_id": uid,
                "username": username,
                "user": username,
                "name": username,
                "display_name": display,
                "last_name": last_name,
                "father_name": father_name,
                "first_name": first_name,
                "jmbg": jmbg,
                "primary_role": role_primary,
                "role": role_primary,
                "user_role": role_primary,
                "active_role": role_primary,
                "roles": roles,
                "sector": sector,
                "org_unit": sector,
                "location": location,
                "email": (r[10] or "").strip(),
                "phone": (r[11] or "").strip(),
                "employee_no": (r[12] or "").strip(),
                "title": (r[13] or "").strip(),
                "note": (r[14] or "").strip(),
                "created_by": (r[15] or "").strip(),
                "updated_by": (r[16] or "").strip(),
                "must_change_creds": int(must_change_creds),
                "iters": int(r[18] or PBKDF2_ITER),
                "is_active": int(r[19] or 0),
                "created_at": r[20] or "",
                "updated_at": r[21] or "",
                "has_pin": bool(has_pin),
                "has_password": bool(has_password),
                "sector_locked": bool(sector_locked),
                # secrets always blank
                "pin_salt": "",
                "pin_hash": "",
                "pass_salt": "",
                "pass_hash": "",
            }
        )
    return out2


def get_user_by_username(
    username: Union[str, Dict[str, Any], None],
    *,
    include_secrets: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Vraća detalje korisnika.

    SECURITY:
    - default include_secrets=False (UI ne treba salt/hash)
    - pre-login vraća MINIMALNO (bez PII) čak i ako UI pozove.
    - include_secrets=True je dozvoljen samo ulogovanom korisniku sa USERS.MANAGE (fail-closed).
    """
    _must(PERM_USERS_VIEW, allow_prelogin=True)
    ensure_users_schema()

    un = _norm_username(username)
    if not un:
        return None

    prelogin = _is_prelogin()
    sector_locked = bool(_is_logged_in() and _is_sector_admin())

    # hardening: secrets samo za MANAGE i samo post-login
    if include_secrets and (prelogin or (not _safe_can(PERM_USERS_MANAGE))):
        include_secrets = False

    with _connect_db() as conn:
        uid, sec, role_primary = _get_user_id_sector_role(conn, un)
        if uid <= 0:
            return None

        if _is_logged_in() and _is_sector_admin():
            _enforce_sector_scope(sec, action="get_user_by_username")

        if prelogin:
            r = conn.execute(
                """
                SELECT
                    id, username, display_name, role,
                    sector, location,
                    must_change_creds,
                    iters, is_active, created_at, updated_at,
                    CASE WHEN TRIM(COALESCE(pin_hash,'')) <> '' THEN 1 ELSE 0 END AS has_pin,
                    CASE WHEN TRIM(COALESCE(pass_hash,'')) <> '' THEN 1 ELSE 0 END AS has_password
                FROM users
                WHERE id=? LIMIT 1;
                """,
                (int(uid),),
            ).fetchone()
            if not r:
                return None

            must_change_creds = 1 if int(r[6] or 0) != 0 else 0
            has_pin = bool(int(r[11] or 0))
            has_password = bool(int(r[12] or 0))

            primary = _canon_role_value(r[3] or "")
            roles = [primary] if primary else ["READONLY"]

            return {
                "id": int(r[0]),
                "user_id": int(r[0]),
                "username": (r[1] or "").strip(),
                "user": (r[1] or "").strip(),
                "display_name": (r[2] or "").strip() or (r[1] or "").strip(),
                "last_name": "",
                "father_name": "",
                "first_name": "",
                "jmbg": "",
                "primary_role": primary,
                "role": primary,
                "user_role": primary,
                "active_role": primary,
                "roles": roles,
                "sector": (r[4] or "").strip(),
                "org_unit": (r[4] or "").strip(),
                "location": (r[5] or "").strip(),
                "email": "",
                "phone": "",
                "employee_no": "",
                "title": "",
                "note": "",
                "created_by": "",
                "updated_by": "",
                "must_change_creds": int(must_change_creds),
                "iters": int(r[7] or PBKDF2_ITER),
                "is_active": int(r[8] or 0),
                "created_at": r[9] or "",
                "updated_at": r[10] or "",
                "has_pin": bool(has_pin),
                "has_password": bool(has_password),
                "sector_locked": False,
                "pin_salt": "",
                "pin_hash": "",
                "pass_salt": "",
                "pass_hash": "",
            }

        if include_secrets:
            r = conn.execute(
                """
                SELECT
                    id, username, display_name, role,
                    last_name, father_name, first_name, jmbg,
                    sector, location,
                    email, phone, employee_no, title, note,
                    created_by, updated_by,
                    must_change_creds,
                    iters, is_active, created_at, updated_at,
                    COALESCE(pin_salt,''), COALESCE(pin_hash,''),
                    COALESCE(pass_salt,''), COALESCE(pass_hash,'')
                FROM users
                WHERE id=? LIMIT 1;
                """,
                (int(uid),),
            ).fetchone()
        else:
            r = conn.execute(
                """
                SELECT
                    id, username, display_name, role,
                    last_name, father_name, first_name, jmbg,
                    sector, location,
                    email, phone, employee_no, title, note,
                    created_by, updated_by,
                    must_change_creds,
                    iters, is_active, created_at, updated_at,
                    CASE WHEN TRIM(COALESCE(pin_hash,'')) <> '' THEN 1 ELSE 0 END AS has_pin,
                    CASE WHEN TRIM(COALESCE(pass_hash,'')) <> '' THEN 1 ELSE 0 END AS has_password
                FROM users
                WHERE id=? LIMIT 1;
                """,
                (int(uid),),
            ).fetchone()

        if not r:
            return None

        roles = _list_roles_for_user_id(conn, uid)
        if not roles and role_primary:
            roles = [role_primary]

        if include_secrets:
            pin_salt = str(r[22] or "")
            pin_hash = str(r[23] or "")
            pass_salt = str(r[24] or "")
            pass_hash = str(r[25] or "")
            has_pin = bool(pin_hash.strip())
            has_password = bool(pass_hash.strip())
        else:
            pin_salt = ""
            pin_hash = ""
            pass_salt = ""
            pass_hash = ""
            has_pin = bool(int(r[22] or 0))
            has_password = bool(int(r[23] or 0))

        must_change_creds = 1 if int(r[17] or 0) != 0 else 0

        return {
            "id": int(r[0]),
            "user_id": int(r[0]),
            "username": (r[1] or "").strip(),
            "user": (r[1] or "").strip(),
            "display_name": (r[2] or "").strip(),
            "last_name": (r[4] or "").strip(),
            "father_name": (r[5] or "").strip(),
            "first_name": (r[6] or "").strip(),
            "jmbg": (r[7] or "").strip(),
            "primary_role": _canon_role_value(r[3] or ""),
            "role": _canon_role_value(r[3] or ""),
            "user_role": _canon_role_value(r[3] or ""),
            "active_role": _canon_role_value(r[3] or ""),
            "roles": [x.strip().upper() for x in roles if x.strip()],
            "sector": (r[8] or "").strip(),
            "org_unit": (r[8] or "").strip(),
            "location": (r[9] or "").strip(),
            "email": (r[10] or "").strip(),
            "phone": (r[11] or "").strip(),
            "employee_no": (r[12] or "").strip(),
            "title": (r[13] or "").strip(),
            "note": (r[14] or "").strip(),
            "created_by": (r[15] or "").strip(),
            "updated_by": (r[16] or "").strip(),
            "must_change_creds": int(must_change_creds),
            "iters": int(r[18] or PBKDF2_ITER),
            "is_active": int(r[19] or 0),
            "created_at": r[20] or "",
            "updated_at": r[21] or "",
            "has_pin": bool(has_pin),
            "has_password": bool(has_password),
            "sector_locked": bool(sector_locked),
            "pin_salt": pin_salt if include_secrets else "",
            "pin_hash": pin_hash if include_secrets else "",
            "pass_salt": pass_salt if include_secrets else "",
            "pass_hash": pass_hash if include_secrets else "",
        }


def list_user_roles(username_or_user: Union[str, Dict[str, Any], None]) -> List[str]:
    _must(PERM_USERS_VIEW, allow_prelogin=True)
    ensure_users_schema()

    un = _norm_username(username_or_user)
    if not un:
        return []

    prelogin = _is_prelogin()
    with _connect_db() as conn:
        uid, sec, role_primary = _get_user_id_sector_role(conn, un)
        if uid <= 0:
            return []

        if _is_logged_in() and _is_sector_admin():
            _enforce_sector_scope(sec, action="list_user_roles")

        if prelogin:
            return [role_primary] if role_primary else ["READONLY"]

        roles = _list_roles_for_user_id(conn, uid)
        if not roles and role_primary:
            roles = [role_primary]
        return _normalize_roles_list(roles)


def set_user_roles(
    username_or_user: Union[str, Dict[str, Any], None],
    roles: List[str],
    *,
    replace: bool = True,
    primary_role: Optional[str] = None,
) -> bool:
    _must(PERM_USERS_MANAGE)
    ensure_users_schema()

    un = _norm_username(username_or_user)
    if not un:
        return False

    ded = _normalize_roles_list(roles or [])
    if not ded:
        raise ValueError("roles je prazno (mora bar 1 rola).")

    prim = _canon_role_value(primary_role) if primary_role else ""
    if prim and prim not in ded:
        ded.insert(0, prim)
    prim = prim or ded[0] or "READONLY"

    _enforce_role_assignment_rules(ded + [prim], action="set_user_roles")
    actor = _actor_username()

    with _connect_db() as conn:
        uid, sec, role_existing = _get_user_id_sector_role(conn, un)
        if uid <= 0:
            return False

        if _is_sector_admin():
            _enforce_sector_scope(sec, action="set_user_roles")
            _forbid_sector_admin_touching_admin(conn, uid, role_existing, action="set_user_roles")

        if replace:
            conn.execute("UPDATE user_roles SET is_active=0 WHERE user_id=?;", (int(uid),))

        for r in ded:
            _ensure_role_active(conn, uid, r, created_by=(actor or "set_user_roles"))

        conn.execute(
            "UPDATE users SET role=?, updated_at=?, updated_by=? WHERE id=?;",
            (prim, _now(), actor, int(uid)),
        )
    return True


# -------------------- users by sector (single API, no duplicates) --------------------


def list_users_for_sector(
    sector: str = "",
    *,
    active_only: bool = True,
    limit: Optional[int] = None,
    payload: str = "full",
) -> List[Dict[str, Any]]:
    """
    Jedna funkcija, bez duplih definicija.

    payload:
    - "picklist": minimalno za combobox (id/username/display_name/sector)
    - "full": puni format (bez salt/hash), filtriran po sektoru

    Pravila:
    - ADMIN: može bilo koji sektor (ili "" = svi)
    - SECTOR_ADMIN: uvek samo svoj sektor (ignoriše prosleđen sector)
    - Ostali: fail-closed: samo svoj sektor (ako nije definisan -> error)
    """
    _must(PERM_USERS_VIEW)
    ensure_users_schema()

    role = (_current_role() or "").strip().upper()
    my_sec = (_current_sector() or "").strip()
    req = _norm_sector(sector).strip()
    tsec = req

    if role == ROLE_ADMIN:
        pass
    elif role == ROLE_SECTOR_ADMIN:
        if not my_sec:
            raise PermissionError("Sektor-scope: SECTOR_ADMIN nema definisan sektor u sesiji.")
        tsec = my_sec
    else:
        if not my_sec:
            raise PermissionError("Sektor-scope: nema definisan sektor u sesiji.")
        tsec = my_sec

    lim: Optional[int] = None
    if limit is not None:
        try:
            lim = int(limit)
            if lim <= 0:
                lim = None
        except Exception:
            lim = None

    want_pick = str(payload or "").strip().lower() in ("pick", "picker", "picklist", "mini", "light")

    # ADMIN + no sector -> global listing
    if role == ROLE_ADMIN and (not tsec):
        if want_pick:
            users = list_users(active_only=active_only, limit=lim)
            return [
                {
                    "id": int(u.get("id") or u.get("user_id") or 0),
                    "user_id": int(u.get("id") or u.get("user_id") or 0),
                    "username": str(u.get("username") or "").strip(),
                    "display_name": str(u.get("display_name") or u.get("username") or "").strip(),
                    "sector": str(u.get("sector") or "").strip(),
                }
                for u in users
                if str(u.get("username") or "").strip()
            ]
        return list_users(active_only=active_only, limit=lim)

    where_parts: List[str] = ["1=1"]
    args: List[Any] = []
    if active_only:
        where_parts.append("u.is_active=1")
    where_parts.append("COALESCE(u.sector,'') = ?")
    args.append(tsec)

    where_sql = " WHERE " + " AND ".join(where_parts)

    if want_pick:
        q = (
            """
            SELECT u.id, u.username, u.display_name, u.sector
            FROM users u
            """
            + where_sql
            + """
            ORDER BY u.display_name COLLATE NOCASE
            """
        )
        if lim is not None:
            q += " LIMIT ?"
            args.append(lim)
        q += ";"

        with _connect_db() as conn:
            rows = conn.execute(q, tuple(args)).fetchall()

        outp: List[Dict[str, Any]] = []
        for r in rows:
            uid = int(r[0] or 0)
            username = str(r[1] or "").strip()
            if uid <= 0 or not username:
                continue
            display = str(r[2] or "").strip() or username
            sec = str(r[3] or "").strip()
            outp.append({"id": uid, "user_id": uid, "username": username, "display_name": display, "sector": sec})
        return outp

    # full (no secrets)
    q = (
        """
        SELECT
            u.id, u.username, u.display_name, u.role,
            u.last_name, u.father_name, u.first_name, u.jmbg,
            u.sector, u.location,
            u.email, u.phone, u.employee_no, u.title, u.note,
            u.created_by, u.updated_by,
            COALESCE(u.must_change_creds,0) AS must_change_creds,
            u.iters, u.is_active, u.created_at, u.updated_at,
            CASE WHEN TRIM(COALESCE(u.pin_hash,'')) <> '' THEN 1 ELSE 0 END AS has_pin,
            CASE WHEN TRIM(COALESCE(u.pass_hash,'')) <> '' THEN 1 ELSE 0 END AS has_password,
            COALESCE(GROUP_CONCAT(CASE WHEN ur.is_active=1 THEN ur.role END, ','), '') AS roles_csv
        FROM users u
        LEFT JOIN user_roles ur ON ur.user_id = u.id
        """
        + where_sql
        + """
        GROUP BY u.id
        ORDER BY u.display_name COLLATE NOCASE
        """
    )
    if lim is not None:
        q += " LIMIT ?"
        args.append(lim)
    q += ";"

    with _connect_db() as conn:
        rows = conn.execute(q, tuple(args)).fetchall()

    outf: List[Dict[str, Any]] = []
    for r in rows:
        uid = int(r[0] or 0)
        username = (r[1] or "").strip()
        display = (r[2] or "").strip() or username
        role_primary = _canon_role_value(r[3] or "")

        must_change_creds = 1 if int(r[17] or 0) != 0 else 0
        has_pin = bool(int(r[22] or 0))
        has_password = bool(int(r[23] or 0))
        roles = _roles_from_csv(str(r[24] or ""))
        if not roles and role_primary:
            roles = [role_primary]

        outf.append(
            {
                "id": uid,
                "user_id": uid,
                "username": username,
                "user": username,
                "name": username,
                "display_name": display,
                "last_name": (r[4] or "").strip(),
                "father_name": (r[5] or "").strip(),
                "first_name": (r[6] or "").strip(),
                "jmbg": (r[7] or "").strip(),
                "primary_role": role_primary,
                "role": role_primary,
                "user_role": role_primary,
                "active_role": role_primary,
                "roles": roles,
                "sector": (r[8] or "").strip(),
                "org_unit": (r[8] or "").strip(),
                "location": (r[9] or "").strip(),
                "email": (r[10] or "").strip(),
                "phone": (r[11] or "").strip(),
                "employee_no": (r[12] or "").strip(),
                "title": (r[13] or "").strip(),
                "note": (r[14] or "").strip(),
                "created_by": (r[15] or "").strip(),
                "updated_by": (r[16] or "").strip(),
                "must_change_creds": int(must_change_creds),
                "iters": int(r[18] or PBKDF2_ITER),
                "is_active": int(r[19] or 0),
                "created_at": r[20] or "",
                "updated_at": r[21] or "",
                "has_pin": bool(has_pin),
                "has_password": bool(has_password),
                "pin_salt": "",
                "pin_hash": "",
                "pass_salt": "",
                "pass_hash": "",
            }
        )
    return outf


def list_users_picklist_for_sector(
    sector: str = "",
    *,
    active_only: bool = True,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Minimalan format za combobox/picker."""
    return list_users_for_sector(sector, active_only=active_only, limit=limit, payload="picklist")


# -------------------- CRUD --------------------


def create_user(
    username: str,
    display_name: str,
    role: str,
    pin: Optional[str] = None,
    password: Optional[str] = None,
    sector: str = "",
    *,
    location: str = "",
    email: str = "",
    phone: str = "",
    employee_no: str = "",
    title: str = "",
    note: str = "",
    last_name: str = "",
    father_name: str = "",
    first_name: str = "",
    jmbg: str = "",
) -> int:
    """
    Pravila sektora:
    - SECTOR_ADMIN: sektor se automatski upisuje iz sesije i “zakucan” je (ignoriše ulaz).
    - ADMIN: može izabrati sektor (ili ostaviti prazno ako baš želi).
    """
    _must(PERM_USERS_MANAGE)
    ensure_users_schema()

    un = _norm_username(username)
    if not un:
        raise ValueError("username je obavezan")

    ln = _norm_text(last_name, 80)
    fn = _norm_text(first_name, 80)
    dn_in = (display_name or "").strip()
    if not dn_in:
        dn_in = f"{ln} {fn}".strip() if (ln and fn) else un
    dn = _norm_text(dn_in, 120)

    rl = _canon_role_value(role or "READONLY")
    _enforce_role_assignment_rules([rl], action="create_user")

    sec = _norm_sector(sector)
    if _is_sector_admin():
        my_sec = _current_sector().strip()
        if not my_sec:
            raise PermissionError("Sektor-scope: SECTOR_ADMIN nema definisan sektor u sesiji (create_user).")
        sec = _norm_sector(my_sec)
        _enforce_sector_scope(sec, action="create_user")
    else:
        if _is_logged_in() and (not _is_admin()) and (not sec.strip()):
            my_sec = _current_sector().strip()
            if my_sec:
                sec = _norm_sector(my_sec)

    loc = _norm_location(location)

    jj = _norm_text(jmbg, 13)
    if jj and (not re.fullmatch(r"\d{13}", jj)):
        raise ValueError("JMBG mora imati tačno 13 cifara.")

    iters = PBKDF2_ITER
    pin_salt = pin_hash = ""
    pass_salt = pass_hash = ""

    if pin:
        msg = validate_pin(pin)
        if msg:
            raise ValueError(msg)
        pin_salt = _new_salt_hex()
        pin_hash = _pbkdf2_hash(pin, pin_salt, iters)

    if password:
        msg = validate_password(password)
        if msg:
            raise ValueError(msg)
        pass_salt = _new_salt_hex()
        pass_hash = _pbkdf2_hash(password, pass_salt, iters)

    actor = _actor_username()

    must_change = 0
    if (pin or password) and actor and (_norm_username(actor) != _norm_username(un)):
        must_change = 1

    try:
        with _connect_db() as conn:
            conn.execute(
                """
                INSERT INTO users(
                    username, display_name, role,
                    last_name, father_name, first_name, jmbg,
                    sector, location,
                    email, phone, employee_no, title, note,
                    created_by, updated_by,
                    pin_salt, pin_hash, pass_salt, pass_hash,
                    must_change_creds,
                    iters, is_active, created_at, updated_at
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
                """,
                (
                    un,
                    dn,
                    rl,
                    _norm_text(last_name, 80),
                    _norm_text(father_name, 80),
                    _norm_text(first_name, 80),
                    jj,
                    sec,
                    loc,
                    _norm_text(email, 160),
                    _norm_text(phone, 80),
                    _norm_text(employee_no, 80),
                    _norm_text(title, 120),
                    _norm_text(note, 500),
                    actor,
                    actor,
                    pin_salt,
                    pin_hash,
                    pass_salt,
                    pass_hash,
                    int(must_change),
                    int(iters),
                    1,
                    _now(),
                    _now(),
                ),
            )
            rid = conn.execute("SELECT last_insert_rowid();").fetchone()[0]
            uid = int(rid)
            _ensure_role_active(conn, uid, rl, created_by=(actor or "create_user"))
            return uid
    except sqlite3.IntegrityError:
        raise ValueError("Korisnik sa tim username već postoji.") from None


def update_user_profile(
    username: Union[str, Dict[str, Any], None],
    display_name: str,
    role: str,
    is_active: Optional[bool] = None,
    sector: Optional[str] = None,
    *,
    location: Optional[str] = None,
    email: Optional[str] = None,
    phone: Optional[str] = None,
    employee_no: Optional[str] = None,
    title: Optional[str] = None,
    note: Optional[str] = None,
    last_name: Optional[str] = None,
    father_name: Optional[str] = None,
    first_name: Optional[str] = None,
    jmbg: Optional[str] = None,
) -> bool:
    """
    None => ne menjaj, "" => upiši prazno.
    SECTOR_ADMIN: sektor je zakucan i ne može se menjati.
    """
    _must(PERM_USERS_MANAGE)
    ensure_users_schema()

    un = _norm_username(username)
    if not un:
        return False

    actor = _actor_username()

    with _connect_db() as conn:
        uid, sec_existing, role_existing = _get_user_id_sector_role(conn, un)
        if uid <= 0:
            return False

        if _is_sector_admin():
            _enforce_sector_scope(sec_existing, action="update_user_profile")
            _forbid_sector_admin_touching_admin(conn, uid, role_existing, action="update_user_profile")

        dn = _norm_text((display_name or "").strip() or un, 120)
        rl = _canon_role_value(role) or role_existing or "READONLY"
        _enforce_role_assignment_rules([rl], action="update_user_profile(role)")

        if is_active is None:
            rr = conn.execute("SELECT is_active FROM users WHERE id=? LIMIT 1;", (int(uid),)).fetchone()
            ia = int(rr[0] if rr else 1)
        else:
            ia = 1 if is_active else 0

        sec_to_set: Optional[str] = None
        if sector is not None:
            sec_norm = _norm_sector(sector)

            if _is_sector_admin():
                if sec_norm.strip() != (sec_existing or "").strip():
                    raise PermissionError("Sektor-scope: SECTOR_ADMIN ne može menjati sektor korisniku.")
                sec_to_set = None
            else:
                if not _is_admin():
                    if sec_norm.strip() != (sec_existing or "").strip():
                        raise PermissionError("Sektor-scope: nije dozvoljeno menjati sektor (samo ADMIN).")
                    sec_to_set = None
                else:
                    sec_to_set = sec_norm

        sets: List[str] = ["display_name=?", "role=?", "is_active=?", "updated_at=?", "updated_by=?"]
        vals: List[Any] = [dn, rl, int(ia), _now(), actor]

        if sec_to_set is not None:
            sets.append("sector=?")
            vals.append(sec_to_set)
        if location is not None:
            sets.append("location=?")
            vals.append(_norm_location(location))

        if email is not None:
            sets.append("email=?")
            vals.append(_norm_text(email, 160))
        if phone is not None:
            sets.append("phone=?")
            vals.append(_norm_text(phone, 80))
        if employee_no is not None:
            sets.append("employee_no=?")
            vals.append(_norm_text(employee_no, 80))
        if title is not None:
            sets.append("title=?")
            vals.append(_norm_text(title, 120))
        if note is not None:
            sets.append("note=?")
            vals.append(_norm_text(note, 500))

        if last_name is not None:
            sets.append("last_name=?")
            vals.append(_norm_text(last_name, 80))
        if father_name is not None:
            sets.append("father_name=?")
            vals.append(_norm_text(father_name, 80))
        if first_name is not None:
            sets.append("first_name=?")
            vals.append(_norm_text(first_name, 80))
        if jmbg is not None:
            jj = _norm_text(jmbg, 13)
            if jj and (not re.fullmatch(r"\d{13}", jj)):
                raise ValueError("JMBG mora imati tačno 13 cifara.")
            sets.append("jmbg=?")
            vals.append(jj)

        vals.append(int(uid))
        conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?;", tuple(vals))
        _ensure_role_active(conn, uid, rl, created_by=(actor or "update_user_profile"))

    return True


# -------------------- pin/password (ADMIN / USERS.MANAGE) --------------------


def set_user_pin(username: Union[str, Dict[str, Any], None], new_pin: Optional[str]) -> bool:
    """
    Admin/sector admin setuje ili briše PIN.

    UX/SAFETY:
    - new_pin == "" (ili whitespace) -> NO-OP (ne menjaj ništa)
    - brisanje je eksplicitno: clear_user_pin() / set_user_pin(..., None)

    Guard: ako user već ima kredencijal -> ne sme da ostane bez oba.
    HARDENING: kad admin postavi PIN drugom korisniku -> must_change_creds=1
    """
    _must(PERM_USERS_MANAGE)
    ensure_users_schema()

    un = _norm_username(username)
    if not un:
        return False

    if new_pin is not None and (not str(new_pin).strip()):
        return True  # NO-OP

    actor = _actor_username()

    with _connect_db() as conn:
        uid, sec, role_existing = _get_user_id_sector_role(conn, un)
        if uid <= 0:
            return False

        if _is_sector_admin():
            _enforce_sector_scope(sec, action="set_user_pin")
            _forbid_sector_admin_touching_admin(conn, uid, role_existing, action="set_user_pin")

        before_has_pin, before_has_pw = _get_user_cred_state(conn, uid)

        r = conn.execute("SELECT iters FROM users WHERE id=? LIMIT 1;", (int(uid),)).fetchone()
        iters = int((r[0] if r else PBKDF2_ITER) or PBKDF2_ITER)

        pin_salt = ""
        pin_hash = ""
        if new_pin is not None:
            msg = validate_pin(str(new_pin))
            if msg:
                raise ValueError(msg)
            pin_salt = _new_salt_hex()
            pin_hash = _pbkdf2_hash(str(new_pin), pin_salt, iters)

        after_has_pin = bool(pin_hash)
        after_has_pw = before_has_pw
        _enforce_not_both_removed(before_has_pin, before_has_pw, after_has_pin, after_has_pw, action="set_user_pin")

        must_change = 0
        if new_pin is not None and actor and (_norm_username(actor) != _norm_username(un)):
            must_change = 1

        conn.execute(
            """
            UPDATE users
               SET pin_salt=?,
                   pin_hash=?,
                   must_change_creds=CASE WHEN ?=1 THEN 1 ELSE must_change_creds END,
                   updated_at=?,
                   updated_by=?
             WHERE id=?;
            """,
            (pin_salt, pin_hash, int(must_change), _now(), actor, int(uid)),
        )
    return True


def clear_user_pin(username: Union[str, Dict[str, Any], None]) -> bool:
    return set_user_pin(username, None)


def set_user_password(username: Union[str, Dict[str, Any], None], new_password: Optional[str]) -> bool:
    """
    Admin/sector admin setuje ili briše lozinku.

    UX/SAFETY:
    - new_password == "" (ili whitespace) -> NO-OP (ne menjaj ništa)
    - brisanje je eksplicitno: clear_user_password() / set_user_password(..., None)

    Guard: ako user već ima kredencijal -> ne sme da ostane bez oba.
    HARDENING: kad admin postavi lozinku drugom korisniku -> must_change_creds=1
    """
    _must(PERM_USERS_MANAGE)
    ensure_users_schema()

    un = _norm_username(username)
    if not un:
        return False

    if new_password is not None and (not str(new_password).strip()):
        return True  # NO-OP

    actor = _actor_username()

    with _connect_db() as conn:
        uid, sec, role_existing = _get_user_id_sector_role(conn, un)
        if uid <= 0:
            return False

        if _is_sector_admin():
            _enforce_sector_scope(sec, action="set_user_password")
            _forbid_sector_admin_touching_admin(conn, uid, role_existing, action="set_user_password")

        before_has_pin, before_has_pw = _get_user_cred_state(conn, uid)

        r = conn.execute("SELECT iters FROM users WHERE id=? LIMIT 1;", (int(uid),)).fetchone()
        iters = int((r[0] if r else PBKDF2_ITER) or PBKDF2_ITER)

        ps = ""
        ph = ""
        if new_password is not None:
            msg = validate_password(str(new_password))
            if msg:
                raise ValueError(msg)
            ps = _new_salt_hex()
            ph = _pbkdf2_hash(str(new_password), ps, iters)

        after_has_pin = before_has_pin
        after_has_pw = bool(ph)
        _enforce_not_both_removed(
            before_has_pin, before_has_pw, after_has_pin, after_has_pw, action="set_user_password"
        )

        must_change = 0
        if new_password is not None and actor and (_norm_username(actor) != _norm_username(un)):
            must_change = 1

        conn.execute(
            """
            UPDATE users
               SET pass_salt=?,
                   pass_hash=?,
                   must_change_creds=CASE WHEN ?=1 THEN 1 ELSE must_change_creds END,
                   updated_at=?,
                   updated_by=?
             WHERE id=?;
            """,
            (ps, ph, int(must_change), _now(), actor, int(uid)),
        )
    return True


def clear_user_password(username: Union[str, Dict[str, Any], None]) -> bool:
    return set_user_password(username, None)


def admin_reset_credentials(
    username: Union[str, Dict[str, Any], None],
    *,
    set_pin: bool = True,
    set_password: bool = True,
) -> Dict[str, str]:
    """
    ADMIN / SECTOR_ADMIN: resetuje kredencijale korisniku.
    Podrazumevano dodeli OBA (PIN + lozinku) i postavi must_change_creds=1.

    Vraća: {"pin": "...", "password": "..."} (samo ono što je setovano).
    """
    _must(PERM_USERS_MANAGE)
    ensure_users_schema()

    un = _norm_username(username)
    if not un:
        raise ValueError("username je obavezan")
    if not set_pin and not set_password:
        raise ValueError("Moraš resetovati bar PIN ili lozinku.")

    actor = _actor_username()
    tmp_pin = ""
    tmp_pw = ""

    if set_pin:
        for _ in range(30):
            cand = "".join(secrets.choice("0123456789") for _ in range(6))
            if validate_pin(cand) is None:
                tmp_pin = cand
                break
        if not tmp_pin:
            tmp_pin = "739184"

    if set_password:
        alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        tmp_pw = "".join(secrets.choice(alphabet) for _ in range(10))

    out: Dict[str, str] = {}
    with _connect_db() as conn:
        uid, sec, role_existing = _get_user_id_sector_role(conn, un)
        if uid <= 0:
            raise ValueError("Korisnik ne postoji.")

        if _is_sector_admin():
            _enforce_sector_scope(sec, action="admin_reset_credentials")
            _forbid_sector_admin_touching_admin(conn, uid, role_existing, action="admin_reset_credentials")

        r = conn.execute("SELECT iters FROM users WHERE id=? LIMIT 1;", (int(uid),)).fetchone()
        iters = int((r[0] if r else PBKDF2_ITER) or PBKDF2_ITER)

        before_has_pin, before_has_pw = _get_user_cred_state(conn, uid)
        after_has_pin = before_has_pin
        after_has_pw = before_has_pw

        sets: List[str] = ["updated_at=?", "updated_by=?", "must_change_creds=1"]
        vals: List[Any] = [_now(), actor]

        if set_pin:
            msg = validate_pin(tmp_pin)
            if msg:
                raise ValueError(msg)
            pin_salt = _new_salt_hex()
            pin_hash = _pbkdf2_hash(tmp_pin, pin_salt, iters)
            after_has_pin = True
            out["pin"] = tmp_pin
            sets += ["pin_salt=?", "pin_hash=?"]
            vals += [pin_salt, pin_hash]

        if set_password:
            msg = validate_password(tmp_pw)
            if msg:
                raise ValueError(msg)
            pass_salt = _new_salt_hex()
            pass_hash = _pbkdf2_hash(tmp_pw, pass_salt, iters)
            after_has_pw = True
            out["password"] = tmp_pw
            sets += ["pass_salt=?", "pass_hash=?"]
            vals += [pass_salt, pass_hash]

        _enforce_not_both_removed(
            before_has_pin, before_has_pw, after_has_pin, after_has_pw, action="admin_reset_credentials"
        )

        vals.append(int(uid))
        conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?;", tuple(vals))

    return out


# -------------------- session helpers + login --------------------


def validate_user_role_choice(user_or_username: Union[str, Dict[str, Any], None], chosen_role: str) -> bool:
    cr = (chosen_role or "").strip().upper()
    if not cr:
        return False
    try:
        if isinstance(user_or_username, dict):
            roles = user_or_username.get("roles")
            if isinstance(roles, list) and roles:
                return cr in [str(x or "").strip().upper() for x in roles]
    except Exception:
        pass
    try:
        roles2 = list_user_roles(user_or_username)
        return cr in [str(x or "").strip().upper() for x in (roles2 or [])]
    except Exception:
        return False


def normalize_user_for_session(user: Dict[str, Any], active_role: Optional[str] = None) -> Dict[str, Any]:
    """
    Standardizuje user dict za core.session/core.rbac:
    - primary_role zasebno
    - active_role (sesijska rola)
    - 'role' mapira na active_role (kompat)
    - ne držimo salt/hash u session-u
    """
    u = dict(user or {})

    try:
        uid = int(u.get("id") or u.get("user_id") or 0)
    except Exception:
        uid = 0
    u["id"] = uid
    u["user_id"] = uid

    username = str(u.get("username") or u.get("user") or u.get("login") or u.get("name") or "").strip()
    u["username"] = username
    u["user"] = username

    u["last_name"] = str(u.get("last_name") or "").strip()
    u["father_name"] = str(u.get("father_name") or "").strip()
    u["first_name"] = str(u.get("first_name") or "").strip()
    u["jmbg"] = str(u.get("jmbg") or "").strip()

    if not str(u.get("display_name") or "").strip():
        if u["last_name"] and u["first_name"]:
            u["display_name"] = f"{u['last_name']} {u['first_name']}".strip()
        else:
            u["display_name"] = str(u.get("full_name") or u.get("display") or username or "user").strip()

    sec = str(u.get("sector") or u.get("org_unit") or "").strip()
    u["sector"] = sec
    u["org_unit"] = sec

    u["location"] = str(u.get("location") or "").strip()
    u["title"] = str(u.get("title") or "").strip()

    primary = str(u.get("primary_role") or u.get("role") or u.get("user_role") or "").strip().upper()
    if not primary:
        primary = str(u.get("active_role") or "").strip().upper()
    if not primary:
        primary = "READONLY"
    u["primary_role"] = primary

    roles_val = u.get("roles")
    roles: List[str] = []
    if isinstance(roles_val, list) and roles_val:
        roles = _normalize_roles_list([str(x or "") for x in roles_val])
    else:
        try:
            roles = list_user_roles(u)
        except Exception:
            roles = []
    if not roles:
        roles = [primary] if primary else ["READONLY"]
    u["roles"] = _normalize_roles_list(roles)

    ar = str(active_role or u.get("active_role") or "").strip().upper()
    if not ar:
        ar = primary or (u["roles"][0] if u.get("roles") else "READONLY")
    if u.get("roles") and isinstance(u["roles"], list) and ar not in u["roles"]:
        ar = u["roles"][0]
    u["active_role"] = ar or "READONLY"

    u["role"] = u["active_role"]
    u["user_role"] = u["active_role"]
    u["rbac_role"] = u["active_role"]
    u["profile"] = u["active_role"]

    u["has_pin"] = bool(u.get("has_pin"))
    u["has_password"] = bool(u.get("has_password"))
    try:
        u["must_change_creds"] = 1 if int(u.get("must_change_creds", 0) or 0) != 0 else 0
    except Exception:
        u["must_change_creds"] = 0

    u["pin_salt"] = ""
    u["pin_hash"] = ""
    u["pass_salt"] = ""
    u["pass_hash"] = ""
    return u


def _canon_login_method(method: str) -> str:
    """Vraća: 'pin' | 'password' | ''."""
    m = (method or "").strip().lower()
    if not m:
        return ""
    if m == "pin":
        return "pin"
    if m in ("password", "pass", "lozinka", "sifra", "šifra"):
        return "password"
    if "pin" in m and ("loz" in m or "pass" in m or "šifr" in m or "sifr" in m):
        return "password"
    if "pin" in m:
        return "pin"
    if "loz" in m or "pass" in m or "šifr" in m or "sifr" in m:
        return "password"
    return ""


def verify_login(username: Union[str, Dict[str, Any], None], method: str, secret: str) -> Optional[Dict[str, Any]]:
    """
    Login mora da radi pre RBAC-a, pa ovde ne radimo _must().
    HARDENING:
    - ne vraćamo salt/hash u user dict
    - compare_digest
    - fail-closed
    """
    ensure_users_schema()
    un = _norm_username(username)
    if not un:
        return None

    m = _canon_login_method(method)
    if not m:
        return None

    secret_val = secret or ""

    with _connect_db() as conn:
        r = conn.execute(
            """
            SELECT id, username, display_name, role,
                   last_name, father_name, first_name, jmbg,
                   sector, location, title,
                   must_change_creds,
                   iters, is_active,
                   COALESCE(pin_salt,''), COALESCE(pin_hash,''),
                   COALESCE(pass_salt,''), COALESCE(pass_hash,'')
            FROM users
            WHERE username=? LIMIT 1;
            """,
            (un,),
        ).fetchone()

        if not r:
            return None
        try:
            if int(r[13] or 0) != 1:
                return None
        except Exception:
            return None

        uid = int(r[0] or 0)
        uname = (r[1] or "").strip()
        display = (r[2] or "").strip()
        role_primary = (r[3] or "").strip().upper() or "READONLY"

        last_name = (r[4] or "").strip()
        father_name = (r[5] or "").strip()
        first_name = (r[6] or "").strip()
        jmbg = (r[7] or "").strip()

        sector = (r[8] or "").strip()
        location = (r[9] or "").strip()
        title = (r[10] or "").strip()

        must_change_creds = 1 if int(r[11] or 0) != 0 else 0
        iters = int(r[12] or PBKDF2_ITER)

        pin_salt = (r[14] or "").strip()
        pin_hash = (r[15] or "").strip()
        pass_salt = (r[16] or "").strip()
        pass_hash = (r[17] or "").strip()

        roles = _list_roles_for_user_id(conn, uid)
        if not roles and role_primary:
            roles = [role_primary]

    def _verify(provided: str, salt_hex: str, hash_hex: str) -> bool:
        try:
            if not salt_hex or not hash_hex:
                return False
            calc = _pbkdf2_hash(provided or "", salt_hex, iters)
            return bool(secrets.compare_digest(calc, hash_hex))
        except Exception:
            return False

    if m == "pin":
        if not _verify(secret_val, pin_salt, pin_hash):
            return None
        return normalize_user_for_session(
            {
                "id": uid,
                "user_id": uid,
                "username": uname,
                "display_name": display,
                "primary_role": role_primary,
                "active_role": role_primary,
                "roles": [x.strip().upper() for x in roles if x.strip()],
                "sector": sector,
                "org_unit": sector,
                "location": location,
                "title": title,
                "last_name": last_name,
                "father_name": father_name,
                "first_name": first_name,
                "jmbg": jmbg,
                "must_change_creds": int(must_change_creds),
                "has_pin": True,
                "has_password": bool(pass_hash),
            },
            active_role=role_primary,
        )

    if m == "password":
        if not _verify(secret_val, pass_salt, pass_hash):
            return None
        return normalize_user_for_session(
            {
                "id": uid,
                "user_id": uid,
                "username": uname,
                "display_name": display,
                "primary_role": role_primary,
                "active_role": role_primary,
                "roles": [x.strip().upper() for x in roles if x.strip()],
                "sector": sector,
                "org_unit": sector,
                "location": location,
                "title": title,
                "last_name": last_name,
                "father_name": father_name,
                "first_name": first_name,
                "jmbg": jmbg,
                "must_change_creds": int(must_change_creds),
                "has_pin": bool(pin_hash),
                "has_password": True,
            },
            active_role=role_primary,
        )

    return None


# -------------------- helperi koje UI često očekuje --------------------


def user_has_pin(username: Union[str, Dict[str, Any], None]) -> bool:
    ensure_users_schema()
    un = _norm_username(username)
    if not un:
        return False
    with _connect_db() as conn:
        r = conn.execute(
            "SELECT pin_hash FROM users WHERE username=? AND is_active=1 LIMIT 1;",
            (un,),
        ).fetchone()
    return bool((r[0] or "").strip()) if r else False


def user_has_password(username: Union[str, Dict[str, Any], None]) -> bool:
    ensure_users_schema()
    un = _norm_username(username)
    if not un:
        return False
    with _connect_db() as conn:
        r = conn.execute(
            "SELECT pass_hash FROM users WHERE username=? AND is_active=1 LIMIT 1;",
            (un,),
        ).fetchone()
    return bool((r[0] or "").strip()) if r else False


def user_has_any_credential(username_or_user: Union[str, Dict[str, Any], None]) -> bool:
    return user_has_pin(username_or_user) or user_has_password(username_or_user)


def get_user_credential_flags(username_or_user: Union[str, Dict[str, Any], None]) -> Dict[str, Any]:
    """UI-friendly: vrati šta postoji + must_change_creds."""
    ensure_users_schema()
    un = _norm_username(username_or_user)
    if not un:
        return {"has_pin": False, "has_password": False, "must_change_creds": 0}

    with _connect_db() as conn:
        r = conn.execute(
            """
            SELECT COALESCE(pin_hash,''), COALESCE(pass_hash,''), COALESCE(must_change_creds,0)
            FROM users
            WHERE username=? AND is_active=1
            LIMIT 1;
            """,
            (un,),
        ).fetchone()
    if not r:
        return {"has_pin": False, "has_password": False, "must_change_creds": 0}

    has_pin = bool(str(r[0] or "").strip())
    has_pw = bool(str(r[1] or "").strip())
    must_change = 1 if int(r[2] or 0) != 0 else 0
    return {"has_pin": has_pin, "has_password": has_pw, "must_change_creds": must_change}


def set_user_must_change_creds(username_or_user: Union[str, Dict[str, Any], None], flag: bool) -> bool:
    """ADMIN/MANAGE: ručno postavi must_change_creds."""
    _must(PERM_USERS_MANAGE)
    ensure_users_schema()

    un = _norm_username(username_or_user)
    if not un:
        return False

    actor = _actor_username()
    with _connect_db() as conn:
        uid, sec, role_existing = _get_user_id_sector_role(conn, un)
        if uid <= 0:
            return False
        if _is_sector_admin():
            _enforce_sector_scope(sec, action="set_user_must_change_creds")
            _forbid_sector_admin_touching_admin(conn, uid, role_existing, action="set_user_must_change_creds")

        conn.execute(
            "UPDATE users SET must_change_creds=?, updated_at=?, updated_by=? WHERE id=?;",
            (1 if flag else 0, _now(), actor, int(uid)),
        )
    return True


def clear_my_must_change_creds() -> bool:
    """Ulogovani user može da obori flag (npr. posle promene kredencijala)."""
    ensure_users_schema()
    username = _current_username()
    if not username:
        raise PermissionError("Moraš biti ulogovan.")
    with _connect_db() as conn:
        uid, _sec, _role = _get_user_id_sector_role(conn, _norm_username(username))
        if uid <= 0:
            return False
        conn.execute(
            "UPDATE users SET must_change_creds=0, updated_at=?, updated_by=? WHERE id=?;",
            (_now(), username, int(uid)),
        )
    return True


# -------------------- backward kompatibilnost (fix za import) --------------------


def verify_user_pin(username: Union[str, Dict[str, Any], None], pin: str) -> Optional[Dict[str, Any]]:
    return verify_login(username=username, method="pin", secret=pin)


def verify_user_password(username: Union[str, Dict[str, Any], None], password: str) -> Optional[Dict[str, Any]]:
    return verify_login(username=username, method="password", secret=password)


if __name__ == "__main__":  # pragma: no cover
    # Mini self-test (bez DB modifikacije):
    assert _canon_login_method("PIN") == "pin"
    assert _canon_login_method("Lozinka") == "password"
    assert _canon_login_method("password") == "password"
    assert _canon_login_method("pin") == "pin"

    s = _new_salt_hex()
    h = _pbkdf2_hash("tajna", s, PBKDF2_ITER)
    assert secrets.compare_digest(_pbkdf2_hash("tajna", s, PBKDF2_ITER), h)
    assert not secrets.compare_digest(_pbkdf2_hash("pogresno", s, PBKDF2_ITER), h)

    print("users_service.py self-test OK")

# (FILENAME: services/users_service.py - END / PART 3 of 3)
