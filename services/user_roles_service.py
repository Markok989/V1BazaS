# (FILENAME: services/user_roles_service.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/user_roles_service.py

Multi-role servis (V1.3) — 100% offline:
- Tabela: user_roles (user_id, role)
- Svaki user može imati 1..N rola
- Aktivna rola je per-session (UI bira), ne čuva se u DB

Cilj:
- Ne diramo postojeći users_service (stabilan), već nadograđujemo preko dodatne tabele.
- Ako user_roles nema zapis za korisnika, servis "backfill"-uje iz users.role (default).

RBAC:
- list_user_roles  -> users.view (allow_prelogin=True)
- set/add/remove   -> users.manage
FAIL-CLOSED (osim allow_prelogin).
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Sequence, Union

# ✅ Prefer centralizovani DB konektor (isti DB kao core/db.py)
try:
    from core.db import connect_db as _core_connect_db  # type: ignore
except Exception:  # pragma: no cover
    _core_connect_db = None  # type: ignore

from core.config import DB_FILE

# RBAC perms
try:
    from core.rbac import PERM_USERS_VIEW, PERM_USERS_MANAGE  # type: ignore
except Exception:  # pragma: no cover
    PERM_USERS_VIEW = "users.view"
    PERM_USERS_MANAGE = "users.manage"


def _safe_can(perm: str) -> bool:
    """FAIL-CLOSED: ako session/can ne radi -> False (deny)."""
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _session_has_user() -> bool:
    """Da li već postoji ulogovan user."""
    try:
        import core.session as s  # type: ignore
        fn = getattr(s, "get_current_user", None)
        if callable(fn):
            try:
                return bool(fn())
            except Exception:
                pass
        u = getattr(s, "_CURRENT_USER", None)
        return bool(u)
    except Exception:
        return False


def _must(perm: str, *, allow_prelogin: bool = False) -> None:
    """
    Service-level RBAC "must".
    - allow_prelogin=True: ako još nema ulogovanog user-a -> NE blokiramo (LoginDialog).
    - inače FAIL-CLOSED.
    """
    if allow_prelogin and (not _session_has_user()):
        return
    if not _safe_can(perm):
        raise PermissionError(f"RBAC: nemaš pravo za akciju ({perm}).")


def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _resolve_db_path() -> Path:
    p = Path(DB_FILE)
    if not p.is_absolute():
        p = (_app_root() / p).resolve()
    return p


@contextmanager
def _connect_db():
    """
    ✅ koristi core.db.connect_db() ako postoji (jedna DB putanja za ceo sistem)
    fallback: lokalni DB_FILE resolver
    """
    if _core_connect_db is not None:
        conn = _core_connect_db()
        try:
            yield conn
            conn.commit()
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return

    db_path = _resolve_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path.as_posix())
    try:
        conn.execute("PRAGMA busy_timeout=2500;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _norm_username(u: Union[str, Dict[str, Any], None]) -> str:
    if isinstance(u, dict):
        u = u.get("username") or u.get("user") or u.get("login") or ""
    s = (u or "")
    if not isinstance(s, str):
        s = str(s)
    s = s.strip().replace(" ", "_")
    return s[:50]


def _norm_role(x: Any) -> str:
    s = ("" if x is None else str(x)).strip().replace("\n", " ").replace("\r", " ").strip()
    return s[:60].upper()


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;", (name,)
    ).fetchone()
    return bool(r)


def _ensure_user_roles_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, role),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role);")


def _backfill_all(conn: sqlite3.Connection) -> None:
    """Popuni user_roles iz users.role (default role) ako fali."""
    if not _table_exists(conn, "users"):
        return
    _ensure_user_roles_schema(conn)
    conn.execute(
        """
        INSERT OR IGNORE INTO user_roles(user_id, role, created_at)
        SELECT id, role, ? FROM users
        WHERE COALESCE(TRIM(role),'') <> '';
        """,
        (_now(),),
    )


def _backfill_one(conn: sqlite3.Connection, username_norm: str) -> None:
    """Backfill samo za jednog user-a (jeftinije za login)."""
    if not _table_exists(conn, "users"):
        return
    _ensure_user_roles_schema(conn)
    conn.execute(
        """
        INSERT OR IGNORE INTO user_roles(user_id, role, created_at)
        SELECT id, role, ? FROM users
        WHERE username=? AND COALESCE(TRIM(role),'') <> '';
        """,
        (_now(), username_norm),
    )


def ensure_user_roles_schema() -> None:
    with _connect_db() as conn:
        _backfill_all(conn)


def list_user_roles(username_or_user: Union[str, Dict[str, Any], None]) -> List[str]:
    """
    ✅ RBAC: users.view (allow_prelogin=True)
    Vraća sve role dodeljene user-u (iz user_roles), sortirano.
    """
    _must(PERM_USERS_VIEW, allow_prelogin=True)

    un = _norm_username(username_or_user)
    if not un:
        return []

    with _connect_db() as conn:
        _backfill_one(conn, un)

        row = conn.execute("SELECT id, role FROM users WHERE username=? LIMIT 1;", (un,)).fetchone()
        if not row:
            return []

        user_id = int(row[0])
        default_role = (row[1] or "").strip()

        roles_rows = conn.execute(
            "SELECT role FROM user_roles WHERE user_id=? ORDER BY role COLLATE NOCASE;",
            (user_id,),
        ).fetchall()

        roles: List[str] = []
        for r in roles_rows:
            s = (r[0] or "").strip()
            if s and s not in roles:
                roles.append(s)

        if default_role and default_role not in roles:
            roles.append(default_role)

        return roles


def set_user_roles(username_or_user: Union[str, Dict[str, Any], None], roles: Sequence[str]) -> bool:
    """
    ✅ RBAC: users.manage
    Potpuno zamenjuje set rola za korisnika.
    - role lista mora imati bar jednu stavku
    - users.role (default_role) se setuje na PRVU rolu iz liste
    """
    _must(PERM_USERS_MANAGE)

    un = _norm_username(username_or_user)
    if not un:
        return False

    clean: List[str] = []
    for x in roles or []:
        rr = _norm_role(x)
        if rr and rr not in clean:
            clean.append(rr)

    if not clean:
        raise ValueError("Moraš dodeliti bar jednu ulogu.")

    with _connect_db() as conn:
        _backfill_one(conn, un)

        row = conn.execute("SELECT id FROM users WHERE username=? LIMIT 1;", (un,)).fetchone()
        if not row:
            return False
        user_id = int(row[0])

        conn.execute("DELETE FROM user_roles WHERE user_id=?;", (user_id,))
        for rr in clean:
            conn.execute(
                "INSERT OR IGNORE INTO user_roles(user_id, role, created_at) VALUES(?,?,?);",
                (user_id, rr, _now()),
            )

        # default role = prva
        conn.execute("UPDATE users SET role=?, updated_at=? WHERE id=?;", (clean[0], _now(), user_id))

    return True


def add_user_role(username_or_user: Union[str, Dict[str, Any], None], role: str) -> bool:
    """✅ RBAC: users.manage — dodaje rolu (ako već postoji, no-op)."""
    _must(PERM_USERS_MANAGE)

    un = _norm_username(username_or_user)
    rr = _norm_role(role)
    if not un or not rr:
        return False

    with _connect_db() as conn:
        _backfill_one(conn, un)

        row = conn.execute("SELECT id, role FROM users WHERE username=? LIMIT 1;", (un,)).fetchone()
        if not row:
            return False
        user_id = int(row[0])
        default_role = (row[1] or "").strip()

        conn.execute(
            "INSERT OR IGNORE INTO user_roles(user_id, role, created_at) VALUES(?,?,?);",
            (user_id, rr, _now()),
        )

        # ako user nema default_role, setuj
        if not default_role:
            conn.execute("UPDATE users SET role=?, updated_at=? WHERE id=?;", (rr, _now(), user_id))
    return True


def remove_user_role(username_or_user: Union[str, Dict[str, Any], None], role: str) -> bool:
    """
    ✅ RBAC: users.manage — uklanja rolu.
    Ne dozvoljava da korisnik ostane bez ijedne role.
    """
    _must(PERM_USERS_MANAGE)

    un = _norm_username(username_or_user)
    rr = _norm_role(role)
    if not un or not rr:
        return False

    with _connect_db() as conn:
        _backfill_one(conn, un)

        row = conn.execute("SELECT id, role FROM users WHERE username=? LIMIT 1;", (un,)).fetchone()
        if not row:
            return False
        user_id = int(row[0])
        default_role = (row[1] or "").strip()

        roles_rows = conn.execute(
            "SELECT role FROM user_roles WHERE user_id=? ORDER BY role COLLATE NOCASE;",
            (user_id,),
        ).fetchall()
        roles = [str(r[0]).strip() for r in roles_rows if str(r[0] or "").strip()]

        if rr not in roles:
            return True  # već uklonjeno

        if len(roles) <= 1:
            raise ValueError("Korisnik mora imati bar jednu ulogu (ne možeš ukloniti poslednju).")

        conn.execute("DELETE FROM user_roles WHERE user_id=? AND role=?;", (user_id, rr))

        # ako je obrisana default role, prebacimo na prvu preostalu
        if default_role == rr:
            roles2 = conn.execute(
                "SELECT role FROM user_roles WHERE user_id=? ORDER BY role COLLATE NOCASE;",
                (user_id,),
            ).fetchall()
            new_default = (roles2[0][0] if roles2 else "READONLY") if roles2 else "READONLY"
            conn.execute("UPDATE users SET role=?, updated_at=? WHERE id=?;", (new_default, _now(), user_id))

    return True
# (FILENAME: services/user_roles_service.py - END)