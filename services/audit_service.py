# FILENAME: services/audit_service.py
# (FILENAME: services/audit_service.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/audit_service.py

Audit read API za UI (V1) — ROBUSTNO + SELF-HEALING.

Cilj:
- Ne zavisi od core.db (izbegavamo circular import / razlike između verzija).
- Ako audit tabela ne postoji -> kreira audit_log.
- Ako postoji neka druga audit tabela (audit, audit_events, audit_trail...) -> pokušava da je koristi.
- Vraća uvek standardne ključeve koje UI očekuje:
  event_time, entity, entity_id, action, actor, source, before_json, after_json

RBAC (service-level):
- PERM_AUDIT_VIEW -> list_audit / list_audit_global
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.config import DB_FILE


# -------------------- RBAC helpers --------------------
try:
    from core.rbac import PERM_AUDIT_VIEW  # type: ignore
except Exception:  # pragma: no cover
    PERM_AUDIT_VIEW = "audit.view"


def _safe_can(perm: str) -> bool:
    """
    Bezbedan wrapper oko session.can().
    Ako can() pukne / nije dostupno -> ne blokiramo (fallback True).
    """
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return True


def _must(perm: str) -> None:
    if not _safe_can(perm):
        raise PermissionError(f"RBAC: nemaš pravo za akciju ({perm}).")


# -------------------- DB helpers --------------------
def _app_root() -> Path:
    # services/.. => root projekta
    return Path(__file__).resolve().parent.parent


def _resolve_db_path() -> Path:
    p = Path(DB_FILE)
    if not p.is_absolute():
        p = (_app_root() / p).resolve()
    return p


@contextmanager
def _connect_db():
    db_path = _resolve_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path.as_posix())
    try:
        conn.execute("PRAGMA busy_timeout=2500;")
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _ensure_audit_log_schema(conn: sqlite3.Connection) -> None:
    """
    Kreira audit_log ako ne postoji.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            entity TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            source TEXT,
            before_json TEXT,
            after_json TEXT
        );
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity, entity_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(event_time);")


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;",
        (name,),
    ).fetchone()
    return bool(r)


def _list_tables(conn: sqlite3.Connection) -> List[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
    out: List[str] = []
    for r in rows:
        try:
            out.append(str(r["name"]))
        except Exception:
            out.append(str(r[0]))
    return out


def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
    cols: List[str] = []
    for r in rows:
        # PRAGMA table_info -> (cid, name, type, notnull, dflt_value, pk)
        try:
            cols.append(str(r["name"]))
        except Exception:
            cols.append(str(r[1]))
    return cols


def _pick_audit_table(conn: sqlite3.Connection) -> Tuple[str, List[str]]:
    """
    Pokušava da pronađe postojeću audit tabelu.
    Preferira audit_log. Ako je nema, traži slične.
    Ako ništa ne nađe -> kreira audit_log i vraća njega.
    """
    preferred = ["audit_log", "audit", "audit_events", "audit_trail", "audits", "event_log"]
    existing = _list_tables(conn)

    for t in preferred:
        if t in existing:
            return t, _table_columns(conn, t)

    for t in existing:
        if "audit" in t.lower():
            return t, _table_columns(conn, t)

    _ensure_audit_log_schema(conn)
    return "audit_log", _table_columns(conn, "audit_log")


def _colmap(cols: List[str]) -> Dict[str, str]:
    """
    Mapiranje stvarnih kolona u standardne alias-e.
    """
    cset = {c.lower() for c in cols}

    def pick(*names: str) -> str:
        for n in names:
            if n.lower() in cset:
                for real in cols:
                    if real.lower() == n.lower():
                        return real
        return ""

    return {
        "id": pick("id"),
        "event_time": pick("event_time", "ts", "created_at", "time", "created", "datetime"),
        "entity": pick("entity", "table", "owner_type", "entity_name"),
        "entity_id": pick("entity_id", "owner_id", "asset_uid", "uid", "record_id"),
        "action": pick("action", "op", "event", "operation", "verb"),
        "actor": pick("actor", "user", "username", "by_user"),
        "source": pick("source", "src", "origin"),
        "before_json": pick("before_json", "before", "old_json", "prev_json"),
        "after_json": pick("after_json", "after", "new_json", "next_json"),
    }


def _safe_int(x: Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _like(s: str) -> str:
    return f"%{(s or '').strip()}%"


def _sel(col: str, alias: str) -> str:
    """
    SELECT izraz za kolonu koja možda ne postoji u target tabeli.
    Ako col ne postoji -> '' AS alias (da SQL nikad ne pukne).
    """
    if col:
        return f"{col} AS {alias}"
    return f"'' AS {alias}"


# -------------------- Public API --------------------
def list_audit(entity: str, entity_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """
    Audit za konkretan entitet + ID (npr. assets / A-2026-0000001).
    Vraća standardne ključeve za UI.
    RBAC: audit.view
    """
    _must(PERM_AUDIT_VIEW)

    entity = (entity or "").strip()
    entity_id = (entity_id or "").strip()
    limit = _safe_int(limit, 500)
    if limit <= 0:
        limit = 500

    with _connect_db() as conn:
        # obavezno obezbedi standard tabelu
        if not _table_exists(conn, "audit_log"):
            _ensure_audit_log_schema(conn)

        table, cols = _pick_audit_table(conn)
        m = _colmap(cols)

        # ako nema bar event_time + action, nema smisla
        if not m["event_time"] or not m["action"]:
            return []

        where: List[str] = []
        params: List[Any] = []

        if m["entity"] and entity:
            where.append(f"{m['entity']} = ?")
            params.append(entity)

        if m["entity_id"] and entity_id:
            where.append(f"{m['entity_id']} = ?")
            params.append(entity_id)

        wsql = ("WHERE " + " AND ".join(where)) if where else ""

        order_col = m["event_time"]
        id_col = m["id"] or "rowid"

        sql = f"""
        SELECT
            {_sel(m['event_time'], 'event_time')},
            {_sel(m['entity'], 'entity')},
            {_sel(m['entity_id'], 'entity_id')},
            {_sel(m['action'], 'action')},
            {_sel(m['actor'], 'actor')},
            {_sel(m['source'], 'source')},
            {_sel(m['before_json'], 'before_json')},
            {_sel(m['after_json'], 'after_json')}
        FROM {table}
        {wsql}
        ORDER BY datetime({order_col}) DESC, {id_col} DESC
        LIMIT ?;
        """
        params.append(limit)

        rows = conn.execute(sql, tuple(params)).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "event_time": str(r["event_time"] or ""),
                "entity": str(r["entity"] or ""),
                "entity_id": str(r["entity_id"] or ""),
                "action": str(r["action"] or ""),
                "actor": str(r["actor"] or ""),
                "source": str(r["source"] or ""),
                "before_json": str(r["before_json"] or ""),
                "after_json": str(r["after_json"] or ""),
            }
        )
    return out


def list_audit_global(
    entity: str = "SVE",
    action: str = "SVE",
    actor_like: str = "",
    source_like: str = "",
    q: str = "",
    limit: int = 5000,
) -> List[Dict[str, Any]]:
    """
    Global audit (filteri za UI).
    - entity: "SVE" ili konkretno (assets/assignments/attachments...)
    - action: "SVE" ili INSERT/UPDATE/DELETE/...
    - actor_like, source_like: LIKE filteri
    - q: general search preko više polja
    RBAC: audit.view
    """
    _must(PERM_AUDIT_VIEW)

    entity = (entity or "SVE").strip()
    action = (action or "SVE").strip()
    actor_like = (actor_like or "").strip()
    source_like = (source_like or "").strip()
    q = (q or "").strip()

    limit = _safe_int(limit, 5000)
    if limit <= 0:
        limit = 5000

    with _connect_db() as conn:
        if not _table_exists(conn, "audit_log"):
            _ensure_audit_log_schema(conn)

        table, cols = _pick_audit_table(conn)
        m = _colmap(cols)

        if not m["event_time"] or not m["action"]:
            return []

        where: List[str] = []
        params: List[Any] = []

        if m["entity"] and entity.upper() != "SVE":
            where.append(f"{m['entity']} = ?")
            params.append(entity)

        if m["action"] and action.upper() != "SVE":
            where.append(f"{m['action']} = ?")
            params.append(action)

        if m["actor"] and actor_like:
            where.append(f"{m['actor']} LIKE ?")
            params.append(_like(actor_like))

        if m["source"] and source_like:
            where.append(f"{m['source']} LIKE ?")
            params.append(_like(source_like))

        if q:
            parts: List[str] = []
            for key in ["entity", "entity_id", "action", "actor", "source", "before_json", "after_json", "event_time"]:
                col = m.get(key, "")
                if col:
                    parts.append(f"{col} LIKE ?")
                    params.append(_like(q))
            if parts:
                where.append("(" + " OR ".join(parts) + ")")

        wsql = ("WHERE " + " AND ".join(where)) if where else ""

        order_col = m["event_time"]
        id_col = m["id"] or "rowid"

        sql = f"""
        SELECT
            {_sel(m['event_time'], 'event_time')},
            {_sel(m['entity'], 'entity')},
            {_sel(m['entity_id'], 'entity_id')},
            {_sel(m['action'], 'action')},
            {_sel(m['actor'], 'actor')},
            {_sel(m['source'], 'source')},
            {_sel(m['before_json'], 'before_json')},
            {_sel(m['after_json'], 'after_json')}
        FROM {table}
        {wsql}
        ORDER BY datetime({order_col}) DESC, {id_col} DESC
        LIMIT ?;
        """
        params.append(limit)

        rows = conn.execute(sql, tuple(params)).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "event_time": str(r["event_time"] or ""),
                "entity": str(r["entity"] or ""),
                "entity_id": str(r["entity_id"] or ""),
                "action": str(r["action"] or ""),
                "actor": str(r["actor"] or ""),
                "source": str(r["source"] or ""),
                "before_json": str(r["before_json"] or ""),
                "after_json": str(r["after_json"] or ""),
            }
        )
    return out


# (FILENAME: services/audit_service.py - END)
# FILENAME: services/audit_service.py