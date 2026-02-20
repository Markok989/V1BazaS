# [START] FILENAME: services/custom_fields_service.py
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/custom_fields_service.py

Custom Fields (V1):
- Admin definiše nova polja (bez ALTER TABLE assets)
- Vrednosti se čuvaju po asset_uid
- Tipovi: TEXT, NUMBER, DATE, BOOL, CHOICE
- Self-heal šema (CREATE/ALTER tolerantno)
- Offline, SQLite

Kompatibilnost (UI):
- list_values_for_asset (alias)
- bulk_set_values_for_asset (alias)
- set_field_active (alias)
- list_fields / create_field / update_field / delete_field (alias-evi)
"""

from __future__ import annotations

import sqlite3
import json
import re
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config import DB_FILE


# -------------------- helpers --------------------

def _app_root() -> Path:
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
        yield conn
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
        (name,)
    ).fetchone()
    return bool(r)

def _cols(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        return [r[1] for r in conn.execute(f"PRAGMA table_info({table});").fetchall()]
    except Exception:
        return []

def _add_col(conn: sqlite3.Connection, table: str, col: str, ddl: str) -> None:
    cols = _cols(conn, table)
    if col not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl};")

def _norm_key(key: str) -> str:
    k = (key or "").strip().lower()
    k = k.replace(" ", "_")
    k = re.sub(r"[^a-z0-9_]+", "_", k)
    k = re.sub(r"_+", "_", k).strip("_")
    return k[:60]

def _validate_type(t: str) -> str:
    tt = (t or "").strip().upper()
    if tt not in ("TEXT", "NUMBER", "DATE", "BOOL", "CHOICE"):
        return "TEXT"
    return tt

def _json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return "[]"

def _json_loads(s: str) -> Any:
    try:
        return json.loads(s or "[]")
    except Exception:
        return []


# -------------------- schema --------------------

def ensure_custom_fields_schema() -> None:
    """
    Tabele:
    - custom_fields_def: definicije polja (admin)
    - custom_fields_val: vrednosti po asset_uid
    """
    with _connect_db() as conn:
        if not _table_exists(conn, "custom_fields_def"):
            conn.execute("""
                CREATE TABLE IF NOT EXISTS custom_fields_def (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    field_key TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    field_type TEXT NOT NULL DEFAULT 'TEXT',
                    choices_json TEXT NOT NULL DEFAULT '[]',
                    default_value TEXT NOT NULL DEFAULT '',
                    is_required INTEGER NOT NULL DEFAULT 0,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cfd_active ON custom_fields_def(is_active);")

        if not _table_exists(conn, "custom_fields_val"):
            conn.execute("""
                CREATE TABLE IF NOT EXISTS custom_fields_val (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_uid TEXT NOT NULL,
                    field_key TEXT NOT NULL,
                    value_text TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    UNIQUE(asset_uid, field_key)
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cfv_asset ON custom_fields_val(asset_uid);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cfv_key ON custom_fields_val(field_key);")

        # tolerantno dodavanje kolona ako je legacy
        _add_col(conn, "custom_fields_def", "choices_json", "choices_json TEXT NOT NULL DEFAULT '[]'")
        _add_col(conn, "custom_fields_def", "default_value", "default_value TEXT NOT NULL DEFAULT ''")
        _add_col(conn, "custom_fields_def", "is_required", "is_required INTEGER NOT NULL DEFAULT 0")
        _add_col(conn, "custom_fields_def", "is_active", "is_active INTEGER NOT NULL DEFAULT 1")

        _add_col(conn, "custom_fields_val", "actor", "actor TEXT NOT NULL DEFAULT ''")
        _add_col(conn, "custom_fields_val", "source", "source TEXT NOT NULL DEFAULT ''")

        # normalize NULL -> ''
        for t, col in [
            ("custom_fields_def", "choices_json"),
            ("custom_fields_def", "default_value"),
            ("custom_fields_val", "value_text"),
            ("custom_fields_val", "actor"),
            ("custom_fields_val", "source"),
        ]:
            cols = _cols(conn, t)
            if col in cols:
                conn.execute(f"UPDATE {t} SET {col}='' WHERE {col} IS NULL;")

        # index ensure
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cfd_active ON custom_fields_def(is_active);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cfv_asset ON custom_fields_val(asset_uid);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cfv_key ON custom_fields_val(field_key);")


# -------------------- defs CRUD (core) --------------------

def list_field_defs(active_only: bool = True) -> List[Dict[str, Any]]:
    ensure_custom_fields_schema()
    with _connect_db() as conn:
        if active_only:
            rows = conn.execute("""
                SELECT field_key, label, field_type, choices_json, default_value, is_required, is_active
                  FROM custom_fields_def
                 WHERE is_active=1
                 ORDER BY label COLLATE NOCASE;
            """).fetchall()
        else:
            rows = conn.execute("""
                SELECT field_key, label, field_type, choices_json, default_value, is_required, is_active
                  FROM custom_fields_def
                 ORDER BY is_active DESC, label COLLATE NOCASE;
            """).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append({
            "field_key": r[0] or "",
            "label": r[1] or "",
            "field_type": r[2] or "TEXT",
            "choices": _json_loads(r[3] or "[]"),
            "default_value": r[4] or "",
            "is_required": int(r[5] or 0),
            "is_active": int(r[6] or 0),
        })
    return out

def get_field_def(field_key: str) -> Optional[Dict[str, Any]]:
    ensure_custom_fields_schema()
    k = _norm_key(field_key)
    if not k:
        return None
    with _connect_db() as conn:
        r = conn.execute("""
            SELECT field_key, label, field_type, choices_json, default_value, is_required, is_active
              FROM custom_fields_def
             WHERE field_key=?
             LIMIT 1;
        """, (k,)).fetchone()
    if not r:
        return None
    return {
        "field_key": r[0] or "",
        "label": r[1] or "",
        "field_type": r[2] or "TEXT",
        "choices": _json_loads(r[3] or "[]"),
        "default_value": r[4] or "",
        "is_required": int(r[5] or 0),
        "is_active": int(r[6] or 0),
    }

def upsert_field_def(
    actor: str,
    field_key: str,
    label: str,
    field_type: str = "TEXT",
    choices: Optional[List[str]] = None,
    default_value: str = "",
    is_required: bool = False,
    is_active: bool = True,
    source: str = "ui_custom_fields_admin"
) -> bool:
    ensure_custom_fields_schema()

    k = _norm_key(field_key)
    if not k:
        raise ValueError("field_key je obavezan")
    lab = (label or "").strip()
    if not lab:
        raise ValueError("label je obavezan")

    t = _validate_type(field_type)
    ch = choices or []
    if t != "CHOICE":
        ch = []
    ch_json = _json_dumps(ch)

    dv = (default_value or "").strip()
    req = 1 if is_required else 0
    act = 1 if is_active else 0

    with _connect_db() as conn:
        row = conn.execute(
            "SELECT field_key FROM custom_fields_def WHERE field_key=? LIMIT 1;",
            (k,)
        ).fetchone()

        if row:
            conn.execute("""
                UPDATE custom_fields_def
                   SET label=?,
                       field_type=?,
                       choices_json=?,
                       default_value=?,
                       is_required=?,
                       is_active=?,
                       updated_at=?
                 WHERE field_key=?;
            """, (lab, t, ch_json, dv, req, act, _now(), k))
        else:
            conn.execute("""
                INSERT INTO custom_fields_def(
                    field_key, label, field_type, choices_json, default_value,
                    is_required, is_active, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?);
            """, (k, lab, t, ch_json, dv, req, act, _now(), _now()))
    return True

def deactivate_field_def(field_key: str) -> bool:
    ensure_custom_fields_schema()
    k = _norm_key(field_key)
    if not k:
        return False
    with _connect_db() as conn:
        conn.execute(
            "UPDATE custom_fields_def SET is_active=0, updated_at=? WHERE field_key=?;",
            (_now(), k)
        )
    return True

def set_field_active_def(field_key: str, active: bool) -> bool:
    ensure_custom_fields_schema()
    k = _norm_key(field_key)
    if not k:
        return False
    with _connect_db() as conn:
        conn.execute(
            "UPDATE custom_fields_def SET is_active=?, updated_at=? WHERE field_key=?;",
            (1 if active else 0, _now(), k)
        )
    return True

def delete_field_def(field_key: str) -> bool:
    """
    “Hard delete” definicije + vrednosti. (Admin-only u UI)
    Ako nećeš hard delete u V1, UI i dalje radi jer postoji alias.
    """
    ensure_custom_fields_schema()
    k = _norm_key(field_key)
    if not k:
        return False
    with _connect_db() as conn:
        conn.execute("DELETE FROM custom_fields_val WHERE field_key=?;", (k,))
        conn.execute("DELETE FROM custom_fields_def WHERE field_key=?;", (k,))
    return True


# -------------------- values CRUD --------------------

def get_values_for_asset(asset_uid: str) -> Dict[str, str]:
    ensure_custom_fields_schema()
    au = (asset_uid or "").strip()
    if not au:
        return {}
    with _connect_db() as conn:
        rows = conn.execute("""
            SELECT field_key, value_text
              FROM custom_fields_val
             WHERE asset_uid=?
        """, (au,)).fetchall()

    out: Dict[str, str] = {}
    for k, v in rows:
        kk = (k or "").strip()
        if kk:
            out[kk] = (v or "")
    return out

def set_value_for_asset(
    actor: str,
    asset_uid: str,
    field_key: str,
    value_text: str,
    source: str = "ui_asset_detail_custom_fields"
) -> bool:
    ensure_custom_fields_schema()
    au = (asset_uid or "").strip()
    k = _norm_key(field_key)
    if not au or not k:
        return False

    val = (value_text or "").strip()
    with _connect_db() as conn:
        conn.execute("""
            INSERT INTO custom_fields_val(asset_uid, field_key, value_text, updated_at, actor, source)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(asset_uid, field_key) DO UPDATE SET
                value_text=excluded.value_text,
                updated_at=excluded.updated_at,
                actor=excluded.actor,
                source=excluded.source;
        """, (au, k, val, _now(), (actor or "").strip(), (source or "").strip()))
    return True

def set_values_for_asset_bulk(
    actor: str,
    asset_uid: str,
    values: Dict[str, str],
    source: str = "ui_asset_detail_custom_fields_bulk"
) -> int:
    ensure_custom_fields_schema()
    au = (asset_uid or "").strip()
    if not au:
        return 0
    cnt = 0
    for k, v in (values or {}).items():
        if set_value_for_asset(actor, au, k, v, source=source):
            cnt += 1
    return cnt

def list_values_for_asset(asset_uid: str) -> List[Dict[str, Any]]:
    """
    UI-friendly list (i polja bez vrednosti).
    """
    ensure_custom_fields_schema()
    au = (asset_uid or "").strip()
    if not au:
        return []

    defs = list_field_defs(active_only=False)
    defs_by_key: Dict[str, Dict[str, Any]] = {d["field_key"]: d for d in defs}

    with _connect_db() as conn:
        rows = conn.execute("""
            SELECT field_key, value_text
              FROM custom_fields_val
             WHERE asset_uid=?
        """, (au,)).fetchall()

    out: List[Dict[str, Any]] = []
    for k, v in rows:
        kk = (k or "").strip()
        if not kk:
            continue
        d = defs_by_key.get(kk, {})
        out.append({
            "field_key": kk,
            "value_text": (v or ""),
            "label": d.get("label", kk),
            "field_type": d.get("field_type", "TEXT"),
            "choices": d.get("choices", []),
            "is_required": int(d.get("is_required", 0) or 0),
            "is_active": int(d.get("is_active", 1) or 1),
        })

    existing_keys = {x["field_key"] for x in out}
    for d in defs:
        fk = (d.get("field_key") or "").strip()
        if not fk or fk in existing_keys:
            continue
        out.append({
            "field_key": fk,
            "value_text": "",
            "label": d.get("label", fk),
            "field_type": d.get("field_type", "TEXT"),
            "choices": d.get("choices", []),
            "is_required": int(d.get("is_required", 0) or 0),
            "is_active": int(d.get("is_active", 1) or 1),
        })

    out.sort(key=lambda x: (str(x.get("label") or "").lower()))
    return out


# -------------------- UI COMPAT ALIASES --------------------
# (Ovo je “lepak” da UI ne puca kad očekuje druga imena funkcija)

def bulk_set_values_for_asset(actor: str, asset_uid: str, values: Dict[str, str], source: str = "ui_asset_detail_custom_fields_bulk") -> int:
    return set_values_for_asset_bulk(actor, asset_uid, values, source=source)

def list_fields(active_only: bool = False) -> List[Dict[str, Any]]:
    # UI često želi i neaktivna (da ih uključi/isključi)
    return list_field_defs(active_only=active_only)

def create_field(
    actor: str,
    field_key: str,
    label: str,
    field_type: str = "TEXT",
    choices: Optional[List[str]] = None,
    default_value: str = "",
    is_required: bool = False,
    source: str = "ui_custom_fields_admin"
) -> bool:
    # kreira aktivno polje
    return upsert_field_def(
        actor=actor,
        field_key=field_key,
        label=label,
        field_type=field_type,
        choices=choices,
        default_value=default_value,
        is_required=is_required,
        is_active=True,
        source=source
    )

def update_field(
    actor: str,
    field_key: str,
    label: str,
    field_type: str = "TEXT",
    choices: Optional[List[str]] = None,
    default_value: str = "",
    is_required: bool = False,
    is_active: bool = True,
    source: str = "ui_custom_fields_admin"
) -> bool:
    return upsert_field_def(
        actor=actor,
        field_key=field_key,
        label=label,
        field_type=field_type,
        choices=choices,
        default_value=default_value,
        is_required=is_required,
        is_active=is_active,
        source=source
    )

def delete_field(field_key: str) -> bool:
    # hard delete (ako UI baš to traži)
    return delete_field_def(field_key)

def set_field_active(field_key: str, active: bool = True, *args, **kwargs) -> bool:
    """
    ✅ UI očekuje set_field_active(field_key, active)
    Dodao sam *args/**kwargs da UI varijacije ne razbiju servis.
    """
    return set_field_active_def(field_key, bool(active))

# [END] FILENAME: services/custom_fields_service.py