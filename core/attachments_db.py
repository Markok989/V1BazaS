# [START] FILENAME: core/attachments_db.py
# -*- coding: utf-8 -*-

from __future__ import annotations

# --- BOOTSTRAP (da radi i kad se pokrene direktno kao fajl) ---
# Ako u VSCode klikneš "Run Python File" na core/attachments_db.py,
# Python neće videti root projekta pa import "core.*" pada.
# Ovo dodaje root (parent od "core") u sys.path samo u tom slučaju.
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    _ROOT = Path(__file__).resolve().parents[1]
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))
# --- /BOOTSTRAP ---

import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.paths import DB_PATH


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Stabilnost: smanji šanse za "database is locked"
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        # Ako neka verzija SQLite ne podrži, ne ruši program
        pass

    return conn


def _init(conn: sqlite3.Connection) -> None:
    conn.execute("""
    CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        rel_path TEXT NOT NULL,
        original_name TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size_bytes INTEGER NOT NULL DEFAULT 0,
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL DEFAULT ''
    );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_att_entity ON attachments(entity, entity_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_att_sha ON attachments(sha256);")
    conn.commit()


def _try_audit(
    conn: sqlite3.Connection,
    *,
    actor: str,
    action: str,
    after_obj: Optional[Dict[str, Any]],
    before_obj: Optional[Dict[str, Any]],
    source: str
) -> None:
    try:
        from core.db import write_audit  # type: ignore
    except Exception:
        return
    try:
        write_audit(
            conn,
            actor=actor or "",
            entity="attachments",
            entity_id=str((after_obj or before_obj or {}).get("id", "")),
            action=action,
            before_obj=before_obj,
            after_obj=after_obj,
            source=source
        )
    except Exception:
        return


def add_attachment_db(
    *,
    entity: str,
    entity_id: str,
    rel_path: str,
    original_name: str,
    sha256: str,
    size_bytes: int,
    note: str = "",
    actor: str = "",
    source: str = "attachments_db:add"
) -> int:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        _init(conn)
        cur = conn.execute("""
            INSERT INTO attachments(entity, entity_id, rel_path, original_name, sha256, size_bytes, note, created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (entity, entity_id, rel_path, original_name, sha256, int(size_bytes), note or "", now, actor or ""))
        att_id = int(cur.lastrowid)

        after_obj = {
            "id": att_id,
            "entity": entity,
            "entity_id": entity_id,
            "rel_path": rel_path,
            "original_name": original_name,
            "sha256": sha256,
            "size_bytes": int(size_bytes),
            "note": note or "",
            "created_at": now,
            "created_by": actor or ""
        }
        _try_audit(conn, actor=actor, action="INSERT", after_obj=after_obj, before_obj=None, source=source)
        conn.commit()
        return att_id


def list_attachments_db(*, entity: str, entity_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    with _connect() as conn:
        _init(conn)
        rows = conn.execute("""
            SELECT *
            FROM attachments
            WHERE entity=? AND entity_id=?
            ORDER BY id DESC
            LIMIT ?
        """, (entity, entity_id, int(limit))).fetchall()
        return [dict(r) for r in rows]


def delete_attachment_db(*, attachment_id: int, actor: str = "", source: str = "attachments_db:delete") -> bool:
    with _connect() as conn:
        _init(conn)
        before = conn.execute("SELECT * FROM attachments WHERE id=?", (int(attachment_id),)).fetchone()
        if not before:
            return False
        before_obj = dict(before)
        conn.execute("DELETE FROM attachments WHERE id=?", (int(attachment_id),))
        _try_audit(conn, actor=actor, action="DELETE", after_obj=None, before_obj=before_obj, source=source)
        conn.commit()
        return True


# [END] FILENAME: core/attachments_db.py