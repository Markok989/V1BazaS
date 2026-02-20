# [START] FILENAME: services/ui_table_view_service.py
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/ui_table_view_service.py

UI Table Views (V1):
- Snimanje/učitavanje prikaza tabela (redosled, vidljivost, širina kolona)
- Per-user view (V1)
- (Spremno za kasnije) role/global default view

Napomena: ovo NE menja DB šemu assets; ovo je samo UI prikaz.
"""

from __future__ import annotations

import sqlite3
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


# -------------------- schema --------------------

def ensure_ui_views_schema() -> None:
    with _connect_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ui_table_views (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                table_key TEXT NOT NULL,
                scope TEXT NOT NULL,         -- 'user' | 'role' | 'global'
                scope_key TEXT NOT NULL,     -- username | role | ''
                name TEXT NOT NULL DEFAULT '',
                is_default INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS ux_ui_table_views
            ON ui_table_views(table_key, scope, scope_key);
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ui_table_view_cols (
                view_id INTEGER NOT NULL,
                col_key TEXT NOT NULL,       -- npr: 'asset_uid', 'name', 'cf:mass_kg'
                title TEXT NOT NULL DEFAULT '',
                visible INTEGER NOT NULL DEFAULT 1,
                order_index INTEGER NOT NULL DEFAULT 0,
                width INTEGER NOT NULL DEFAULT 0,   -- 0 = auto
                PRIMARY KEY(view_id, col_key),
                FOREIGN KEY(view_id) REFERENCES ui_table_views(id) ON DELETE CASCADE
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_ui_table_view_cols_order
            ON ui_table_view_cols(view_id, order_index);
        """)


# -------------------- internal --------------------

def _get_view_id(conn: sqlite3.Connection, table_key: str, scope: str, scope_key: str) -> Optional[int]:
    r = conn.execute(
        "SELECT id FROM ui_table_views WHERE table_key=? AND scope=? AND scope_key=? LIMIT 1;",
        (table_key, scope, scope_key)
    ).fetchone()
    return int(r[0]) if r else None

def _create_view(conn: sqlite3.Connection, table_key: str, scope: str, scope_key: str, name: str = "", is_default: int = 0) -> int:
    conn.execute(
        "INSERT INTO ui_table_views(table_key, scope, scope_key, name, is_default, updated_at) VALUES(?,?,?,?,?,?);",
        (table_key, scope, scope_key, name or "", int(is_default), _now())
    )
    rid = conn.execute("SELECT last_insert_rowid();").fetchone()[0]
    return int(rid)

def _upsert_cols(conn: sqlite3.Connection, view_id: int, cols: List[Dict[str, Any]]) -> None:
    for c in cols or []:
        ck = str(c.get("col_key", "") or "").strip()
        if not ck:
            continue
        title = str(c.get("title", "") or "")
        vis = 1 if int(c.get("visible", 1) or 0) != 0 else 0
        order_index = int(c.get("order_index", 0) or 0)
        width = int(c.get("width", 0) or 0)

        conn.execute(
            """
            INSERT INTO ui_table_view_cols(view_id, col_key, title, visible, order_index, width)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(view_id, col_key) DO UPDATE SET
                title=excluded.title,
                visible=excluded.visible,
                order_index=excluded.order_index,
                width=excluded.width;
            """,
            (int(view_id), ck, title, int(vis), int(order_index), int(width))
        )

def _read_cols(conn: sqlite3.Connection, view_id: int) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT col_key, title, visible, order_index, width
        FROM ui_table_view_cols
        WHERE view_id=?
        ORDER BY order_index ASC, col_key ASC;
        """,
        (int(view_id),)
    ).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append({
            "col_key": r[0] or "",
            "title": r[1] or "",
            "visible": int(r[2] or 0),
            "order_index": int(r[3] or 0),
            "width": int(r[4] or 0),
        })
    return out


# -------------------- public API --------------------

def get_or_create_user_view(table_key: str, username: str, default_cols: List[Dict[str, Any]]) -> Dict[str, Any]:
    ensure_ui_views_schema()
    tk = (table_key or "").strip()
    un = (username or "").strip()
    if not tk or not un:
        return {"table_key": tk, "scope": "user", "scope_key": un, "cols": default_cols or []}

    with _connect_db() as conn:
        vid = _get_view_id(conn, tk, "user", un)
        if vid is None:
            vid = _create_view(conn, tk, "user", un, name="", is_default=0)
            _upsert_cols(conn, vid, default_cols or [])
        cols = _read_cols(conn, vid)
        conn.execute("UPDATE ui_table_views SET updated_at=? WHERE id=?;", (_now(), int(vid)))
        return {"table_key": tk, "scope": "user", "scope_key": un, "cols": cols}

def save_user_view(table_key: str, username: str, cols: List[Dict[str, Any]]) -> None:
    ensure_ui_views_schema()
    tk = (table_key or "").strip()
    un = (username or "").strip()
    if not tk or not un:
        return

    with _connect_db() as conn:
        vid = _get_view_id(conn, tk, "user", un)
        if vid is None:
            vid = _create_view(conn, tk, "user", un, name="", is_default=0)
        _upsert_cols(conn, vid, cols or [])
        conn.execute("UPDATE ui_table_views SET updated_at=? WHERE id=?;", (_now(), int(vid)))

def delete_user_view(table_key: str, username: str) -> None:
    ensure_ui_views_schema()
    tk = (table_key or "").strip()
    un = (username or "").strip()
    if not tk or not un:
        return

    with _connect_db() as conn:
        vid = _get_view_id(conn, tk, "user", un)
        if vid is None:
            return
        conn.execute("DELETE FROM ui_table_view_cols WHERE view_id=?;", (int(vid),))
        conn.execute("DELETE FROM ui_table_views WHERE id=?;", (int(vid),))

# [END] FILENAME: services/ui_table_view_service.py