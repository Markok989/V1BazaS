# FILENAME: services/attachments_service.py
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/attachments_service.py

Robustan servis za priloge (V1):
- Self-healing schema (radi sa raznim šemama attachments tabele)
- Ne oslanja se na kolonu 'id' (koristi rowid/INTEGER PRIMARY KEY)
- UI kompatibilnost: vraća i 'att_id' i 'id', i 'file_name' i 'name'
- Kompatibilni wrapperi: add_attachment(...) i add_attachment_to_asset(...)
- Kopira fajl u data/attachments/<kategorija>/<asset_uid>__<slug_naziva>/...
- Čuva REL putanju (rel_path) u bazi, portabilno

MARKER: ATTACHMENTS_SERVICE_V6_ONE_DB_2026_02_07
"""

from __future__ import annotations

import hashlib
import re
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.db import connect_db


# -------------------- helpers --------------------

def _app_root() -> Path:
    """
    Jedinstven root (da rel_path bude konzistentan sa ostatkom aplikacije).
    Prefer: core.paths.APP_ROOT
    Fallback: parent.parent od services/...
    """
    try:
        from core.paths import APP_ROOT  # type: ignore
        if APP_ROOT:
            return Path(APP_ROOT).resolve()
    except Exception:
        pass
    return Path(__file__).resolve().parent.parent


def _attachments_root() -> Path:
    d = _app_root() / "data" / "attachments"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _safe_name(name: str) -> str:
    name = (name or "").strip() or "file"
    name = name.replace("\\", "_").replace("/", "_").replace(":", "_")
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name[:180] if len(name) > 180 else name


def _slug(s: str) -> str:
    s = (s or "").strip().lower()
    if not s:
        return "bez-naziva"
    s = s.replace("đ", "dj").replace("č", "c").replace("ć", "c").replace("š", "s").replace("ž", "z")
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s[:60] if len(s) > 60 else s


def _safe_folder(seg: str) -> str:
    seg = (seg or "").strip() or "Ostalo"
    seg = seg.replace("\\", "_").replace("/", "_").replace(":", "_")
    seg = re.sub(r"[^A-Za-z0-9._ -]+", "_", seg)
    seg = re.sub(r"\s+", " ", seg).strip()
    return seg[:80] if len(seg) > 80 else seg


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _to_rel(path_abs: Path) -> str:
    """
    Čuva REL putanju u bazi (portabilno).
    """
    try:
        return path_abs.resolve().relative_to(_app_root().resolve()).as_posix()
    except Exception:
        return path_abs.name


def _to_abs(rel_path: str) -> Path:
    rp = (rel_path or "").strip()
    if not rp:
        return Path()
    p = Path(rp)
    if p.is_absolute():
        return p
    return (_app_root() / p).resolve()


@contextmanager
def _connect_db():
    """
    ✅ Jedna istina za DB: koristi core.db.connect_db() (core.paths.DB_PATH).
    """
    conn = connect_db()
    try:
        # core.db već setuje pragme; ovde samo dodatno osiguranje (ne škodi)
        try:
            conn.execute("PRAGMA busy_timeout=2500;")
        except Exception:
            pass
        yield conn
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;",
        (name,)
    ).fetchone()
    return bool(r)


def _table_info(conn: sqlite3.Connection, name: str) -> List[Tuple[Any, ...]]:
    try:
        return conn.execute(f"PRAGMA table_info({name});").fetchall()
    except Exception:
        return []


def _table_cols(conn: sqlite3.Connection, name: str) -> List[str]:
    rows = _table_info(conn, name)
    cols: List[str] = []
    for r in rows:
        try:
            cols.append(str(r[1]))
        except Exception:
            pass
    return cols


def _detect_path_col(cols: List[str]) -> str:
    if "rel_path" in cols:
        return "rel_path"
    if "stored_path" in cols:
        return "stored_path"
    if "path" in cols:
        return "path"
    return ""


def _has_cols(cols: List[str], names: List[str]) -> bool:
    return all(n in cols for n in names)


def _get_asset_meta(asset_uid: str) -> Dict[str, str]:
    """
    Pokušaj da pročita meta iz assets tabele (ako postoji).
    Ne zavisi od services.assets_service (da izbegnemo cikluse).
    """
    au = (asset_uid or "").strip()
    if not au:
        return {}

    with _connect_db() as conn:
        if not _table_exists(conn, "assets"):
            return {}
        cols = _table_cols(conn, "assets")

        name_col = "name" if "name" in cols else ""
        cat_col = "category" if "category" in cols else ""
        toc_col = "toc_number" if "toc_number" in cols else ("toc" if "toc" in cols else "")
        sn_col = "serial_number" if "serial_number" in cols else ("serial" if "serial" in cols else "")

        sel = []
        if name_col:
            sel.append(name_col)
        if cat_col:
            sel.append(cat_col)
        if toc_col:
            sel.append(toc_col)
        if sn_col:
            sel.append(sn_col)

        if not sel:
            return {}

        q = f"SELECT {', '.join(sel)} FROM assets WHERE asset_uid=? LIMIT 1;"
        row = conn.execute(q, (au,)).fetchone()
        if not row:
            return {}

        out: Dict[str, str] = {}
        idx = 0
        if name_col:
            out["name"] = str(row[idx] or "")
            idx += 1
        if cat_col:
            out["category"] = str(row[idx] or "")
            idx += 1
        if toc_col:
            out["toc_number"] = str(row[idx] or "")
            idx += 1
        if sn_col:
            out["serial_number"] = str(row[idx] or "")
            idx += 1
        return out


def _asset_folder_for(asset_uid: str) -> Path:
    """
    Folder za asset:
      data/attachments/<KATEGORIJA>/<ASSET_UID>__<slug_naziva>/
    Fallback: data/attachments/Ostalo/<ASSET_UID>/
    """
    meta = _get_asset_meta(asset_uid)
    cat = _safe_folder(meta.get("category", "") or "Ostalo")
    name_slug = _slug(meta.get("name", "") or "")
    au = (asset_uid or "").strip()

    if name_slug and name_slug != "bez-naziva":
        folder = f"{au}__{name_slug}"
    else:
        folder = au

    folder = _safe_folder(folder)
    return _attachments_root() / cat / folder


# -------------------- schema (self-heal) --------------------

def ensure_attachments_schema() -> None:
    _attachments_root()

    with _connect_db() as conn:
        if not _table_exists(conn, "attachments"):
            conn.execute("""
                CREATE TABLE IF NOT EXISTS attachments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity TEXT,
                    entity_id TEXT,
                    asset_uid TEXT,
                    file_name TEXT NOT NULL,
                    rel_path TEXT NOT NULL,
                    note TEXT,
                    actor TEXT,
                    source TEXT,
                    file_size INTEGER,
                    sha256 TEXT,
                    created_at TEXT NOT NULL,
                    is_deleted INTEGER NOT NULL DEFAULT 0
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_att_asset_uid ON attachments(asset_uid);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_att_entity ON attachments(entity, entity_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_att_created ON attachments(created_at);")
            return

        cols = _table_cols(conn, "attachments")

        def _add(col: str, ddl: str):
            nonlocal cols
            if col not in cols:
                conn.execute(f"ALTER TABLE attachments ADD COLUMN {ddl};")
                cols = _table_cols(conn, "attachments")

        _add("entity", "entity TEXT")
        _add("entity_id", "entity_id TEXT")
        _add("asset_uid", "asset_uid TEXT")
        _add("file_name", "file_name TEXT")
        _add("rel_path", "rel_path TEXT")
        _add("stored_path", "stored_path TEXT")
        _add("path", "path TEXT")
        _add("note", "note TEXT")
        _add("actor", "actor TEXT")
        _add("source", "source TEXT")
        _add("file_size", "file_size INTEGER")
        _add("sha256", "sha256 TEXT")
        _add("created_at", "created_at TEXT")
        _add("is_deleted", "is_deleted INTEGER NOT NULL DEFAULT 0")

        cols = _table_cols(conn, "attachments")
        if "asset_uid" in cols and "entity" in cols and "entity_id" in cols:
            conn.execute("""
                UPDATE attachments
                   SET asset_uid = COALESCE(asset_uid, entity_id)
                 WHERE (asset_uid IS NULL OR asset_uid = '')
                   AND entity = 'assets'
                   AND entity_id IS NOT NULL
                   AND entity_id <> '';
            """)

        cols = _table_cols(conn, "attachments")
        if "rel_path" in cols and "stored_path" in cols:
            conn.execute("""
                UPDATE attachments
                   SET rel_path = COALESCE(rel_path, stored_path)
                 WHERE (rel_path IS NULL OR rel_path = '')
                   AND stored_path IS NOT NULL
                   AND stored_path <> '';
            """)
        cols = _table_cols(conn, "attachments")
        if "rel_path" in cols and "path" in cols:
            conn.execute("""
                UPDATE attachments
                   SET rel_path = COALESCE(rel_path, path)
                 WHERE (rel_path IS NULL OR rel_path = '')
                   AND path IS NOT NULL
                   AND path <> '';
            """)

        cols = _table_cols(conn, "attachments")
        if "created_at" in cols:
            conn.execute("""
                UPDATE attachments
                   SET created_at = COALESCE(created_at, ?)
                 WHERE created_at IS NULL OR created_at = '';
            """, (_now_str(),))

        cols = _table_cols(conn, "attachments")
        for c in ("entity", "entity_id", "asset_uid", "note", "actor", "source", "file_name", "rel_path", "stored_path", "path"):
            if c in cols:
                conn.execute(f"UPDATE attachments SET {c}='' WHERE {c} IS NULL;")


# -------------------- internal: SELECT with rowid --------------------

def _select_list_sql(conn: sqlite3.Connection) -> Tuple[str, str, bool, bool]:
    cols = _table_cols(conn, "attachments")
    path_col = _detect_path_col(cols)
    if not path_col:
        raise RuntimeError("Tabela attachments nema rel_path/stored_path/path kolonu.")

    has_asset_uid = "asset_uid" in cols
    has_entity = _has_cols(cols, ["entity", "entity_id"])

    if "file_name" not in cols:
        raise RuntimeError("Tabela attachments nema file_name kolonu.")

    created = "created_at" if "created_at" in cols else "'' AS created_at"
    note = "note" if "note" in cols else "'' AS note"
    actor = "actor" if "actor" in cols else "'' AS actor"
    source = "source" if "source" in cols else "'' AS source"
    file_size = "file_size" if "file_size" in cols else "0 AS file_size"
    sha256 = "sha256" if "sha256" in cols else "'' AS sha256"
    asset = "asset_uid" if has_asset_uid else "entity_id"

    select_cols = (
        f"rowid AS __rid, {asset} AS asset_uid, file_name, {path_col} AS rel_path, "
        f"{created}, {note}, {actor}, {source}, {file_size}, {sha256}"
    )
    return path_col, select_cols, has_asset_uid, has_entity


# -------------------- public API --------------------

def list_attachments_for_asset(asset_uid: str, limit: int = 2000) -> List[Dict[str, Any]]:
    ensure_attachments_schema()
    au = (asset_uid or "").strip()
    if not au:
        return []

    with _connect_db() as conn:
        _, select_cols, has_asset_uid, has_entity = _select_list_sql(conn)

        if has_asset_uid:
            q = f"""
                SELECT {select_cols}
                  FROM attachments
                 WHERE is_deleted=0 AND asset_uid=?
                 ORDER BY rowid DESC
                 LIMIT ?;
            """
            rows = conn.execute(q, (au, int(limit))).fetchall()
        elif has_entity:
            q = f"""
                SELECT {select_cols}
                  FROM attachments
                 WHERE is_deleted=0 AND entity='assets' AND entity_id=?
                 ORDER BY rowid DESC
                 LIMIT ?;
            """
            rows = conn.execute(q, (au, int(limit))).fetchall()
        else:
            return []

    out: List[Dict[str, Any]] = []
    for r in rows:
        att_id = int(r[0])
        file_name = r[2] or ""
        out.append({
            "att_id": att_id,
            "id": att_id,
            "file_name": file_name,
            "name": file_name,

            "asset_uid": r[1] or "",
            "rel_path": r[3] or "",
            "created_at": r[4] or "",
            "note": r[5] or "",
            "actor": r[6] or "",
            "source": r[7] or "",
            "file_size": r[8] or 0,
            "sha256": r[9] or "",
        })
    return out


def add_attachment_to_asset(
    actor: str,
    asset_uid: str,
    src_file_path: str,
    note: str = "",
    source: str = "ui_add_attachment"
) -> int:
    ensure_attachments_schema()

    au = (asset_uid or "").strip()
    if not au:
        raise ValueError("asset_uid je prazan. Ne mogu da dodam prilog.")

    src = Path((src_file_path or "").strip())
    if not src.exists() or not src.is_file():
        raise FileNotFoundError(f"Fajl ne postoji: {src}")

    dst_dir = _asset_folder_for(au)
    dst_dir.mkdir(parents=True, exist_ok=True)

    safe = _safe_name(src.name)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = dst_dir / f"{ts}__{safe}"

    shutil.copy2(src.as_posix(), dst.as_posix())

    relp = _to_rel(dst) or dst.name

    try:
        size = int(dst.stat().st_size)
    except Exception:
        size = 0

    try:
        sha = _sha256_file(dst)
    except Exception:
        sha = ""

    now = _now_str()
    act = (actor or "").strip() or "user"
    nt = (note or "").strip()
    src_tag = (source or "").strip() or "ui_add_attachment"

    with _connect_db() as conn:
        cols = _table_cols(conn, "attachments")
        path_col = _detect_path_col(cols)
        if not path_col:
            raise RuntimeError("Tabela attachments nema rel_path/stored_path/path kolonu.")

        has_asset = "asset_uid" in cols
        has_entity = _has_cols(cols, ["entity", "entity_id"])

        if "file_name" not in cols:
            raise RuntimeError("Tabela attachments nema file_name kolonu.")

        fields: List[str] = []
        vals: List[Any] = []

        if has_asset:
            fields.append("asset_uid")
            vals.append(au)

        if has_entity:
            fields.append("entity")
            vals.append("assets")
            fields.append("entity_id")
            vals.append(au)

        fields.append("file_name")
        vals.append(safe)

        fields.append(path_col)
        vals.append(relp)

        if "rel_path" in cols and path_col != "rel_path":
            fields.append("rel_path")
            vals.append(relp)
        if "stored_path" in cols and path_col != "stored_path":
            fields.append("stored_path")
            vals.append(relp)
        if "path" in cols and path_col != "path":
            fields.append("path")
            vals.append(relp)

        if "note" in cols:
            fields.append("note")
            vals.append(nt)
        if "actor" in cols:
            fields.append("actor")
            vals.append(act)
        if "source" in cols:
            fields.append("source")
            vals.append(src_tag)
        if "file_size" in cols:
            fields.append("file_size")
            vals.append(int(size))
        if "sha256" in cols:
            fields.append("sha256")
            vals.append(sha)
        if "created_at" in cols:
            fields.append("created_at")
            vals.append(now)
        if "is_deleted" in cols:
            fields.append("is_deleted")
            vals.append(0)

        q = f"INSERT INTO attachments ({', '.join(fields)}) VALUES ({', '.join(['?'] * len(fields))});"
        cur = conn.execute(q, tuple(vals))

        try:
            rid = int(cur.lastrowid)  # type: ignore[attr-defined]
        except Exception:
            rid = int(conn.execute("SELECT last_insert_rowid();").fetchone()[0])
        return rid


def delete_attachment(actor: str, att_id: int, source: str = "ui_delete_attachment") -> bool:
    ensure_attachments_schema()
    rid = int(att_id)

    with _connect_db() as conn:
        row = conn.execute("SELECT rowid FROM attachments WHERE rowid=? AND is_deleted=0;", (rid,)).fetchone()
        if not row:
            return False

        cols = _table_cols(conn, "attachments")
        if "actor" in cols and "source" in cols:
            conn.execute(
                "UPDATE attachments SET is_deleted=1, actor=?, source=? WHERE rowid=?;",
                ((actor or "user").strip(), (source or "ui_delete_attachment").strip(), rid)
            )
        else:
            conn.execute("UPDATE attachments SET is_deleted=1 WHERE rowid=?;", (rid,))
    return True


def get_attachment_abs_path(att_id: int) -> str:
    ensure_attachments_schema()
    rid = int(att_id)

    with _connect_db() as conn:
        cols = _table_cols(conn, "attachments")
        for col in ("rel_path", "stored_path", "path"):
            if col in cols:
                row = conn.execute(f"SELECT {col} FROM attachments WHERE rowid=?;", (rid,)).fetchone()
                rp = (row[0] if row and row[0] else "") or ""
                rp = (rp or "").strip()
                if not rp:
                    continue  # ✅ ne vraćaj "."
                p = _to_abs(rp)
                return p.as_posix() if str(p).strip() else ""
        return ""


# -------- kompatibilni aliasi za UI (razni pozivi) --------

def list_attachments(asset_uid: str = "", entity: str = "assets", entity_id: str = "", limit: int = 2000) -> List[Dict[str, Any]]:
    au = (asset_uid or "").strip() or (entity_id or "").strip()
    return list_attachments_for_asset(au, limit=int(limit))


def add_attachment(*args, **kwargs) -> int:
    """
    Kompatibilni wrapper jer razni UI kodovi zovu add_attachment različito.

    Podržava tipične pozive:
      add_attachment(actor, asset_uid, src_file_path, note="", source="...")
      add_attachment(actor=..., asset_uid=..., src_file_path=..., note=..., source=...)
      add_attachment(actor=..., entity="assets", entity_id=asset_uid, src_file_path=..., note=..., source=...)

    Ako UI pogrešno prosledi parametre, ovde ih "ispeglamo" koliko god možemo.
    """
    actor = kwargs.get("actor", "") or ""
    asset_uid = kwargs.get("asset_uid", "") or ""
    src_file_path = kwargs.get("src_file_path", "") or ""
    note = kwargs.get("note", "") or ""
    source = kwargs.get("source", "ui_add_attachment") or "ui_add_attachment"
    entity = kwargs.get("entity", "assets") or "assets"
    entity_id = kwargs.get("entity_id", "") or ""

    if args:
        if not actor and len(args) >= 1:
            actor = str(args[0] or "")
        if not asset_uid and len(args) >= 2:
            asset_uid = str(args[1] or "")
        if not src_file_path and len(args) >= 3:
            src_file_path = str(args[2] or "")
        if len(args) >= 4 and kwargs.get("note", None) is None:
            note = str(args[3] or "")
        if len(args) >= 5 and kwargs.get("source", None) is None:
            source = str(args[4] or source)

    au = (asset_uid or "").strip()
    if not au and entity == "assets":
        au = (entity_id or "").strip()

    return add_attachment_to_asset(
        actor=str(actor or "user"),
        asset_uid=au,
        src_file_path=str(src_file_path or ""),
        note=str(note or ""),
        source=str(source or "ui_add_attachment"),
    )


# END FILENAME: services/attachments_service.py