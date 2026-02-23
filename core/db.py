# FILENAME: core/db.py
# (FILENAME: core/db.py - START PART 1/4)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — core/db.py

- SQLite konekcija + stabilne pragme
- Migracije (schema_version)
- Audit log
- asset_uid generator
- Assets CRUD (V1)
- Assignments (V1)
- Audit read (po entitetu i globalno)

NOVO:
- assets.sector, assets.is_metrology
- assets.rb + asset_rb_seq (stabilan redni broj)
- asset_events (timeline)

PATCH (bitno):
- db_conn() context manager koji UVEK zatvara sqlite konekciju
  (sqlite3.Connection kao context manager NE zatvara konekciju).

DODATO (2026-02):
- assets.nomenclature_number (nomenklaturni broj) — TEXT, nije unique
- migration v7 (ALTER TABLE + index)

REV (2026-02-12+):
- Uklonjen dupli __future__ import (mora biti samo jednom i pri vrhu)
- Fajl je jedan (nema "PART 2" mini-headera)
- init_db stabilizovan (commit i kad nema migracija)
- Audit write fail-safe i za ne-JSON objekte
- Minimalna zaštita identifikatora (table/col) protiv SQL foot-gun
- Clamp limit vrednosti (za list_* upite)
- Kompatibilni aliasi ostaju

Hardening (2026-02-22):
- Migration v1: UNIQUE TOC index pravi se best-effort (ne ruši app ako legacy DB ima duplikate).
- Write transakcije: schema ensure ide pre BEGIN IMMEDIATE (manje lock contention-a).
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, date
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Callable

log = logging.getLogger(__name__)

try:
    from core.paths import DB_PATH  # type: ignore
except Exception:
    DB_PATH = None  # type: ignore

try:
    from core.config import DB_FILE  # type: ignore
except Exception:
    DB_FILE = "data/db/bazas2.sqlite"  # fallback


# =========================
# CONSTANTS
# =========================

NOMENCLATURE_COL = "nomenclature_number"
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _is_safe_ident(name: str) -> bool:
    try:
        return bool(name) and bool(_IDENT_RE.match(str(name)))
    except Exception:
        return False


def _clamp_int(v: Any, default: int, *, min_v: int = 1, max_v: int = 100000) -> int:
    try:
        iv = int(v)
    except Exception:
        iv = int(default)
    if iv < min_v:
        iv = min_v
    if iv > max_v:
        iv = max_v
    return iv


# =========================
# TIME / PATH HELPERS
# =========================

def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_path_any(p: Any) -> Path:
    if p is None:
        return Path("")
    try:
        pp = Path(p)  # type: ignore[arg-type]
    except Exception:
        pp = Path(str(p))

    if not pp.is_absolute():
        pp = (_project_root() / pp).resolve()
    else:
        pp = pp.resolve()
    return pp


def _resolve_db_path() -> str:
    # Jedna istina: DB_PATH (ako postoji) inače DB_FILE, oba resolve na apsolutno
    if DB_PATH is not None:
        try:
            raw = str(DB_PATH).strip()
        except Exception:
            raw = ""
        if raw:
            p = _resolve_path_any(raw)
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            return str(p)

    p2 = _resolve_path_any(DB_FILE)
    try:
        p2.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return str(p2)


def get_db_path() -> str:
    return _resolve_db_path()


def _apply_pragmas_best_effort(conn: sqlite3.Connection) -> None:
    """
    Best-effort PRAGMA set. Ne ruši app na mrežnim share-ovima / read-only / starim FS.
    """
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA busy_timeout = 5000;")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA synchronous = NORMAL;")
    except Exception:
        pass


def connect_db() -> sqlite3.Connection:
    """
    Vraca sqlite3.Connection (kompatibilno sa ostatkom sistema).

    ⚠️ Napomena:
      sqlite3.Connection kao context manager NE zatvara konekciju.
      Zato u ovom fajlu koristi db_conn() umesto `with connect_db() as conn:`.
    """
    db_path = _resolve_db_path()
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    _apply_pragmas_best_effort(conn)
    return conn


@contextmanager
def db_conn():
    """
    Siguran context manager koji UVEK zatvara konekciju.
    """
    conn = connect_db()
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


# =========================
# SCHEMA VERSION HELPERS
# =========================

def _ensure_schema_version_table(conn: sqlite3.Connection) -> bool:
    """
    Kreira schema_version i osigurava da postoji red id=1.
    Vraća True ako je upis izvršen (potreban commit).
    """
    changed = False
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            id INTEGER PRIMARY KEY CHECK (id=1),
            version INTEGER NOT NULL
        );
    """)
    row = conn.execute("SELECT version FROM schema_version WHERE id=1;").fetchone()
    if row is None:
        conn.execute("INSERT INTO schema_version (id, version) VALUES (1, 0);")
        changed = True
    return changed


def _get_schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT version FROM schema_version WHERE id=1;").fetchone()
    return int(row["version"]) if row else 0


def _set_schema_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute("UPDATE schema_version SET version=? WHERE id=1;", (int(version),))


def row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    try:
        return {k: row[k] for k in row.keys()}
    except Exception:
        return dict(row)  # type: ignore[arg-type]


# =========================
# DB INTROSPECTION HELPERS
# =========================

def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    if not _is_safe_ident(table):
        return False
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;",
        (table,),
    ).fetchone()
    return row is not None


def _column_exists(conn: sqlite3.Connection, table: str, col: str) -> bool:
    if not _is_safe_ident(table) or not col:
        return False
    if not _table_exists(conn, table):
        return False
    try:
        rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
    except Exception:
        return False
    for r in rows:
        try:
            if (r["name"] or "").lower() == str(col).lower():
                return True
        except Exception:
            continue
    return False


# =========================
# AUDIT LOG
# =========================

def _safe_json(obj: Any) -> Optional[str]:
    try:
        if obj is None:
            return None
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        try:
            return json.dumps(str(obj), ensure_ascii=False)
        except Exception:
            return None


def write_audit(
    conn: sqlite3.Connection,
    actor: str,
    entity: str,
    entity_id: Optional[str],
    action: str,
    before_obj: Optional[Dict[str, Any]],
    after_obj: Optional[Dict[str, Any]],
    source: Optional[str] = None,
) -> None:
    # Fail-safe: osiguraj da audit_log postoji (ako init_db nije pozvan)
    try:
        if not _table_exists(conn, "audit_log"):
            _migration_v1(conn)
            try:
                conn.commit()
            except Exception:
                pass
    except Exception:
        pass

    conn.execute(
        """
        INSERT INTO audit_log (event_time, actor, entity, entity_id, action, before_json, after_json, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            _now_iso(),
            (actor or "").strip() or "user",
            (entity or "").strip() or "unknown",
            (entity_id or None),
            (action or "").strip() or "UNKNOWN",
            _safe_json(before_obj),
            _safe_json(after_obj),
            (source or None),
        ),
    )


# =========================
# TIMELINE / ASSET EVENTS
# =========================

def write_asset_event(
    conn: sqlite3.Connection,
    *,
    actor: str,
    asset_uid: str,
    event_type: str,
    data_obj: Optional[Dict[str, Any]] = None,
    source: Optional[str] = None,
    event_time: Optional[str] = None,
) -> None:
    et = (event_type or "").strip().upper()
    uid = (asset_uid or "").strip()
    if not et or not uid:
        return

    # Fail-safe: osiguraj da tabela postoji
    try:
        _migration_v6(conn)
    except Exception:
        pass

    tm = (event_time or "").strip() or _now_iso()
    conn.execute(
        """
        INSERT INTO asset_events (event_time, actor, asset_uid, event_type, data_json, source)
        VALUES (?, ?, ?, ?, ?, ?);
        """,
        (
            tm,
            (actor or "").strip() or "user",
            uid,
            et,
            _safe_json(data_obj),
            (source or "").strip() or None,
        ),
    )


def _diff_fields(before: Dict[str, Any], after: Dict[str, Any], keys: List[str]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for k in keys:
        bv = before.get(k)
        av = after.get(k)
        bsn = "" if bv is None else str(bv)
        asn = "" if av is None else str(av)
        if bsn != asn:
            out[k] = {"from": bv, "to": av}
    return out


# =========================
# METROLOGY EXISTENCE HELPER (compat)
# =========================

def asset_has_metrology_record(conn: sqlite3.Connection, asset_uid: str) -> bool:
    uid = (asset_uid or "").strip()
    if not uid:
        return False

    candidates = ["metrology_records", "metrology", "calibration_records"]
    for t in candidates:
        if not _table_exists(conn, t):
            continue
        if not _column_exists(conn, t, "asset_uid"):
            continue
        row = conn.execute(f"SELECT 1 FROM {t} WHERE asset_uid=? LIMIT 1;", (uid,)).fetchone()
        if row is not None:
            return True
    return False


def has_metrology_record_for_asset(asset_uid: str) -> bool:
    uid = (asset_uid or "").strip()
    if not uid:
        return False
    with db_conn() as conn:
        try:
            return bool(asset_has_metrology_record(conn, uid))
        except Exception:
            return False


def has_metrology_for_asset(asset_uid: str) -> bool:
    return has_metrology_record_for_asset(asset_uid)


# =========================
# MIGRATIONS
# =========================
# (FILENAME: core/db.py - END PART 1/4)

# FILENAME: core/db.py
# (FILENAME: core/db.py - START PART 2/4)
def _try_create_assets_toc_unique_index(conn: sqlite3.Connection) -> None:
    """
    Best-effort: UNIQUE TOC index.
    Legacy baze mogu već imati duplikate -> UNIQUE index pada.
    Ne rušimo app, ali ostavljamo signal u logu.
    """
    # Partial unique index: enforce uniqueness only for non-empty values
    sql = """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_toc_unique ON assets(toc_number)
            WHERE toc_number IS NOT NULL AND toc_number <> '';
    """
    try:
        conn.execute(sql)
    except Exception as e:
        try:
            log.warning("TOC unique index not created (legacy duplicates?) — continuing. (%s)", e)
        except Exception:
            pass
        # fallback non-unique index for performance (best-effort)
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_toc ON assets(toc_number);")
        except Exception:
            pass


def _migration_v1(conn: sqlite3.Connection) -> None:
    # NOTE: UNIQUE idx_assets_toc_unique se pravi best-effort posle executescript-a (vidi helper gore)
    conn.executescript(f"""
        CREATE TABLE IF NOT EXISTS assets (
            asset_uid TEXT PRIMARY KEY,
            toc_number TEXT,
            serial_number TEXT,
            {NOMENCLATURE_COL} TEXT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            location TEXT,
            current_holder TEXT,
            sector TEXT,
            is_metrology INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_assets_name ON assets(name);
        CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
        CREATE INDEX IF NOT EXISTS idx_assets_category ON assets(category);
        CREATE INDEX IF NOT EXISTS idx_assets_sector ON assets(sector);
        CREATE INDEX IF NOT EXISTS idx_assets_is_metrology ON assets(is_metrology);
        CREATE INDEX IF NOT EXISTS idx_assets_nomenclature ON assets({NOMENCLATURE_COL});

        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            actor TEXT NOT NULL,
            entity TEXT NOT NULL,
            entity_id TEXT,
            action TEXT NOT NULL,
            before_json TEXT,
            after_json TEXT,
            source TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(event_time);

        CREATE TABLE IF NOT EXISTS asset_uid_seq (
            year INTEGER PRIMARY KEY,
            last_num INTEGER NOT NULL
        );
    """)
    _try_create_assets_toc_unique_index(conn)


def _migration_v2(conn: sqlite3.Connection) -> None:
    if not _column_exists(conn, "assets", "current_holder"):
        conn.execute("ALTER TABLE assets ADD COLUMN current_holder TEXT;")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS assignments (
            assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            asset_uid TEXT NOT NULL,
            action TEXT NOT NULL,
            from_holder TEXT,
            to_holder TEXT,
            from_location TEXT,
            to_location TEXT,
            note TEXT,
            FOREIGN KEY (asset_uid) REFERENCES assets(asset_uid) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_assignments_asset ON assignments(asset_uid);
        CREATE INDEX IF NOT EXISTS idx_assignments_time ON assignments(created_at);
    """)


def _migration_v3(conn: sqlite3.Connection) -> None:
    if not _column_exists(conn, "assets", "current_holder"):
        conn.execute("ALTER TABLE assets ADD COLUMN current_holder TEXT;")

    if not _table_exists(conn, "assignments"):
        _migration_v2(conn)
        return

    required_cols = [
        ("created_at", "TEXT NOT NULL"),
        ("asset_uid", "TEXT NOT NULL"),
        ("action", "TEXT NOT NULL"),
        ("from_holder", "TEXT"),
        ("to_holder", "TEXT"),
        ("from_location", "TEXT"),
        ("to_location", "TEXT"),
        ("note", "TEXT"),
    ]
    for col, decl in required_cols:
        if not _column_exists(conn, "assignments", col):
            conn.execute(f"ALTER TABLE assignments ADD COLUMN {col} {decl};")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_assignments_asset ON assignments(asset_uid);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assignments_time ON assignments(created_at);")


def _migration_v4(conn: sqlite3.Connection) -> None:
    if not _column_exists(conn, "assets", "sector"):
        conn.execute("ALTER TABLE assets ADD COLUMN sector TEXT;")

    if not _column_exists(conn, "assets", "is_metrology"):
        conn.execute("ALTER TABLE assets ADD COLUMN is_metrology INTEGER NOT NULL DEFAULT 0;")

    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_sector ON assets(sector);")
    except Exception:
        pass
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_is_metrology ON assets(is_metrology);")
    except Exception:
        pass

    # Best-effort: ensure TOC unique index exists when possible
    try:
        _try_create_assets_toc_unique_index(conn)
    except Exception:
        pass


def _migration_v5(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "assets"):
        try:
            _migration_v1(conn)
        except Exception:
            pass

    if not _column_exists(conn, "assets", "rb"):
        conn.execute("ALTER TABLE assets ADD COLUMN rb INTEGER;")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS asset_rb_seq (
            id INTEGER PRIMARY KEY CHECK (id=1),
            last_rb INTEGER NOT NULL
        );
    """)

    rows = conn.execute("""
        SELECT asset_uid
        FROM assets
        WHERE rb IS NULL
        ORDER BY COALESCE(created_at,'') ASC, asset_uid ASC
    """).fetchall()

    if rows:
        mx = conn.execute("SELECT COALESCE(MAX(rb), 0) AS m FROM assets;").fetchone()
        cur_rb = int(mx["m"] or 0) if mx else 0
        for rr in rows:
            cur_rb += 1
            conn.execute(
                "UPDATE assets SET rb=? WHERE asset_uid=? AND rb IS NULL;",
                (cur_rb, rr["asset_uid"])
            )

    mx2 = conn.execute("SELECT COALESCE(MAX(rb), 0) AS m FROM assets;").fetchone()
    last_rb = int(mx2["m"] or 0) if mx2 else 0

    row = conn.execute("SELECT last_rb FROM asset_rb_seq WHERE id=1;").fetchone()
    if row is None:
        conn.execute("INSERT INTO asset_rb_seq (id, last_rb) VALUES (1, ?);", (last_rb,))
    else:
        conn.execute("UPDATE asset_rb_seq SET last_rb=? WHERE id=1;", (last_rb,))

    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_rb ON assets(rb);")
    except Exception:
        pass
    try:
        # Ako postoje duplikati iz legacy baze, unique index može da padne — ne rušimo aplikaciju.
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_rb_unique ON assets(rb);")
    except Exception:
        pass


def _migration_v6(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS asset_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            actor TEXT NOT NULL,
            asset_uid TEXT NOT NULL,
            event_type TEXT NOT NULL,
            data_json TEXT,
            source TEXT,
            FOREIGN KEY (asset_uid) REFERENCES assets(asset_uid) ON DELETE CASCADE
        );
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_events_uid_time ON asset_events(asset_uid, event_time);")
    except Exception:
        pass
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_events_type ON asset_events(event_type);")
    except Exception:
        pass
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_events_time ON asset_events(event_time);")
    except Exception:
        pass


def _migration_v7(conn: sqlite3.Connection) -> None:
    """
    Nomenklaturni broj (nomenclature_number) — TEXT, nije unique.
    """
    try:
        if not _table_exists(conn, "assets"):
            _migration_v1(conn)
    except Exception:
        pass

    try:
        if not _column_exists(conn, "assets", NOMENCLATURE_COL):
            conn.execute(f"ALTER TABLE assets ADD COLUMN {NOMENCLATURE_COL} TEXT;")
    except Exception:
        pass

    try:
        conn.execute(f"CREATE INDEX IF NOT EXISTS idx_assets_nomenclature ON assets({NOMENCLATURE_COL});")
    except Exception:
        pass

    # Best-effort: ensure TOC unique index exists when possible
    try:
        _try_create_assets_toc_unique_index(conn)
    except Exception:
        pass


MIGRATIONS: List[Tuple[int, Callable[[sqlite3.Connection], None]]] = [
    (1, _migration_v1),
    (2, _migration_v2),
    (3, _migration_v3),
    (4, _migration_v4),
    (5, _migration_v5),
    (6, _migration_v6),
    (7, _migration_v7),  # ✅ nomenklaturni broj
]


def init_db() -> Tuple[int, int]:
    with db_conn() as conn:
        changed = False
        try:
            changed = _ensure_schema_version_table(conn)
        except Exception:
            changed = False

        current = _get_schema_version(conn)
        latest = max([v for v, _ in MIGRATIONS], default=0)

        if current != latest:
            for v, fn in sorted(MIGRATIONS, key=lambda x: x[0]):
                if v <= current:
                    continue
                fn(conn)
                _set_schema_version(conn, v)
                changed = True
            try:
                conn.commit()
            except Exception:
                pass
        else:
            if changed:
                try:
                    conn.commit()
                except Exception:
                    pass

        return current, latest


# =========================
# UID + RB GENERATORS
# =========================

def generate_asset_uid(conn: sqlite3.Connection, prefix: str = "A") -> str:
    y = date.today().year
    row = conn.execute("SELECT last_num FROM asset_uid_seq WHERE year=?;", (y,)).fetchone()
    if row is None:
        conn.execute("INSERT INTO asset_uid_seq (year, last_num) VALUES (?, ?);", (y, 0))
        last = 0
    else:
        last = int(row["last_num"])
    new_num = last + 1
    conn.execute("UPDATE asset_uid_seq SET last_num=? WHERE year=?;", (new_num, y))
    return f"{prefix}-{y}-{new_num:07d}"


def generate_asset_rb(conn: sqlite3.Connection) -> int:
    # fail-safe: obezbedi rb
    try:
        _migration_v5(conn)
    except Exception:
        pass

    conn.execute("""
        CREATE TABLE IF NOT EXISTS asset_rb_seq (
            id INTEGER PRIMARY KEY CHECK (id=1),
            last_rb INTEGER NOT NULL
        );
    """)
    row = conn.execute("SELECT last_rb FROM asset_rb_seq WHERE id=1;").fetchone()
    if row is None:
        mx = conn.execute("SELECT COALESCE(MAX(rb), 0) AS m FROM assets;").fetchone()
        last_rb = int(mx["m"] or 0) if mx else 0
        conn.execute("INSERT INTO asset_rb_seq (id, last_rb) VALUES (1, ?);", (last_rb,))
    else:
        last_rb = int(row["last_rb"] or 0)

    new_rb = last_rb + 1
    conn.execute("UPDATE asset_rb_seq SET last_rb=? WHERE id=1;", (new_rb,))
    return new_rb


# =========================
# INTERNAL TX HELPERS
# =========================

def _begin_immediate(conn: sqlite3.Connection) -> None:
    """Pokušaj da podigneš write-lock rano (stabilnije pod opterećenjem)."""
    try:
        conn.execute("BEGIN IMMEDIATE;")
    except Exception:
        pass


def _commit_quiet(conn: sqlite3.Connection) -> None:
    try:
        conn.commit()
    except Exception:
        pass


def _rollback_quiet(conn: sqlite3.Connection) -> None:
    try:
        conn.rollback()
    except Exception:
        pass


def _ensure_schema_for_assets(conn: sqlite3.Connection, *, with_events: bool = False, with_rb: bool = False) -> None:
    """
    Fail-safe schema za assets (i opciono events/rb).
    Ne menja logiku, samo sprečava 'no such table/column' edge-case kad init_db nije pozvan.
    """
    try:
        _migration_v1(conn)
    except Exception:
        pass
    if with_rb:
        try:
            _migration_v5(conn)
        except Exception:
            pass
    if with_events:
        try:
            _migration_v6(conn)
        except Exception:
            pass
    try:
        _migration_v7(conn)
    except Exception:
        pass


def _ensure_schema_for_assignments(conn: sqlite3.Connection) -> None:
    try:
        _migration_v1(conn)
    except Exception:
        pass
    try:
        _migration_v2(conn)
    except Exception:
        pass
    try:
        _migration_v5(conn)
    except Exception:
        pass
    try:
        _migration_v6(conn)
    except Exception:
        pass
    try:
        _migration_v7(conn)
    except Exception:
        pass


# =========================
# ASSETS (DB)
# =========================
# (FILENAME: core/db.py - END PART 2/4)


# FILENAME: core/db.py
# (FILENAME: core/db.py - START PART 3/4)
def create_asset_db(
    actor: str,
    name: str,
    category: str,
    toc_number: str = "",
    serial_number: str = "",
    nomenclature_number: str = "",
    location: str = "",
    status: str = "active",
    sector: str = "",
    is_metrology: int = 0,
    source: str = "create_asset",
) -> str:
    if not (name or "").strip():
        raise ValueError("name cannot be empty")
    if not (category or "").strip():
        raise ValueError("category cannot be empty")

    allowed_status = {"active", "on_loan", "service", "scrapped"}
    st = (status or "active").strip().lower()
    if st not in allowed_status:
        raise ValueError(f"status must be one of: {sorted(allowed_status)}")

    with db_conn() as conn:
        # fail-safe schema pre lock-a (manje contention-a)
        _ensure_schema_for_assets(conn, with_events=True, with_rb=True)
        _commit_quiet(conn)

        _begin_immediate(conn)

        try:
            rb = generate_asset_rb(conn)
            uid = generate_asset_uid(conn, prefix="A")
            now = _now_iso()

            nom = (nomenclature_number or "").strip()

            conn.execute(
                f"""
                INSERT INTO assets (
                    rb,
                    asset_uid, toc_number, serial_number, {NOMENCLATURE_COL}, name, category, status, location,
                    current_holder, sector, is_metrology, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    int(rb),
                    uid,
                    (toc_number or "").strip() or None,
                    (serial_number or "").strip() or None,
                    nom or None,
                    name.strip(),
                    category.strip(),
                    st,
                    (location or "").strip() or None,
                    None,
                    (sector or "").strip() or None,
                    1 if int(is_metrology or 0) == 1 else 0,
                    now,
                    now,
                ),
            )

            after = row_to_dict(conn.execute("SELECT * FROM assets WHERE asset_uid=?;", (uid,)).fetchone())
            write_audit(conn, actor, "assets", uid, "INSERT", None, after, source)

            try:
                write_asset_event(
                    conn,
                    actor=actor,
                    asset_uid=uid,
                    event_type="CREATED",
                    data_obj={
                        "rb": int(rb),
                        "name": name.strip(),
                        "category": category.strip(),
                        "status": st,
                        "location": (location or "").strip(),
                        "sector": (sector or "").strip(),
                        "is_metrology": 1 if int(is_metrology or 0) == 1 else 0,
                        NOMENCLATURE_COL: nom,
                    },
                    source=source,
                    event_time=now,
                )
            except Exception:
                pass

            conn.commit()
            return uid

        except sqlite3.IntegrityError as e:
            _rollback_quiet(conn)
            msg = str(e).lower()
            if "idx_assets_toc_unique" in msg or "toc_number" in msg:
                raise ValueError("TOC broj već postoji u bazi (mora biti jedinstven).") from e
            if "idx_assets_rb_unique" in msg or "rb" in msg:
                raise ValueError("RB kolizija (legacy duplikati). Pokreni servisnu proveru baze.") from e
            raise

        except Exception:
            _rollback_quiet(conn)
            raise


def update_asset_db(
    actor: str,
    asset_uid: str,
    *,
    status: Optional[str] = None,
    location: Optional[str] = None,
    toc_number: Optional[str] = None,
    serial_number: Optional[str] = None,
    nomenclature_number: Optional[str] = None,
    name: Optional[str] = None,
    category: Optional[str] = None,
    sector: Optional[str] = None,
    is_metrology: Optional[int] = None,
    source: str = "update_asset",
) -> None:
    uid = (asset_uid or "").strip()
    if not uid:
        raise ValueError("asset_uid cannot be empty")

    allowed_status = {"active", "on_loan", "service", "scrapped"}

    fields: Dict[str, Any] = {}
    if status is not None:
        st = (status or "").strip().lower()
        if st not in allowed_status:
            raise ValueError(f"status must be one of: {sorted(allowed_status)}")
        fields["status"] = st

    if location is not None:
        fields["location"] = ((location or "").strip() or None)

    if toc_number is not None:
        fields["toc_number"] = ((toc_number or "").strip() or None)

    if serial_number is not None:
        fields["serial_number"] = ((serial_number or "").strip() or None)

    if nomenclature_number is not None:
        fields[NOMENCLATURE_COL] = ((nomenclature_number or "").strip() or None)

    if name is not None:
        nm = (name or "").strip()
        if not nm:
            raise ValueError("name cannot be empty")
        fields["name"] = nm

    if category is not None:
        cat = (category or "").strip()
        if not cat:
            raise ValueError("category cannot be empty")
        fields["category"] = cat

    if sector is not None:
        fields["sector"] = ((sector or "").strip() or None)

    if is_metrology is not None:
        fields["is_metrology"] = 1 if int(is_metrology or 0) == 1 else 0

    if not fields:
        return

    now = _now_iso()

    with db_conn() as conn:
        # fail-safe schema pre lock-a
        _ensure_schema_for_assets(conn, with_events=True, with_rb=True)
        _commit_quiet(conn)

        _begin_immediate(conn)

        try:
            before = row_to_dict(conn.execute("SELECT * FROM assets WHERE asset_uid=?;", (uid,)).fetchone())
            if before is None:
                raise ValueError("asset not found")

            # Legacy: ako status nije on_loan -> očisti holder
            if "status" in fields and fields["status"] != "on_loan":
                fields["current_holder"] = None

            fields["updated_at"] = now

            cols = list(fields.keys())
            set_sql = ", ".join([f"{c}=?" for c in cols])
            params = [fields[c] for c in cols] + [uid]

            try:
                conn.execute(f"UPDATE assets SET {set_sql} WHERE asset_uid=?;", tuple(params))
            except sqlite3.IntegrityError as e:
                msg = str(e).lower()
                if "idx_assets_toc_unique" in msg or "toc_number" in msg:
                    raise ValueError("TOC broj već postoji u bazi (mora biti jedinstven).") from e
                raise

            after = row_to_dict(conn.execute("SELECT * FROM assets WHERE asset_uid=?;", (uid,)).fetchone())
            write_audit(conn, actor, "assets", uid, "UPDATE", before, after, source)

            # Timeline events (best-effort)
            try:
                if isinstance(before, dict) and isinstance(after, dict):
                    diffs = _diff_fields(
                        before,
                        after,
                        keys=[
                            "status", "location", "toc_number", "serial_number",
                            NOMENCLATURE_COL,
                            "name", "category", "sector", "is_metrology", "current_holder",
                        ],
                    )

                    if "status" in diffs:
                        frm = diffs["status"].get("from")
                        to = diffs["status"].get("to")
                        write_asset_event(
                            conn,
                            actor=actor,
                            asset_uid=uid,
                            event_type="STATUS_CHANGED",
                            data_obj={"from": frm, "to": to},
                            source=source,
                            event_time=now,
                        )

                        t = str(to or "").strip().lower()
                        f = str(frm or "").strip().lower()

                        if t == "scrapped":
                            write_asset_event(
                                conn, actor=actor, asset_uid=uid, event_type="SCRAPPED",
                                data_obj={"from": frm, "to": to}, source=source, event_time=now
                            )
                        if f == "scrapped" and t == "active":
                            write_asset_event(
                                conn, actor=actor, asset_uid=uid, event_type="RESTORED",
                                data_obj={"from": frm, "to": to}, source=source, event_time=now
                            )
                        if t == "service" and f != "service":
                            write_asset_event(
                                conn, actor=actor, asset_uid=uid, event_type="SERVICE_ENTER",
                                data_obj={"from": frm, "to": to}, source=source, event_time=now
                            )
                        if f == "service" and t != "service":
                            write_asset_event(
                                conn, actor=actor, asset_uid=uid, event_type="SERVICE_EXIT",
                                data_obj={"from": frm, "to": to}, source=source, event_time=now
                            )

                    if "location" in diffs:
                        write_asset_event(
                            conn, actor=actor, asset_uid=uid, event_type="LOCATION_CHANGED",
                            data_obj=diffs["location"], source=source, event_time=now
                        )

                    if "current_holder" in diffs:
                        write_asset_event(
                            conn, actor=actor, asset_uid=uid, event_type="HOLDER_CHANGED",
                            data_obj=diffs["current_holder"], source=source, event_time=now
                        )

                    for k, etype in (
                        ("toc_number", "TOC_CHANGED"),
                        ("serial_number", "SERIAL_CHANGED"),
                        (NOMENCLATURE_COL, "NOMENCLATURE_CHANGED"),
                        ("name", "NAME_CHANGED"),
                        ("category", "CATEGORY_CHANGED"),
                        ("sector", "SECTOR_CHANGED"),
                        ("is_metrology", "METRO_FLAG_CHANGED"),
                    ):
                        if k in diffs:
                            write_asset_event(
                                conn, actor=actor, asset_uid=uid, event_type=etype,
                                data_obj=diffs[k], source=source, event_time=now
                            )
            except Exception:
                pass

            conn.commit()

        except Exception:
            _rollback_quiet(conn)
            raise


def list_assets_db(
    search: str = "",
    category: str = "SVE",
    status: str = "SVE",
    sector: str = "SVE",
    metrology_only: bool = False,
    limit: int = 5000,
) -> List[Dict[str, Any]]:
    lim = _clamp_int(limit, 5000, min_v=1, max_v=100000)

    with db_conn() as conn:
        # fail-safe schema (rb bitan za pretragu)
        _ensure_schema_for_assets(conn, with_events=False, with_rb=True)
        _commit_quiet(conn)

        has_nom = False
        try:
            has_nom = _column_exists(conn, "assets", NOMENCLATURE_COL)
        except Exception:
            has_nom = False

        where: List[str] = []
        params: List[Any] = []

        s = (search or "").strip()
        if s:
            like = f"%{s}%"
            or_parts = [
                "asset_uid LIKE ?",
                "toc_number LIKE ?",
                "serial_number LIKE ?",
                "name LIKE ?",
                "location LIKE ?",
                "current_holder LIKE ?",
                "sector LIKE ?",
                "CAST(COALESCE(rb,'') AS TEXT) LIKE ?",
            ]
            params.extend([like, like, like, like, like, like, like, like])

            if has_nom:
                or_parts.append(f"{NOMENCLATURE_COL} LIKE ?")
                params.append(like)

            where.append("(" + " OR ".join(or_parts) + ")")

        if category and category != "SVE":
            where.append("category = ?")
            params.append(category)

        if status and status != "SVE":
            where.append("status = ?")
            params.append(status)

        sec = (sector or "SVE").strip()
        if sec and sec != "SVE":
            where.append("LOWER(TRIM(COALESCE(sector,''))) = LOWER(TRIM(?))")
            params.append(sec)

        if bool(metrology_only):
            where.append("COALESCE(is_metrology,0) = 1")

        select_cols = ["rb", "asset_uid", "toc_number", "serial_number"]
        if has_nom:
            select_cols.append(NOMENCLATURE_COL)
        select_cols += [
            "name", "category", "status", "location",
            "current_holder", "sector", "is_metrology", "created_at", "updated_at",
        ]

        sql = f"SELECT {', '.join(select_cols)} FROM assets"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(int(lim))

        rows = conn.execute(sql, tuple(params)).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]


def get_asset_db(asset_uid: str) -> Optional[Dict[str, Any]]:
    uid = (asset_uid or "").strip()
    if not uid:
        return None
    with db_conn() as conn:
        _ensure_schema_for_assets(conn, with_events=False, with_rb=True)
        _commit_quiet(conn)
        row = conn.execute("SELECT * FROM assets WHERE asset_uid=?;", (uid,)).fetchone()
        return row_to_dict(row)


# =========================
# TIMELINE READ API
# =========================

def list_asset_events_db(asset_uid: str, limit: int = 500) -> List[Dict[str, Any]]:
    uid = (asset_uid or "").strip()
    if not uid:
        return []
    lim = _clamp_int(limit, 500, min_v=1, max_v=100000)

    with db_conn() as conn:
        try:
            _migration_v6(conn)
        except Exception:
            pass
        _commit_quiet(conn)

        rows = conn.execute(
            """
            SELECT event_id, event_time, actor, asset_uid, event_type, data_json, source
            FROM asset_events
            WHERE asset_uid=?
            ORDER BY event_time DESC, event_id DESC
            LIMIT ?;
            """,
            (uid, int(lim)),
        ).fetchall()

        out: List[Dict[str, Any]] = []
        for r in rows:
            d = {k: r[k] for k in r.keys()}
            try:
                dj = d.get("data_json")
                d["data"] = json.loads(dj) if dj else None
            except Exception:
                d["data"] = None
            out.append(d)
        return out


# --- Kompatibilni aliasi ---------------------------------------

def get_asset_by_uid_db(*, asset_uid: str) -> Optional[Dict[str, Any]]:
    return get_asset_db(asset_uid)


def get_asset_by_uid(*, asset_uid: str) -> Optional[Dict[str, Any]]:
    return get_asset_db(asset_uid)


def get_asset(*, asset_uid: str) -> Optional[Dict[str, Any]]:
    return get_asset_db(asset_uid)


# (FILENAME: core/db.py - END PART 3/4)


# FILENAME: core/db.py
# (FILENAME: core/db.py - START PART 4/4)
def list_assets(
    *,
    q: str = "",
    search: str = "",
    category: str = "SVE",
    status: str = "SVE",
    sector: str = "SVE",
    metrology_only: bool = False,
    limit: int = 5000,
) -> List[Dict[str, Any]]:
    s = (q or "").strip() or (search or "").strip()
    return list_assets_db(
        search=s,
        category=category,
        status=status,
        sector=sector,
        metrology_only=metrology_only,
        limit=limit,
    )


def list_assets_brief_db(limit: int = 1000, sector: str = "SVE", metrology_only: bool = False) -> List[Dict[str, Any]]:
    lim = _clamp_int(limit, 1000, min_v=1, max_v=100000)

    with db_conn() as conn:
        _ensure_schema_for_assets(conn, with_events=False, with_rb=True)
        _commit_quiet(conn)

        has_nom = False
        try:
            has_nom = _column_exists(conn, "assets", NOMENCLATURE_COL)
        except Exception:
            has_nom = False

        where: List[str] = []
        params: List[Any] = []

        sec = (sector or "SVE").strip()
        if sec and sec != "SVE":
            where.append("LOWER(TRIM(COALESCE(sector,''))) = LOWER(TRIM(?))")
            params.append(sec)

        if bool(metrology_only):
            where.append("COALESCE(is_metrology,0) = 1")

        select_cols = ["rb", "asset_uid", "name", "category", "status", "current_holder", "sector", "is_metrology"]
        if has_nom:
            select_cols.append(NOMENCLATURE_COL)

        sql = f"SELECT {', '.join(select_cols)} FROM assets"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(int(lim))

        rows = conn.execute(sql, tuple(params)).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]


def list_assets_brief(*, limit: int = 1000, sector: str = "SVE", metrology_only: bool = False) -> List[Dict[str, Any]]:
    return list_assets_brief_db(limit=limit, sector=sector, metrology_only=metrology_only)


def create_asset(
    *,
    actor: str,
    name: str,
    category: str,
    toc: str = "",
    toc_number: str = "",
    serial: str = "",
    serial_number: str = "",
    nomenclature_number: str = "",
    location: str = "",
    status: str = "active",
    sector: str = "",
    is_metrology: int = 0,
    source: str = "create_asset",
    **_extra: Any,
) -> str:
    t = (toc_number or toc or "").strip()
    sn = (serial_number or serial or "").strip()
    nom = (nomenclature_number or "").strip()
    return create_asset_db(
        actor=actor,
        name=name,
        category=category,
        toc_number=t,
        serial_number=sn,
        nomenclature_number=nom,
        location=location,
        status=status,
        sector=sector,
        is_metrology=is_metrology,
        source=source,
    )


# =========================
# ASSIGNMENTS (DB)
# =========================

def create_assignment_db(
    actor: str,
    asset_uid: str,
    action: str,
    to_holder: str = "",
    to_location: str = "",
    note: str = "",
    source: str = "ui_new_assignment",
) -> int:
    action = (action or "").strip().lower()
    if action not in ("assign", "transfer", "return"):
        raise ValueError("action must be assign/transfer/return")

    uid = (asset_uid or "").strip()
    if not uid:
        raise ValueError("asset_uid cannot be empty")

    with db_conn() as conn:
        # fail-safe schema pre lock-a
        _ensure_schema_for_assignments(conn)
        _commit_quiet(conn)

        _begin_immediate(conn)

        try:
            asset_before = row_to_dict(conn.execute("SELECT * FROM assets WHERE asset_uid=?;", (uid,)).fetchone())
            if asset_before is None:
                raise ValueError("asset not found")

            from_holder = asset_before.get("current_holder") or ""
            from_location = asset_before.get("location") or ""

            if action in ("assign", "transfer"):
                new_holder = (to_holder or "").strip()
                new_location = (to_location or "").strip() or from_location
                new_status = "on_loan"
            else:
                new_holder = ""
                new_location = (to_location or "").strip() or from_location
                new_status = "active"

            now = _now_iso()

            cur = conn.execute(
                """
                INSERT INTO assignments (created_at, asset_uid, action, from_holder, to_holder, from_location, to_location, note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    now,
                    uid,
                    action,
                    from_holder or None,
                    (new_holder if action != "return" else None),
                    from_location or None,
                    new_location or None,
                    (note or "").strip() or None,
                ),
            )
            assignment_id = int(cur.lastrowid)

            assignment_after = row_to_dict(
                conn.execute("SELECT * FROM assignments WHERE assignment_id=?;", (assignment_id,)).fetchone()
            )
            write_audit(conn, actor, "assignments", str(assignment_id), "INSERT", None, assignment_after, source)

            conn.execute(
                """
                UPDATE assets
                SET current_holder=?, location=?, status=?, updated_at=?
                WHERE asset_uid=?;
                """,
                (new_holder or None, new_location or None, new_status, now, uid),
            )

            asset_after = row_to_dict(conn.execute("SELECT * FROM assets WHERE asset_uid=?;", (uid,)).fetchone())
            write_audit(conn, actor, "assets", uid, "UPDATE", asset_before, asset_after, source)

            try:
                write_asset_event(
                    conn,
                    actor=actor,
                    asset_uid=uid,
                    event_type="ASSIGNMENT",
                    data_obj={
                        "action": action,
                        "assignment_id": assignment_id,
                        "from_holder": from_holder,
                        "to_holder": new_holder,
                        "from_location": from_location,
                        "to_location": new_location,
                        "note": (note or "").strip(),
                        "status_to": new_status,
                    },
                    source=source,
                    event_time=now,
                )
                if str(from_location or "") != str(new_location or ""):
                    write_asset_event(
                        conn, actor=actor, asset_uid=uid, event_type="LOCATION_CHANGED",
                        data_obj={"from": from_location, "to": new_location}, source=source, event_time=now
                    )
                if str(from_holder or "") != str(new_holder or ""):
                    write_asset_event(
                        conn, actor=actor, asset_uid=uid, event_type="HOLDER_CHANGED",
                        data_obj={"from": from_holder, "to": new_holder}, source=source, event_time=now
                    )
                b_st = (asset_before.get("status") or "")
                if str(b_st) != str(new_status):
                    write_asset_event(
                        conn, actor=actor, asset_uid=uid, event_type="STATUS_CHANGED",
                        data_obj={"from": b_st, "to": new_status}, source=source, event_time=now
                    )
            except Exception:
                pass

            conn.commit()
            return assignment_id

        except Exception:
            _rollback_quiet(conn)
            raise


def list_assignments_db(search: str = "", action: str = "SVE", limit: int = 1000) -> List[Dict[str, Any]]:
    lim = _clamp_int(limit, 1000, min_v=1, max_v=100000)

    where: List[str] = []
    params: List[Any] = []

    s = (search or "").strip()
    if s:
        where.append("(a.asset_uid LIKE ? OR ass.from_holder LIKE ? OR ass.to_holder LIKE ? OR a.name LIKE ? OR ass.note LIKE ?)")
        like = f"%{s}%"
        params.extend([like, like, like, like, like])

    act = (action or "SVE").strip().lower()
    if act != "sve":
        where.append("ass.action = ?")
        params.append(act)

    sql = """
        SELECT
            ass.assignment_id, ass.created_at, ass.asset_uid, ass.action,
            ass.from_holder, ass.to_holder, ass.from_location, ass.to_location, ass.note,
            a.name AS asset_name, a.category AS asset_category, a.status AS asset_status
        FROM assignments ass
        JOIN assets a ON a.asset_uid = ass.asset_uid
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ass.created_at DESC LIMIT ?"
    params.append(int(lim))

    with db_conn() as conn:
        try:
            _migration_v1(conn)
            _migration_v2(conn)
        except Exception:
            pass
        _commit_quiet(conn)

        rows = conn.execute(sql, tuple(params)).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]


def list_assignments_for_asset_db(asset_uid: str, limit: int = 500) -> List[Dict[str, Any]]:
    uid = (asset_uid or "").strip()
    if not uid:
        return []
    lim = _clamp_int(limit, 500, min_v=1, max_v=100000)

    sql = """
        SELECT assignment_id, created_at, asset_uid, action,
               from_holder, to_holder, from_location, to_location, note
        FROM assignments
        WHERE asset_uid=?
        ORDER BY created_at DESC
        LIMIT ?;
    """
    with db_conn() as conn:
        try:
            _migration_v2(conn)
        except Exception:
            pass
        _commit_quiet(conn)

        rows = conn.execute(sql, (uid, int(lim))).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]


# =========================
# AUDIT (DB)
# =========================

def list_audit_db(entity: str, entity_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    lim = _clamp_int(limit, 500, min_v=1, max_v=100000)
    sql = """
        SELECT audit_id, event_time, actor, entity, entity_id, action, before_json, after_json, source
        FROM audit_log
        WHERE entity=? AND entity_id=?
        ORDER BY event_time DESC
        LIMIT ?;
    """
    with db_conn() as conn:
        try:
            _migration_v1(conn)
        except Exception:
            pass
        _commit_quiet(conn)

        rows = conn.execute(sql, (entity, entity_id, int(lim))).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]


def list_audit_global_db(
    entity: str = "SVE",
    action: str = "SVE",
    actor_like: str = "",
    source_like: str = "",
    q: str = "",
    limit: int = 5000,
) -> List[Dict[str, Any]]:
    lim = _clamp_int(limit, 5000, min_v=1, max_v=100000)

    where: List[str] = []
    params: List[Any] = []

    ent = (entity or "SVE").strip()
    if ent and ent.upper() != "SVE":
        where.append("entity = ?")
        params.append(ent)

    act = (action or "SVE").strip().upper()
    if act != "SVE":
        where.append("action = ?")
        params.append(act)

    al = (actor_like or "").strip()
    if al:
        where.append("actor LIKE ?")
        params.append(f"%{al}%")

    sl = (source_like or "").strip()
    if sl:
        where.append("source LIKE ?")
        params.append(f"%{sl}%")

    qq = (q or "").strip()
    if qq:
        like = f"%{qq}%"
        where.append(
            "("
            "entity LIKE ? OR entity_id LIKE ? OR action LIKE ? OR actor LIKE ? OR source LIKE ? "
            "OR before_json LIKE ? OR after_json LIKE ?"
            ")"
        )
        params.extend([like, like, like, like, like, like, like])

    sql = """
        SELECT audit_id, event_time, actor, entity, entity_id, action, before_json, after_json, source
        FROM audit_log
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY event_time DESC LIMIT ?"
    params.append(int(lim))

    with db_conn() as conn:
        try:
            _migration_v1(conn)
        except Exception:
            pass
        _commit_quiet(conn)

        rows = conn.execute(sql, tuple(params)).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]
# (FILENAME: core/db.py - END PART 4/4)