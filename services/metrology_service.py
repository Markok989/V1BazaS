# FILENAME: services/metrology_service.py
# (FILENAME: services/metrology_service.py - START PART 1/3)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/metrology_service.py

Metrologija (V1):
- metrology_records (CRUD)
- metrology_audit (INSERT/UPDATE/DELETE audit)
- Tip etaloniranja: interno / domace_eksterno / inostrano
- Status (alarm): ISTEKLO / ISTICE / OK / NEPOZNATO

RBAC (service-level, fail-closed):
- metrology.view   -> read
- metrology.edit   -> write
- metrology.manage -> ALL-scope (GLOBAL) bypass

SCOPE (anti-"curenje"):
- Primarno: core.session.effective_scope() => ALL | SECTOR | MY
- Fail-safe: ALL je dozvoljen samo ADMIN-u (ako dođe ALL a nije admin -> SECTOR)
- DOPUNA: SECTOR_ADMIN + REFERENT_* preferiraju SECTOR čak i ako session vrati MY —
  ali SAMO ako je SECTOR tehnički moguć (assets + sector kolona + current_sector).
  Ako nije moguće, vraćamo se na MY (fail-closed, ali funkcionalno).

NOVO (po tvom zahtevu, bez promene UI):
1) Metrologija prikazuje SAMO sredstva sa flagom "is_metrology=1" (ako kolona postoji).
   - Važi za sve role/scope režime.
   - Ako kolona ne postoji u legacy bazi, ponašanje ostaje kompatibilno (bez hard blokade).
2) Status je "NEPOZNATO" ako NIJE unet datum etaloniranja (calib_date).
   - Ako calib_date postoji → status se računa po valid_until kao do sada.

Stabilnost:
- FIX: više ne koristimo `with connect_db() as conn:` (ne zatvara konekciju).
  Koristimo db_conn() (ako postoji) ili lokalni close-context fallback.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, date
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# core.db: prefer db_conn() (closes), fallback to connect_db only if needed
try:
    from core.db import db_conn as _db_conn  # type: ignore
except Exception:  # pragma: no cover
    _db_conn = None  # type: ignore

from core.db import connect_db  # type: ignore  # postoji u projektu (WAL/busy_timeout/putanja)

CALIB_TYPES = ["interno", "domace_eksterno", "inostrano"]

try:
    from core.rbac import (
        PERM_METRO_VIEW,
        PERM_METRO_EDIT,
        PERM_METRO_MANAGE,
        PERM_ASSETS_METRO_VIEW,
        PERM_ASSETS_MY_VIEW,
    )  # type: ignore
except Exception:  # pragma: no cover
    PERM_METRO_VIEW = "metrology.view"
    PERM_METRO_EDIT = "metrology.edit"
    PERM_METRO_MANAGE = "metrology.manage"
    PERM_ASSETS_METRO_VIEW = "assets.metrology.view"
    PERM_ASSETS_MY_VIEW = "assets.my.view"

# Canonical kolone za metrology_records (za tuple fallback)
_MET_COLS = [
    "met_uid",
    "asset_uid",
    "calib_type",
    "calib_date",
    "valid_until",
    "provider_name",
    "cert_no",
    "notes",
    "created_at",
    "updated_at",
    "is_deleted",
]

# Limits / guardrails (stabilnost + anti-abuse)
_MAX_LIST_LIMIT = 100_000
_MAX_AUDIT_LIMIT = 50_000
_MAX_MY_ASSETS_FETCH = 50_000

# Schema init guard (perf + stabilnost)
_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False


@contextmanager
def _conn_ctx():
    """
    UVEK zatvara sqlite konekciju:
    - prefer core.db.db_conn() (ako postoji)
    - fallback: connect_db() + close()
    """
    if callable(_db_conn):
        with _db_conn() as c:  # type: ignore[misc]
            yield c
        return

    c = connect_db()
    try:
        yield c
    finally:
        try:
            c.close()
        except Exception:
            pass


# -------------------- RBAC/session helpers (FAIL-CLOSED) --------------------
def _safe_can(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _require_login(context: str = "") -> None:
    """Fail-closed: ako nema prijavljenog user-a -> PermissionError."""
    try:
        from core.session import require_login  # type: ignore
        require_login(context or "metrology")
        return
    except PermissionError:
        raise
    except Exception:
        # fallback ako require_login nije dostupan
        try:
            from core.session import get_current_user  # type: ignore
            if not get_current_user():
                raise PermissionError("Nisi prijavljen.")
        except PermissionError:
            raise
        except Exception:
            raise PermissionError("Nisi prijavljen.")


def _must(perm: str) -> None:
    if not _safe_can(perm):
        raise PermissionError(f"RBAC: nemaš pravo ({perm}).")


def _active_role_safe() -> str:
    try:
        from core.session import active_role  # type: ignore
        return str(active_role() or "").strip().upper()
    except Exception:
        try:
            from core.session import get_current_user  # type: ignore
            u = get_current_user() or {}
            return str(u.get("active_role") or u.get("role") or u.get("user_role") or "READONLY").strip().upper()
        except Exception:
            return "READONLY"


def _effective_scope_from_session() -> str:
    """
    Primarni izvor: core.session.effective_scope() -> ALL/SECTOR/MY.
    Ako nije dostupno ili vrati glupost -> "" (pa dalje radimo bezbedan fallback).
    """
    try:
        from core.session import effective_scope  # type: ignore
        sc = str(effective_scope() or "").strip().upper()
        return sc
    except Exception:
        return ""


def _can_manage() -> bool:
    return _safe_can(PERM_METRO_MANAGE)


def _actor_name_for_audit() -> str:
    try:
        from core.session import actor_name  # type: ignore
        return (actor_name() or "").strip() or "user"
    except Exception:
        return "user"


def _actor_key_for_scope() -> str:
    """
    KRITIČNO: za MY identitet ne vraćamo placeholder "user" (to je opasno).
    Ako nemamo key, vrati "" (fail-closed).
    """
    try:
        from core.session import actor_key  # type: ignore
        return (actor_key() or "").strip()
    except Exception:
        return ""


def _actor_name_for_scope() -> str:
    """Za MY identitet: bez placeholder-a."""
    try:
        from core.session import actor_name  # type: ignore
        return (actor_name() or "").strip()
    except Exception:
        return ""


def _current_sector_safe() -> str:
    try:
        from core.session import current_sector  # type: ignore
        return (current_sector() or "").strip()
    except Exception:
        return ""


def _get_current_user_dict() -> Dict[str, Any]:
    try:
        from core.session import get_current_user  # type: ignore
        return dict(get_current_user() or {})
    except Exception:
        return {}


def _is_referent_metro() -> bool:
    return _active_role_safe() == "REFERENT_METRO"


def _is_sector_role(role: Optional[str] = None) -> bool:
    """
    Role koje po tvojoj specifikaciji treba da vide DASHBOARD u okviru sektora:
    - SECTOR_ADMIN
    - referenti (IT/OS/METRO)
    """
    r = (role or _active_role_safe()).strip().upper()
    return r in ("SECTOR_ADMIN", "REFERENT_IT", "REFERENT_OS", "REFERENT_METRO")


# -------------------- DB/schema helpers --------------------
def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _is_safe_ident(name: str) -> bool:
    """SQLite ident hardening (defanzivno). Dozvoli samo [A-Za-z0-9_]."""
    if not name:
        return False
    for ch in name:
        if not (ch.isalnum() or ch == "_"):
            return False
    return True


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    try:
        r = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
            (name,),
        ).fetchone()
        return bool(r)
    except Exception:
        return False


def _cols(conn: sqlite3.Connection, table: str) -> List[str]:
    """Siguran PRAGMA poziv (table ime mora biti safe ident)."""
    if not _is_safe_ident(table):
        return []
    try:
        rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
        out: List[str] = []
        for r in rows:
            try:
                out.append(str(r["name"]))  # type: ignore[index]
            except Exception:
                try:
                    out.append(str(r[1]))
                except Exception:
                    pass
        return out
    except Exception:
        return []


def ensure_metrology_schema() -> None:
    """
    Kreira šemu jednom po procesu (perf).
    Fail-safe: ako padne, sledeći poziv će opet pokušati (SCHEMA_READY ostaje False).
    """
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return

    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return

        with _conn_ctx() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metrology_records (
                    met_uid TEXT PRIMARY KEY,
                    asset_uid TEXT NOT NULL,
                    calib_type TEXT NOT NULL,
                    calib_date TEXT,
                    valid_until TEXT,
                    provider_name TEXT,
                    cert_no TEXT,
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    is_deleted INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrology_asset_uid ON metrology_records(asset_uid);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrology_updated_at ON metrology_records(updated_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrology_is_deleted ON metrology_records(is_deleted);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metrology_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    met_uid TEXT NOT NULL,
                    asset_uid TEXT NOT NULL,
                    before_json TEXT,
                    after_json TEXT,
                    note TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrology_audit_met_uid ON metrology_audit(met_uid);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrology_audit_ts ON metrology_audit(ts);")
            try:
                conn.commit()
            except Exception:
                pass

        _SCHEMA_READY = True


def _make_met_uid() -> str:
    return "M-" + datetime.now().strftime("%Y%m%d%H%M%S%f")


def _row_to_dict(row: Any, cols_hint: Optional[List[str]] = None) -> Dict[str, Any]:
    if row is None:
        return {}
    try:
        keys = list(row.keys())  # type: ignore[attr-defined]
        return {k: row[k] for k in keys}
    except Exception:
        pass
    try:
        seq = list(row)
        cols = cols_hint or []
        if cols and len(seq) == len(cols):
            return {cols[i]: seq[i] for i in range(len(cols))}
    except Exception:
        pass
    return {}


def _json_dump(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)


def _audit(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    met_uid: str,
    asset_uid: str,
    *,
    before_obj: Optional[Dict[str, Any]] = None,
    after_obj: Optional[Dict[str, Any]] = None,
    note: str = "",
) -> None:
    conn.execute(
        """
        INSERT INTO metrology_audit(ts, actor, action, met_uid, asset_uid, before_json, after_json, note)
        VALUES(?,?,?,?,?,?,?,?);
        """,
        (
            _now_str(),
            (actor or "").strip(),
            (action or "").strip(),
            (met_uid or "").strip(),
            (asset_uid or "").strip(),
            _json_dump(before_obj) if before_obj is not None else "",
            _json_dump(after_obj) if after_obj is not None else "",
            (note or "").strip(),
        ),
    )


def _normalize_date_str(s: Any) -> str:
    t = ("" if s is None else str(s)).strip()
    if not t:
        return ""
    if len(t) >= 10:
        t = t[:10]
    return t


def _date_iso(d: Any) -> str:
    if d is None:
        return ""
    if isinstance(d, str):
        return _normalize_date_str(d)
    if isinstance(d, datetime):
        return d.date().isoformat()
    if isinstance(d, date):
        return d.isoformat()
    return _normalize_date_str(d)


def _validate_calib_type(calib_type: str) -> str:
    ct = (calib_type or "").strip()
    if ct not in CALIB_TYPES:
        raise ValueError(f"Nevalidan calib_type: {ct}. Dozvoljeno: {CALIB_TYPES}")
    return ct


def status_for_valid_until(valid_until: Any, warn_days: int = 30) -> str:
    """
    Kompat helper (ostaje).
    Status je baziran na valid_until (ako je prazno/invalidno -> NEPOZNATO).
    """
    vu = _normalize_date_str(valid_until)
    if not vu:
        return "NEPOZNATO"
    try:
        vu_date = date.fromisoformat(vu)
    except Exception:
        return "NEPOZNATO"

    today = date.today()
    if vu_date < today:
        return "ISTEKLO"

    try:
        wd = int(warn_days)
    except Exception:
        wd = 30
    if wd < 0:
        wd = 0

    if (vu_date - today).days <= wd:
        return "ISTICE"
    return "OK"


def status_for_record(calib_date: Any, valid_until: Any, warn_days: int = 30) -> str:
    """
    NOVO (po zahtevu):
    - ako calib_date nije unet -> NEPOZNATO (bez obzira na valid_until)
    - inače koristi valid_until status
    """
    cd = _normalize_date_str(calib_date)
    if not cd:
        return "NEPOZNATO"
    return status_for_valid_until(valid_until, warn_days=warn_days)

# (FILENAME: services/metrology_service.py - END PART 1/3)

# FILENAME: services/metrology_service.py
# (FILENAME: services/metrology_service.py - START PART 2/3)
# -------------------- Scope helpers (SQL-first) --------------------
def _assets_sector_col(conn: sqlite3.Connection) -> str:
    if not _table_exists(conn, "assets"):
        return ""
    cols = _cols(conn, "assets")
    for cand in ("sector", "sektor", "sector_id", "sector_code", "org_unit", "unit", "department", "dept", "section"):
        if cand in cols:
            return cand
    return ""


def _assets_holder_col(conn: sqlite3.Connection) -> str:
    if not _table_exists(conn, "assets"):
        return ""
    cols = _cols(conn, "assets")
    for cand in ("current_holder", "assigned_to", "holder", "zaduzeno_kod", "kod_koga"):
        if cand in cols:
            return cand
    return ""


def _assets_is_metro_col(conn: sqlite3.Connection) -> str:
    """
    Metrology flag kolona je OPTIONAL.
    Ako postoji:
      - možemo enforce-ovati prikaz "samo metrologija"
    """
    if not _table_exists(conn, "assets"):
        return ""
    cols = _cols(conn, "assets")
    for cand in ("is_metrology", "is_metro", "metrology_flag", "metro_flag", "metrology_scope"):
        if cand in cols:
            return cand
    return ""


def _metrology_only_sql(conn: sqlite3.Connection, alias: str = "a") -> str:
    """
    SQL uslov za 'samo sredstva koja imaju metrologija flag'.
    Ako ne možemo detektovati kolonu -> vrati "" (ne blokiramo legacy baze).
    """
    mcol = _assets_is_metro_col(conn)
    if not mcol:
        return ""
    if not _is_safe_ident(alias) or not _is_safe_ident(mcol):
        return ""
    return f"COALESCE({alias}.{mcol},0) = 1"


def _asset_is_metrology_flag(conn: sqlite3.Connection, asset_uid: str) -> Optional[bool]:
    """
    True/False ako možemo proveriti flag (assets + is_metrology kolona).
    None ako ne možemo proveriti (legacy schema) -> ne blokiramo.
    """
    au = (asset_uid or "").strip()
    if not au:
        return False
    if not _table_exists(conn, "assets"):
        return None
    mcol = _assets_is_metro_col(conn)
    if not mcol:
        return None
    try:
        row = conn.execute(
            f"SELECT COALESCE({mcol},0) AS v FROM assets WHERE asset_uid=? LIMIT 1;",
            (au,),
        ).fetchone()
        if not row:
            return False
        try:
            v = row["v"]  # type: ignore[index]
        except Exception:
            v = row[0]
        return bool(int(v or 0) == 1)
    except Exception:
        return None


def _norm(s: str) -> str:
    return (s or "").strip().casefold()


def _identity_candidates() -> List[str]:
    u = _get_current_user_dict()
    cand: List[str] = []

    ak = _actor_key_for_scope()
    if ak:
        cand.append(ak)
    an = _actor_name_for_scope()
    if an:
        cand.append(an)

    for k in ("username", "login", "email", "display_name", "name", "full_name", "user"):
        v = u.get(k)
        if v:
            cand.append(str(v))

    for k in ("id", "user_id", "uid"):
        v = u.get(k)
        if v is not None and str(v).strip():
            cand.append(str(v).strip())

    out: List[str] = []
    seen = set()
    for c in cand:
        cc = _norm(str(c))
        if cc and cc not in seen:
            seen.add(cc)
            out.append(cc)
    return out


def _clamp_limit(limit: Any, default: int, max_limit: int) -> int:
    try:
        lim = int(limit or 0)
    except Exception:
        lim = default
    if lim <= 0:
        lim = default
    if lim > max_limit:
        lim = max_limit
    return lim


def _sector_possible(conn: sqlite3.Connection) -> bool:
    if not _table_exists(conn, "assets"):
        return False
    if not _assets_sector_col(conn):
        return False
    if not _current_sector_safe():
        return False
    if _is_referent_metro() and (not _safe_can(PERM_ASSETS_METRO_VIEW)):
        return False
    return True


def _my_possible(conn: sqlite3.Connection) -> bool:
    if not _table_exists(conn, "assets"):
        return False
    if not _assets_holder_col(conn):
        return False
    if not (_safe_can(PERM_ASSETS_MY_VIEW) or _safe_can("assets.view")):
        return False
    return bool(_identity_candidates())


def _resolved_scope(conn: sqlite3.Connection) -> str:
    role = _active_role_safe()
    sc = _effective_scope_from_session()

    if sc == "ALL" and role != "ADMIN":
        sc = "SECTOR"
    if sc not in ("ALL", "SECTOR", "MY"):
        sc = "MY"

    if sc == "ALL":
        return "ALL"

    if sc == "MY" and _is_sector_role(role):
        if _sector_possible(conn):
            return "SECTOR"
        return "MY"

    if sc == "SECTOR" and (not _sector_possible(conn)):
        return "MY" if _my_possible(conn) else "MY"

    return sc


def _sql_scope_predicate(conn: sqlite3.Connection) -> Tuple[str, List[Any]]:
    """
    Vraća (where_sql, params) za scope nad assets tabelom, za JOIN filtriranje.

    Pravila:
    - ALL: 1=1
    - SECTOR: sector match
    - MY: holder match (casefold)

    DODATO:
    - Metrologija-only: ako postoji is_metrology kolona -> AND is_metrology=1 (ZA SVE osim ALL koji se rešava u list_*)
    """
    sc = _resolved_scope(conn)

    if sc == "ALL":
        return "1=1", []

    if not _table_exists(conn, "assets"):
        return "0=1", []

    metro_only = _metrology_only_sql(conn, alias="a")

    if sc == "SECTOR":
        scol = _assets_sector_col(conn)
        sec = _current_sector_safe()
        if not (scol and sec):
            if _my_possible(conn):
                sc = "MY"
            else:
                return "0=1", []

        if sc == "SECTOR":
            base = f"LOWER(TRIM(COALESCE(a.{scol},''))) = LOWER(TRIM(?))"
            if metro_only:
                base = f"({base}) AND {metro_only}"
            return base, [sec]

    if not (_safe_can(PERM_ASSETS_MY_VIEW) or _safe_can("assets.view")):
        return "0=1", []

    hcol = _assets_holder_col(conn)
    if not hcol:
        return "0=1", []

    cands = _identity_candidates()
    if not cands:
        return "0=1", []

    ors = []
    params2: List[Any] = []
    for c in cands:
        ors.append(f"LOWER(TRIM(COALESCE(a.{hcol},''))) = ?")
        params2.append(c)

    where = "(" + " OR ".join(ors) + ")"
    if metro_only:
        where = f"({where}) AND {metro_only}"

    return where, params2


def _must_read_scope(conn: sqlite3.Connection, asset_uid: str) -> None:
    """
    Read scope: proverava da li je asset_uid u dozvoljenom scope-u.
    PLUS: enforce metrology flag (ako postoji kolona).
    """
    _must(PERM_METRO_VIEW)

    if _resolved_scope(conn) == "ALL" or _can_manage():
        chk = _asset_is_metrology_flag(conn, asset_uid)
        if chk is False:
            raise PermissionError("Metrologija: sredstvo nije označeno kao metrologija (is_metrology=0).")
        return

    au = (asset_uid or "").strip()
    if not au:
        raise PermissionError("RBAC: asset_uid je prazan.")

    if not _table_exists(conn, "assets"):
        raise PermissionError("RBAC: nema assets tabele (fail-closed).")

    where, params = _sql_scope_predicate(conn)
    row = conn.execute(
        f"SELECT 1 FROM assets a WHERE a.asset_uid=? AND ({where}) LIMIT 1;",
        tuple([au] + params),
    ).fetchone()
    if not row:
        raise PermissionError("RBAC: nemaš pravo (metrology scope).")


def _must_write_scope(conn: sqlite3.Connection, asset_uid: str) -> None:
    _must(PERM_METRO_EDIT)
    _must_read_scope(conn, asset_uid)

# (FILENAME: services/metrology_service.py - END PART 2/3)

# FILENAME: services/metrology_service.py
# (FILENAME: services/metrology_service.py - START PART 3/3)
# -------------------- MY API helpers --------------------
def _extract_asset_uids(rows: Any) -> List[str]:
    out: List[str] = []
    seen = set()

    if not isinstance(rows, list):
        return out

    for r in rows:
        uid = ""

        if isinstance(r, dict):
            uid = str(
                r.get("asset_uid")
                or r.get("uid")
                or r.get("assetUid")
                or r.get("assetUID")
                or ""
            ).strip()
        else:
            try:
                uid = str(getattr(r, "asset_uid", "") or "").strip()
            except Exception:
                uid = ""

            if not uid:
                try:
                    if isinstance(r, (list, tuple)) and r:
                        uid = str(r[0] or "").strip()
                except Exception:
                    uid = ""

        if not uid:
            continue
        if uid in seen:
            continue
        seen.add(uid)
        out.append(uid)

    return out


def _my_asset_uids_via_assets_service(limit: int = 5000) -> List[str]:
    if not (_safe_can(PERM_ASSETS_MY_VIEW) or _safe_can("assets.view")):
        return []

    try:
        from services.assets_service import list_assets_my  # type: ignore
    except Exception:
        return []

    lim = _clamp_limit(limit, 5000, _MAX_MY_ASSETS_FETCH)

    try:
        rows = list_assets_my(limit=lim)
    except PermissionError:
        return []
    except Exception:
        return []

    return _extract_asset_uids(rows)


# -------------------- Public API (CRUD + list) --------------------
def get_metrology_record(met_uid: str, warn_days: int = 30) -> Optional[Dict[str, Any]]:
    ensure_metrology_schema()
    _require_login("metrology.get_metrology_record")

    mu = (met_uid or "").strip()
    if not mu:
        return None

    with _conn_ctx() as conn:
        row = conn.execute("SELECT * FROM metrology_records WHERE met_uid=? LIMIT 1;", (mu,)).fetchone()
        if not row:
            return None

        rec = _row_to_dict(row, cols_hint=_MET_COLS)
        if int(rec.get("is_deleted") or 0) == 1:
            return None

        au = str(rec.get("asset_uid") or "").strip()
        if not au:
            return None

        try:
            _must_read_scope(conn, au)
        except PermissionError:
            return None

        rec["status"] = status_for_record(rec.get("calib_date", ""), rec.get("valid_until", ""), warn_days=warn_days)
        return rec


def list_metrology_records(
    q: str = "",
    limit: int = 5000,
    warn_days: int = 30,
    include_deleted: bool = False,
) -> List[Dict[str, Any]]:
    """
    Scope enforce u servisu (ALL/SECTOR/MY).
    DODATO: prikaz samo assets gde je is_metrology=1 (ako kolona postoji).
    """
    ensure_metrology_schema()
    _require_login("metrology.list_metrology_records")
    _must(PERM_METRO_VIEW)

    qq = (q or "").strip()
    lim = _clamp_limit(limit, 5000, _MAX_LIST_LIMIT)

    with _conn_ctx() as conn:
        sc = _resolved_scope(conn)

        # ALL (ili manage): može orphan-scan, ali ako flag postoji, orphans otpadaju (ne možemo dokazati flag)
        if sc == "ALL" or _can_manage():
            assets_exist = _table_exists(conn, "assets")
            mcol = _assets_is_metro_col(conn) if assets_exist else ""
            use_flag_filter = bool(assets_exist and mcol)

            where: List[str] = []
            params: List[Any] = []

            if not include_deleted:
                where.append("mr.is_deleted=0" if assets_exist else "is_deleted=0")

            if qq:
                like = f"%{qq}%"
                if assets_exist:
                    where.append(
                        "("
                        "mr.met_uid LIKE ? OR mr.asset_uid LIKE ? OR mr.calib_type LIKE ? OR mr.provider_name LIKE ? "
                        "OR mr.cert_no LIKE ? OR mr.notes LIKE ?"
                        ")"
                    )
                else:
                    where.append(
                        "("
                        "met_uid LIKE ? OR asset_uid LIKE ? OR calib_type LIKE ? OR provider_name LIKE ? "
                        "OR cert_no LIKE ? OR notes LIKE ?"
                        ")"
                    )
                params.extend([like, like, like, like, like, like])

            if assets_exist:
                # LEFT JOIN da zadržimo is_orphan signal (a_uid NULL)
                sql = "SELECT mr.*, a.asset_uid AS _a_uid FROM metrology_records mr LEFT JOIN assets a ON a.asset_uid = mr.asset_uid"
                if use_flag_filter:
                    where.append(f"COALESCE(a.{mcol},0)=1")
                if where:
                    sql += " WHERE " + " AND ".join(where)
                sql += " ORDER BY mr.updated_at DESC LIMIT ?;"
                rows = conn.execute(sql, tuple(params + [lim])).fetchall()
            else:
                sql = "SELECT * FROM metrology_records"
                if where:
                    sql += " WHERE " + " AND ".join(where)
                sql += " ORDER BY updated_at DESC LIMIT ?;"
                rows = conn.execute(sql, tuple(params + [lim])).fetchall()

            out: List[Dict[str, Any]] = []
            for row in rows:
                rec = _row_to_dict(row, cols_hint=_MET_COLS)
                if (not include_deleted) and int(rec.get("is_deleted") or 0) == 1:
                    continue

                rec["status"] = status_for_record(rec.get("calib_date", ""), rec.get("valid_until", ""), warn_days=warn_days)

                # Orphan signal samo kada smo radili LEFT JOIN i flag nije enforce-ovan (ili nije postojao)
                is_orphan = 0
                if assets_exist:
                    try:
                        a_uid = rec.get("_a_uid")
                        is_orphan = 1 if (a_uid is None or str(a_uid).strip() == "") else 0
                    except Exception:
                        is_orphan = 0
                    # ukloni internu kolonu da UI ne “pokupi” slučajno
                    try:
                        rec.pop("_a_uid", None)
                    except Exception:
                        pass
                rec["is_orphan"] = is_orphan

                out.append(rec)

            return out

        # SECTOR/MY: mora assets tabela
        if not _table_exists(conn, "assets"):
            return []

        where_scope, scope_params = _sql_scope_predicate(conn)
        if where_scope == "0=1":
            return []

        where: List[str] = []
        params2: List[Any] = []

        if not include_deleted:
            where.append("mr.is_deleted=0")

        if qq:
            like = f"%{qq}%"
            where.append(
                "("
                "mr.met_uid LIKE ? OR mr.asset_uid LIKE ? OR mr.calib_type LIKE ? OR mr.provider_name LIKE ? "
                "OR mr.cert_no LIKE ? OR mr.notes LIKE ?"
                ")"
            )
            params2.extend([like, like, like, like, like, like])

        sql2 = """
            SELECT mr.*
            FROM metrology_records mr
            JOIN assets a ON a.asset_uid = mr.asset_uid
        """

        where_all: List[str] = []
        if where:
            where_all.append("(" + " AND ".join(where) + ")")
        where_all.append(f"({where_scope})")

        sql2 += " WHERE " + " AND ".join(where_all)
        sql2 += " ORDER BY mr.updated_at DESC LIMIT ?;"

        rows2 = conn.execute(sql2, tuple(params2 + scope_params + [lim])).fetchall()

        out2: List[Dict[str, Any]] = []
        for row in rows2:
            rec = _row_to_dict(row, cols_hint=_MET_COLS)
            if (not include_deleted) and int(rec.get("is_deleted") or 0) == 1:
                continue
            rec["status"] = status_for_record(rec.get("calib_date", ""), rec.get("valid_until", ""), warn_days=warn_days)
            rec["is_orphan"] = 0
            out2.append(rec)

        return out2


def list_metrology_records_my(
    q: str = "",
    limit: int = 5000,
    warn_days: int = 30,
    include_deleted: bool = False,
) -> List[Dict[str, Any]]:
    """
    MY API: metrology samo za sredstva koja korisnik trenutno duži.
    DODATO: + samo ona koja imaju is_metrology=1 (ako kolona postoji).
    """
    ensure_metrology_schema()
    _require_login("metrology.list_metrology_records_my")
    _must(PERM_METRO_VIEW)

    qq = (q or "").strip()
    lim = _clamp_limit(limit, 5000, _MAX_LIST_LIMIT)

    fetch_lim = max(5000, min(_MAX_MY_ASSETS_FETCH, lim))
    my_uids = _my_asset_uids_via_assets_service(limit=fetch_lim)
    if not my_uids:
        return []

    with _conn_ctx() as conn:
        if not _table_exists(conn, "metrology_records"):
            return []

        assets_exist = _table_exists(conn, "assets")
        mcol = _assets_is_metro_col(conn) if assets_exist else ""
        use_flag_filter = bool(assets_exist and mcol)

        where: List[str] = []
        params: List[Any] = []

        if not include_deleted:
            where.append("mr.is_deleted=0" if use_flag_filter else "is_deleted=0")

        if qq:
            like = f"%{qq}%"
            if use_flag_filter:
                where.append(
                    "("
                    "mr.met_uid LIKE ? OR mr.asset_uid LIKE ? OR mr.calib_type LIKE ? OR mr.provider_name LIKE ? "
                    "OR mr.cert_no LIKE ? OR mr.notes LIKE ?"
                    ")"
                )
            else:
                where.append(
                    "("
                    "met_uid LIKE ? OR asset_uid LIKE ? OR calib_type LIKE ? OR provider_name LIKE ? "
                    "OR cert_no LIKE ? OR notes LIKE ?"
                    ")"
                )
            params.extend([like, like, like, like, like, like])

        try:
            conn.execute("CREATE TEMP TABLE IF NOT EXISTS tmp_my_assets(uid TEXT PRIMARY KEY);")
            conn.execute("DELETE FROM tmp_my_assets;")
            conn.executemany(
                "INSERT OR IGNORE INTO tmp_my_assets(uid) VALUES(?);",
                [(u,) for u in my_uids],
            )

            if use_flag_filter:
                where.append("mr.asset_uid IN (SELECT uid FROM tmp_my_assets)")
                where.append(f"COALESCE(a.{mcol},0)=1")

                sql = "SELECT mr.* FROM metrology_records mr JOIN assets a ON a.asset_uid = mr.asset_uid"
                if where:
                    sql += " WHERE " + " AND ".join(where)
                sql += " ORDER BY mr.updated_at DESC LIMIT ?;"
            else:
                where.append("asset_uid IN (SELECT uid FROM tmp_my_assets)")
                sql = "SELECT * FROM metrology_records"
                if where:
                    sql += " WHERE " + " AND ".join(where)
                sql += " ORDER BY updated_at DESC LIMIT ?;"

            rows = conn.execute(sql, tuple(params + [lim])).fetchall()
        except Exception:
            return []

        out: List[Dict[str, Any]] = []
        for row in rows:
            rec = _row_to_dict(row, cols_hint=_MET_COLS)
            if (not include_deleted) and int(rec.get("is_deleted") or 0) == 1:
                continue
            rec["status"] = status_for_record(rec.get("calib_date", ""), rec.get("valid_until", ""), warn_days=warn_days)
            rec["is_orphan"] = 0
            out.append(rec)

        return out


# kompat alias
list_metrology_my = list_metrology_records_my


def list_metrology_records_for_asset(
    asset_uid: str,
    limit: int = 200,
    warn_days: int = 30,
    include_deleted: bool = False,
) -> List[Dict[str, Any]]:
    """
    Vraća metrology zapise za konkretan asset_uid.
    DODATO: ako možemo proveriti is_metrology i flag je 0 -> [] (fail-closed).
    """
    ensure_metrology_schema()
    _require_login("metrology.list_metrology_records_for_asset")
    _must(PERM_METRO_VIEW)

    au = (asset_uid or "").strip()
    if not au:
        return []

    lim = _clamp_limit(limit, 200, _MAX_AUDIT_LIMIT)

    with _conn_ctx() as conn:
        try:
            _must_read_scope(conn, au)
        except PermissionError:
            return []

        chk = _asset_is_metrology_flag(conn, au)
        if chk is False:
            return []

        where = "asset_uid=?"
        params: List[Any] = [au]
        if not include_deleted:
            where += " AND is_deleted=0"

        rows = conn.execute(
            f"""
            SELECT * FROM metrology_records
             WHERE {where}
             ORDER BY updated_at DESC
             LIMIT ?;
            """,
            tuple(params + [lim]),
        ).fetchall()

        out: List[Dict[str, Any]] = []
        for row in rows:
            rec = _row_to_dict(row, cols_hint=_MET_COLS)
            if (not include_deleted) and int(rec.get("is_deleted") or 0) == 1:
                continue
            rec["status"] = status_for_record(rec.get("calib_date", ""), rec.get("valid_until", ""), warn_days=warn_days)
            rec["is_orphan"] = 0
            out.append(rec)
        return out


# aliasi da ne puca
list_metrology_for_asset = list_metrology_records_for_asset
list_metrology_by_asset_uid = list_metrology_records_for_asset


def list_metrology_audit(met_uid: str, limit: int = 200) -> List[Dict[str, Any]]:
    ensure_metrology_schema()
    _require_login("metrology.list_metrology_audit")
    _must(PERM_METRO_VIEW)

    mu = (met_uid or "").strip()
    if not mu:
        return []

    lim = _clamp_limit(limit, 200, _MAX_AUDIT_LIMIT)

    with _conn_ctx() as conn:
        row = conn.execute("SELECT asset_uid FROM metrology_records WHERE met_uid=? LIMIT 1;", (mu,)).fetchone()
        if not row:
            return []
        asset_uid = str(row[0] or "").strip()
        if not asset_uid:
            return []

        try:
            _must_read_scope(conn, asset_uid)
        except PermissionError:
            return []

        rows = conn.execute(
            """
            SELECT ts, actor, action, met_uid, asset_uid, before_json, after_json, note
              FROM metrology_audit
             WHERE met_uid=?
             ORDER BY ts DESC
             LIMIT ?;
            """,
            (mu, lim),
        ).fetchall()

        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "ts": r[0] or "",
                    "actor": r[1] or "",
                    "action": r[2] or "",
                    "met_uid": r[3] or "",
                    "asset_uid": r[4] or "",
                    "before_json": r[5] or "",
                    "after_json": r[6] or "",
                    "note": r[7] or "",
                }
            )
        return out


def create_metrology_record(
    actor: str,  # kompatibilnost: IGNORIŠE SE (uzima se iz session-a)
    asset_uid: str,
    calib_type: str,
    calib_date: str = "",
    valid_until: str = "",
    provider_name: str = "",
    cert_no: str = "",
    notes: str = "",
    note_audit: str = "ui_create_metrology",
) -> str:
    ensure_metrology_schema()
    _require_login("metrology.create_metrology_record")

    au = (asset_uid or "").strip()
    if not au:
        raise ValueError("asset_uid je obavezan.")
    ct = _validate_calib_type(calib_type)

    actor_eff = _actor_name_for_audit()
    met_uid = _make_met_uid()
    now = _now_str()

    rec = {
        "met_uid": met_uid,
        "asset_uid": au,
        "calib_type": ct,
        "calib_date": _date_iso(calib_date),
        "valid_until": _date_iso(valid_until),
        "provider_name": (provider_name or "").strip(),
        "cert_no": (cert_no or "").strip(),
        "notes": (notes or "").strip(),
        "created_at": now,
        "updated_at": now,
        "is_deleted": 0,
    }

    with _conn_ctx() as conn:
        _must_write_scope(conn, au)

        chk = _asset_is_metrology_flag(conn, au)
        if chk is False:
            raise ValueError("Ne može metrologija: sredstvo nije označeno kao metrologija (is_metrology=0).")

        try:
            conn.execute(
                """
                INSERT INTO metrology_records(
                    met_uid, asset_uid, calib_type, calib_date, valid_until,
                    provider_name, cert_no, notes, created_at, updated_at, is_deleted
                ) VALUES(?,?,?,?,?,?,?,?,?,?,0);
                """,
                (
                    rec["met_uid"],
                    rec["asset_uid"],
                    rec["calib_type"],
                    rec["calib_date"],
                    rec["valid_until"],
                    rec["provider_name"],
                    rec["cert_no"],
                    rec["notes"],
                    rec["created_at"],
                    rec["updated_at"],
                ),
            )
            _audit(conn, actor_eff, "INSERT", met_uid, au, before_obj=None, after_obj=rec, note=note_audit)
            try:
                conn.commit()
            except Exception:
                pass
        except sqlite3.IntegrityError as e:
            raise ValueError(f"Greška pri upisu metrologije (integritet): {e}")
        except sqlite3.Error as e:
            raise RuntimeError(f"DB greška pri kreiranju metrologije: {e}")

    return met_uid


def update_metrology_record(
    actor: str,  # kompatibilnost: IGNORIŠE SE (uzima se iz session-a)
    met_uid: str,
    calib_type: str,
    calib_date: str = "",
    valid_until: str = "",
    provider_name: str = "",
    cert_no: str = "",
    notes: str = "",
    note_audit: str = "ui_update_metrology",
) -> bool:
    ensure_metrology_schema()
    _require_login("metrology.update_metrology_record")

    mu = (met_uid or "").strip()
    if not mu:
        return False

    actor_eff = _actor_name_for_audit()
    ct = _validate_calib_type(calib_type)
    now = _now_str()

    with _conn_ctx() as conn:
        before_row = conn.execute("SELECT * FROM metrology_records WHERE met_uid=? LIMIT 1;", (mu,)).fetchone()
        if not before_row:
            return False

        before = _row_to_dict(before_row, cols_hint=_MET_COLS)
        if int(before.get("is_deleted") or 0) == 1:
            return False

        au = str(before.get("asset_uid") or "").strip()
        if not au:
            return False

        _must_write_scope(conn, au)

        chk = _asset_is_metrology_flag(conn, au)
        if chk is False:
            raise ValueError("Ne može izmena: sredstvo nije označeno kao metrologija (is_metrology=0).")

        try:
            conn.execute(
                """
                UPDATE metrology_records
                   SET calib_type=?, calib_date=?, valid_until=?,
                       provider_name=?, cert_no=?, notes=?,
                       updated_at=?
                 WHERE met_uid=?;
                """,
                (
                    ct,
                    _date_iso(calib_date),
                    _date_iso(valid_until),
                    (provider_name or "").strip(),
                    (cert_no or "").strip(),
                    (notes or "").strip(),
                    now,
                    mu,
                ),
            )

            after_row = conn.execute("SELECT * FROM metrology_records WHERE met_uid=? LIMIT 1;", (mu,)).fetchone()
            after = _row_to_dict(after_row, cols_hint=_MET_COLS) if after_row else {}
            _audit(conn, actor_eff, "UPDATE", mu, au, before_obj=before, after_obj=after, note=note_audit)
            try:
                conn.commit()
            except Exception:
                pass
        except sqlite3.Error as e:
            raise RuntimeError(f"DB greška pri izmeni metrologije: {e}")

    return True


def delete_metrology_record(
    actor: str,  # kompatibilnost: IGNORIŠE SE (uzima se iz session-a)
    met_uid: str,
    note_audit: str = "ui_delete_metrology",
) -> bool:
    ensure_metrology_schema()
    _require_login("metrology.delete_metrology_record")

    mu = (met_uid or "").strip()
    if not mu:
        return False

    actor_eff = _actor_name_for_audit()

    with _conn_ctx() as conn:
        before_row = conn.execute("SELECT * FROM metrology_records WHERE met_uid=? LIMIT 1;", (mu,)).fetchone()
        if not before_row:
            return False

        before = _row_to_dict(before_row, cols_hint=_MET_COLS)
        if int(before.get("is_deleted") or 0) == 1:
            return True  # idempotentno

        au = str(before.get("asset_uid") or "").strip()
        if not au:
            return False

        _must_write_scope(conn, au)

        chk = _asset_is_metrology_flag(conn, au)
        if chk is False:
            raise ValueError("Ne može brisanje: sredstvo nije označeno kao metrologija (is_metrology=0).")

        try:
            conn.execute(
                "UPDATE metrology_records SET is_deleted=1, updated_at=? WHERE met_uid=?;",
                (_now_str(), mu),
            )

            after_row = conn.execute("SELECT * FROM metrology_records WHERE met_uid=? LIMIT 1;", (mu,)).fetchone()
            after = _row_to_dict(after_row, cols_hint=_MET_COLS) if after_row else {}
            _audit(conn, actor_eff, "DELETE", mu, au, before_obj=before, after_obj=after, note=note_audit)
            try:
                conn.commit()
            except Exception:
                pass
        except sqlite3.Error as e:
            raise RuntimeError(f"DB greška pri brisanju metrologije: {e}")

    return True


__all__ = [
    "ensure_metrology_schema",
    "status_for_valid_until",
    "status_for_record",
    "get_metrology_record",
    "list_metrology_records",
    "list_metrology_records_my",
    "list_metrology_my",
    "list_metrology_records_for_asset",
    "list_metrology_for_asset",
    "list_metrology_by_asset_uid",
    "list_metrology_audit",
    "create_metrology_record",
    "update_metrology_record",
    "delete_metrology_record",
]
# (FILENAME: services/metrology_service.py - END PART 3/3)