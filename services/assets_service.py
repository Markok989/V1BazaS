# FILENAME: services/assets_service.py
# (FILENAME: services/assets_service.py - START PART 1/3)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/assets_service.py

Servis sloj za sredstva (assets) sa RBAC + scope filtriranjem (FAIL-CLOSED):
- FULL: assets.view
- METRO: assets.metrology.view (metrology-scope)
- MY: assets.my.view (samo sredstva koja korisnik trenutno duži)

REV (2026-02) — hardening + metrology-only konsolidacija:
- FIX: MY identitet više NE koristi placeholder "user" (sprečava cross-user match).
- FIX: metrology_only / METRO scope sada PRIMARNO znači assets.is_metrology==1 (ako kolona postoji).
  Legacy fallback ostaje (metrology_records / heuristike) samo kad flag nije dostupan.
- FIX: list_assets / list_assets_brief prosleđuju core.db `metrology_only` kada je tražen METRO
  (nije se slalo ranije → UI je videla “sva sredstva” u metrology dijalozima).
- Stabilniji SQLite schema cache: invalidacija preko PRAGMA user_version, a ako je 0 → schema_version table.
- Perf: DB putanja keširana (sprečava “dve baze” + manje overhead-a).
- Bez promene osnovne logike: i dalje FAIL-CLOSED + tolerantno na UI scope stringove.

Napomena:
- Offline only, bez interneta.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set, Iterable
import inspect
import logging
import re
import sqlite3

logger = logging.getLogger(__name__)

# -------------------- RBAC (service-level, FAIL-CLOSED) --------------------
try:
    from core.rbac import (
        PERM_ASSETS_VIEW,
        PERM_ASSETS_CREATE,
        PERM_ASSETS_METRO_VIEW,
        PERM_ASSETS_MY_VIEW,
        effective_role,
    )
except Exception:  # pragma: no cover
    PERM_ASSETS_VIEW = "assets.view"
    PERM_ASSETS_CREATE = "assets.create"
    PERM_ASSETS_METRO_VIEW = "assets.metrology.view"
    PERM_ASSETS_MY_VIEW = "assets.my.view"

    def effective_role(user: Optional[Dict[str, Any]]) -> str:  # type: ignore
        try:
            if not user:
                return "READONLY"
            ar = str(user.get("active_role") or "").strip()
            if ar:
                return ar.upper()
            r = str(user.get("role") or "").strip()
            return (r or "READONLY").upper()
        except Exception:
            return "READONLY"


_ASSETS_LIST_PERMS: List[str] = [PERM_ASSETS_VIEW, PERM_ASSETS_METRO_VIEW, PERM_ASSETS_MY_VIEW]


# -------------------- Scope normalization (UI <-> Service contract) --------------------
SCOPE_AUTO = "AUTO"
SCOPE_ALL = "ALL"
SCOPE_MY = "MY"
SCOPE_METRO = "METRO"


def _norm_scope(scope: Any) -> str:
    """
    Normalizuje scope iz UI (srpski tekst) ili internog koda u:
      - ALL, MY, METRO, ili "" (nepoznato / nije traženo)

    Tolerantno:
    - "Sva sredstva" -> ALL
    - "Moja oprema" -> MY
    - "Metrologija..." -> METRO
    """
    s = ("" if scope is None else str(scope)).strip().casefold()
    if not s:
        return ""
    if s in ("all", "sva", "sve", "sredstva", "sva sredstva", "sva_sredstva"):
        return SCOPE_ALL
    if "sva" in s and "sred" in s:
        return SCOPE_ALL

    if s in ("my", "moja", "moje", "moja oprema", "moj", "moj dashboard"):
        return SCOPE_MY
    if "moja" in s or "moje" in s:
        return SCOPE_MY

    if s in ("metro", "metrology", "metrologija", "metrologija (scope)"):
        return SCOPE_METRO
    if "metrolog" in s or "kalibr" in s:
        return SCOPE_METRO

    return ""


def _parse_scope(scope: Any) -> str:
    """
    Jedan ulaz za scope: vraća AUTO/ALL/MY/METRO.
    """
    s = _norm_scope(scope)
    if s in (SCOPE_ALL, SCOPE_MY, SCOPE_METRO):
        return s
    return SCOPE_AUTO


def _safe_can(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _require_login(src: str = "") -> None:
    """Fail-closed login check. Prefer core.session.require_login() ako postoji."""
    try:
        from core.session import require_login  # type: ignore
        try:
            require_login(src or "assets")
        except TypeError:
            require_login()
        return
    except PermissionError:
        raise
    except Exception:
        pass

    try:
        from core.session import get_current_user  # type: ignore
        if not get_current_user():
            raise PermissionError("Nisi prijavljen.")
    except PermissionError:
        raise
    except Exception:
        raise PermissionError("Session nije dostupna (nisi prijavljen).")


def _actor_name_for_audit() -> str:
    """
    Audit identitet može fallback na "user" (nije security boundary).
    """
    try:
        from core.session import actor_name  # type: ignore
        return (actor_name() or "").strip() or "user"
    except Exception:
        return "user"


def _actor_key_for_identity() -> str:
    """
    Identitet za MY scope: bez placeholder-a.
    Vraća "" ako ne znamo ko je user (fail-closed).
    """
    try:
        from core.session import actor_key  # type: ignore
        ak = (actor_key() or "").strip()
    except Exception:
        ak = ""
    if not ak:
        return ""
    low = ak.strip().casefold()
    if low == "user" or low == "unknown":
        return ""
    if low.startswith("user#0"):
        return ""
    return ak


def _actor_name_for_identity() -> str:
    """
    Identitet za MY scope: bez placeholder-a.
    """
    try:
        from core.session import actor_name  # type: ignore
        an = (actor_name() or "").strip()
    except Exception:
        an = ""
    low = an.casefold()
    if not an or low == "user" or low == "unknown":
        return ""
    return an


def _require_perm(perm: str, src: str = "") -> None:
    if not _safe_can(perm):
        where = f" ({src})" if src else ""
        raise PermissionError(f"Nemaš pravo: {perm}{where}")


def _require_perm_any(perms: List[str], src: str = "") -> None:
    for p in perms:
        if _safe_can(p):
            return
    where = f" ({src})" if src else ""
    raise PermissionError(f"Nemaš pravo: {', '.join(perms)}{where}")


def _has_full_assets_view() -> bool:
    return _safe_can(PERM_ASSETS_VIEW)


def _has_metro_assets_view() -> bool:
    return _safe_can(PERM_ASSETS_METRO_VIEW)


def _has_my_assets_view() -> bool:
    return _safe_can(PERM_ASSETS_MY_VIEW)


def _clamp_limit(limit: Any, default: int, *, min_v: int = 1, max_v: int = 100000) -> int:
    try:
        v = int(limit or 0)
    except Exception:
        v = int(default)
    if v < min_v:
        v = min_v
    if v > max_v:
        v = max_v
    return v


# -------------------- Nomenclature (backward compatible, canonical output) --------------------
NOMENCLATURE_CANON_KEY = "nomenclature_no"
NOMENCLATURE_LEGACY_KEY = "nomenclature_number"

_NOMENCLATURE_ALIASES = (
    "nomenclature_no",
    "nomenclature_number",
    "nomenclature_num",
    "nomenklaturni_broj",
    "nomenklatura_broj",
    "nom_broj",
    "nom_no",
    "nom_number",
    "nomen_broj",
    "nomen",
)


def _norm_nomenclature_value(x: Any) -> str:
    s = ("" if x is None else str(x))
    return s.replace("\r", " ").replace("\n", " ").strip()


def _extract_nomenclature_from_dict(d: Dict[str, Any]) -> str:
    for k in _NOMENCLATURE_ALIASES:
        if k in d:
            v = _norm_nomenclature_value(d.get(k))
            if v:
                return v
    return ""


# -------------------- Session helpers (sector scope + identity) --------------------
def _get_current_user() -> Dict[str, Any]:
    try:
        from core.session import get_current_user  # type: ignore
        u = get_current_user()
        if not u:
            return {}
        if isinstance(u, dict):
            return dict(u)
        try:
            return dict(vars(u))
        except Exception:
            return {}
    except Exception:
        return {}


def _norm_sector(x: Any) -> str:
    s = ("" if x is None else str(x)).replace("\n", " ").replace("\r", " ").strip()
    return s[:80]


def _current_role() -> str:
    u = _get_current_user()
    try:
        r = effective_role(u)
        return (r or "READONLY").strip().upper()
    except Exception:
        r2 = (u.get("active_role") or u.get("role") or u.get("user_role") or "")
        return str(r2).strip().upper() or "READONLY"


def _current_sector() -> str:
    try:
        from core.session import current_sector as _cs  # type: ignore
        sec = _cs()
        if sec and str(sec).strip():
            return _norm_sector(sec)
    except Exception:
        pass

    u = _get_current_user()
    sec = u.get("active_sector") or u.get("sector") or u.get("org_unit") or u.get("unit") or ""
    return _norm_sector(sec)


def _is_sector_scoped_metro() -> bool:
    # postojeća logika (ne širimo scope bez dogovora)
    return _current_role() == "REFERENT_METRO"


def _asset_sector_value(r: Dict[str, Any]) -> str:
    for k in ("sector", "sektor", "org_unit", "orgunit", "unit", "department", "dept", "sector_code", "sector_id"):
        v = r.get(k)
        if v is not None and str(v).strip():
            return _norm_sector(v)
    return ""


def _sector_eq(a: str, b: str) -> bool:
    return (a or "").strip().casefold() == (b or "").strip().casefold()


def _sector_filter_rows(rows: List[Dict[str, Any]], sector: str, *, strict: bool = True) -> List[Dict[str, Any]]:
    sec = _norm_sector(sector)
    if not sec:
        return [] if strict else rows

    out: List[Dict[str, Any]] = []
    for rr in rows:
        if not isinstance(rr, dict):
            continue
        asec = _asset_sector_value(rr)
        if not asec:
            if not strict:
                out.append(rr)
            continue
        if _sector_eq(asec, sec):
            out.append(rr)
    return out

# (FILENAME: services/assets_service.py - END PART 1/3)

# FILENAME: services/assets_service.py
# (FILENAME: services/assets_service.py - START PART 2/3)

# -------------------- MY scope helpers --------------------
_TOKEN_SPLIT_RE = re.compile(r"[^\w]+", flags=re.UNICODE)


def _norm_text(x: Any) -> str:
    return ("" if x is None else str(x)).replace("\n", " ").replace("\r", " ").strip()


def _identity_candidates() -> List[str]:
    """
    Kandidati identiteta za MY scope (bez placeholder-a):
    - actor_key (username/id)  [najpouzdanije]
    - actor_name              [display]
    - atributi iz sesije: username/login/email/display_name/name/full_name/account/user
    - id/user_id/uid (kao string)
    Sve se normalizuje u lower-case, deduplikacija.
    """
    u = _get_current_user()
    cand: List[str] = []

    ak = _actor_key_for_identity()
    if ak:
        cand.append(ak)

    an = _actor_name_for_identity()
    if an:
        cand.append(an)

    for k in ("username", "login", "email", "display_name", "name", "full_name", "account", "user"):
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
        cc = _norm_text(c).casefold()
        if cc and cc not in seen:
            seen.add(cc)
            out.append(cc)
    return out


def _asset_holder_value(r: Dict[str, Any]) -> str:
    for k in (
        "current_holder", "assigned_to", "holder", "zaduzeno_kod", "kod_koga",
        "current_holder_name", "assigned_to_name",
        "current_holder_id", "assigned_to_id",
    ):
        v = r.get(k)
        if v is not None and str(v).strip():
            return _norm_text(v)
    return ""


def _tokens(s: str) -> Set[str]:
    ss = _norm_text(s).casefold()
    if not ss:
        return set()
    return {t for t in _TOKEN_SPLIT_RE.split(ss) if t}


def _is_my_scope_asset(r: Dict[str, Any], *, cands: Optional[List[str]] = None) -> bool:
    """
    MY scope:
    - holder mora postojati
    - poklapanje:
      1) exact match (lower)
      2) token match (bez “marko” -> “markovic” lažnih pogodaka)
    """
    if not isinstance(r, dict):
        return False
    holder = _asset_holder_value(r).strip()
    if not holder:
        return False

    h = holder.casefold()
    cands2 = cands if cands is not None else _identity_candidates()
    if not cands2:
        return False

    for c in cands2:
        if c and h == c:
            return True

    ht = _tokens(holder)
    if not ht:
        return False

    for c in cands2:
        if not c:
            continue
        # token match, ali tek kad kandidat ima neku “težinu”
        if len(c) >= 4 and c in ht:
            return True
    return False


def _my_scope_filter(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cands = _identity_candidates()
    return [r for r in rows if isinstance(r, dict) and _is_my_scope_asset(r, cands=cands)]


# -------------------- DB helpers (robust) --------------------
def _try_import_db_func(*names: str) -> Tuple[Optional[Any], Optional[str]]:
    try:
        import core.db as db  # type: ignore
    except Exception:
        return None, None
    for n in names:
        fn = getattr(db, n, None)
        if callable(fn):
            return fn, n
    return None, None


_SIG_CACHE: Dict[int, Optional[inspect.Signature]] = {}


def _call_compatible(func, **kwargs):
    """
    Pozovi core.db funkciju čak i kad se potpis razlikuje:
    - ako funkcija prima **kwargs -> prosledi sve
    - inače filtriraj samo dozvoljene parametre
    """
    if func is None:
        raise RuntimeError("DB funkcija nije pronađena (core.db).")

    fid = id(func)
    if fid not in _SIG_CACHE:
        try:
            _SIG_CACHE[fid] = inspect.signature(func)
        except Exception:
            _SIG_CACHE[fid] = None

    sig = _SIG_CACHE.get(fid)
    if sig is None:
        return func(**kwargs)

    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
        return func(**kwargs)

    allowed = set(sig.parameters.keys())
    return func(**{k: v for k, v in kwargs.items() if k in allowed})


_db_create_asset, _ = _try_import_db_func("create_asset_db", "create_asset")
_db_list_assets, _ = _try_import_db_func("list_assets_db", "list_assets")
_db_list_assets_brief, _ = _try_import_db_func("list_assets_brief_db", "list_assets_brief")
_db_get_asset_by_uid, _ = _try_import_db_func("get_asset_by_uid_db", "get_asset_by_uid", "get_asset")
_db_asset_has_metrology, _ = _try_import_db_func(
    "asset_has_metrology_record", "has_metrology_record_for_asset", "has_metrology_for_asset"
)


# -------------------- SQLite helpers (fallback + enrichment) --------------------
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _is_safe_ident(name: str) -> bool:
    return bool(name and _IDENT_RE.match(name))


def _safe_cols(cols: Set[str]) -> Set[str]:
    return {c for c in cols if _is_safe_ident(c)}


def _app_root() -> Path:
    # services/ -> project root
    return Path(__file__).resolve().parent.parent


_DB_PATH_CACHE: Optional[str] = None


def _abspath_db(p: Any) -> str:
    try:
        pp = Path(str(p))
        if not pp.is_absolute():
            pp = (_app_root() / pp).resolve()
        return pp.as_posix()
    except Exception:
        return str(p)


def _get_db_path_str() -> str:
    """
    “Dve baze” guard:
    - pokušaj core.db.get_db_path / _resolve_db_path / core.paths.DB_PATH / core.config.DB_FILE
    - apsolutizuj putanju relativno prema app root
    """
    global _DB_PATH_CACHE
    if _DB_PATH_CACHE:
        return _DB_PATH_CACHE

    db_path: Any = None
    try:
        from core.db import get_db_path as _get_db_path  # type: ignore
        db_path = _get_db_path()
    except Exception:
        db_path = None

    if not db_path:
        try:
            from core.db import _resolve_db_path as _core_resolve_db_path  # type: ignore
            db_path = _core_resolve_db_path()
        except Exception:
            db_path = None

    if not db_path:
        try:
            from core.paths import DB_PATH  # type: ignore
            db_path = DB_PATH or None
        except Exception:
            db_path = None

    if not db_path:
        try:
            from core.config import DB_FILE  # type: ignore
            db_path = DB_FILE
        except Exception:
            db_path = "baza.db"

    _DB_PATH_CACHE = _abspath_db(db_path)
    return _DB_PATH_CACHE


def _iter_chunks(items: List[str], *, chunk_size: int = 800) -> Iterable[List[str]]:
    if chunk_size <= 0:
        chunk_size = 800
    for i in range(0, len(items), chunk_size):
        yield items[i:i + chunk_size]


# Schema cache po DB fajlu (invalidacija na schema token promenu)
_SQLITE_SCHEMA_TOKEN: Dict[str, int] = {}
_SQLITE_TABLE_EXISTS_CACHE: Dict[Tuple[str, str], bool] = {}
_SQLITE_COLS_CACHE: Dict[Tuple[str, str], Set[str]] = {}


def _schema_token(conn) -> int:
    """
    Stabilniji token od "user_version":
    - ako PRAGMA user_version > 0 koristi ga
    - inače, ako postoji schema_version tabela, koristi njen version
    - fallback 0
    """
    uv = 0
    try:
        row = conn.execute("PRAGMA user_version;").fetchone()
        uv = int(row[0] if row else 0)
    except Exception:
        uv = 0

    if uv > 0:
        return uv

    try:
        r = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version' LIMIT 1;"
        ).fetchone()
        if not r:
            return 0
        row2 = conn.execute("SELECT version FROM schema_version WHERE id=1;").fetchone()
        if not row2:
            return 0
        try:
            return int(row2[0])
        except Exception:
            return int(row2["version"])  # type: ignore[index]
    except Exception:
        return 0


def _ensure_schema_cache_current(conn, db_path: str) -> None:
    tok = _schema_token(conn)
    old = _SQLITE_SCHEMA_TOKEN.get(db_path)
    if old is None:
        _SQLITE_SCHEMA_TOKEN[db_path] = tok
        return
    if old != tok:
        # invalidiraj cache za taj DB
        for k in [k for k in _SQLITE_TABLE_EXISTS_CACHE.keys() if k[0] == db_path]:
            _SQLITE_TABLE_EXISTS_CACHE.pop(k, None)
        for k in [k for k in _SQLITE_COLS_CACHE.keys() if k[0] == db_path]:
            _SQLITE_COLS_CACHE.pop(k, None)
        _SQLITE_SCHEMA_TOKEN[db_path] = tok


@contextmanager
def _sqlite_conn():
    db_path = _get_db_path_str()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        try:
            conn.execute("PRAGMA busy_timeout=2500;")
            conn.execute("PRAGMA foreign_keys=ON;")
        except Exception:
            pass

        _ensure_schema_cache_current(conn, db_path)
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _sqlite_table_exists(conn, table: str) -> bool:
    if not _is_safe_ident(table):
        return False

    db_path = _get_db_path_str()
    key = (db_path, table.lower())
    cached = _SQLITE_TABLE_EXISTS_CACHE.get(key)
    if cached is not None:
        return cached

    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (table,),
        )
        ok = cur.fetchone() is not None
    except Exception:
        ok = False

    _SQLITE_TABLE_EXISTS_CACHE[key] = ok
    return ok


def _sqlite_cols(conn, table: str) -> Set[str]:
    if not _is_safe_ident(table):
        return set()

    db_path = _get_db_path_str()
    key = (db_path, table.lower())
    cached = _SQLITE_COLS_CACHE.get(key)
    if cached is not None:
        return set(cached)

    if not _sqlite_table_exists(conn, table):
        _SQLITE_COLS_CACHE[key] = set()
        return set()

    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        out = {str(r["name"]) for r in cur.fetchall()}
        out2 = _safe_cols(out)
    except Exception:
        out2 = set()

    _SQLITE_COLS_CACHE[key] = set(out2)
    return set(out2)


def _sqlite_select_assets_basic(
    conn,
    *,
    limit: int,
    where_sql: str = "",
    params: Tuple[Any, ...] = (),
) -> List[Dict[str, Any]]:
    cols = _sqlite_cols(conn, "assets")
    wanted = [
        "rb",
        "asset_uid", "name", "category", "status",
        "toc_number", "serial_number",
        "nomenclature_no", "nomenclature_number", "nomenklaturni_broj",
        "current_holder", "assigned_to",
        "location",
        "updated_at", "modified_at",
        "sector", "org_unit", "unit",
        "is_metrology",  # ✅ bitno za METRO scope
    ]
    sel = [c for c in wanted if c in cols]
    if not sel:
        sel = ["asset_uid"] if "asset_uid" in cols else []
    if not sel:
        return []

    sql = f"SELECT {', '.join(sel)} FROM assets"
    if where_sql:
        sql += f" WHERE {where_sql}"

    if "updated_at" in cols:
        sql += " ORDER BY updated_at DESC"
    elif "modified_at" in cols:
        sql += " ORDER BY modified_at DESC"
    else:
        sql += " ORDER BY rowid DESC"

    sql += " LIMIT ?"

    try:
        cur = conn.execute(sql, tuple(params) + (int(limit),))
        return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def _sqlite_assets_have_any_nomen(conn) -> bool:
    cols = _sqlite_cols(conn, "assets")
    return any(k in cols for k in _NOMENCLATURE_ALIASES)


def _sqlite_bulk_fetch_nomen(conn, uids: List[str]) -> Dict[str, str]:
    if not uids:
        return {}
    if not _sqlite_table_exists(conn, "assets"):
        return {}
    cols = _sqlite_cols(conn, "assets")
    if "asset_uid" not in cols:
        return {}
    if not _sqlite_assets_have_any_nomen(conn):
        return {}

    candidates = [c for c in _NOMENCLATURE_ALIASES if c in cols]
    if not candidates:
        return {}

    sel = ["asset_uid"] + candidates[:2]
    out: Dict[str, str] = {}

    for chunk in _iter_chunks(uids, chunk_size=800):
        qmarks = ",".join(["?"] * len(chunk))
        sql = f"SELECT {', '.join(sel)} FROM assets WHERE asset_uid IN ({qmarks})"
        try:
            rows = conn.execute(sql, tuple(chunk)).fetchall()
        except Exception:
            continue
        for r in rows:
            d = dict(r)
            uid = str(d.get("asset_uid") or "").strip()
            if not uid:
                continue
            v = _extract_nomenclature_from_dict(d)
            if v:
                out[uid] = v

    return out


# -------------------- Normalizacija izlaza za UI --------------------
def _norm_asset_row(r: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(r, dict):
        return r  # type: ignore

    rr: Dict[str, Any] = dict(r)

    # RB aliasi (fallback)
    if "rb" not in rr:
        for k in ("RB", "rownum", "row_no", "redni_broj"):
            if k in rr and rr.get(k) is not None:
                try:
                    rr["rb"] = int(rr.get(k))
                except Exception:
                    rr["rb"] = rr.get(k)
                break

    # UID trim
    if "asset_uid" in rr:
        try:
            rr["asset_uid"] = str(rr.get("asset_uid") or "").strip()
        except Exception:
            pass

    # TOC alias
    toc = rr.get("toc_number") or rr.get("toc") or rr.get("tocNo") or rr.get("toc_broj") or rr.get("tocbroj")
    if toc and not rr.get("toc_number"):
        rr["toc_number"] = toc

    # Serial alias
    sn = rr.get("serial_number") or rr.get("serial") or rr.get("sn") or rr.get("serijski") or rr.get("serijski_broj")
    if sn and not rr.get("serial_number"):
        rr["serial_number"] = sn

    # is_metrology normalize (0/1)
    if "is_metrology" in rr:
        try:
            rr["is_metrology"] = 1 if int(rr.get("is_metrology") or 0) == 1 else 0
        except Exception:
            rr["is_metrology"] = 0

    # Nomenclature canonicalize -> uvek popuni oba ključa ako ima vrednosti
    canon_val = _norm_nomenclature_value(rr.get(NOMENCLATURE_CANON_KEY))
    legacy_val = _norm_nomenclature_value(rr.get(NOMENCLATURE_LEGACY_KEY))
    if not canon_val and not legacy_val:
        v = _extract_nomenclature_from_dict(rr)
        if v:
            canon_val = v
    if canon_val or legacy_val:
        vfinal = canon_val or legacy_val
        rr[NOMENCLATURE_CANON_KEY] = vfinal
        rr[NOMENCLATURE_LEGACY_KEY] = vfinal

    # Holder unify
    holder = rr.get("current_holder") or rr.get("assigned_to") or rr.get("holder") or rr.get("zaduzeno_kod") or rr.get("kod_koga")
    if holder and not rr.get("current_holder"):
        rr["current_holder"] = holder

    # updated_at fallback
    if not rr.get("updated_at"):
        ua = rr.get("modified_at") or rr.get("updated") or rr.get("last_update") or rr.get("last_updated")
        if ua:
            rr["updated_at"] = ua

    return rr


def _enrich_rows_with_nomen_if_missing(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    only = [r for r in rows if isinstance(r, dict) and r]
    if not only:
        return rows

    need_uids: List[str] = []
    for r in only:
        uid = str(r.get("asset_uid") or "").strip()
        if not uid:
            continue
        nom = str(r.get(NOMENCLATURE_CANON_KEY) or r.get(NOMENCLATURE_LEGACY_KEY) or "").strip()
        if not nom:
            need_uids.append(uid)

    if not need_uids:
        return rows

    seen = set()
    need_uids2: List[str] = []
    for u in need_uids:
        if u not in seen:
            seen.add(u)
            need_uids2.append(u)

    try:
        with _sqlite_conn() as conn:
            mp = _sqlite_bulk_fetch_nomen(conn, need_uids2)
            if not mp:
                return rows
            out: List[Dict[str, Any]] = []
            for r in only:
                rr = dict(r)
                uid = str(rr.get("asset_uid") or "").strip()
                if uid and uid in mp:
                    v = mp[uid]
                    if v:
                        rr[NOMENCLATURE_CANON_KEY] = v
                        rr[NOMENCLATURE_LEGACY_KEY] = v
                out.append(rr)
            return out
    except Exception:
        return rows


def missing_fields_for_asset(asset: Dict[str, Any]) -> List[str]:
    if not isinstance(asset, dict):
        return []
    a = _norm_asset_row(dict(asset))
    missing: List[str] = []
    nom = str(a.get(NOMENCLATURE_CANON_KEY) or a.get(NOMENCLATURE_LEGACY_KEY) or "").strip()
    if not nom:
        missing.append("Nomenklaturni broj")
    return missing

# (FILENAME: services/assets_service.py - END PART 2/3)

# FILENAME: services/assets_service.py
# (FILENAME: services/assets_service.py - START PART 3/3)

# -------------------- Metrology-scope --------------------
def _row_metrology_flag(r: Dict[str, Any]) -> Optional[bool]:
    """
    Vraća True/False ako imamo eksplicitni flag u redu.
    None ako nema informacije (legacy).
    """
    if not isinstance(r, dict):
        return None

    for k in ("is_metrology", "is_metro", "metrology_flag", "metro_flag", "metrology_scope"):
        if k in r:
            try:
                return bool(int(r.get(k) or 0) == 1)
            except Exception:
                return bool(r.get(k))
    return None


def _asset_has_metrology_record(asset_uid: str) -> bool:
    uid = (asset_uid or "").strip()
    if not uid:
        return False

    if _db_asset_has_metrology is not None:
        try:
            return bool(_call_compatible(_db_asset_has_metrology, asset_uid=uid))
        except Exception:
            return False

    try:
        with _sqlite_conn() as conn:
            for t in ("metrology_records", "metrology", "calibration_records"):
                if not _sqlite_table_exists(conn, t):
                    continue
                if "asset_uid" not in _sqlite_cols(conn, t):
                    continue
                cur = conn.execute(f"SELECT 1 FROM {t} WHERE asset_uid=? LIMIT 1", (uid,))
                if cur.fetchone() is not None:
                    return True
    except Exception:
        return False
    return False


def _bulk_assets_metrology_flag(conn, uids: List[str]) -> Set[str]:
    """
    Bulk fetch: vrati set asset_uid gde je is_metrology=1 (ako kolona postoji).
    Ako nema kolone ili tabele -> prazan set.
    """
    out: Set[str] = set()
    if not uids:
        return out
    if not _sqlite_table_exists(conn, "assets"):
        return out
    cols = _sqlite_cols(conn, "assets")
    if "asset_uid" not in cols or "is_metrology" not in cols:
        return out

    try:
        conn.execute("CREATE TEMP TABLE IF NOT EXISTS tmp_uids(uid TEXT PRIMARY KEY);")
        conn.execute("DELETE FROM tmp_uids;")
        for chunk in _iter_chunks(uids, chunk_size=5000):
            conn.executemany("INSERT OR IGNORE INTO tmp_uids(uid) VALUES(?);", [(u,) for u in chunk])

        rows = conn.execute(
            "SELECT a.asset_uid FROM assets a JOIN tmp_uids u ON u.uid=a.asset_uid WHERE COALESCE(a.is_metrology,0)=1;"
        ).fetchall()
        out = {str(r[0] or "").strip() for r in rows if str(r[0] or "").strip()}
    except Exception:
        return set()
    return out


def _is_metrology_scope_asset(r: Dict[str, Any], *, met_flag_uids: Optional[Set[str]] = None) -> bool:
    """
    METRO scope pravilo:
    - Ako imamo is_metrology flag (u redu ili u šemi) -> samo flag=1
    - Legacy fallback (ako flag nije dostupan): heuristike + metrology_records existence
    """
    if not isinstance(r, dict):
        return False

    uid = str(r.get("asset_uid") or "").strip()
    if not uid:
        return False

    f = _row_metrology_flag(r)
    if f is not None:
        return bool(f)

    if met_flag_uids is not None:
        return uid in met_flag_uids

    # Legacy fallback: (samo kad nemamo flag)
    cat = (r.get("category") or r.get("kategorija") or "").strip().lower()
    if cat and ("metrolog" in cat or cat in {"merna oprema", "merni uredjaji", "merni uređaji"}):
        return True

    for k in (
        "needs_calibration", "calibration_required", "is_calibration_asset",
    ):
        if k in r:
            try:
                if bool(r.get(k)):
                    return True
            except Exception:
                pass

    return _asset_has_metrology_record(uid)


def _metrology_scope_filter(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    only = [r for r in rows if isinstance(r, dict)]
    if not only:
        return []

    # Ako makar jedan red ima eksplicitni flag key, koristimo samo to (najsigurnije).
    has_flag_in_rows = any(_row_metrology_flag(r) is not None for r in only)
    if has_flag_in_rows:
        return [r for r in only if bool(_row_metrology_flag(r) is True)]

    # Ako nemamo flag u rezultatima, ali šema možda ima kolonu -> bulk fetch flags.
    uids = [str(r.get("asset_uid") or "").strip() for r in only if str(r.get("asset_uid") or "").strip()]
    met_set: Optional[Set[str]] = None
    try:
        with _sqlite_conn() as conn:
            met_set = _bulk_assets_metrology_flag(conn, uids)
    except Exception:
        met_set = None

    if met_set is not None and len(met_set) > 0:
        return [r for r in only if _is_metrology_scope_asset(r, met_flag_uids=met_set)]

    # Legacy fallback (nema kolone ili nije dostupno)
    return [r for r in only if _is_metrology_scope_asset(r)]


def _enforce_scope_one(asset: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Enforce scope na nivou jednog sredstva (get_asset_by_uid).
    FAIL-CLOSED.
    """
    if not asset or not isinstance(asset, dict):
        return asset

    if _has_full_assets_view():
        return asset

    if _has_my_assets_view() and _is_my_scope_asset(asset):
        return asset

    if _has_metro_assets_view():
        if not _is_metrology_scope_asset(asset):
            raise PermissionError("Nemaš pravo da vidiš sredstvo van metrology-scope.")
        return asset

    if _has_my_assets_view():
        raise PermissionError("Nemaš pravo da vidiš sredstvo van MY scope (moja zaduženja).")

    return asset


# -------------------- Requested scope (UI switch) --------------------
def _choose_effective_scope(requested: Any) -> str:
    """
    Bira stvarni scope koji smemo da damo (FAIL-CLOSED).
    - requested=ALL -> treba assets.view, inače fallback.
    - requested=MY -> treba assets.my.view ili assets.view
    - requested=METRO -> treba assets.metrology.view ili assets.view
    - AUTO -> prefer FULL, zatim METRO, zatim MY (stari behavior)
    """
    req = _parse_scope(requested)

    has_full = _has_full_assets_view()
    has_metro = _has_metro_assets_view()
    has_my = _has_my_assets_view()

    if req == SCOPE_ALL:
        if has_full:
            return SCOPE_ALL
        if has_metro:
            return SCOPE_METRO
        if has_my:
            return SCOPE_MY
        return SCOPE_AUTO

    if req == SCOPE_METRO:
        if has_full or has_metro:
            return SCOPE_METRO
        if has_my:
            return SCOPE_MY
        return SCOPE_AUTO

    if req == SCOPE_MY:
        if has_full or has_my:
            return SCOPE_MY
        if has_metro:
            return SCOPE_METRO
        return SCOPE_AUTO

    # AUTO
    if has_full:
        return SCOPE_ALL
    if has_metro:
        return SCOPE_METRO
    if has_my:
        return SCOPE_MY
    return SCOPE_AUTO


def _apply_list_scope(
    rows: List[Dict[str, Any]],
    *,
    requested_scope: Any = "",
    metrology_only: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    """
    Centralizovano scope filtriranje za list_* pozive.
    - Ako UI prosledi scope, poštujemo ga ako je dozvoljen.
    - metrology_only=True forsira METRO (ali i dalje RBAC/sector važe).
    - Sector-scope (REFERENT_METRO) kao dodatni FAIL-CLOSED filter.
    """
    is_sector = _is_sector_scoped_metro()
    sector = _current_sector() if is_sector else ""

    req_scope = requested_scope
    if metrology_only is True:
        req_scope = SCOPE_METRO

    eff = _choose_effective_scope(req_scope)

    if eff == SCOPE_ALL:
        out = rows
    elif eff == SCOPE_METRO:
        out = _metrology_scope_filter(rows)
    elif eff == SCOPE_MY:
        out = _my_scope_filter(rows)
    else:
        out = []

    if is_sector:
        out = _sector_filter_rows(out, sector, strict=True)

    return out


# -------------------- SQLite search helpers --------------------
def _sqlite_build_where(
    cols_in: Set[str],
    *,
    final_q: str,
    category: str,
    status: str,
    metrology_only: bool = False,
) -> Tuple[str, List[Any]]:
    cols = _safe_cols(set(cols_in))
    where: List[str] = []
    params: List[Any] = []

    if metrology_only and "is_metrology" in cols:
        where.append("COALESCE(is_metrology,0)=1")

    cat = (category or "SVE").strip()
    if cat and cat.upper() != "SVE" and "category" in cols:
        where.append("category = ?")
        params.append(cat)

    st = (status or "SVE").strip()
    if st and st.upper() != "SVE" and "status" in cols:
        where.append("status = ?")
        params.append(st)

    if final_q:
        like = f"%{final_q}%"
        search_cols: List[str] = [
            c for c in (
                "rb",
                "asset_uid", "name",
                "toc_number", "serial_number",
                "location",
                "current_holder", "assigned_to",
            )
            if c in cols
        ]
        for nc in _NOMENCLATURE_ALIASES:
            if nc in cols and nc not in search_cols:
                search_cols.append(nc)
        if search_cols:
            where.append("(" + " OR ".join([f"{c} LIKE ?" for c in search_cols]) + ")")
            params.extend([like] * len(search_cols))

    return " AND ".join(where), params


def _sqlite_list_assets(*, final_q: str, category: str, status: str, limit: int, metrology_only: bool = False) -> List[Dict[str, Any]]:
    with _sqlite_conn() as conn:
        if not _sqlite_table_exists(conn, "assets"):
            return []
        cols = _sqlite_cols(conn, "assets")
        where_sql, params = _sqlite_build_where(cols, final_q=final_q, category=category, status=status, metrology_only=metrology_only)
        rows = _sqlite_select_assets_basic(conn, limit=limit, where_sql=where_sql, params=tuple(params))
        normed = [r for r in (_norm_asset_row(x) for x in rows) if isinstance(r, dict)]
        return _enrich_rows_with_nomen_if_missing(normed)


# -------------------- Public API --------------------
def create_asset(
    *,
    actor: str,
    toc: Optional[str] = None,
    toc_number: Optional[str] = None,
    serial: Optional[str] = None,
    serial_number: Optional[str] = None,
    nomenclature_no: Optional[str] = None,
    nomenclature_number: Optional[str] = None,
    name: str = "",
    category: str = "SI",
    status: str = "active",
    assigned_to: str = "",
    location: str = "",
    notes_summary: str = "",
    source: str = "assets_service.create_asset",
    **extra: Any,
) -> str:
    _require_login("assets.create_asset")
    _require_perm(PERM_ASSETS_CREATE, "assets.create_asset")

    # actor param zadržan radi kompatibilnosti, ali audit prati sesiju
    actor_eff = _actor_name_for_audit()

    if toc is None and toc_number is not None:
        toc = str(toc_number).strip()
    if serial is None and serial_number is not None:
        serial = str(serial_number).strip()

    t_str = str(toc or "").strip()
    sn_str = str(serial or "").strip()

    tn_str = str(toc_number if toc_number is not None else t_str).strip()
    sdn_str = str(serial_number if serial_number is not None else sn_str).strip()

    try:
        extra_dict = dict(extra or {})
    except Exception:
        extra_dict = {}

    nom = (
        _norm_nomenclature_value(nomenclature_no)
        or _norm_nomenclature_value(nomenclature_number)
        or _extract_nomenclature_from_dict(extra_dict)
    )
    if nom:
        extra_dict[NOMENCLATURE_CANON_KEY] = nom
        extra_dict[NOMENCLATURE_LEGACY_KEY] = nom

    if _current_role() == "SECTOR_ADMIN":
        sec = _current_sector()
        if not sec:
            raise PermissionError("SECTOR_ADMIN nema definisan sektor u sesiji (fail-closed).")
        extra_dict["sector"] = sec

    if _db_create_asset is None:
        raise RuntimeError(
            "Nedostaje core.db.create_asset_db (ili create_asset). "
            "Ne radim ručni INSERT da ne pokvarimo UID/RB logiku."
        )

    payload = dict(
        actor=actor_eff,
        toc_number=tn_str,
        serial_number=sdn_str,
        name=(name or "").strip(),
        category=(category or "").strip() or "SI",
        status=(status or "").strip() or "active",
        location=(location or "").strip(),
        source=(source or "").strip(),
        assigned_to=(assigned_to or "").strip(),
        notes_summary=(notes_summary or "").strip(),
        **extra_dict,
    )
    return _call_compatible(_db_create_asset, **payload)


def list_assets(
    *,
    q: str = "",
    search: str = "",
    category: str = "SVE",
    status: str = "SVE",
    limit: int = 5000,
    scope: Any = "",                        # ✅ UI scope switch
    metrology_only: Optional[bool] = None,  # ✅ kompat (True => METRO)
) -> List[Dict[str, Any]]:
    """
    Vraća listu sredstava uz FAIL-CLOSED RBAC i scope.
    - Ako scope nije zadat: stara precedenca (FULL->METRO->MY).
    - metrology_only=True -> forsira METRO i pokušava DB filter.
    """
    _require_perm_any(_ASSETS_LIST_PERMS, "assets.list_assets")

    final_q = (q or "").strip() or (search or "").strip()
    lim = _clamp_limit(limit, 5000)

    eff_scope = scope
    if metrology_only is True:
        eff_scope = SCOPE_METRO

    eff = _choose_effective_scope(eff_scope)
    want_metro_only = (eff == SCOPE_METRO)

    # pokušaj DB sloj (core.db)
    if _db_list_assets is not None:
        payload = dict(
            q=final_q,
            search=final_q,
            category=(category or "SVE"),
            status=(status or "SVE"),
            limit=lim,
            sector=_current_sector() if _is_sector_scoped_metro() else "SVE",
            metrology_only=bool(want_metro_only),
        )

        try:
            res = _call_compatible(_db_list_assets, **payload)
        except sqlite3.OperationalError as e:
            # legacy DB bez kolone: retry bez metrology_only (fail-soft, a filter će se uraditi servisno)
            msg = str(e).lower()
            if "no such column" in msg and "is_metrology" in msg:
                payload.pop("metrology_only", None)
                res = _call_compatible(_db_list_assets, **payload)
            else:
                logger.exception("core.db.list_assets failed: %s", e)
                res = []
        except Exception as e:
            logger.exception("core.db.list_assets failed: %s", e)
            res = []

        if not isinstance(res, list):
            try:
                res = list(res)  # type: ignore
            except Exception:
                res = []

        rows = [(_norm_asset_row(r) if isinstance(r, dict) else {}) for r in res]  # type: ignore
        rows = [r for r in rows if isinstance(r, dict) and r]
        rows = _enrich_rows_with_nomen_if_missing(rows)
        return _apply_list_scope(rows, requested_scope=eff_scope, metrology_only=metrology_only)

    # sqlite fallback
    try:
        rows2 = _sqlite_list_assets(final_q=final_q, category=category, status=status, limit=lim, metrology_only=want_metro_only)
        return _apply_list_scope(rows2, requested_scope=eff_scope, metrology_only=metrology_only)
    except Exception as e:
        logger.exception("sqlite list_assets failed: %s", e)
        return []


def list_assets_brief(
    *,
    limit: int = 1000,
    scope: Any = "",                         # ✅ UI scope switch radi i za brief
    metrology_only: Optional[bool] = None,   # ✅ kompat
) -> List[Dict[str, Any]]:
    """
    Brief list (manje kolona), uz FAIL-CLOSED RBAC + scope.
    metrology_only=True => forsira METRO (ali i dalje RBAC/sector važe).
    """
    _require_perm_any(_ASSETS_LIST_PERMS, "assets.list_assets_brief")
    lim = _clamp_limit(limit, 1000)

    eff_scope = scope
    if metrology_only is True:
        eff_scope = SCOPE_METRO

    eff = _choose_effective_scope(eff_scope)
    want_metro_only = (eff == SCOPE_METRO)

    if _db_list_assets_brief is not None:
        try:
            res = _call_compatible(
                _db_list_assets_brief,
                limit=lim,
                sector=_current_sector() if _is_sector_scoped_metro() else "SVE",
                metrology_only=bool(want_metro_only),
            )
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "no such column" in msg and "is_metrology" in msg:
                # retry bez metrology_only (servisni filter)
                res = _call_compatible(
                    _db_list_assets_brief,
                    limit=lim,
                    sector=_current_sector() if _is_sector_scoped_metro() else "SVE",
                )
            else:
                logger.exception("core.db.list_assets_brief failed: %s", e)
                res = []
        except Exception as e:
            logger.exception("core.db.list_assets_brief failed: %s", e)
            res = []

        if not isinstance(res, list):
            try:
                res = list(res)  # type: ignore
            except Exception:
                res = []
        rows = [(_norm_asset_row(r) if isinstance(r, dict) else {}) for r in res]  # type: ignore
        rows = [r for r in rows if isinstance(r, dict) and r]
    else:
        try:
            with _sqlite_conn() as conn:
                if not _sqlite_table_exists(conn, "assets"):
                    return []
                rows = [(_norm_asset_row(r) if isinstance(r, dict) else {}) for r in _sqlite_select_assets_basic(conn, limit=lim)]  # type: ignore
                rows = [r for r in rows if isinstance(r, dict) and r]
        except Exception as e:
            logger.exception("sqlite list_assets_brief failed: %s", e)
            return []

    rows = _enrich_rows_with_nomen_if_missing(rows)
    return _apply_list_scope(rows, requested_scope=eff_scope, metrology_only=metrology_only)


def get_asset_by_uid(*, asset_uid: str) -> Optional[Dict[str, Any]]:
    _require_perm_any(_ASSETS_LIST_PERMS, "assets.get_asset_by_uid")
    uid = (asset_uid or "").strip()
    if not uid:
        return None

    sector = _current_sector() if _is_sector_scoped_metro() else ""

    def _enforce_sector(rr: Dict[str, Any]) -> None:
        if _is_sector_scoped_metro() and (not _has_full_assets_view()):
            if _has_my_assets_view() and _is_my_scope_asset(rr):
                return
            if not sector:
                raise PermissionError("Nemaš definisan sektor u sesiji (sector-scope je fail-closed).")
            a_sec = _asset_sector_value(rr)
            if (not a_sec) or (not _sector_eq(a_sec, sector)):
                raise PermissionError("Nemaš pravo da vidiš sredstvo van svog sektora.")

    if _db_get_asset_by_uid is not None:
        try:
            r = _call_compatible(_db_get_asset_by_uid, asset_uid=uid)
        except Exception as e:
            logger.exception("core.db.get_asset_by_uid failed: %s", e)
            r = None

        if isinstance(r, dict):
            rr = _enforce_scope_one(_norm_asset_row(r))
            if rr is None:
                return None
            _enforce_sector(rr)
            rr2 = _enrich_rows_with_nomen_if_missing([rr])
            return rr2[0] if rr2 else rr
        return None

    try:
        with _sqlite_conn() as conn:
            if not _sqlite_table_exists(conn, "assets"):
                return None
            if "asset_uid" not in _sqlite_cols(conn, "assets"):
                return None
            rows = _sqlite_select_assets_basic(conn, limit=1, where_sql="asset_uid=?", params=(uid,))
            if not rows:
                return None
            rr = _enforce_scope_one(_norm_asset_row(rows[0]))
            if rr is None:
                return None
            _enforce_sector(rr)
            rr2 = _enrich_rows_with_nomen_if_missing([rr])
            return rr2[0] if rr2 else rr
    except PermissionError:
        raise
    except Exception as e:
        logger.exception("sqlite get_asset_by_uid failed: %s", e)
        return None


def list_assets_my(
    *,
    q: str = "",
    search: str = "",
    category: str = "SVE",
    status: str = "SVE",
    limit: int = 5000,
) -> List[Dict[str, Any]]:
    """
    Kompatibilni API: MY list.
    Interno koristi list_assets + MY scope.
    """
    _require_login("assets.list_assets_my")
    _require_perm_any([PERM_ASSETS_VIEW, PERM_ASSETS_MY_VIEW], "assets.list_assets_my")
    return list_assets(q=q, search=search, category=category, status=status, limit=limit, scope=SCOPE_MY)


# alias (kompatibilnost)
list_assets_my_brief = list_assets_my

# (FILENAME: services/assets_service.py - END PART 3/3)