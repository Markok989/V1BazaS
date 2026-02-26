# FILENAME: services/assets_service.py
# (FILENAME: services/assets_service.py - START PART 1/2)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/assets_service.py

Servis sloj za sredstva (assets) sa RBAC + scope filtriranjem (FAIL-CLOSED):
- FULL: assets.view
- METRO: assets.metrology.view (metrology-scope)
- MY: assets.my.view (samo sredstva koja korisnik trenutno duži)

Senior rev (2026-02-26) — HARDENED:
- Security scope je PRVOKLASNI filter: koristi core.session.effective_scope() (ALL|SECTOR|MY) kad postoji.
- SECTOR scope bez sektora -> eksplicitno fail-closed (PermissionError), ne “tiho prazno”.
- MY scope: preferira DB-level identitet (current_holder_user_id / current_holder_key) kad postoji,
  tek onda fallback na tekstualno poređenje (legacy).
- Requested scope (UI): ALL/MY/METRO je samo narrowing, nikad widening.
- Compat: _call_compatible za različite potpise core.db funkcija.
- Perf: signature cache + schema token invalidacija + DB path cache.

Output:
- canonical nomenclature field (nomenclature_no + nomenclature_number).

Patch (2026-02-26, disposal enablement):
- FIX: prepare/approve/cancel/dispose fail-closed ako asset ne postoji ili nije vidljiv u scope-u.
- NEW: get_open_disposal_case_for_asset() i list_disposal_queue() (UI tab “Priprema za rashod”).
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


# Optional perms for disposal workflow (ako core.rbac još nema konstante – fallback strings)
try:
    from core.rbac import (  # type: ignore
        PERM_DISPOSAL_PREPARE,
        PERM_DISPOSAL_APPROVE,
        PERM_DISPOSAL_DISPOSE,
    )
except Exception:  # pragma: no cover
    PERM_DISPOSAL_PREPARE = "disposal.prepare"
    PERM_DISPOSAL_APPROVE = "disposal.approve"
    PERM_DISPOSAL_DISPOSE = "disposal.dispose"


_ASSETS_LIST_PERMS: List[str] = [PERM_ASSETS_VIEW, PERM_ASSETS_METRO_VIEW, PERM_ASSETS_MY_VIEW]
_DISPOSAL_ANY_PERMS: List[str] = [PERM_DISPOSAL_PREPARE, PERM_DISPOSAL_APPROVE, PERM_DISPOSAL_DISPOSE]

# -------------------- Scope normalization (UI <-> Service contract) --------------------
SCOPE_AUTO = "AUTO"
SCOPE_ALL = "ALL"
SCOPE_MY = "MY"
SCOPE_METRO = "METRO"


def _norm_scope(scope: Any) -> str:
    """
    Normalizuje requested scope iz UI (srpski tekst) ili internog koda u:
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
    """Jedan ulaz za requested scope: vraća AUTO/ALL/MY/METRO."""
    s = _norm_scope(scope)
    if s in (SCOPE_ALL, SCOPE_MY, SCOPE_METRO):
        return s
    return SCOPE_AUTO


# -------------------- Session / RBAC helpers --------------------
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


def _actor_name_for_audit() -> str:
    """Audit identitet može fallback na 'user' (nije security boundary)."""
    try:
        from core.session import actor_name  # type: ignore
        return (actor_name() or "").strip() or "user"
    except Exception:
        return "user"


def _session_user_id() -> int:
    try:
        from core.session import current_user_id  # type: ignore
        return int(current_user_id() or 0)
    except Exception:
        try:
            from core.session import get_current_user_copy  # type: ignore
            u = get_current_user_copy() or {}
            raw = u.get("id", None) if isinstance(u, dict) else None
            return int(raw or 0)
        except Exception:
            return 0


def _session_actor_key_raw() -> str:
    try:
        from core.session import actor_key  # type: ignore
        return (actor_key() or "").strip()
    except Exception:
        return ""


def _actor_key_for_identity() -> str:
    """
    Identitet za MY scope: bez placeholder-a.
    Vraća "" ako ne znamo ko je user (fail-closed).
    """
    ak = _session_actor_key_raw()
    if not ak:
        return ""
    low = ak.strip().casefold()
    if low in ("user", "unknown"):
        return ""
    if low.startswith("user#0"):
        return ""
    return ak


def _actor_name_for_identity() -> str:
    """Identitet za MY scope (display)."""
    try:
        from core.session import actor_name  # type: ignore
        an = (actor_name() or "").strip()
    except Exception:
        an = ""
    low = an.casefold()
    if not an or low in ("user", "unknown"):
        return ""
    return an


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


# -------------------- Session helpers (sector + role) --------------------
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


def _current_role() -> str:
    u = _get_current_user()
    try:
        r = effective_role(u)
        return (r or "READONLY").strip().upper()
    except Exception:
        r2 = (u.get("active_role") or u.get("role") or u.get("user_role") or "")
        return str(r2).strip().upper() or "READONLY"


def _is_global_admin_like() -> bool:
    r = _current_role()
    return r in ("GLOBAL_ADMIN", "ADMIN", "SUPERADMIN")


def _norm_sector(x: Any) -> str:
    s = ("" if x is None else str(x)).replace("\n", " ").replace("\r", " ").strip()
    return s[:80]


def _current_sector() -> str:
    """Jedno mesto za sektor iz sesije."""
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


def _require_sector(context: str = "") -> str:
    """
    Fail-closed: ako smo u SECTOR security scope, sektor MORA postojati.
    Prefer core.session.require_sector().
    """
    try:
        from core.session import require_sector as _rs  # type: ignore
        return str(_rs(context or "assets") or "").strip()
    except PermissionError:
        raise
    except Exception:
        sec = _current_sector()
        if sec:
            return sec
        ctx = (context or "").strip()
        raise PermissionError(
            f"Nedostaje sektor u sesiji za SECTOR scope. ({ctx})" if ctx else "Nedostaje sektor u sesiji za SECTOR scope."
        )


def _session_effective_scope() -> str:
    """
    Security scope iz sesije (ako postoji): ALL | SECTOR | MY.
    Fail-soft: ako nema, vraća "" (nepoznato).
    """
    try:
        from core.session import effective_scope  # type: ignore
        sc = effective_scope()
        s = ("" if sc is None else str(sc)).strip().upper()
        if s in ("ALL", "SECTOR", "MY"):
            return s
    except Exception:
        pass
    return ""


def _asset_sector_value(r: Dict[str, Any]) -> str:
    for k in ("sector", "sektor", "org_unit", "orgunit", "unit", "department", "dept", "sector_code", "sector_id"):
        v = r.get(k)
        if v is not None and str(v).strip():
            return _norm_sector(v)
    return ""


def _sector_eq(a: str, b: str) -> bool:
    return (a or "").strip().casefold() == (b or "").strip().casefold()


def _sector_filter_rows(rows: List[Dict[str, Any]], sector: str, *, strict: bool = True) -> List[Dict[str, Any]]:
    """
    strict=True (fail-closed):
      - ako asset nema sektor -> ne prikazuj
      - ako nema sector u sesiji -> PermissionError
    """
    sec = _norm_sector(sector)
    if not sec:
        if strict:
            raise PermissionError("Nedostaje sektor u sesiji (SECTOR scope je fail-closed).")
        return rows

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


def _security_scope_policy() -> str:
    """
    Konačni security scope (FAIL-CLOSED):
    - Ako sesija eksplicitno kaže ALL/SECTOR/MY -> to je maksimalni scope (sa clamp-om ALL).
    - Ako nema -> derivacija iz RBAC:
        assets.view => ALL
        assets.metrology.view => SECTOR
        assets.my.view => MY
    """
    sc = _session_effective_scope()
    if sc:
        if sc == "ALL":
            # ALL je realno dozvoljen samo admin-like + assets.view
            if _has_full_assets_view() and _is_global_admin_like():
                return "ALL"
            # clamp
            if _has_full_assets_view():
                return "SECTOR"
            return "MY" if _has_my_assets_view() else ""
        if sc in ("SECTOR", "MY"):
            return sc
        return ""

    if _has_full_assets_view():
        return "ALL"
    if _has_metro_assets_view():
        return "SECTOR"
    if _has_my_assets_view():
        return "MY"
    return ""


# -------------------- MY scope helpers (DB-first, legacy fallback) --------------------
ASSET_HOLDER_USER_ID_COL = "current_holder_user_id"
ASSET_HOLDER_KEY_COL = "current_holder_key"

_TOKEN_SPLIT_RE = re.compile(r"[^\w]+", flags=re.UNICODE)


def _norm_text(x: Any) -> str:
    return ("" if x is None else str(x)).replace("\n", " ").replace("\r", " ").strip()


def _identity_candidates() -> List[str]:
    """
    Legacy MY fallback (string-based). DB-first je iznad ovog.
    """
    u = _get_current_user()
    cand: List[str] = []

    ak = _actor_key_for_identity()
    if ak:
        cand.append(ak)

    an = _actor_name_for_identity()
    if an:
        cand.append(an)

    for k in ("username", "login", "email", "display_name", "name", "full_name", "account"):
        v = u.get(k)
        if v is not None and str(v).strip():
            cand.append(str(v).strip())

    for k in ("id", "user_id", "uid"):
        v = u.get(k)
        if v is not None and str(v).strip():
            cand.append(str(v).strip())

    out: List[str] = []
    seen = set()
    for c in cand:
        cc = _norm_text(c).casefold()
        if cc and cc not in seen and cc not in ("user", "unknown"):
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


def _is_my_scope_asset_dbfirst(r: Dict[str, Any]) -> bool:
    """
    MY scope (security relevant) — DB-first:
    1) ako red ima current_holder_user_id i poklapa se sa session user_id -> True
    2) else, ako ima current_holder_key i poklapa se sa session actor_key -> True
    3) else -> legacy string fallback (oprezno)
    """
    if not isinstance(r, dict):
        return False

    # mora postojati holder (da ne prikažemo “bez zaduženja” u MY)
    if not _asset_holder_value(r).strip():
        return False

    uid = _session_user_id()
    if uid > 0 and ASSET_HOLDER_USER_ID_COL in r:
        try:
            return int(r.get(ASSET_HOLDER_USER_ID_COL) or 0) == int(uid)
        except Exception:
            pass

    ak = _actor_key_for_identity()
    if ak and ASSET_HOLDER_KEY_COL in r:
        try:
            return str(r.get(ASSET_HOLDER_KEY_COL) or "").strip().casefold() == ak.casefold()
        except Exception:
            pass

    # legacy fallback
    cands = _identity_candidates()
    if not cands:
        return False

    holder = _asset_holder_value(r).strip()
    h = holder.casefold()

    # exact
    for c in cands:
        if c and h == c:
            return True

    # token match (oprezno)
    ht = _tokens(holder)
    if not ht:
        return False
    for c in cands:
        if c and len(c) >= 4 and c in ht:
            return True

    return False


def _my_scope_filter(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in rows:
        if isinstance(r, dict) and _is_my_scope_asset_dbfirst(r):
            out.append(r)
    return out


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

# disposal workflow (optional, introduced in core/db.py v8)
_db_prepare_disposal, _ = _try_import_db_func("prepare_disposal_db", "prepare_disposal")
_db_approve_disposal, _ = _try_import_db_func("approve_disposal_db", "approve_disposal")
_db_cancel_disposal, _ = _try_import_db_func("cancel_disposal_db", "cancel_disposal")
_db_dispose_from_case, _ = _try_import_db_func("dispose_from_case_db", "dispose_from_case")

# -------------------- SQLite helpers (fallback + enrichment) --------------------
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _is_safe_ident(name: str) -> bool:
    return bool(name and _IDENT_RE.match(name))


def _safe_cols(cols: Set[str]) -> Set[str]:
    return {c for c in cols if _is_safe_ident(c)}


def _app_root() -> Path:
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


_SQLITE_SCHEMA_TOKEN: Dict[str, int] = {}
_SQLITE_TABLE_EXISTS_CACHE: Dict[Tuple[str, str], bool] = {}
_SQLITE_COLS_CACHE: Dict[Tuple[str, str], Set[str]] = {}


def _schema_token(conn) -> int:
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
        for k in [k for k in list(_SQLITE_TABLE_EXISTS_CACHE.keys()) if k[0] == db_path]:
            _SQLITE_TABLE_EXISTS_CACHE.pop(k, None)
        for k in [k for k in list(_SQLITE_COLS_CACHE.keys()) if k[0] == db_path]:
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

# (FILENAME: services/assets_service.py - END PART 1/2)

# FILENAME: services/assets_service.py
# (FILENAME: services/assets_service.py - START PART 2/2)

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
        # nomenclature variants
        "nomenclature_no", "nomenclature_number", "nomenklaturni_broj",
        # holder variants
        "current_holder", "assigned_to",
        # MY DB-first holder columns (optional)
        ASSET_HOLDER_USER_ID_COL, ASSET_HOLDER_KEY_COL,
        "location",
        "updated_at", "modified_at",
        "sector", "org_unit", "unit", "department", "dept",
        "is_metrology",
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

    # sector normalize
    if "sector" in rr:
        rr["sector"] = _norm_sector(rr.get("sector"))
    else:
        for k in ("org_unit", "unit", "department", "dept", "sector_code"):
            if k in rr and rr.get(k) is not None and str(rr.get(k)).strip():
                rr["sector"] = _norm_sector(rr.get(k))
                break

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


# -------------------- Metrology-scope --------------------
def _row_metrology_flag(r: Dict[str, Any]) -> Optional[bool]:
    """Vraća True/False ako imamo eksplicitni flag u redu. None ako nema informacije (legacy)."""
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
    """
    out: Set[str] = set()
    if not uids:
        return out
    if not _sqlite_table_exists(conn, "assets"):
        return out
    cols = _sqlite_cols(conn, "assets")
    if "asset_uid" not in cols or "is_metrology" not in cols:
        return out

    if len(uids) <= 900:
        qmarks = ",".join(["?"] * len(uids))
        try:
            rows = conn.execute(
                f"SELECT asset_uid FROM assets WHERE asset_uid IN ({qmarks}) AND COALESCE(is_metrology,0)=1;",
                tuple(uids),
            ).fetchall()
            return {str(r[0] or "").strip() for r in rows if str(r[0] or "").strip()}
        except Exception:
            return set()

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
    - Ako imamo is_metrology flag -> samo flag=1
    - Legacy fallback: heuristike + metrology_records existence
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

    cat = (r.get("category") or r.get("kategorija") or "").strip().lower()
    if cat and ("metrolog" in cat or cat in {"merna oprema", "merni uredjaji", "merni uređaji"}):
        return True

    for k in ("needs_calibration", "calibration_required", "is_calibration_asset"):
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

    has_flag_in_rows = any(_row_metrology_flag(r) is not None for r in only)
    if has_flag_in_rows:
        return [r for r in only if bool(_row_metrology_flag(r) is True)]

    uids = [str(r.get("asset_uid") or "").strip() for r in only if str(r.get("asset_uid") or "").strip()]
    met_set: Optional[Set[str]] = None
    try:
        with _sqlite_conn() as conn:
            met_set = _bulk_assets_metrology_flag(conn, uids)
    except Exception:
        met_set = None

    if met_set is not None and len(met_set) > 0:
        return [r for r in only if _is_metrology_scope_asset(r, met_flag_uids=met_set)]

    return [r for r in only if _is_metrology_scope_asset(r)]


def _enforce_view_perms_one(asset: Dict[str, Any]) -> None:
    """
    Dodatni RBAC “view-type” guard (ne mešati sa security scope):
    - assets.view -> može sve (subject to security scope)
    - assets.metrology.view -> samo metrology sredstva
    - assets.my.view -> samo MY sredstva
    FAIL-CLOSED.
    """
    if _has_full_assets_view():
        return

    if _has_my_assets_view() and _is_my_scope_asset_dbfirst(asset):
        return

    if _has_metro_assets_view():
        if not _is_metrology_scope_asset(asset):
            raise PermissionError("Nemaš pravo da vidiš sredstvo van metrology-scope.")
        return

    if _has_my_assets_view():
        raise PermissionError("Nemaš pravo da vidiš sredstvo van MY scope (moja zaduženja).")

    raise PermissionError("Nemaš pravo da vidiš sredstva (RBAC).")


# -------------------- Security scope enforcement --------------------
def _apply_security_scope(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Primenjuje maksimalni security scope iz sesije/RBAC:
      ALL -> ništa dodatno (ALL dozvoljen samo admin-like + assets.view)
      SECTOR -> strict filter po sector (fail-closed ako sektor fali)
      MY -> strict filter po my zaduženjima
    """
    sec_scope = _security_scope_policy()

    if sec_scope == "ALL":
        return rows

    if sec_scope == "SECTOR":
        sec = _require_sector("assets.security_scope")
        return _sector_filter_rows(rows, sec, strict=True)

    if sec_scope == "MY":
        return _my_scope_filter(rows)

    return []


# -------------------- Requested scope (UI narrowing) --------------------
def _choose_requested_scope(requested: Any) -> str:
    """
    Requested scope je UI filter (narrowing), ali ga validiramo RBAC-om.
    - requested=ALL -> treba assets.view
    - requested=MY -> treba assets.my.view ili assets.view
    - requested=METRO -> treba assets.metrology.view ili assets.view
    - AUTO -> prefer FULL, zatim METRO, zatim MY
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

    if has_full:
        return SCOPE_ALL
    if has_metro:
        return SCOPE_METRO
    if has_my:
        return SCOPE_MY
    return SCOPE_AUTO


def _apply_requested_scope(
    rows: List[Dict[str, Any]],
    *,
    requested_scope: Any = "",
    metrology_only: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    """
    Requested scope je UI narrowing filter.
    metrology_only=True forsira METRO narrowing.
    """
    req_scope = requested_scope
    if metrology_only is True:
        req_scope = SCOPE_METRO

    eff = _choose_requested_scope(req_scope)
    if eff == SCOPE_ALL:
        return rows
    if eff == SCOPE_METRO:
        return _metrology_scope_filter(rows)
    if eff == SCOPE_MY:
        return _my_scope_filter(rows)
    return []


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
                "sector",
                ASSET_HOLDER_KEY_COL,
            )
            if c in cols
        ]
        if ASSET_HOLDER_USER_ID_COL in cols:
            search_cols.append(f"CAST(COALESCE({ASSET_HOLDER_USER_ID_COL},'') AS TEXT)")

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
    """
    Security: actor param se NE koristi kao identitet (anti-spoof).
    Audit identitet se uzima iz sesije (_actor_name_for_audit()).
    """
    _require_login("assets.create_asset")
    _require_perm(PERM_ASSETS_CREATE, "assets.create_asset")

    _ = actor  # anti-spoof: namerno ignorišemo input actor, uzimamo iz session
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

    sec_scope = _security_scope_policy()
    if sec_scope in ("SECTOR", "MY") and not _is_global_admin_like():
        sec = _require_sector("assets.create_asset")
        extra_dict["sector"] = _norm_sector(sec)
    else:
        if "sector" in extra_dict:
            extra_dict["sector"] = _norm_sector(extra_dict.get("sector"))

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
    scope: Any = "",
    metrology_only: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    """
    FAIL-CLOSED pipeline:
    1) login + RBAC
    2) fetch (core.db ili sqlite fallback)
    3) normalize + nomen enrichment
    4) security scope (ALL/SECTOR/MY)
    5) requested scope (UI narrowing: ALL/MY/METRO)
    """
    _require_login("assets.list_assets")
    _require_perm_any(_ASSETS_LIST_PERMS, "assets.list_assets")

    final_q = (q or "").strip() or (search or "").strip()
    lim = _clamp_limit(limit, 5000)

    req_scope = scope
    if metrology_only is True:
        req_scope = SCOPE_METRO

    want_metro_requested = (_choose_requested_scope(req_scope) == SCOPE_METRO)

    rows: List[Dict[str, Any]] = []
    if _db_list_assets is not None:
        payload = dict(
            q=final_q,
            search=final_q,
            category=(category or "SVE"),
            status=(status or "SVE"),
            limit=lim,
            sector=_current_sector() if _security_scope_policy() == "SECTOR" else "SVE",
            metrology_only=bool(want_metro_requested),
        )
        try:
            res = _call_compatible(_db_list_assets, **payload)
        except sqlite3.OperationalError as e:
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
    else:
        try:
            rows = _sqlite_list_assets(
                final_q=final_q,
                category=category,
                status=status,
                limit=lim,
                metrology_only=bool(want_metro_requested),
            )
        except Exception as e:
            logger.exception("sqlite list_assets failed: %s", e)
            rows = []

    rows = _apply_security_scope(rows)
    rows = _apply_requested_scope(rows, requested_scope=req_scope, metrology_only=metrology_only)
    return rows


def list_assets_brief(
    *,
    limit: int = 1000,
    scope: Any = "",
    metrology_only: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    _require_login("assets.list_assets_brief")
    _require_perm_any(_ASSETS_LIST_PERMS, "assets.list_assets_brief")
    lim = _clamp_limit(limit, 1000)

    req_scope = scope
    if metrology_only is True:
        req_scope = SCOPE_METRO

    want_metro_requested = (_choose_requested_scope(req_scope) == SCOPE_METRO)

    rows: List[Dict[str, Any]] = []
    if _db_list_assets_brief is not None:
        try:
            res = _call_compatible(
                _db_list_assets_brief,
                limit=lim,
                sector=_current_sector() if _security_scope_policy() == "SECTOR" else "SVE",
                metrology_only=bool(want_metro_requested),
            )
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "no such column" in msg and "is_metrology" in msg:
                res = _call_compatible(
                    _db_list_assets_brief,
                    limit=lim,
                    sector=_current_sector() if _security_scope_policy() == "SECTOR" else "SVE",
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
    rows = _apply_security_scope(rows)
    rows = _apply_requested_scope(rows, requested_scope=req_scope, metrology_only=metrology_only)
    return rows


def get_asset_by_uid(*, asset_uid: str) -> Optional[Dict[str, Any]]:
    """
    Jedno sredstvo uz FAIL-CLOSED:
    - login + RBAC
    - view-type guard (FULL/METRO/MY)
    - security scope guard (ALL/SECTOR/MY)
    """
    _require_login("assets.get_asset_by_uid")
    _require_perm_any(_ASSETS_LIST_PERMS, "assets.get_asset_by_uid")
    uid = (asset_uid or "").strip()
    if not uid:
        return None

    def _security_one(rr: Dict[str, Any]) -> None:
        sec_scope = _security_scope_policy()
        if sec_scope == "ALL":
            return
        if sec_scope == "SECTOR":
            sec = _require_sector("assets.get_asset_by_uid")
            asec = _asset_sector_value(rr)
            if (not asec) or (not _sector_eq(asec, sec)):
                raise PermissionError("Nemaš pravo da vidiš sredstvo van svog sektora.")
            return
        if sec_scope == "MY":
            if not _is_my_scope_asset_dbfirst(rr):
                raise PermissionError("Nemaš pravo da vidiš sredstvo van MY scope (moja zaduženja).")
            return
        raise PermissionError("Scope nije validan (fail-closed).")

    if _db_get_asset_by_uid is not None:
        try:
            r = _call_compatible(_db_get_asset_by_uid, asset_uid=uid)
        except Exception as e:
            logger.exception("core.db.get_asset_by_uid failed: %s", e)
            r = None

        if isinstance(r, dict):
            rr = _norm_asset_row(r)
            _enforce_view_perms_one(rr)
            _security_one(rr)
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
            rr = _norm_asset_row(rows[0])
            _enforce_view_perms_one(rr)
            _security_one(rr)
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
    _require_login("assets.list_assets_my")
    _require_perm_any([PERM_ASSETS_VIEW, PERM_ASSETS_MY_VIEW], "assets.list_assets_my")
    return list_assets(q=q, search=search, category=category, status=status, limit=limit, scope=SCOPE_MY)


list_assets_my_brief = list_assets_my


# -------------------- Disposal workflow (service wrappers + query helpers) --------------------
_DISPOSAL_OPEN_STATUSES = ("PREPARED", "APPROVED")


def _assert_asset_visible_or_raise(asset_uid: str, ctx: str) -> Dict[str, Any]:
    a = get_asset_by_uid(asset_uid=asset_uid)
    if not a:
        raise PermissionError(f"Sredstvo nije pronađeno ili nije dostupno u scope-u. ({ctx})")
    return a


def _disposal_case_asset_uid(disposal_id: int) -> str:
    """
    Minimal helper da enforce-ujemo scope kod approve/cancel/dispose.
    Fail-closed: ako ne možemo da nađemo case -> error.
    """
    did = int(disposal_id or 0)
    if did <= 0:
        raise ValueError("disposal_id must be > 0")

    try:
        with _sqlite_conn() as conn:
            if not _sqlite_table_exists(conn, "disposal_cases"):
                raise RuntimeError("disposal_cases tabela ne postoji (schema nije migrirana).")
            cur = conn.execute(
                "SELECT asset_uid FROM disposal_cases WHERE disposal_id=? LIMIT 1;",
                (did,),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError("disposal case not found")
            uid = str(row[0] if isinstance(row, (tuple, list)) else row["asset_uid"]).strip()  # type: ignore[index]
            if not uid:
                raise RuntimeError("disposal case has empty asset_uid")
            return uid
    except PermissionError:
        raise
    except Exception as e:
        raise RuntimeError(str(e)) from e


def get_open_disposal_case_for_asset(
    *,
    asset_uid: str,
    include_reason_notes: bool = True,
) -> Optional[Dict[str, Any]]:
    """
    Vraća poslednji OTVOREN disposal case za asset (PREPARED/APPROVED), ili None.

    Security:
    - traži login
    - traži bar jedno disposal pravo (prepare/approve/dispose)
    - traži da asset bude vidljiv u scope-u (get_asset_by_uid)
    """
    _require_login("assets.get_open_disposal_case_for_asset")
    _require_perm_any(_DISPOSAL_ANY_PERMS, "assets.get_open_disposal_case_for_asset")

    uid = (asset_uid or "").strip()
    if not uid:
        return None

    _assert_asset_visible_or_raise(uid, "assets.get_open_disposal_case_for_asset")

    try:
        with _sqlite_conn() as conn:
            if not _sqlite_table_exists(conn, "disposal_cases"):
                return None

            cols = _sqlite_cols(conn, "disposal_cases")
            if "asset_uid" not in cols or "status" not in cols or "disposal_id" not in cols:
                return None

            sel = [
                "disposal_id", "asset_uid", "status",
                "created_at", "prepared_by",
                "approved_by", "approved_at",
                "disposed_by", "disposed_at",
                "disposed_doc_no", "source",
            ]
            if include_reason_notes:
                if "reason" in cols:
                    sel.append("reason")
                if "notes" in cols:
                    sel.append("notes")

            sql = (
                f"SELECT {', '.join(sel)} FROM disposal_cases "
                "WHERE asset_uid=? AND status IN ('PREPARED','APPROVED') "
                "ORDER BY created_at DESC, disposal_id DESC LIMIT 1;"
            )
            row = conn.execute(sql, (uid,)).fetchone()
            if not row:
                return None
            return {k: row[k] for k in row.keys()}
    except Exception:
        return None


def list_disposal_queue(
    *,
    status: str = "OPEN",
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """
    Lista “Priprema za rashod” za UI tab:
    - OPEN => PREPARED + APPROVED
    - PREPARED => samo PREPARED
    - APPROVED => samo APPROVED

    Output: kombinuje asset info + case info.
    Security: fail-closed per asset (ne curi cross-scope).
    """
    _require_login("assets.list_disposal_queue")
    _require_perm_any(_DISPOSAL_ANY_PERMS, "assets.list_disposal_queue")
    _require_perm_any(_ASSETS_LIST_PERMS, "assets.list_disposal_queue.assets_view")

    lim = _clamp_limit(limit, 500, min_v=1, max_v=5000)

    st = (status or "OPEN").strip().upper()
    if st == "PREPARED":
        statuses = ("PREPARED",)
    elif st == "APPROVED":
        statuses = ("APPROVED",)
    else:
        statuses = _DISPOSAL_OPEN_STATUSES

    out: List[Dict[str, Any]] = []
    try:
        with _sqlite_conn() as conn:
            if not _sqlite_table_exists(conn, "disposal_cases"):
                return []

            cols = _sqlite_cols(conn, "disposal_cases")
            if "disposal_id" not in cols or "asset_uid" not in cols or "status" not in cols:
                return []

            sel = [
                "disposal_id", "asset_uid", "status",
                "created_at", "prepared_by",
                "approved_by", "approved_at",
                "reason", "notes",
                "source",
            ]
            sel = [c for c in sel if c in cols]

            qmarks = ",".join(["?"] * len(statuses))
            sql = (
                f"SELECT {', '.join(sel)} FROM disposal_cases "
                f"WHERE status IN ({qmarks}) "
                "ORDER BY created_at DESC, disposal_id DESC LIMIT ?;"
            )
            rows = conn.execute(sql, tuple(statuses) + (int(lim),)).fetchall()

        for r in rows:
            rr = dict(r)
            uid = str(rr.get("asset_uid") or "").strip()
            if not uid:
                continue
            try:
                a = get_asset_by_uid(asset_uid=uid)
                if not a:
                    continue
            except PermissionError:
                continue
            except Exception:
                continue

            merged = dict(a)
            merged["disposal_case"] = rr
            merged["disposal_id"] = rr.get("disposal_id")
            merged["disposal_status"] = rr.get("status")
            merged["disposal_reason"] = rr.get("reason", "")
            merged["disposal_notes"] = rr.get("notes", "")
            merged["disposal_created_at"] = rr.get("created_at", "")
            merged["disposal_prepared_by"] = rr.get("prepared_by", "")
            merged["disposal_approved_by"] = rr.get("approved_by", "")
            merged["disposal_approved_at"] = rr.get("approved_at", "")
            out.append(merged)

    except Exception:
        return out

    return out


def prepare_disposal(
    *,
    asset_uid: str,
    reason: str = "",
    notes: str = "",
    data: Optional[Dict[str, Any]] = None,
    source: str = "assets_service.prepare_disposal",
) -> int:
    _require_login("assets.prepare_disposal")
    _require_perm(PERM_DISPOSAL_PREPARE, "assets.prepare_disposal")

    uid = (asset_uid or "").strip()
    if not uid:
        raise ValueError("asset_uid je obavezan.")

    _assert_asset_visible_or_raise(uid, "assets.prepare_disposal")

    if _db_prepare_disposal is None:
        raise RuntimeError("DB funkcija prepare_disposal_db nije dostupna (core.db).")

    return int(_call_compatible(
        _db_prepare_disposal,
        actor=_actor_name_for_audit(),
        asset_uid=uid,
        reason=(reason or "").strip(),
        notes=(notes or "").strip(),
        data_obj=(data or None),
        source=(source or "").strip(),
    ))


def approve_disposal(
    *,
    disposal_id: int,
    source: str = "assets_service.approve_disposal",
) -> None:
    _require_login("assets.approve_disposal")
    _require_perm(PERM_DISPOSAL_APPROVE, "assets.approve_disposal")

    did = int(disposal_id or 0)
    if did <= 0:
        raise ValueError("disposal_id mora biti > 0")

    if _db_approve_disposal is None:
        raise RuntimeError("DB funkcija approve_disposal_db nije dostupna (core.db).")

    uid = _disposal_case_asset_uid(did)
    _assert_asset_visible_or_raise(uid, "assets.approve_disposal")

    _call_compatible(
        _db_approve_disposal,
        actor=_actor_name_for_audit(),
        disposal_id=did,
        source=(source or "").strip(),
    )


def cancel_disposal(
    *,
    disposal_id: int,
    reason: str = "",
    source: str = "assets_service.cancel_disposal",
) -> None:
    _require_login("assets.cancel_disposal")
    _require_perm(PERM_DISPOSAL_PREPARE, "assets.cancel_disposal")

    did = int(disposal_id or 0)
    if did <= 0:
        raise ValueError("disposal_id mora biti > 0")

    if _db_cancel_disposal is None:
        raise RuntimeError("DB funkcija cancel_disposal_db nije dostupna (core.db).")

    uid = _disposal_case_asset_uid(did)
    _assert_asset_visible_or_raise(uid, "assets.cancel_disposal")

    _call_compatible(
        _db_cancel_disposal,
        actor=_actor_name_for_audit(),
        disposal_id=did,
        reason=(reason or "").strip(),
        source=(source or "").strip(),
    )


def dispose_from_case(
    *,
    disposal_id: int,
    disposed_doc_no: str = "",
    source: str = "assets_service.dispose_from_case",
) -> None:
    _require_login("assets.dispose_from_case")
    _require_perm(PERM_DISPOSAL_DISPOSE, "assets.dispose_from_case")

    did = int(disposal_id or 0)
    if did <= 0:
        raise ValueError("disposal_id mora biti > 0")

    if _db_dispose_from_case is None:
        raise RuntimeError("DB funkcija dispose_from_case_db nije dostupna (core.db).")

    uid = _disposal_case_asset_uid(did)
    _assert_asset_visible_or_raise(uid, "assets.dispose_from_case")

    _call_compatible(
        _db_dispose_from_case,
        actor=_actor_name_for_audit(),
        disposal_id=did,
        disposed_doc_no=(disposed_doc_no or "").strip(),
        source=(source or "").strip(),
    )


__all__ = [
    "create_asset",
    "list_assets",
    "list_assets_brief",
    "get_asset_by_uid",
    "list_assets_my",
    "list_assets_my_brief",
    "missing_fields_for_asset",
    # disposal
    "prepare_disposal",
    "approve_disposal",
    "cancel_disposal",
    "dispose_from_case",
    "get_open_disposal_case_for_asset",
    "list_disposal_queue",
]

# (FILENAME: services/assets_service.py - END PART 2/2)
# END FILENAME: services/assets_service.py