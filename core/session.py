# FILENAME: core/session.py
# (FILENAME: core/session.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — core/session.py

In-memory session state: multi-role + active_role + active_scope (ALL/SECTOR/MY).

SEC principles:
- FAIL-CLOSED: can()/must() deny when not logged in.
- active_role is canonical and MUST be one of assigned roles.
- active_scope is session state (single source of truth); non-admin cannot keep ALL.
- SECTOR scope is meaningful only if a sector identifier exists in session; require_sector() fails otherwise.

Scope policy:
- Admin-like roles default to ALL
- Non-admin defaults to SECTOR (safer against cross-sector data leak)
"""

from __future__ import annotations

import inspect
import logging
import sqlite3
from collections.abc import Mapping
from threading import RLock
from typing import Any, Dict, List, Optional, Tuple

from core.rbac import require_perm as _require_perm
from core.rbac import user_has_perm as _user_has_perm

log = logging.getLogger(__name__)

# Prefer RBAC primitives (single source of truth). These may not exist in older builds.
try:
    from core.rbac import normalize_role as _rbac_normalize_role  # type: ignore
except Exception:  # pragma: no cover
    _rbac_normalize_role = None  # type: ignore

try:
    from core.rbac import list_assigned_roles as _rbac_list_assigned_roles  # type: ignore
except Exception:  # pragma: no cover
    _rbac_list_assigned_roles = None  # type: ignore

try:
    from core.rbac import pick_highest_role as _rbac_pick_highest_role  # type: ignore
except Exception:  # pragma: no cover
    _rbac_pick_highest_role = None  # type: ignore


ROLE_READONLY = "READONLY"
ROLE_ADMIN = "ADMIN"
ROLE_GLOBAL_ADMIN = "GLOBAL_ADMIN"
ROLE_SUPERADMIN = "SUPERADMIN"

SCOPE_ALL = "ALL"
SCOPE_SECTOR = "SECTOR"
SCOPE_MY = "MY"

_VALID_SCOPES = {SCOPE_ALL, SCOPE_SECTOR, SCOPE_MY}

_CURRENT_USER: Optional[Dict[str, Any]] = None
_ACTIVE_SCOPE: Optional[str] = None
_LOCK = RLock()

_MAX_ROLES = 64


# -------------------- internals --------------------
def _coerce_user_to_dict(u: Any) -> Optional[Dict[str, Any]]:
    """Coerce user -> dict (FAIL-CLOSED)."""
    if u is None:
        return None

    if isinstance(u, dict):
        return dict(u)

    if isinstance(u, Mapping):
        try:
            d = dict(u)
            return d if d else None
        except Exception:
            return None

    try:
        fn = getattr(u, "to_dict", None)
        if callable(fn):
            d = fn()
            if isinstance(d, dict) and d:
                return dict(d)
    except Exception:
        pass

    try:
        d = vars(u)
        if isinstance(d, dict) and d:
            return dict(d)
    except Exception:
        pass

    return None


def _first_nonempty(u: Dict[str, Any], keys: Tuple[str, ...]) -> str:
    for k in keys:
        try:
            v = u.get(k)
        except Exception:
            v = None
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def _split_items(s: str) -> List[str]:
    s = (s or "").strip()
    if not s:
        return []
    for sep in (",", ";", "|"):
        if sep in s:
            return [p.strip() for p in s.split(sep) if p.strip()]
    return [s]


def _canon_role(role: Any) -> str:
    """Canonicalize role string (alias-aware)."""
    s = str(role or "").strip()
    if not s:
        return ROLE_READONLY

    parts = _split_items(s)
    s0 = parts[0] if parts else s

    # Prefer RBAC role normalization.
    if callable(_rbac_normalize_role):
        try:
            rr = _rbac_normalize_role(s0)
            rr = str(rr or "").strip().upper()
            return rr or ROLE_READONLY
        except Exception:
            pass

    return str(s0).strip().upper() or ROLE_READONLY


def _normalize_roles_value(v: Any) -> List[str]:
    """Normalize roles input into unique canonical list (order-preserving)."""
    raw: List[str] = []
    if v is None:
        raw = []
    elif isinstance(v, (list, tuple, set)):
        for x in v:
            s = str(x or "").strip()
            if not s:
                continue
            raw.extend(_split_items(s))
    else:
        raw = _split_items(str(v or ""))

    out: List[str] = []
    seen: set[str] = set()
    for r in raw:
        rr = _canon_role(r)
        if not rr:
            continue
        if rr in seen:
            continue
        seen.add(rr)
        out.append(rr)
        if len(out) >= _MAX_ROLES:
            break
    return out


def _pick_highest_role(roles: List[str]) -> str:
    roles_n = _normalize_roles_value(roles) or [ROLE_READONLY]
    if callable(_rbac_pick_highest_role):
        try:
            rr = _rbac_pick_highest_role(roles_n)
            rr = _canon_role(rr)
            return rr or ROLE_READONLY
        except Exception:
            pass
    return _canon_role(roles_n[0]) if roles_n else ROLE_READONLY


def _sync_role_keys(u: Dict[str, Any], role: str) -> None:
    """Keep legacy/compat keys in sync with active_role."""
    r = _canon_role(role)
    u["active_role"] = r
    u["role"] = r
    u["user_role"] = r
    u["rbac_role"] = r
    u["profile"] = r


def _ensure_roles_on_user(u: Dict[str, Any]) -> List[str]:
    """
    Ensure u['roles'] exists and is normalized.
    Priority:
      1) already-provided roles (login should provide)
      2) core.rbac.list_assigned_roles(user) if available
      3) roles/user_roles/rbac_roles/profiles
      4) fallback: active_role/role/...
    """
    roles = _normalize_roles_value(u.get("roles"))

    if not roles and callable(_rbac_list_assigned_roles):
        try:
            roles = list(_rbac_list_assigned_roles(u) or [])
        except Exception:
            roles = []

    if not roles:
        v = u.get("user_roles")
        if v is None:
            v = u.get("rbac_roles")
        if v is None:
            v = u.get("profiles")
        if v is None:
            v = u.get("roles")
        roles = _normalize_roles_value(v)

    if not roles:
        prim = _canon_role(_first_nonempty(u, ("active_role", "role", "user_role", "rbac_role", "profile")))
        roles = [prim] if prim else [ROLE_READONLY]

    roles = _normalize_roles_value(roles) or [ROLE_READONLY]
    u["roles"] = roles
    return roles


def _canon_scope(scope: Any) -> str:
    s = str(scope or "").strip().upper()
    return s if s in _VALID_SCOPES else ""


def _is_admin_like(role: str) -> bool:
    r = _canon_role(role)
    return r in (ROLE_ADMIN, ROLE_GLOBAL_ADMIN, ROLE_SUPERADMIN)


def _default_scope_for_role(role: str) -> str:
    return SCOPE_ALL if _is_admin_like(role) else SCOPE_SECTOR


def _coerce_scope_for_role(scope: str, role: str) -> str:
    """Fail-safe: non-admin can never hold ALL scope."""
    sc = _canon_scope(scope)
    if not sc:
        return ""
    if sc == SCOPE_ALL and (not _is_admin_like(role)):
        return SCOPE_SECTOR
    return sc


def _infer_scope_from_user(u: Dict[str, Any], role: str) -> str:
    hinted = _canon_scope(u.get("active_scope") or u.get("scope") or u.get("data_scope"))
    hinted = _coerce_scope_for_role(hinted, role)
    if hinted:
        return hinted
    return _default_scope_for_role(role)


def _sync_scope_keys(u: Dict[str, Any], scope: str, role: str) -> str:
    sc = _coerce_scope_for_role(scope, role)
    if not sc:
        return ""
    u["active_scope"] = sc
    u["scope"] = sc
    u["data_scope"] = sc
    return sc


def _get_current_user_copy_locked() -> Optional[Dict[str, Any]]:
    with _LOCK:
        return dict(_CURRENT_USER) if _CURRENT_USER else None


def _call_compatible(fn: Any, **kwargs: Any) -> None:
    """Call fn only with kwargs it accepts (robust across signature changes)."""
    if not callable(fn):
        return
    try:
        sig = inspect.signature(fn)
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
            fn(**kwargs)
            return
        filtered = {k: v for k, v in kwargs.items() if k in sig.parameters}
        fn(**filtered)
    except Exception:
        try:
            fn(**kwargs)
        except Exception:
            return


# -------------------- Public session API --------------------
def set_current_user(u: Optional[Any]) -> None:
    """
    Set current user (FAIL-CLOSED). If coercion fails -> clear session.

    Login default:
    - ensure roles exist
    - if active_role missing/invalid -> pick highest assigned role
    - set active_scope (policy + fail-safe)
    """
    global _CURRENT_USER, _ACTIVE_SCOPE
    coerced = _coerce_user_to_dict(u)
    with _LOCK:
        if not coerced:
            _CURRENT_USER = None
            _ACTIVE_SCOPE = None
            return

        cur = dict(coerced)

        roles = _ensure_roles_on_user(cur)

        # active role selection (fail-safe)
        ar_raw = cur.get("active_role", None)
        ar = _canon_role(ar_raw) if str(ar_raw or "").strip() else ""

        if not ar:
            cand = _first_nonempty(cur, ("role", "user_role", "rbac_role", "profile"))
            ar = _canon_role(cand) if cand else ""

        if not ar or (roles and ar not in roles):
            ar = _pick_highest_role(roles)

        _sync_role_keys(cur, ar or ROLE_READONLY)

        # scope selection (policy + fail-safe)
        sc = _infer_scope_from_user(cur, role=ar or ROLE_READONLY)
        sc = sc or _default_scope_for_role(ar or ROLE_READONLY)
        sc = _sync_scope_keys(cur, sc, role=ar or ROLE_READONLY) or _default_scope_for_role(ar or ROLE_READONLY)

        _ACTIVE_SCOPE = sc
        _CURRENT_USER = cur


def clear_current_user() -> None:
    global _CURRENT_USER, _ACTIVE_SCOPE
    with _LOCK:
        _CURRENT_USER = None
        _ACTIVE_SCOPE = None


def get_current_user() -> Optional[Dict[str, Any]]:
    """
    Compatibility:
    - returns a reference to session dict.
    - Avoid mutating it directly (prefer get_current_user_copy()).
    """
    with _LOCK:
        return _CURRENT_USER


def get_current_user_copy() -> Optional[Dict[str, Any]]:
    """Safe snapshot of session user dict."""
    return _get_current_user_copy_locked()


def is_logged_in() -> bool:
    with _LOCK:
        return bool(_CURRENT_USER)


def require_login(context: str = "") -> None:
    if not is_logged_in():
        ctx = (context or "").strip()
        raise PermissionError(f"Nisi prijavljen. ({ctx})" if ctx else "Nisi prijavljen.")


def current_user_id() -> int:
    u = _get_current_user_copy_locked() or {}
    raw = u.get("id", None)
    if raw is None:
        raw = u.get("user_id")
    try:
        return int(raw or 0)
    except Exception:
        return 0


def actor_name() -> str:
    u = _get_current_user_copy_locked() or {}
    dn = str(u.get("display_name") or "").strip()
    un = str(u.get("username") or "").strip()
    return dn or un or "user"


def actor_key() -> str:
    u = _get_current_user_copy_locked() or {}
    un = str(u.get("username") or "").strip()
    if un:
        return un
    uid = current_user_id()
    return f"user#{uid}" if uid > 0 else "user"


def current_sector() -> str:
    """
    Best-effort sector hint from session.

    IMPORTANT:
    - Prefer string codes/names for matching assets.sector (TEXT).
    - sector_id is still accepted as last fallback (some deployments store numeric sector as text).
    """
    u = _get_current_user_copy_locked() or {}
    keys = (
        "active_sector",
        "sector",
        "sector_code",
        "org_unit_code",
        "org_unit",
        "orgUnit",
        "department",
        "unit",
        "org",
        # last resort (may be numeric):
        "sector_id",
        "sectorId",
    )
    return _first_nonempty(u, keys).strip()


def current_sector_id() -> int:
    """Numeric sector id if present (0 if unknown)."""
    u = _get_current_user_copy_locked() or {}
    raw = u.get("sector_id", None)
    if raw is None:
        raw = u.get("sectorId", None)
    try:
        return int(raw or 0)
    except Exception:
        return 0


def list_user_roles(user: Optional[Any] = None) -> List[str]:
    """List normalized roles for current user (default) or provided user."""
    if user is None:
        with _LOCK:
            if not _CURRENT_USER:
                return [ROLE_READONLY]
            return list(_ensure_roles_on_user(_CURRENT_USER) or [ROLE_READONLY])

    uu = _coerce_user_to_dict(user)
    if not uu:
        return [ROLE_READONLY]
    return list(_ensure_roles_on_user(uu) or [ROLE_READONLY])


def active_role() -> str:
    """Return canonical active_role (always in roles, else highest)."""
    with _LOCK:
        if not _CURRENT_USER:
            return ROLE_READONLY

        roles = _ensure_roles_on_user(_CURRENT_USER) or [ROLE_READONLY]
        ar_raw = _CURRENT_USER.get("active_role", None)
        ar = _canon_role(ar_raw) if str(ar_raw or "").strip() else ""

        if not ar:
            cand = _first_nonempty(_CURRENT_USER, ("role", "user_role", "rbac_role", "profile"))
            ar = _canon_role(cand) if cand else ""

        if roles and (not ar or ar not in roles):
            ar = _pick_highest_role(roles)
            _sync_role_keys(_CURRENT_USER, ar)

        return ar or ROLE_READONLY


def current_role() -> str:
    """Alias for callers (app.py, legacy code)."""
    return active_role()


def get_active_scope() -> str:
    """
    Return active scope for session.
    FAIL-CLOSED when logged out -> ''.
    Also enforces: non-admin cannot keep ALL.
    """
    global _ACTIVE_SCOPE
    with _LOCK:
        if not _CURRENT_USER:
            return ""

        role = active_role()
        sc = _canon_scope(_ACTIVE_SCOPE or _CURRENT_USER.get("active_scope"))
        sc = _coerce_scope_for_role(sc, role)

        if not sc:
            sc = _default_scope_for_role(role)

        _ACTIVE_SCOPE = sc
        _sync_scope_keys(_CURRENT_USER, sc, role=role)
        return sc


def effective_scope() -> str:
    """Convenience: logged out -> MY; logged in -> active scope."""
    if not is_logged_in():
        return SCOPE_MY
    return get_active_scope() or SCOPE_MY


def set_active_scope(scope: str, source: str = "ui", audit: bool = True) -> None:
    """
    Switch active scope.
    - Requires login.
    - Unknown scope -> error.
    - Non-admin cannot set ALL (fail-safe).
    """
    require_login("set_active_scope")
    new_sc = _canon_scope(scope)
    if not new_sc:
        raise PermissionError("Nevažeći scope. Dozvoljeno: ALL/SECTOR/MY.")

    with _LOCK:
        if not _CURRENT_USER:
            raise PermissionError("Nisi prijavljen.")
        old_sc = get_active_scope() or ""
        role = active_role()
        if (not _is_admin_like(role)) and new_sc == SCOPE_ALL:
            raise PermissionError("Nemaš pravo na ALL scope.")
        global _ACTIVE_SCOPE
        _ACTIVE_SCOPE = new_sc
        _sync_scope_keys(_CURRENT_USER, new_sc, role=role)

    if audit and old_sc != new_sc:
        _audit_scope_switch(old_sc, new_sc, source=source)


def set_active_role(role: str, source: str = "ui", audit: bool = True) -> None:
    """
    Switch active role for session.
    - Requires login.
    - Role must be one of assigned roles.
    - Also enforces scope policy after switch (non-admin cannot keep ALL).
    """
    require_login("set_active_role")
    with _LOCK:
        if not _CURRENT_USER:
            raise PermissionError("Nisi prijavljen.")

        roles = _ensure_roles_on_user(_CURRENT_USER)
        new_role = _canon_role(role)

        if new_role not in roles:
            raise PermissionError(f"Nemaš rolu '{new_role}'. Dodeljene role: {roles}")

        old_role = active_role()

        # set role keys
        _sync_role_keys(_CURRENT_USER, new_role)

        # re-apply scope policy (fail-safe)
        global _ACTIVE_SCOPE
        sc = _canon_scope(_ACTIVE_SCOPE or _CURRENT_USER.get("active_scope") or "")
        sc = _coerce_scope_for_role(sc, new_role)
        if not sc:
            sc = _default_scope_for_role(new_role)

        _ACTIVE_SCOPE = sc
        _sync_scope_keys(_CURRENT_USER, sc, role=new_role)

    if audit and old_role != new_role:
        _audit_role_switch(old_role, new_role, source=source)


def can(perm: str) -> bool:
    """FAIL-CLOSED: no login or failure -> deny."""
    p = (perm or "").strip()
    if not p:
        return False
    if not is_logged_in():
        return False
    u = _get_current_user_copy_locked()
    if not u:
        return False
    try:
        return bool(_user_has_perm(u, p))
    except Exception:
        return False


def must(perm: str) -> None:
    """Enforce permission for current user (FAIL-CLOSED)."""
    require_login("must")
    u = _get_current_user_copy_locked()
    if not u:
        raise PermissionError("Nisi prijavljen.")
    _require_perm(u, perm)


def require_sector(context: str = "") -> str:
    """
    FAIL-CLOSED helper for SECTOR scope.
    If scope is SECTOR and sector is unknown -> raise.
    Returns sector string when available.
    """
    require_login("require_sector")
    sc = get_active_scope()
    if sc != SCOPE_SECTOR:
        return ""
    sec = current_sector()
    if sec:
        return sec
    ctx = (context or "").strip()
    raise PermissionError(
        f"Nedostaje sektor u sesiji za SECTOR scope. ({ctx})" if ctx else "Nedostaje sektor u sesiji za SECTOR scope."
    )


def get_scope_context() -> Dict[str, Any]:
    """
    Single payload services can use to build WHERE filters safely.
    Example usage:
      ctx = session.get_scope_context()
      if ctx['scope'] == 'SECTOR': session.require_sector('assets.list')
    """
    if not is_logged_in():
        return {
            "logged_in": False,
            "scope": SCOPE_MY,
            "role": ROLE_READONLY,
            "user_id": 0,
            "sector": "",
            "sector_id": 0,
        }

    return {
        "logged_in": True,
        "user_id": current_user_id(),
        "role": active_role(),
        "scope": get_active_scope(),
        "sector": current_sector(),
        "sector_id": current_sector_id(),
        "actor": actor_key(),
        "actor_name": actor_name(),
    }


# -------------------- audit helpers (role/scope switches) --------------------
def _audit_role_switch(old_role: str, new_role: str, source: str = "ui") -> None:
    try:
        from core.db import db_conn, write_audit  # type: ignore
    except Exception:
        return

    if not callable(db_conn) or not callable(write_audit):
        return

    before_obj = {"active_role": old_role, "active_scope": get_active_scope() or ""}
    after_obj = {"active_role": new_role, "active_scope": get_active_scope() or ""}
    actor = actor_key()
    entity_id = str(current_user_id() or "")

    try:
        with db_conn() as conn:
            write_audit(
                conn,
                actor=actor,
                entity="session",
                entity_id=entity_id,
                action="ROLE_SWITCH",
                before_obj=before_obj,
                after_obj=after_obj,
                source=(source or "ui"),
            )
            try:
                conn.commit()
            except Exception:
                pass
    except Exception:
        return


def _audit_scope_switch(old_scope: str, new_scope: str, source: str = "ui") -> None:
    try:
        from core.db import db_conn, write_audit  # type: ignore
    except Exception:
        return

    if not callable(db_conn) or not callable(write_audit):
        return

    before_obj = {"active_scope": old_scope, "active_role": active_role()}
    after_obj = {"active_scope": new_scope, "active_role": active_role(), "sector": current_sector()}
    actor = actor_key()
    entity_id = str(current_user_id() or "")

    try:
        with db_conn() as conn:
            write_audit(
                conn,
                actor=actor,
                entity="session",
                entity_id=entity_id,
                action="SCOPE_SWITCH",
                before_obj=before_obj,
                after_obj=after_obj,
                source=(source or "ui"),
            )
            try:
                conn.commit()
            except Exception:
                pass
    except Exception:
        return


__all__ = [
    "set_current_user",
    "clear_current_user",
    "get_current_user",
    "get_current_user_copy",
    "is_logged_in",
    "require_login",
    "current_user_id",
    "actor_name",
    "actor_key",
    "current_sector",
    "current_sector_id",
    "list_user_roles",
    "active_role",
    "current_role",
    "set_active_role",
    "SCOPE_ALL",
    "SCOPE_SECTOR",
    "SCOPE_MY",
    "get_active_scope",
    "effective_scope",
    "set_active_scope",
    "can",
    "must",
    "require_sector",
    "get_scope_context",
]


if __name__ == "__main__":  # pragma: no cover
    # Minimal smoke-test (offline, no DB needed; audit is best-effort)
    clear_current_user()
    assert is_logged_in() is False
    assert can("assets.view") is False
    assert effective_scope() == SCOPE_MY

    # non-admin defaults to SECTOR
    set_current_user({"id": 1, "username": "m", "roles": ["READONLY"], "sector": "S2"})
    assert is_logged_in() is True
    assert active_role() == "READONLY"
    assert get_active_scope() == SCOPE_SECTOR
    assert current_sector() == "S2"

    # admin defaults to ALL
    set_current_user({"id": 2, "username": "a", "roles": ["ADMIN"]})
    assert active_role() == "ADMIN"
    assert get_active_scope() == SCOPE_ALL

    # switching to non-admin must auto-drop ALL
    set_current_user({"id": 3, "username": "x", "roles": ["ADMIN", "BASIC_USER"], "active_role": "ADMIN", "active_scope": "ALL", "sector": "S2"})
    set_active_role("BASIC_USER", audit=False)
    assert active_role() == "BASIC_USER"
    assert get_active_scope() == SCOPE_SECTOR

    # require_sector should fail when missing sector in SECTOR scope
    set_current_user({"id": 4, "username": "y", "roles": ["READONLY"], "active_scope": "SECTOR"})
    try:
        require_sector("smoke")
        raise RuntimeError("Expected require_sector to fail when sector missing.")
    except PermissionError:
        pass

    print("core/session.py smoke-test OK")

# (FILENAME: core/session.py - END)