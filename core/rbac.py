# FILENAME: core/rbac.py
# (FILENAME: core/rbac.py - START PART 1/2)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — core/rbac.py

RBAC (V1/V1.1 + multi-role support), offline.

Senior hardening / best practices:
- Determinističko biranje efektivne role (highest po ROLE_PRIORITY; tie-break lex).
- active_role mora biti među dodeljenim rolama (sprečava eskalaciju).
- Ako user već ima 'roles' listu, polje 'role' ne sme da eskalira prava van te liste.
- FAIL-SAFE: BASIC_USER i READONLY nikad users.*; wildcard '*' ignorisan za te role čak i ako “procure”.
- Kompatibilnost: can/can_any/can_all helper-i (UI fallback koristi core.rbac.can).

Napomena:
- RBAC ne rešava “cross-sector leak” sam po sebi. To rešava scope + servisni WHERE filter.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Permissions (string konstante)
# ---------------------------------------------------------------------------

# assets
PERM_ASSETS_VIEW = "assets.view"                   # FULL list
PERM_ASSETS_CREATE = "assets.create"
PERM_ASSETS_EDIT = "assets.edit"
PERM_ASSETS_DELETE = "assets.delete"
PERM_ASSETS_METRO_VIEW = "assets.metrology.view"   # metrology scope list
PERM_ASSETS_MY_VIEW = "assets.my.view"             # MY assets list (duženja)

# assignments
PERM_ASSIGN_VIEW = "assignments.view"
PERM_ASSIGN_CREATE = "assignments.create"
PERM_ASSIGN_EDIT = "assignments.edit"
PERM_ASSIGN_DELETE = "assignments.delete"

# audit
PERM_AUDIT_VIEW = "audit.view"

# metrology
PERM_METRO_VIEW = "metrology.view"                 # feature access; scope filter radi servis
PERM_METRO_MY_VIEW = "metrology.my.view"           # eksplicitno: MY metrology view
PERM_METRO_SCOPE_VIEW = "metrology.scope.view"     # eksplicitno: metrology-scope view
PERM_METRO_EDIT = "metrology.edit"
PERM_METRO_MANAGE = "metrology.manage"

# kompatibilni aliasi
PERM_METRO_WRITE = PERM_METRO_EDIT
PERM_METRO_ADMIN = PERM_METRO_MANAGE

# disposal (Priprema za rashod / Rashod)
PERM_DISPOSAL_PREPARE = "disposal.prepare"
PERM_DISPOSAL_APPROVE = "disposal.approve"
PERM_DISPOSAL_DISPOSE = "disposal.dispose"

# users/settings/reports
PERM_USERS_VIEW = "users.view"
PERM_USERS_MANAGE = "users.manage"
PERM_SETTINGS_VIEW = "settings.view"
PERM_SETTINGS_MANAGE = "settings.manage"
PERM_REPORTS_PRINT = "reports.print"

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

ROLE_ADMIN = "ADMIN"
ROLE_SECTOR_ADMIN = "SECTOR_ADMIN"
ROLE_REFERENT_IT = "REFERENT_IT"
ROLE_REFERENT_METRO = "REFERENT_METRO"
ROLE_REFERENT_OS = "REFERENT_OS"
ROLE_BASIC = "BASIC_USER"
ROLE_READONLY = "READONLY"

ROLE_ALIASES: Dict[str, str] = {
    # admin
    "ADMINISTRATOR": ROLE_ADMIN,
    "SUPERADMIN": ROLE_ADMIN,
    "GLOBAL_ADMIN": ROLE_ADMIN,
    "GLOBALADMIN": ROLE_ADMIN,

    # sector admin
    "SECTORADMIN": ROLE_SECTOR_ADMIN,
    "ADMIN_SEKTORA": ROLE_SECTOR_ADMIN,
    "SEKTOR_ADMIN": ROLE_SECTOR_ADMIN,
    "SEKTORADMIN": ROLE_SECTOR_ADMIN,

    # readonly
    "READ_ONLY": ROLE_READONLY,
    "RO": ROLE_READONLY,
    "VIEW_ONLY": ROLE_READONLY,
    "VIEWONLY": ROLE_READONLY,

    # basic
    "BASIC": ROLE_BASIC,
    "USER": ROLE_BASIC,
    "EMPLOYEE": ROLE_BASIC,
    "KORISNIK": ROLE_BASIC,
    "OBICAN": ROLE_BASIC,
    "OBICAN_KORISNIK": ROLE_BASIC,

    # referent metro
    "REFERENT_METROLOGIJE": ROLE_REFERENT_METRO,
    "METRO_REFERENT": ROLE_REFERENT_METRO,
    "REFERENT_METROLOGIJA": ROLE_REFERENT_METRO,
    "REFERENT_METRO": ROLE_REFERENT_METRO,
}

# ---------------------------------------------------------------------------
# Role permissions
# NOTE:
# - Service layer i dalje radi finalni scope filter (fail-closed).
# - Ovde samo definišemo "ko sme da pristupi feature-u".
# ---------------------------------------------------------------------------

ROLE_PERMS: Dict[str, Set[str]] = {
    ROLE_ADMIN: {"*"},
    ROLE_SECTOR_ADMIN: {
        PERM_ASSETS_VIEW,
        PERM_ASSETS_CREATE,
        PERM_ASSETS_EDIT,
        PERM_ASSETS_MY_VIEW,

        PERM_ASSIGN_VIEW,
        PERM_ASSIGN_CREATE,
        PERM_ASSIGN_EDIT,

        PERM_AUDIT_VIEW,

        PERM_METRO_VIEW,
        PERM_METRO_EDIT,

        PERM_DISPOSAL_PREPARE,
        PERM_DISPOSAL_APPROVE,
        PERM_DISPOSAL_DISPOSE,

        PERM_SETTINGS_VIEW,
        PERM_SETTINGS_MANAGE,
        PERM_USERS_VIEW,
        PERM_USERS_MANAGE,
        PERM_REPORTS_PRINT,
    },

    # BASIC_USER: minimalno (BASIC UI: Moj Dashboard + Moja oprema)
    ROLE_BASIC: {
        PERM_ASSETS_MY_VIEW,
        PERM_ASSIGN_VIEW,
        PERM_METRO_MY_VIEW,
        PERM_SETTINGS_VIEW,
        PERM_REPORTS_PRINT,
    },

    # READONLY: “čitam sve, ne menjam”
    ROLE_READONLY: {
        PERM_ASSETS_VIEW,
        PERM_ASSETS_MY_VIEW,
        PERM_ASSIGN_VIEW,
        PERM_AUDIT_VIEW,
        PERM_METRO_VIEW,
        PERM_SETTINGS_VIEW,
        PERM_REPORTS_PRINT,
    },

    ROLE_REFERENT_IT: {
        PERM_ASSETS_VIEW,
        PERM_ASSETS_CREATE,
        PERM_ASSETS_EDIT,
        PERM_ASSETS_MY_VIEW,

        PERM_ASSIGN_VIEW,
        PERM_ASSIGN_CREATE,

        PERM_AUDIT_VIEW,
        PERM_METRO_VIEW,

        PERM_DISPOSAL_PREPARE,

        PERM_USERS_VIEW,
        PERM_SETTINGS_VIEW,
        PERM_REPORTS_PRINT,
    },

    ROLE_REFERENT_OS: {
        PERM_ASSETS_VIEW,
        PERM_ASSETS_CREATE,
        PERM_ASSETS_EDIT,
        PERM_ASSETS_MY_VIEW,

        PERM_ASSIGN_VIEW,
        PERM_ASSIGN_CREATE,

        PERM_AUDIT_VIEW,
        PERM_METRO_VIEW,

        PERM_DISPOSAL_PREPARE,

        PERM_USERS_VIEW,
        PERM_SETTINGS_VIEW,
        PERM_REPORTS_PRINT,
    },

    # REFERENT_METRO: metrology scope + MY
    ROLE_REFERENT_METRO: {
        PERM_ASSETS_METRO_VIEW,
        PERM_ASSETS_MY_VIEW,

        PERM_METRO_VIEW,
        PERM_METRO_SCOPE_VIEW,
        PERM_METRO_MY_VIEW,
        PERM_METRO_EDIT,

        PERM_DISPOSAL_PREPARE,

        PERM_SETTINGS_VIEW,
        PERM_REPORTS_PRINT,
    },
}

# ---------------------------------------------------------------------------
# Role hierarchy (highest wins) — veći broj = veća prava
# ---------------------------------------------------------------------------

ROLE_PRIORITY: Dict[str, int] = {
    ROLE_ADMIN: 100,
    ROLE_SECTOR_ADMIN: 90,
    ROLE_REFERENT_IT: 70,
    ROLE_REFERENT_OS: 70,
    ROLE_REFERENT_METRO: 60,
    ROLE_BASIC: 20,
    ROLE_READONLY: 10,
}

# ---------------------------------------------------------------------------
# Internals / guards
# ---------------------------------------------------------------------------

_USERS_PERM_PREFIX = "users."
_FAILSAFE_DENY_ROLES = {ROLE_BASIC, ROLE_READONLY}
_SEPS = (",", ";", "|")


def _user_as_dict(user: Any) -> Dict[str, Any]:
    """Best-effort konverzija korisnika u dict (dict/Mapping/keys()/vars())."""
    if not user:
        return {}
    if isinstance(user, dict):
        return dict(user)
    if isinstance(user, Mapping):
        try:
            return dict(user)
        except Exception:
            return {}
    try:
        if hasattr(user, "keys"):
            ks = list(user.keys())  # type: ignore[attr-defined]
            if ks:
                return {str(k): user[k] for k in ks}  # type: ignore[index]
    except Exception:
        pass
    try:
        d = vars(user)
        if isinstance(d, dict):
            return dict(d)
    except Exception:
        pass
    return {}


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


def _split_listish_or_string(v: Any) -> List[str]:
    """
    Normalizuje roles polje:
    - list/tuple/set: flatten + split CSV/;/|
    - str: split CSV/;/|
    - dict: uzmi role/name/profile ako postoji (id je namerno ignorisan)
    - ostalo: str(v)
    """
    raw: List[str] = []
    if v is None:
        return raw

    if isinstance(v, dict):
        for kk in ("role", "name", "profile"):
            s = str(v.get(kk) or "").strip()
            if s:
                return _split_listish_or_string(s)
        return []

    if isinstance(v, (list, tuple, set)):
        items = list(v)
        if isinstance(v, set):
            items = sorted([str(x) for x in items if x is not None], key=lambda x: x.strip())
        for x in items:
            if x is None:
                continue
            if isinstance(x, dict):
                raw.extend(_split_listish_or_string(x))
                continue
            s = str(x or "").strip()
            if not s:
                continue
            for sep in _SEPS:
                if sep in s:
                    raw.extend([p.strip() for p in s.split(sep) if p.strip()])
                    break
            else:
                raw.append(s)
        return raw

    s = str(v or "").strip()
    if not s:
        return []
    for sep in _SEPS:
        if sep in s:
            return [p.strip() for p in s.split(sep) if p.strip()]
    return [s]


def _is_empty_roles_value(v: Any) -> bool:
    if v is None:
        return True
    if isinstance(v, (list, tuple, set)):
        return len(v) == 0
    if isinstance(v, str):
        return not v.strip()
    return False


def _role_key(role: Any) -> str:
    if role is None:
        return ""
    if isinstance(role, (list, tuple, set, dict)):
        parts = _split_listish_or_string(role)
        return str(parts[0] if parts else "")
    return str(role)


@lru_cache(maxsize=256)
def _normalize_role_cached(role_key: str) -> str:
    r = str(role_key or "").strip().upper()
    if not r:
        return ROLE_READONLY
    for sep in _SEPS:
        if sep in r:
            r = (r.split(sep, 1)[0] or "").strip().upper()
            break
    r = ROLE_ALIASES.get(r, r) or ROLE_READONLY
    return r


def normalize_role(role: Any) -> str:
    return _normalize_role_cached(_role_key(role))


def _role_sort_key(role: str) -> Tuple[int, str]:
    rr = normalize_role(role)
    return (-int(ROLE_PRIORITY.get(rr, ROLE_PRIORITY.get(ROLE_READONLY, 0))), rr)


def list_assigned_roles(user: Any) -> List[str]:
    u = _user_as_dict(user)

    v = u.get("roles")
    if _is_empty_roles_value(v):
        v = u.get("user_roles")
    if _is_empty_roles_value(v):
        v = u.get("rbac_roles")
    if _is_empty_roles_value(v):
        v = u.get("profiles")

    roles = _split_listish_or_string(v)
    if not roles:
        roles = _split_listish_or_string(u.get("role"))

    seen: Set[str] = set()
    out: List[str] = []
    for r in roles:
        rr = normalize_role(r)
        if rr and rr not in seen:
            seen.add(rr)
            out.append(rr)

    if not out:
        out = [ROLE_READONLY]

    return sorted(out, key=_role_sort_key)


def pick_highest_role(roles: Iterable[Any]) -> str:
    best = ROLE_READONLY
    best_score = int(ROLE_PRIORITY.get(best, 0))

    for r in roles or []:
        rr = normalize_role(r)
        if not rr:
            continue
        score = int(ROLE_PRIORITY.get(rr, ROLE_PRIORITY.get(ROLE_READONLY, 0)))
        if (score > best_score) or (score == best_score and rr < best):
            best = rr
            best_score = score

    return best or ROLE_READONLY


def _role_from_user(user: Any) -> str:
    u = _user_as_dict(user)
    assigned = list_assigned_roles(u)
    assigned_set = set(assigned)

    ar = _first_nonempty(u, ("active_role", "active_profile"))
    if ar:
        nar = normalize_role(ar)
        if nar in assigned_set:
            return nar

    r = _first_nonempty(u, ("role", "user_role", "rbac_role", "profile"))
    if r:
        parts = _split_listish_or_string(r)
        if parts:
            cand = normalize_role(parts[0])
            if cand in assigned_set:
                return cand

    return pick_highest_role(assigned) if assigned else ROLE_READONLY


def _perm_match(granted: str, required: str) -> bool:
    g = (granted or "").strip().lower()
    r = (required or "").strip().lower()
    if not g or not r:
        return False
    if g == "*" or g == r:
        return True
    if g.endswith(".*"):
        return r.startswith(g[:-2] + ".")
    return False


def _is_users_perm(perm: str) -> bool:
    return (perm or "").strip().lower().startswith(_USERS_PERM_PREFIX)


@lru_cache(maxsize=64)
def _perms_for_role(role: str) -> FrozenSet[str]:
    r = normalize_role(role)
    base = ROLE_PERMS.get(r) or ROLE_PERMS.get(ROLE_READONLY, set())
    return frozenset(str(p) for p in base if str(p or "").strip())


def _apply_security_guards_to_role_perms() -> None:
    for rr in (ROLE_BASIC, ROLE_READONLY):
        rp = ROLE_PERMS.get(rr)
        if not rp:
            continue
        if "*" in rp:
            rp.discard("*")
        for p in list(rp):
            if _is_users_perm(str(p)):
                rp.discard(p)


_apply_security_guards_to_role_perms()


def clear_rbac_caches(reapply_guards: bool = True) -> None:
    _normalize_role_cached.cache_clear()
    _perms_for_role.cache_clear()
    if reapply_guards:
        _apply_security_guards_to_role_perms()
        _perms_for_role.cache_clear()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def user_has_perm(user: Any, perm: str) -> bool:
    p = (perm or "").strip()
    if not p:
        return False

    role = _role_from_user(user)

    if role in _FAILSAFE_DENY_ROLES and _is_users_perm(p):
        return False

    for g in _perms_for_role(role):
        gg = (g or "").strip()

        if role in _FAILSAFE_DENY_ROLES and gg == "*":
            continue

        if _perm_match(gg, p):
            if role in _FAILSAFE_DENY_ROLES and _is_users_perm(p):
                return False
            return True

    return False


def user_has_any_perm(user: Any, perms: Optional[Iterable[str]]) -> bool:
    if perms is None:
        return False
    for p in perms:
        if user_has_perm(user, p):
            return True
    return False


def user_has_all_perms(user: Any, perms: Optional[Iterable[str]]) -> bool:
    """
    True samo ako user ima SVE perms.
    - perms=None -> False
    - perms=[] -> True (standardna logika all([])==True)
    """
    if perms is None:
        return False
    any_seen = False
    for p in perms:
        any_seen = True
        if not user_has_perm(user, p):
            return False
    return True if not any_seen else True


def require_perm(user: Any, perm: str) -> None:
    p = (perm or "").strip()
    if not p:
        raise PermissionError("RBAC: perm je prazan.")
    if not user_has_perm(user, p):
        raise PermissionError(f"Nemaš pravo: {p} (role={_role_from_user(user)})")


def effective_role(user: Any) -> str:
    return _role_from_user(user)


def effective_roles(user: Any) -> List[str]:
    return list_assigned_roles(user)


def effective_perms(user: Any) -> Set[str]:
    return set(_perms_for_role(_role_from_user(user)))

# (FILENAME: core/rbac.py - END PART 1/2)

# FILENAME: core/rbac.py
# (FILENAME: core/rbac.py - START PART 2/2)

# ---------------------------------------------------------------------------
# Compatibility helpers: core.rbac.can (UI fallback)
# ---------------------------------------------------------------------------

def can(perm: str, user: Any = None) -> bool:
    """
    Kompatibilni helper:
    - Ako user nije prosleđen, pokuša da uzme core.session.get_current_user()
    - Ako session nije dostupna, vraća False (fail-closed)
    """
    u = user
    if u is None:
        try:
            from core.session import get_current_user  # type: ignore
            u = get_current_user()
        except Exception:
            u = None
    return user_has_perm(u, perm)


def can_any(perms: Iterable[str], user: Any = None) -> bool:
    u = user
    if u is None:
        try:
            from core.session import get_current_user  # type: ignore
            u = get_current_user()
        except Exception:
            u = None
    return user_has_any_perm(u, perms)


def can_all(perms: Iterable[str], user: Any = None) -> bool:
    u = user
    if u is None:
        try:
            from core.session import get_current_user  # type: ignore
            u = get_current_user()
        except Exception:
            u = None
    return user_has_all_perms(u, perms)


# ---------------------------------------------------------------------------
# Config validation (diagnostika)
# ---------------------------------------------------------------------------

def validate_rbac_config() -> List[str]:
    warns: List[str] = []

    if ROLE_READONLY not in ROLE_PERMS:
        warns.append("ROLE_PERMS: nedostaje READONLY set (fallback može biti pogrešan).")

    for role in (ROLE_BASIC, ROLE_READONLY):
        rp = ROLE_PERMS.get(role, set())
        if "*" in rp:
            warns.append(f"{role} ima wildcard '*' (ne bi smelo).")
        for p in rp:
            if _is_users_perm(str(p)):
                warns.append(f"{role} ima users.* permisiju ({p}) (ne bi smelo).")

    for role, rp in ROLE_PERMS.items():
        for p in rp:
            if not str(p or "").strip():
                warns.append(f"{role} ima praznu permisiju.")

    for src, tgt in ROLE_ALIASES.items():
        if tgt not in ROLE_PERMS:
            warns.append(f"ROLE_ALIASES: '{src}' mapira na nepoznatu rolu '{tgt}'.")

    for role in ROLE_PERMS.keys():
        if role not in ROLE_PRIORITY:
            warns.append(f"ROLE_PRIORITY: nema prioritet za rolu '{role}' (fallback=READONLY score).")

    return warns


__all__ = [
    # perms
    "PERM_ASSETS_VIEW",
    "PERM_ASSETS_CREATE",
    "PERM_ASSETS_EDIT",
    "PERM_ASSETS_DELETE",
    "PERM_ASSETS_METRO_VIEW",
    "PERM_ASSETS_MY_VIEW",

    "PERM_ASSIGN_VIEW",
    "PERM_ASSIGN_CREATE",
    "PERM_ASSIGN_EDIT",
    "PERM_ASSIGN_DELETE",

    "PERM_AUDIT_VIEW",

    "PERM_METRO_VIEW",
    "PERM_METRO_MY_VIEW",
    "PERM_METRO_SCOPE_VIEW",
    "PERM_METRO_EDIT",
    "PERM_METRO_MANAGE",
    "PERM_METRO_WRITE",
    "PERM_METRO_ADMIN",

    "PERM_DISPOSAL_PREPARE",
    "PERM_DISPOSAL_APPROVE",
    "PERM_DISPOSAL_DISPOSE",

    "PERM_USERS_VIEW",
    "PERM_USERS_MANAGE",
    "PERM_SETTINGS_VIEW",
    "PERM_SETTINGS_MANAGE",
    "PERM_REPORTS_PRINT",

    # roles
    "ROLE_ADMIN",
    "ROLE_SECTOR_ADMIN",
    "ROLE_REFERENT_IT",
    "ROLE_REFERENT_METRO",
    "ROLE_REFERENT_OS",
    "ROLE_BASIC",
    "ROLE_READONLY",

    # config
    "ROLE_ALIASES",
    "ROLE_PERMS",
    "ROLE_PRIORITY",

    # api
    "normalize_role",
    "pick_highest_role",
    "user_has_perm",
    "require_perm",
    "effective_role",
    "effective_roles",
    "effective_perms",
    "user_has_any_perm",
    "user_has_all_perms",
    "list_assigned_roles",
    "validate_rbac_config",
    "clear_rbac_caches",

    # compat helpers
    "can",
    "can_any",
    "can_all",
]


if __name__ == "__main__":  # pragma: no cover
    # Minimalni self-test: možeš pokrenuti `python core/rbac.py`
    u_admin = {"role": "ADMIN"}
    u_basic = {"role": "BASIC_USER"}

    # multi-role sa active_role validnim
    u_multi = {"roles": ["REFERENT_IT", "REFERENT_METRO"], "active_role": "REFERENT_METRO"}

    assert user_has_perm(u_admin, "anything.goes") is True
    assert user_has_perm(u_basic, PERM_USERS_VIEW) is False
    assert effective_role(u_multi) == "REFERENT_METRO"
    assert user_has_perm(u_multi, PERM_METRO_EDIT) is True

    # 🔒 Security regression test: nema eskalacije preko 'role' ako već postoji 'roles'
    u_escalate = {"roles": ["BASIC_USER"], "role": "ADMIN"}
    assert effective_role(u_escalate) == "BASIC_USER"
    assert user_has_perm(u_escalate, PERM_USERS_MANAGE) is False

    # invalid active_role -> fallback na NAJVEĆU dodeljenu (ovde BASIC_USER)
    u_bad = {"roles": ["BASIC_USER"], "active_role": "ADMIN"}
    assert effective_role(u_bad) == "BASIC_USER"
    assert user_has_perm(u_bad, PERM_USERS_MANAGE) is False

    # bez active_role -> bira se najveća (REFERENT_IT > REFERENT_METRO po priority)
    u_no_active = {"roles": ["REFERENT_METRO", "REFERENT_IT"]}
    assert effective_role(u_no_active) == "REFERENT_IT"

    # nepoznate role -> READONLY fallback
    u_unknown = {"roles": ["SOMETHING_NEW"]}
    assert effective_role(u_unknown) == ROLE_READONLY

    # prazna roles lista ne blokira fallback na 'role'
    u_empty_roles = {"roles": [], "role": "REFERENT_IT"}
    assert effective_role(u_empty_roles) == "REFERENT_IT"

    # cache-safety regression: normalize_role sa unhashable input (lista)
    assert normalize_role(["ADMIN", "BASIC_USER"]) == "ADMIN"

    warns = validate_rbac_config()
    # Ne pada test na warnings, ali možeš da ih ispišeš ako želiš.
    print("core/rbac.py self-test OK")
    if warns:
        print("WARNINGS:")
        for w in warns:
            print(" -", w)

# (FILENAME: core/rbac.py - END PART 2/2)
# FILENAME: core/rbac.py