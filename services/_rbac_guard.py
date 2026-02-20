# FILENAME: services/_rbac_guard.py
# (FILENAME: services/_rbac_guard.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/_rbac_guard.py

Centralni guard za service-level RBAC (FAIL-CLOSED).

- require_login(): mora biti ulogovan korisnik
- require_perm(PERM_X): mora imati permisiju
- require_any([...]): mora imati bar jednu permisiju iz liste
- safe_can(PERM_X): bez bacanja, vraća True/False (fail-closed)
- current_actor(): actor iz trenutno ulogovanog korisnika (display_name -> username)
"""

from __future__ import annotations

from typing import Iterable

from core.session import can, actor_name, get_current_user


class RBACDenied(PermissionError):
    """Standardizovan PermissionError za servise."""
    pass


def _safe_bool(value: object) -> bool:
    try:
        return bool(value)
    except Exception:
        return False


def safe_can(perm: str) -> bool:
    """Fail-closed: ako RBAC pukne, vraća False."""
    try:
        return _safe_bool(can(perm))
    except Exception:
        return False


def require_login(reason: str = "") -> None:
    """Zabranjuje pozive bez ulogovanog korisnika."""
    try:
        u = get_current_user()
    except Exception:
        u = None

    if not isinstance(u, dict) or not u:
        msg = "Nedozvoljeno: korisnik nije prijavljen."
        if reason:
            msg += f" ({reason})"
        raise RBACDenied(msg)


def require_perm(perm: str, reason: str = "") -> None:
    """FAIL-CLOSED provera permisije."""
    if not perm or not isinstance(perm, str) or not perm.strip():
        raise RBACDenied("RBAC greška: perm nije definisan.")

    if safe_can(perm):
        return

    who = "?"
    try:
        who = actor_name()
    except Exception:
        pass

    msg = f"Nedozvoljeno: '{who}' nema permisiju '{perm}'."
    if reason:
        msg += f" ({reason})"
    raise RBACDenied(msg)


def require_any(perms: Iterable[str], reason: str = "") -> None:
    """Dozvoli ako korisnik ima bar jednu permisiju iz liste."""
    perms_list = [p.strip() for p in (perms or []) if isinstance(p, str) and p.strip()]
    if not perms_list:
        raise RBACDenied("RBAC greška: require_any bez permisija.")

    for p in perms_list:
        if safe_can(p):
            return

    who = "?"
    try:
        who = actor_name()
    except Exception:
        pass

    msg = f"Nedozvoljeno: '{who}' nema nijednu od permisija: {', '.join(perms_list)}."
    if reason:
        msg += f" ({reason})"
    raise RBACDenied(msg)


def current_actor() -> str:
    """Normalizovan actor za MY-scope filtriranje u servisima."""
    try:
        return (actor_name() or "").strip() or "user"
    except Exception:
        return "user"

# (FILENAME: services/_rbac_guard.py - END)