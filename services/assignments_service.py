# FILENAME: services/assignments_service.py
# (FILENAME: services/assignments_service.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/assignments_service.py

Zaduženja: assign / transfer / return.

Cilj:
- servisni sloj kompatibilan sa više UI/DB varijanti, bez "unexpected keyword"
- ✅ RBAC (service-level): prava se proveravaju OVDE (FAIL-CLOSED), ne samo u UI
- ✅ actor dolazi iz session-a (ulogovani korisnik), parametar actor je kompatibilnost

RBAC:
- PERM_ASSIGN_VIEW   -> list_assignments / list_assignments_for_asset
- PERM_ASSIGN_CREATE -> create_assignment
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import inspect


# -------------------- RBAC (service-level, FAIL-CLOSED) --------------------
try:
    from core.rbac import PERM_ASSIGN_VIEW, PERM_ASSIGN_CREATE  # type: ignore
except Exception:  # pragma: no cover
    PERM_ASSIGN_VIEW = "assignments.view"
    PERM_ASSIGN_CREATE = "assignments.create"


def _safe_can(perm: str) -> bool:
    """
    FAIL-CLOSED: ako session/can pukne -> False.
    """
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _require_login(src: str = "") -> None:
    """
    Ako nema ulogovanog korisnika, prekid (bolje nego da servis radi “sam”).
    """
    try:
        from core.session import get_current_user  # type: ignore
        if not get_current_user():
            raise PermissionError("Nisi prijavljen.")
    except PermissionError:
        raise
    except Exception:
        # Ako session nije dostupan, tretiraj kao neprijavljen (FAIL-CLOSED)
        raise PermissionError("Session nije dostupna (nisi prijavljen).")


def _current_actor() -> str:
    """
    Actor za audit i logove — uzimamo iz session-a.
    """
    try:
        from core.session import actor_name  # type: ignore
        return (actor_name() or "").strip() or "user"
    except Exception:
        return "user"


def _require_perm(perm: str, src: str = "") -> None:
    if not _safe_can(perm):
        where = f" ({src})" if src else ""
        raise PermissionError(f"RBAC: nemaš pravo za akciju: {perm}{where}")


# -------------------- DB func import + compatible call --------------------
def _try_import_db_func(*names: str) -> Tuple[Optional[Any], Optional[str]]:
    """
    Pokuša da uveze funkciju iz core.db pod bilo kojim od prosleđenih imena.
    Vraća (func, used_name) ili (None, None).
    """
    try:
        import core.db as db  # type: ignore
    except Exception:
        return None, None

    for n in names:
        fn = getattr(db, n, None)
        if callable(fn):
            return fn, n
    return None, None


def _call_compatible(func, **kwargs):
    """
    Pozove func tako što automatski izbacuje kwargs koje func ne prihvata.
    Rešava: TypeError: got an unexpected keyword argument '...'
    """
    if func is None:
        raise RuntimeError("DB funkcija nije pronađena (core.db).")

    try:
        sig = inspect.signature(func)
    except Exception:
        return func(**kwargs)

    # Ako func prima **kwargs, nema potrebe da filtriramo.
    for p in sig.parameters.values():
        if p.kind == inspect.Parameter.VAR_KEYWORD:
            return func(**kwargs)

    allowed = set(sig.parameters.keys())
    filtered = {k: v for k, v in kwargs.items() if k in allowed}
    return func(**filtered)


_db_create_assignment, _ = _try_import_db_func("create_assignment_db", "create_assignment")
_db_list_assignments, _ = _try_import_db_func("list_assignments_db", "list_assignments")
_db_list_for_asset, _ = _try_import_db_func("list_assignments_for_asset_db", "list_assignments_for_asset")


# -------------------- Public API --------------------
def create_assignment(
    actor: str,
    asset_uid: str,
    action: str,
    to_holder: str = "",
    to_location: str = "",
    note: str = "",
    source: str = "ui_new_assignment",
    from_holder: str = "",
    **extra: Any,
) -> int:
    """
    Upis zaduženja: assign / transfer / return.

    ✅ RBAC: PERM_ASSIGN_CREATE (FAIL-CLOSED)
    ✅ actor: uzima se iz session-a (ulogovani korisnik)
    """
    _require_login("assignments.create_assignment")
    _require_perm(PERM_ASSIGN_CREATE, "assignments.create_assignment")

    actor_eff = _current_actor()

    payload = dict(
        actor=actor_eff,
        asset_uid=(asset_uid or "").strip(),
        action=(action or "").strip().lower(),
        to_holder=(to_holder or "").strip(),
        to_location=(to_location or "").strip(),
        from_holder=(from_holder or "").strip(),
        note=(note or "").strip(),
        source=(source or "").strip(),
        **extra,
    )

    rid = _call_compatible(_db_create_assignment, **payload)
    try:
        return int(rid)
    except Exception:
        return int(str(rid).strip() or "0")


def list_assignments(
    search: str = "",
    action: str = "SVE",
    limit: int = 1000,
    q: str = "",
) -> List[Dict[str, Any]]:
    """
    Lista zaduženja (tabela).

    ✅ RBAC: PERM_ASSIGN_VIEW (FAIL-CLOSED)
    """
    _require_perm(PERM_ASSIGN_VIEW, "assignments.list_assignments")

    lim = int(limit or 0)
    if lim <= 0:
        lim = 1000

    # kompatibilnost: q ili search
    s = (search or "").strip()
    qq = (q or "").strip()
    final_search = s if s else qq

    rows = _call_compatible(
        _db_list_assignments,
        search=final_search,
        q=final_search,  # prosledi oba, DB sloj filtrira
        action=(action or "SVE").strip(),
        limit=lim,
    )
    return rows  # type: ignore


def list_assignments_for_asset(asset_uid: str, limit: int = 500) -> List[Dict[str, Any]]:
    """
    Lista zaduženja za jedno sredstvo (detalji sredstva).

    ✅ RBAC: PERM_ASSIGN_VIEW (FAIL-CLOSED)
    """
    _require_perm(PERM_ASSIGN_VIEW, "assignments.list_assignments_for_asset")

    lim = int(limit or 0)
    if lim <= 0:
        lim = 500

    rows = _call_compatible(
        _db_list_for_asset,
        asset_uid=(asset_uid or "").strip(),
        limit=lim,
    )
    return rows  # type: ignore


# (FILENAME: services/assignments_service.py - END)