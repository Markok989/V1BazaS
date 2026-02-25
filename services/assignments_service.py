# FILENAME: services/assignments_service.py
# (FILENAME: services/assignments_service.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/assignments_service.py

Zaduženja: assign / transfer / return.

Cilj:
- servisni sloj kompatibilan sa više UI/DB varijanti (bez "unexpected keyword")
- ✅ RBAC (service-level): prava se proveravaju OVDE (FAIL-CLOSED), ne samo u UI
- ✅ actor dolazi iz session-a (ulogovani korisnik), parametar actor je kompatibilnost

RBAC:
- PERM_ASSIGN_VIEW   -> list_assignments / list_assignments_for_asset
- PERM_ASSIGN_CREATE -> create_assignment
"""

from __future__ import annotations

import inspect
from typing import Any, Dict, List, Optional, Tuple

# -------------------- RBAC (service-level, FAIL-CLOSED) --------------------
try:
    from core.rbac import PERM_ASSIGN_VIEW, PERM_ASSIGN_CREATE  # type: ignore
except Exception:  # pragma: no cover
    PERM_ASSIGN_VIEW = "assignments.view"
    PERM_ASSIGN_CREATE = "assignments.create"


def _safe_can(perm: str) -> bool:
    """FAIL-CLOSED: ako session/can pukne -> False."""
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _require_login(src: str = "") -> None:
    """
    Ako nema ulogovanog korisnika, prekid (FAIL-CLOSED).
    Prefer core.session.require_login() ako postoji.
    """
    try:
        from core.session import require_login  # type: ignore
        try:
            require_login(src or "assignments")
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


def _current_actor() -> str:
    """Actor za audit i logove — uzimamo iz session-a."""
    try:
        from core.session import actor_name  # type: ignore
        return (actor_name() or "").strip() or "user"
    except Exception:
        return "user"


def _require_perm(perm: str, src: str = "") -> None:
    if not _safe_can(perm):
        where = f" ({src})" if src else ""
        raise PermissionError(f"RBAC: nemaš pravo za akciju: {perm}{where}")


def _norm_text(x: Any) -> str:
    return ("" if x is None else str(x)).replace("\r", " ").replace("\n", " ").strip()


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


_SIG_CACHE: Dict[int, Optional[inspect.Signature]] = {}


def _call_compatible(func, **kwargs):
    """
    Pozove func tako što automatski izbacuje kwargs koje func ne prihvata.
    Rešava: TypeError: got an unexpected keyword argument '...'
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

    # Ako func prima **kwargs, nema potrebe da filtriramo.
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
        return func(**kwargs)

    allowed = set(sig.parameters.keys())
    filtered = {k: v for k, v in kwargs.items() if k in allowed}
    return func(**filtered)


_db_create_assignment, _ = _try_import_db_func("create_assignment_db", "create_assignment")
_db_list_assignments, _ = _try_import_db_func("list_assignments_db", "list_assignments")
_db_list_for_asset, _ = _try_import_db_func("list_assignments_for_asset_db", "list_assignments_for_asset")


# -------------------- Public API --------------------
def create_assignment(
    actor: str,  # kompatibilnost (ne koristimo, uzimamo iz session-a)
    asset_uid: str,
    action: str,
    to_holder: str = "",
    to_location: str = "",
    note: str = "",
    source: str = "ui_new_assignment",
    from_holder: str = "",  # kompatibilnost (DB ga ignoriše u V1)
    **extra: Any,
) -> int:
    """
    Upis zaduženja: assign / transfer / return.
    ✅ RBAC: PERM_ASSIGN_CREATE (FAIL-CLOSED)
    ✅ actor: uzima se iz session-a (ulogovani korisnik)
    """
    _ = actor  # ne verujemo input-u za actor
    _require_login("assignments.create_assignment")
    _require_perm(PERM_ASSIGN_CREATE, "assignments.create_assignment")

    if _db_create_assignment is None:
        raise RuntimeError("Nedostaje core.db.create_assignment_db (ili create_assignment).")

    uid = _norm_text(asset_uid)
    if not uid:
        raise ValueError("asset_uid cannot be empty")

    act = _norm_text(action).lower()
    if act not in ("assign", "transfer", "return"):
        raise ValueError("action must be assign/transfer/return")

    # Extra može sadržati svašta; ne dozvoli override kritičnih polja.
    safe_extra: Dict[str, Any] = {}
    try:
        for k, v in dict(extra or {}).items():
            if k in ("actor", "asset_uid", "action"):
                continue
            safe_extra[k] = v
    except Exception:
        safe_extra = {}

    actor_eff = _current_actor()

    payload = dict(
        actor=actor_eff,
        asset_uid=uid,
        action=act,
        to_holder=_norm_text(to_holder),
        to_location=_norm_text(to_location),
        from_holder=_norm_text(from_holder),
        note=_norm_text(note),
        source=_norm_text(source) or "ui_new_assignment",
        **safe_extra,
    )

    rid = _call_compatible(_db_create_assignment, **payload)
    try:
        return int(rid)
    except Exception:
        try:
            return int(str(rid).strip() or "0")
        except Exception:
            return 0


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
    _require_login("assignments.list_assignments")
    _require_perm(PERM_ASSIGN_VIEW, "assignments.list_assignments")

    if _db_list_assignments is None:
        raise RuntimeError("Nedostaje core.db.list_assignments_db (ili list_assignments).")

    lim = _clamp_int(limit, 1000, min_v=1, max_v=100000)

    # kompatibilnost: q ili search
    s = _norm_text(search)
    qq = _norm_text(q)
    final_search = s if s else qq

    rows = _call_compatible(
        _db_list_assignments,
        search=final_search,
        q=final_search,  # prosledi oba, DB sloj filtrira
        action=_norm_text(action) or "SVE",
        limit=lim,
    )

    # normalize output: uvek list[dict]
    if rows is None:
        return []
    if isinstance(rows, list):
        return [dict(r) if isinstance(r, dict) else r for r in rows]  # type: ignore[return-value]
    try:
        out = list(rows)  # type: ignore[arg-type]
        return [dict(r) if isinstance(r, dict) else r for r in out]  # type: ignore[return-value]
    except Exception:
        return []


def list_assignments_for_asset(asset_uid: str, limit: int = 500) -> List[Dict[str, Any]]:
    """
    Lista zaduženja za jedno sredstvo (detalji sredstva).
    ✅ RBAC: PERM_ASSIGN_VIEW (FAIL-CLOSED)
    """
    _require_login("assignments.list_assignments_for_asset")
    _require_perm(PERM_ASSIGN_VIEW, "assignments.list_assignments_for_asset")

    if _db_list_for_asset is None:
        raise RuntimeError("Nedostaje core.db.list_assignments_for_asset_db (ili list_assignments_for_asset).")

    uid = _norm_text(asset_uid)
    if not uid:
        return []

    lim = _clamp_int(limit, 500, min_v=1, max_v=100000)

    rows = _call_compatible(
        _db_list_for_asset,
        asset_uid=uid,
        limit=lim,
    )

    if rows is None:
        return []
    if isinstance(rows, list):
        return [dict(r) if isinstance(r, dict) else r for r in rows]  # type: ignore[return-value]
    try:
        out = list(rows)  # type: ignore[arg-type]
        return [dict(r) if isinstance(r, dict) else r for r in out]  # type: ignore[return-value]
    except Exception:
        return []

# (FILENAME: services/assignments_service.py - END)