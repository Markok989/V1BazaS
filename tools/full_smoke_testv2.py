# FILENAME: tools/full_smoke_testv2.py
# (FILENAME: tools/full_smoke_testv2.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 — FULL SMOKE TEST (offline)

Cilj:
- Brza provera import-a, DB init/connect, schema ensure
- Provera servis funkcija uz RBAC:
  - Ako can() kaže DENY -> PermissionError je EXPECTED (PASS)
  - Ako can() kaže ALLOW -> poziv mora proći (PASS)
  - Sve ostalo -> FAIL

Napomena:
- Ne pokreće Qt event loop (UI import only).
- Ne radi deep UI automation, već proverava da moduli i servisi rade + RBAC je konzistentan.
"""

from __future__ import annotations

import os
import sys
import traceback
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, List, Tuple


# -------------------- Bootstrap sys.path (FIX: tools run) --------------------
THIS_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# -------------------- Pretty printing helpers --------------------
def _section(title: str) -> None:
    print("\n" + "-" * 78)
    print(title)
    print("-" * 78 + "\n")


def _fmt_exc(e: BaseException) -> str:
    return "".join(traceback.format_exception(type(e), e, e.__traceback__))


# -------------------- Result model --------------------
@dataclass
class CallResult:
    ok: bool
    expected: bool
    label: str
    detail: str = ""


# -------------------- RBAC helpers --------------------
def _can(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _expected_allowed(action: str) -> bool:
    """
    Očekivanje se računa iz *stvarnog* RBAC-a (can()).

    action -> perm map (minimalno što nam treba za ovaj test)
    """
    a = (action or "").strip().lower()

    # Users service
    if a == "users.list" or a == "users.roles":
        return _can("users.view")

    # Assets service
    if a in ("assets.list_assets_brief", "assets.get_asset_by_uid"):
        # U tvom projektu assets_service često dozvoljava list_assets_brief i preko MY/METRO scope,
        # pa ovde tretiramo "bilo koji view" kao allow signal.
        return _can("assets.view") or _can("assets.my.view") or _can("assets.metrology.view")

    # Metrology service
    if a in ("metrology.list", "metrology.audit"):
        return _can("metrology.view")

    # default conservative
    return False


# -------------------- Safe call wrapper --------------------
def _safe_call(
    label: str,
    action: str,
    fn: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> CallResult:
    allow = _expected_allowed(action)

    try:
        _ = fn(*args, **kwargs)
        if allow:
            return CallResult(ok=True, expected=True, label=label)
        return CallResult(ok=False, expected=False, label=label, detail="UNEXPECTED ALLOW (RBAC leak?)")

    except PermissionError as e:
        if allow:
            return CallResult(ok=False, expected=False, label=label, detail=f"UNEXPECTED DENY: {e}")
        return CallResult(ok=True, expected=True, label=label, detail=f"EXPECTED DENY: {e}")

    except Exception as e:
        return CallResult(ok=False, expected=False, label=label, detail=_fmt_exc(e))


# -------------------- Session patch for tests --------------------
def _patch_session_for_tests(role: str) -> None:
    """
    Namesti minimalnog korisnika u session (bez UI).
    """
    from core.session import set_current_user  # type: ignore

    r = (role or "").strip().upper()
    u: Dict[str, Any] = {
        "id": 999,
        "username": r.lower(),
        "display_name": r,
        "role": r,
        "active_role": r,
        "roles": [r],
        "user_roles": [r],
        # sektor je bitan za REFERENT_METRO scope (ako servis koristi)
        "active_sector": "S2",
        "sector": "S2",
        "org_unit": "S2",
    }
    set_current_user(u)


# -------------------- Main test runner --------------------
def main() -> int:
    _section("BazaS2 — FULL SMOKE TEST (offline)")

    _section("ENV / PATH")
    print("Python:", sys.version.replace("\n", " "))
    print("CWD:", os.getcwd())
    print("ROOT:", ROOT)
    print("sys.path[0]:", sys.path[0])

    # ----- CORE IMPORTS
    _section("CORE IMPORTS")
    core_mods = ["core.config", "core.db", "core.session", "core.rbac", "core.logger", "core.selfcheck"]
    for m in core_mods:
        try:
            __import__(m)
            print("[ OK ] import", m)
        except Exception as e:
            print("[FAIL] import", m, "->", e)
            print(_fmt_exc(e))
            return 10

    # ----- SERVICES IMPORTS
    _section("SERVICES IMPORTS")
    svc_mods = ["services.users_service", "services.assets_service", "services.metrology_service", "services.dashboard_service"]
    for m in svc_mods:
        try:
            __import__(m)
            print("[ OK ] import", m)
        except Exception as e:
            print("[FAIL] import", m, "->", e)
            print(_fmt_exc(e))
            return 11

    # ----- DB INIT / CONNECT
    _section("DB INIT / CONNECT")
    try:
        from core.db import init_db, connect_db  # type: ignore
        init_db()
        print("[ OK ] core.db.init_db()")
        with connect_db() as conn:
            conn.execute("SELECT 1;").fetchone()
        print("[ OK ] core.db.connect_db()")
        print("[ OK ] DB SELECT 1")
    except Exception as e:
        print("[FAIL] DB INIT/CONNECT ->", e)
        print(_fmt_exc(e))
        return 12

    # ----- ENSURE SCHEMAS
    _section("ENSURE SCHEMAS")
    try:
        from services.users_service import ensure_users_schema  # type: ignore
        ensure_users_schema()
        print("[ OK ] services.users_service.ensure_users_schema()")
    except Exception as e:
        print("[FAIL] ensure_users_schema ->", e)
        print(_fmt_exc(e))
        return 13

    try:
        from services.metrology_service import ensure_metrology_schema  # type: ignore
        ensure_metrology_schema()
        print("[ OK ] services.metrology_service.ensure_metrology_schema()")
    except Exception as e:
        print("[FAIL] ensure_metrology_schema ->", e)
        print(_fmt_exc(e))
        return 14

    # ----- UI IMPORTS (no event loop)
    _section("UI IMPORTS (no event loop)")
    ui_mods = [
        "PySide6",
        "ui.login_dialog",
        "ui.dashboard_page",
        "ui.assets_page",
        "ui.metrology_page",
        "ui.my_assets_page",
        "ui.assignments_page",
        "ui.audit_page",
        "ui.settings_page",
        "ui.users_page",
    ]
    for m in ui_mods:
        try:
            __import__(m)
            print("[ OK ] import", m)
        except Exception as e:
            print("[FAIL] import", m, "->", e)
            print(_fmt_exc(e))
            return 15

    # ----- TESTS BY ROLE
    from services import users_service, assets_service, metrology_service  # type: ignore

    roles_to_test = ["ADMIN", "REFERENT_METRO", "BASIC_USER"]
    overall_fail = False

    for role in roles_to_test:
        _patch_session_for_tests(role)
        print("\n[ OK ] session patch -> role =", role)
        print("        can(users.view)         =", _can("users.view"))
        print("        can(assets.view)        =", _can("assets.view"))
        print("        can(assets.my.view)     =", _can("assets.my.view"))
        print("        can(assets.metrology.view) =", _can("assets.metrology.view"))
        print("        can(metrology.view)     =", _can("metrology.view"))

        # USERS
        _section(f"USERS SERVICE (role={role})")
        results: List[CallResult] = []
        results.append(_safe_call(
            "users_service.list_users(limit=20)",
            "users.list",
            getattr(users_service, "list_users"),
            limit=20,
        ))
        results.append(_safe_call(
            "users_service.list_users()",
            "users.list",
            getattr(users_service, "list_users"),
        ))
        dummy_user = {"id": 1, "username": "x", "role": "ADMIN", "active_role": "ADMIN", "roles": ["ADMIN"]}
        results.append(_safe_call(
            "users_service.list_user_roles(user)",
            "users.roles",
            getattr(users_service, "list_user_roles"),
            dummy_user,
        ))

        for r in results:
            if r.ok:
                print("[ OK ]", r.label, ("-> " + r.detail if r.detail else ""))
            else:
                overall_fail = True
                print("[FAIL]", r.label, "->", r.detail)

        # ASSETS
        _section(f"ASSETS SERVICE (role={role})")
        results = []
        results.append(_safe_call(
            "assets_service.list_assets_brief(limit=20)",
            "assets.list_assets_brief",
            getattr(assets_service, "list_assets_brief"),
            limit=20,
        ))

        asset_uid: Optional[str] = None
        try:
            rows = assets_service.list_assets_brief(limit=5)
            if isinstance(rows, list) and rows:
                a0 = rows[0]
                if isinstance(a0, dict):
                    asset_uid = str(a0.get("asset_uid") or "").strip() or None
        except Exception:
            asset_uid = None

        if asset_uid:
            results.append(_safe_call(
                f"assets_service.get_asset_by_uid({asset_uid})",
                "assets.get_asset_by_uid",
                getattr(assets_service, "get_asset_by_uid"),
                asset_uid=asset_uid,
            ))
        else:
            print("[WARN] Nema assets za get_asset_by_uid test (OK ako je prazna baza ili scope=0).")

        for r in results:
            if r.ok:
                print("[ OK ]", r.label, ("-> " + r.detail if r.detail else ""))
            else:
                overall_fail = True
                print("[FAIL]", r.label, "->", r.detail)

        # METROLOGY
        _section(f"METROLOGY SERVICE (role={role})")
        results = []
        results.append(_safe_call(
            "metrology_service.list_metrology_records(limit=20)",
            "metrology.list",
            getattr(metrology_service, "list_metrology_records"),
            limit=20,
        ))

        met_uid: Optional[str] = None
        try:
            mrows = metrology_service.list_metrology_records(limit=5)
            if isinstance(mrows, list) and mrows:
                m0 = mrows[0]
                if isinstance(m0, dict):
                    met_uid = str(m0.get("met_uid") or "").strip() or None
        except Exception:
            met_uid = None

        if met_uid:
            results.append(_safe_call(
                f"metrology_service.list_metrology_audit({met_uid}, limit=10)",
                "metrology.audit",
                getattr(metrology_service, "list_metrology_audit"),
                met_uid,
                10,
            ))
        else:
            print("[WARN] Nema metrology record-a za audit test (OK ako je prazno ili scope=0).")

        for r in results:
            if r.ok:
                print("[ OK ]", r.label, ("-> " + r.detail if r.detail else ""))
            else:
                overall_fail = True
                print("[FAIL]", r.label, "->", r.detail)

    _section("SUMMARY")
    if overall_fail:
        print("[FAIL] FULL SMOKE TEST: FAIL ❌ (vidi log iznad)")
        return 1

    print("[ OK ] FULL SMOKE TEST: PASS ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# (FILENAME: tools/full_smoke_testv2.py - END)