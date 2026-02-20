# FILENAME: tools/full_smoke_testv1.py
# (FILENAME: tools/full_smoke_testv1.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 — FULL SMOKE TEST (offline)

Cilj:
- Brza provera import-a, DB init/connect, schema ensure
- Provera servis funkcija uz RBAC:
  - Ako rola NEMA pravo: PermissionError se tretira kao EXPECTED DENY (PASS)
  - Ako rola IMA pravo: poziv mora proći (PASS)
  - Sve ostalo: FAIL

Napomena:
- Ovaj test ne pokreće Qt event loop (UI import only).
- Ne radi “deep UI automation”, već proverava da se moduli učitavaju
  i da se servis-level RBAC ponaša kako očekujemo.
"""

from __future__ import annotations

import os
import sys
import traceback
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple, List


# -------------------- Pretty printing helpers --------------------
def _hr() -> None:
    print("-" * 78)


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


# -------------------- RBAC expectations --------------------
def _perm_check(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _expected_allowed(role: str, action: str) -> bool:
    """
    Matrix očekivanja:
    - ADMIN: sve allowed (u praksi)
    - REFERENT_METRO: users.* DENY, assets_brief OK, metrology_list OK
    - BASIC_USER: users.* DENY, assets_brief OK, metrology_list OK (može biti 0 results)
    """
    r = (role or "").strip().upper()

    if r == "ADMIN":
        return True

    if r == "REFERENT_METRO":
        if action.startswith("users."):
            return False
        if action in ("assets.list_assets_brief", "assets.get_asset_by_uid", "metrology.list", "metrology.audit"):
            return True
        return False

    if r == "BASIC_USER":
        if action.startswith("users."):
            return False
        if action in ("assets.list_assets_brief", "assets.get_asset_by_uid", "metrology.list"):
            return True
        return False

    # default conservative
    return False


# -------------------- Safe call wrapper --------------------
def _safe_call(
    label: str,
    role: str,
    action: str,
    fn: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> CallResult:
    allow = _expected_allowed(role, action)

    try:
        out = fn(*args, **kwargs)
        # poziv prošao
        if allow:
            return CallResult(ok=True, expected=True, label=label)
        # prošao a očekivali deny -> FAIL
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
        # sector je bitan za REFERENT_METRO scope (ako koristi)
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
    root = os.path.abspath(os.path.dirname(__file__) + "/..")
    print("ROOT:", root)
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

        # Users service tests
        _section(f"USERS SERVICE (role={role})")

        results: List[CallResult] = []

        results.append(_safe_call(
            "users_service.list_users(limit=20)",
            role, "users.list",
            getattr(users_service, "list_users"),
            limit=20,
        ))

        # list_users() without args (compat)
        results.append(_safe_call(
            "users_service.list_users()",
            role, "users.list",
            getattr(users_service, "list_users"),
        ))

        # list_user_roles(user)
        try:
            dummy_user = {"id": 1, "username": "x", "role": "ADMIN", "active_role": "ADMIN", "roles": ["ADMIN"]}
        except Exception:
            dummy_user = {}
        results.append(_safe_call(
            "users_service.list_user_roles(user)",
            role, "users.roles",
            getattr(users_service, "list_user_roles"),
            dummy_user,
        ))

        # Print results
        for r in results:
            if r.ok:
                print("[ OK ]", r.label, ("-> " + r.detail if r.detail else ""))
            else:
                overall_fail = True
                print("[FAIL]", r.label, "->", r.detail)

        # Assets service tests
        _section(f"ASSETS SERVICE (role={role})")
        results = []

        results.append(_safe_call(
            "assets_service.list_assets_brief(limit=20)",
            role, "assets.list_assets_brief",
            getattr(assets_service, "list_assets_brief"),
            limit=20,
        ))

        # If we got assets, try get_asset_by_uid on first element
        asset_uid: Optional[str] = None
        try:
            rows = assets_service.list_assets_brief(limit=5)  # may raise PermissionError; if so it's ok for this role matrix
            if isinstance(rows, list) and rows:
                a0 = rows[0]
                if isinstance(a0, dict):
                    asset_uid = str(a0.get("asset_uid") or "").strip() or None
        except Exception:
            asset_uid = None

        if asset_uid:
            results.append(_safe_call(
                f"assets_service.get_asset_by_uid({asset_uid})",
                role, "assets.get_asset_by_uid",
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

        # Metrology service tests
        _section(f"METROLOGY SERVICE (role={role})")
        results = []

        results.append(_safe_call(
            "metrology_service.list_metrology_records(limit=20)",
            role, "metrology.list",
            getattr(metrology_service, "list_metrology_records"),
            limit=20,
        ))

        # audit test only if we can read some record
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
                role, "metrology.audit",
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

# (FILENAME: tools/full_smoke_testv1.py - END)