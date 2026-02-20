# FILENAME: tools/full_smoke_test.py
# -*- coding: utf-8 -*-
"""
BazaS2 — FULL SMOKE TEST (offline)

Cilj:
- testira imports (core/services/ui)
- inicijalizuje DB (init_db)
- pozove ensure_*_schema
- uradi "service-level" testove uz fake session user-a
- ne pokreće GUI event-loop (QApplication.exec), ali može da importuje UI module

Pokretanje (iz ROOT foldera projekta):
    python -m tools.full_smoke_test
ili:
    python tools/full_smoke_test.py

Napomena:
- Ovo je "best-effort" i FAIL-CLOSED: ako nešto nema u projektu, test to prijavi.
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# -------------------- PATH FIX (da radi i kad pokreneš direktno) --------------------
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# -------------------- tiny helpers --------------------
def _hr(title: str = "") -> None:
    line = "-" * 78
    if title:
        print(f"\n{line}\n{title}\n{line}")
    else:
        print(f"\n{line}")


def _ok(msg: str) -> None:
    print(f"[ OK ] {msg}")


def _warn(msg: str) -> None:
    print(f"[WARN] {msg}")


def _fail(msg: str) -> None:
    print(f"[FAIL] {msg}")


def _try_import(path: str):
    try:
        __import__(path)
        _ok(f"import {path}")
        return True
    except Exception as e:
        _fail(f"import {path} -> {e}")
        return False


def _safe_call(label: str, fn, *args, **kwargs):
    try:
        out = fn(*args, **kwargs)
        _ok(f"{label}")
        return True, out
    except Exception as e:
        _fail(f"{label} -> {e}")
        tb = traceback.format_exc()
        print(tb)
        return False, None


# -------------------- Session patching --------------------
def _patch_session_for_tests(user: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Pokušaj da "uloguje" korisnika u core.session tako da servisi mogu da rade.
    Radi best-effort, jer session API može varirati.
    """
    try:
        import core.session as session  # type: ignore
    except Exception as e:
        return False, f"Ne mogu import core.session: {e}"

    # set_current_user je najvažniji
    try:
        if hasattr(session, "set_current_user") and callable(session.set_current_user):
            session.set_current_user(user)  # type: ignore
        else:
            return False, "core.session.set_current_user ne postoji"
    except Exception as e:
        return False, f"set_current_user failed: {e}"

    # set_active_role ako postoji (multi-role)
    try:
        ar = str(user.get("active_role") or user.get("role") or "").strip()
        if ar and hasattr(session, "set_active_role") and callable(session.set_active_role):
            session.set_active_role(ar, source="full_smoke_test", audit=False)  # type: ignore
    except Exception:
        pass

    # set active sector ako postoji
    try:
        sec = str(user.get("active_sector") or user.get("sector") or "").strip()
        if sec and hasattr(session, "set_active_sector") and callable(session.set_active_sector):
            session.set_active_sector(sec, source="full_smoke_test", audit=False)  # type: ignore
    except Exception:
        pass

    return True, "session patched"


def _build_test_users() -> List[Dict[str, Any]]:
    """
    Napravimo nekoliko profila da proverimo scope:
    - ADMIN (FULL)
    - REFERENT_METRO (sector-scope + metro scope)
    - BASIC_USER (MY scope)
    """
    return [
        {
            "id": 1,
            "username": "admin",
            "display_name": "Admin",
            "role": "ADMIN",
            "active_role": "ADMIN",
            "roles": ["ADMIN"],
            "sector": "S2",
            "active_sector": "S2",
        },
        {
            "id": 2,
            "username": "metro",
            "display_name": "Referent Metro",
            "role": "REFERENT_METRO",
            "active_role": "REFERENT_METRO",
            "roles": ["REFERENT_METRO"],
            "sector": "2.1",
            "active_sector": "2.1",
        },
        {
            "id": 3,
            "username": "basic",
            "display_name": "Basic User",
            "role": "BASIC_USER",
            "active_role": "BASIC_USER",
            "roles": ["BASIC_USER"],
            "sector": "2.1",
            "active_sector": "2.1",
        },
    ]


def _print_env_info() -> None:
    _hr("ENV / PATH")
    print("Python:", sys.version)
    print("CWD:", os.getcwd())
    print("ROOT:", ROOT.as_posix())
    print("sys.path[0]:", sys.path[0])


# -------------------- DB helpers --------------------
def _init_db() -> bool:
    """
    Pozove core.db.init_db (ako postoji) i proveri connect_db.
    """
    _hr("DB INIT / CONNECT")
    ok = True

    try:
        from core.db import init_db, connect_db  # type: ignore
    except Exception as e:
        _fail(f"import core.db (init_db/connect_db) -> {e}")
        return False

    ok1, res = _safe_call("core.db.init_db()", init_db)
    ok = ok and ok1

    ok2, conn = _safe_call("core.db.connect_db()", connect_db)
    ok = ok and ok2
    if conn is not None:
        try:
            # connect_db može biti context manager ili connection
            if hasattr(conn, "__enter__") and hasattr(conn, "__exit__"):
                with conn as c:
                    c.execute("SELECT 1;")
            else:
                conn.execute("SELECT 1;")
                try:
                    conn.close()
                except Exception:
                    pass
            _ok("DB SELECT 1")
        except Exception as e:
            _fail(f"DB SELECT 1 -> {e}")
            ok = False

    return ok


def _ensure_schemas() -> bool:
    _hr("ENSURE SCHEMAS")
    ok = True

    # users schema
    try:
        from services.users_service import ensure_users_schema  # type: ignore
        ok1, _ = _safe_call("services.users_service.ensure_users_schema()", ensure_users_schema)
        ok = ok and ok1
    except Exception as e:
        _fail(f"import ensure_users_schema -> {e}")
        ok = False

    # metrology schema
    try:
        from services.metrology_service import ensure_metrology_schema  # type: ignore
        ok2, _ = _safe_call("services.metrology_service.ensure_metrology_schema()", ensure_metrology_schema)
        ok = ok and ok2
    except Exception as e:
        _fail(f"import ensure_metrology_schema -> {e}")
        ok = False

    return ok


# -------------------- Service tests --------------------
def _test_assets_service(user: Dict[str, Any]) -> bool:
    _hr(f"ASSETS SERVICE (role={user.get('active_role')})")
    ok = True

    try:
        import services.assets_service as assets_service  # type: ignore
    except Exception as e:
        _fail(f"import services.assets_service -> {e}")
        return False

    # list_assets_brief (RBAC any view)
    ok1, rows = _safe_call("assets_service.list_assets_brief(limit=20)", assets_service.list_assets_brief, limit=20)
    ok = ok and ok1
    if ok1 and isinstance(rows, list):
        _ok(f"assets rows: {len(rows)}")

    # get_asset_by_uid (probaj uzeti prvi iz brief)
    if ok1 and isinstance(rows, list) and rows:
        uid = str((rows[0] or {}).get("asset_uid") or "").strip()
        if uid:
            ok2, one = _safe_call(f"assets_service.get_asset_by_uid({uid})", assets_service.get_asset_by_uid, asset_uid=uid)
            ok = ok and ok2
        else:
            _warn("Prvi asset iz brief nema asset_uid (preskačem get_asset_by_uid).")
    else:
        _warn("Nema assets za get_asset_by_uid test (OK ako je prazna baza).")

    return ok


def _test_metrology_service(user: Dict[str, Any]) -> bool:
    _hr(f"METROLOGY SERVICE (role={user.get('active_role')})")
    ok = True

    try:
        import services.metrology_service as ms  # type: ignore
    except Exception as e:
        _fail(f"import services.metrology_service -> {e}")
        return False

    # list
    ok1, rows = _safe_call("metrology_service.list_metrology_records(limit=20)", ms.list_metrology_records, limit=20)
    ok = ok and ok1
    if ok1 and isinstance(rows, list):
        _ok(f"metrology rows: {len(rows)}")

    # audit list (ako ima bar 1)
    if ok1 and isinstance(rows, list) and rows:
        mu = str((rows[0] or {}).get("met_uid") or "").strip()
        if mu:
            ok2, aud = _safe_call(f"metrology_service.list_metrology_audit({mu}, limit=10)", ms.list_metrology_audit, mu, 10)
            ok = ok and ok2
        else:
            _warn("Prvi metrology record nema met_uid (preskačem audit).")
    else:
        _warn("Nema metrology record-a (OK ako je prazno).")

    return ok


def _test_users_service(user: Dict[str, Any]) -> bool:
    _hr(f"USERS SERVICE (role={user.get('active_role')})")
    ok = True

    try:
        import services.users_service as us  # type: ignore
    except Exception as e:
        _fail(f"import services.users_service -> {e}")
        return False

    ok1, rows = _safe_call("users_service.list_users(limit=20)", us.list_users, True, 20)  # active_only=True
    if not ok1:
        # fallback ako potpis ne odgovara
        ok1, rows = _safe_call("users_service.list_users()", us.list_users)

    ok = ok and ok1
    if ok1 and isinstance(rows, list):
        _ok(f"users rows: {len(rows)}")

    # list roles for current user object (ako postoji funkcija)
    if hasattr(us, "list_user_roles") and callable(us.list_user_roles):
        ok2, rr = _safe_call("users_service.list_user_roles(user)", us.list_user_roles, user)
        ok = ok and ok2
        if ok2 and isinstance(rr, list):
            _ok(f"user roles: {rr}")

    return ok


def _test_ui_imports() -> bool:
    _hr("UI IMPORTS (no event loop)")
    ok = True

    # PySide6 core import
    try:
        from PySide6 import QtCore  # type: ignore
        _ok("import PySide6")
    except Exception as e:
        _fail(f"import PySide6 -> {e}")
        return False

    # import ključnih UI modula
    ui_modules = [
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
    for m in ui_modules:
        ok = _try_import(m) and ok

    return ok


def main() -> int:
    _hr("BazaS2 — FULL SMOKE TEST (offline)")
    _print_env_info()

    # 1) ključni importi
    _hr("CORE IMPORTS")
    core_mods = [
        "core.config",
        "core.db",
        "core.session",
        "core.rbac",
        "core.logger",
        "core.selfcheck",
    ]
    imports_ok = True
    for m in core_mods:
        imports_ok = _try_import(m) and imports_ok

    _hr("SERVICES IMPORTS")
    svc_mods = [
        "services.users_service",
        "services.assets_service",
        "services.metrology_service",
        "services.dashboard_service",
    ]
    for m in svc_mods:
        imports_ok = _try_import(m) and imports_ok

    # 2) db init
    db_ok = _init_db()

    # 3) ensure schema
    schema_ok = _ensure_schemas()

    # 4) ui imports (bez event loop)
    ui_ok = _test_ui_imports()

    # 5) service tests po rolama
    role_ok_all = True
    users = _build_test_users()

    for u in users:
        ok_sess, msg = _patch_session_for_tests(u)
        if not ok_sess:
            _fail(f"session patch -> {msg}")
            role_ok_all = False
            continue
        _ok(f"session patch -> {msg}")

        # test users service (uvek)
        role_ok_all = _test_users_service(u) and role_ok_all
        # test assets
        role_ok_all = _test_assets_service(u) and role_ok_all
        # test metrology
        role_ok_all = _test_metrology_service(u) and role_ok_all

    # summary
    _hr("SUMMARY")
    all_ok = bool(imports_ok and db_ok and schema_ok and ui_ok and role_ok_all)
    if all_ok:
        _ok("FULL SMOKE TEST: PASS ✅")
        return 0
    _fail("FULL SMOKE TEST: FAIL ❌ (vidi log iznad)")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
# END FILENAME: tools/full_smoke_test.py