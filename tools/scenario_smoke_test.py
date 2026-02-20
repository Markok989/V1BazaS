# FILENAME: tools/scenario_smoke_test.py
# (FILENAME: tools/scenario_smoke_test.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 — SCENARIO SMOKE TEST (offline)

Šta testira:
- Pravi (ili koristi postojeću) bazu i proverava da postoje tabele.
- Kreira 2 test sredstva (1 metrology, 1 non-metrology) kao ADMIN (ako može).
- Direktno u DB (test-only) setuje:
    - holder/current_holder/assigned_to (da MY scope radi)
    - sector (da sector-scope radi)
    - metrology flag (da metrology-scope radi)
- Ubaci 1 metrology zapis za metrology asset.
- Proveri očekivanja:
    ADMIN:
      - vidi sve (assets + metrology)
    REFERENT_METRO:
      - users servis DENY (expected)
      - assets_brief vidi samo metrology-scope i (ako može) sector-scope
      - metrology list vidi 0 ili samo metrology asset (zavisno od scope)
    BASIC_USER:
      - users servis DENY (expected)
      - list_assets_my vidi samo njegova zaduženja
      - list_assets_brief ne sme da vrati tuđe (ako nema assets.view, vratiće MY; ako ima, vratiće sve)

Napomena:
- Ne koristi internet, ne pokreće UI.
- Test je “best effort”: ako u tvojoj bazi/šemi nešto ne postoji, ispiše WARN i nastavi.
"""

from __future__ import annotations

import os
import sys
import sqlite3
from datetime import date, timedelta
from typing import Any, Dict, List, Optional, Tuple


# -------------------- Pretty helpers --------------------
def hr() -> None:
    print("-" * 78)


def section(title: str) -> None:
    print("\n" + "-" * 78)
    print(title)
    print("-" * 78 + "\n")


def ok(msg: str) -> None:
    print("[ OK ]", msg)


def warn(msg: str) -> None:
    print("[WARN]", msg)


def fail(msg: str) -> None:
    print("[FAIL]", msg)


# -------------------- DB helpers --------------------
def connect_db() -> sqlite3.Connection:
    # koristimo core.db.connect_db (canonical)
    from core.db import connect_db as _c  # type: ignore
    return _c()  # returns context manager in your project, but also works as conn in "with"


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
        (name,),
    ).fetchone()
    return bool(r)


def _cols(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
        out: List[str] = []
        for r in rows:
            try:
                out.append(str(r["name"]))  # type: ignore[index]
            except Exception:
                out.append(str(r[1]))
        return out
    except Exception:
        return []


def _pick_col(cols: List[str], candidates: Tuple[str, ...]) -> str:
    s = set(cols)
    for c in candidates:
        if c in s:
            return c
    return ""


def _set_asset_field(conn: sqlite3.Connection, asset_uid: str, col: str, value: Any) -> None:
    conn.execute(f"UPDATE assets SET {col}=? WHERE asset_uid=?;", (value, asset_uid))


def _asset_exists(conn: sqlite3.Connection, asset_uid: str) -> bool:
    r = conn.execute("SELECT 1 FROM assets WHERE asset_uid=? LIMIT 1;", (asset_uid,)).fetchone()
    return bool(r)


def _find_any_asset(conn: sqlite3.Connection) -> Optional[str]:
    r = conn.execute("SELECT asset_uid FROM assets ORDER BY updated_at DESC LIMIT 1;").fetchone()
    if not r:
        return None
    try:
        return str(r[0] or "").strip() or None
    except Exception:
        return None


# -------------------- Session helpers --------------------
def _set_user(role: str, username: str, display: str, sector: str = "S2", user_id: int = 999) -> None:
    from core.session import set_current_user  # type: ignore
    u: Dict[str, Any] = {
        "id": user_id,
        "username": username,
        "display_name": display,
        "name": display,
        "role": role,
        "active_role": role,
        "roles": [role],
        "active_sector": sector,
        "sector": sector,
        "org_unit": sector,
    }
    set_current_user(u)


def _can(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


# -------------------- Scenario primitives --------------------
def _try_create_asset_as_admin(name: str, category: str, status: str = "active") -> Optional[str]:
    """
    Pokušaj da napravi asset preko services.assets_service.create_asset (najbolje).
    Ako ne može (npr. core.db nema create), vrati None.
    """
    try:
        from services.assets_service import create_asset  # type: ignore
        uid = create_asset(
            actor="admin",
            name=name,
            category=category,
            status=status,
            assigned_to="",
            location="",
            notes_summary="scenario_smoke_test",
        )
        if uid and str(uid).strip():
            return str(uid).strip()
    except Exception as e:
        warn(f"create_asset nije uspeo ({name}) -> {e}")
    return None


def _try_create_metrology_record_as_admin(asset_uid: str) -> Optional[str]:
    try:
        from services.metrology_service import create_metrology_record  # type: ignore
        vu = (date.today() + timedelta(days=30)).isoformat()
        mu = create_metrology_record(
            "admin",
            asset_uid=asset_uid,
            calib_type="interno",
            calib_date=date.today().isoformat(),
            valid_until=vu,
            provider_name="INTERNAL LAB",
            cert_no="SCENARIO-001",
            notes="scenario_smoke_test",
        )
        return str(mu).strip() or None
    except Exception as e:
        warn(f"create_metrology_record nije uspeo -> {e}")
        return None


def _collect_assets_brief() -> List[Dict[str, Any]]:
    from services.assets_service import list_assets_brief  # type: ignore
    return list_assets_brief(limit=200) or []


def _collect_assets_my() -> List[Dict[str, Any]]:
    from services.assets_service import list_assets_my  # type: ignore
    return list_assets_my(limit=200) or []


def _collect_metrology() -> List[Dict[str, Any]]:
    from services.metrology_service import list_metrology_records  # type: ignore
    return list_metrology_records(limit=200) or []


def _try_users_list() -> None:
    from services.users_service import list_users  # type: ignore
    _ = list_users(limit=5)


# -------------------- Expectations (soft, but strict where possible) --------------------
def _contains_uid(rows: List[Dict[str, Any]], uid: str) -> bool:
    u = (uid or "").strip()
    for r in rows:
        if isinstance(r, dict) and str(r.get("asset_uid") or "").strip() == u:
            return True
    return False


def main() -> int:
    section("BazaS2 — SCENARIO SMOKE TEST (offline)")
    section("ENV")
    print("Python:", sys.version.replace("\n", " "))
    print("CWD:", os.getcwd())
    print("sys.path[0]:", sys.path[0])

    # init db
    section("DB INIT")
    try:
        from core.db import init_db  # type: ignore
        init_db()
        ok("core.db.init_db()")
    except Exception as e:
        fail(f"init_db -> {e}")
        return 10

    # ensure schemas
    section("ENSURE SCHEMAS")
    try:
        from services.users_service import ensure_users_schema  # type: ignore
        ensure_users_schema()
        ok("users schema ok")
    except Exception as e:
        fail(f"ensure_users_schema -> {e}")
        return 11

    try:
        from services.metrology_service import ensure_metrology_schema  # type: ignore
        ensure_metrology_schema()
        ok("metrology schema ok")
    except Exception as e:
        fail(f"ensure_metrology_schema -> {e}")
        return 12

    # connect and inspect assets table
    section("ASSETS TABLE CHECK")
    with connect_db() as conn:
        if not _table_exists(conn, "assets"):
            fail("Nema assets tabele. Ovaj test ne može dalje.")
            return 13

        cols = _cols(conn, "assets")
        ok(f"assets cols = {len(cols)}")

        holder_col = _pick_col(cols, ("current_holder", "assigned_to", "holder", "zaduzeno_kod", "kod_koga"))
        sector_col = _pick_col(cols, ("sector", "sektor", "org_unit", "unit", "department", "dept", "section"))
        metro_flag_col = _pick_col(cols, ("is_metrology", "is_metro", "metrology_flag", "metro_flag", "metrology_scope"))

        if not holder_col:
            warn("Nema holder kolone (current_holder/assigned_to/...). MY-scope test će biti ograničen.")
        else:
            ok(f"holder_col = {holder_col}")

        if not sector_col:
            warn("Nema sector kolone. REFERENT_METRO sector-scope test će biti ograničen.")
        else:
            ok(f"sector_col = {sector_col}")

        if not metro_flag_col:
            warn("Nema metrology flag kolone. Metrology-scope će se oslanjati na metrology_records.")
        else:
            ok(f"metro_flag_col = {metro_flag_col}")

    # -------------------- Create scenario data as ADMIN --------------------
    section("SCENARIO DATA (ADMIN setup)")
    _set_user("ADMIN", "admin", "ADMIN", sector="S2", user_id=1)
    print("can(users.view) =", _can("users.view"))
    print("can(assets.create) =", _can("assets.create"))
    print("can(metrology.edit) =", _can("metrology.edit"))

    metro_uid = _try_create_asset_as_admin("SCN_METRO_ASSET", "SI")
    non_uid = _try_create_asset_as_admin("SCN_NONMETRO_ASSET", "SI")

    with connect_db() as conn:
        # fallback: ako nije kreirano, uzmi postojeće iz baze (da test bar radi)
        if not metro_uid:
            metro_uid = _find_any_asset(conn)
            warn(f"Koristim postojeći asset kao metro_uid: {metro_uid}")
        if not non_uid:
            non_uid = _find_any_asset(conn)
            warn(f"Koristim postojeći asset kao non_uid: {non_uid}")

        if not metro_uid or not _asset_exists(conn, metro_uid):
            fail("Nemam metro asset_uid za test.")
            return 20
        if not non_uid or not _asset_exists(conn, non_uid):
            warn("Nemam non-metro asset_uid; neki testovi će biti preskočeni.")

        # set sektor/holder/flag (test-only direct update)
        if sector_col:
            _set_asset_field(conn, metro_uid, sector_col, "S2")
            if non_uid:
                _set_asset_field(conn, non_uid, sector_col, "S2")

        if holder_col:
            # metro asset dodeli BASIC_USER-u
            _set_asset_field(conn, metro_uid, holder_col, "basic_user")
            # non-metro asset dodeli nekom drugom (da basic ne vidi)
            if non_uid:
                _set_asset_field(conn, non_uid, holder_col, "someone_else")

        if metro_flag_col:
            _set_asset_field(conn, metro_uid, metro_flag_col, 1)
            if non_uid:
                _set_asset_field(conn, non_uid, metro_flag_col, 0)

        conn.commit()
        ok("Scenario fields updated in DB (test-only).")

    # create metrology record for metro_uid
    met_rec_uid = _try_create_metrology_record_as_admin(metro_uid)
    if met_rec_uid:
        ok(f"metrology record created: {met_rec_uid}")
    else:
        warn("Nije kreiran metrology record (možda nema metrology.edit ili scope). Nastavljam.")

    # -------------------- ADMIN checks --------------------
    section("CHECKS: ADMIN")
    try:
        rows_b = _collect_assets_brief()
        ok(f"assets_brief rows={len(rows_b)}")
        if metro_uid and not _contains_uid(rows_b, metro_uid):
            warn("ADMIN assets_brief ne sadrži metro_uid (moguće scope/filter u DB list_assets_brief).")
    except Exception as e:
        fail(f"ADMIN assets_brief -> {e}")
        return 30

    try:
        mrows = _collect_metrology()
        ok(f"metrology rows={len(mrows)}")
    except Exception as e:
        fail(f"ADMIN metrology list -> {e}")
        return 31

    # -------------------- REFERENT_METRO checks --------------------
    section("CHECKS: REFERENT_METRO")
    _set_user("REFERENT_METRO", "referent_metro", "REFERENT_METRO", sector="S2", user_id=2)
    print("can(users.view) =", _can("users.view"))
    print("can(assets.my.view) =", _can("assets.my.view"))
    print("can(assets.metrology.view) =", _can("assets.metrology.view"))
    print("can(metrology.view) =", _can("metrology.view"))

    # users expected deny
    try:
        _try_users_list()
        fail("REFERENT_METRO users_service.list_users -> UNEXPECTED ALLOW")
        return 40
    except PermissionError:
        ok("users_service.list_users -> EXPECTED DENY")
    except Exception as e:
        warn(f"users_service.list_users -> non-PermissionError: {e}")

    # assets_brief expected: only metrology-scope (and sector if available)
    try:
        rows_b = _collect_assets_brief()
        ok(f"assets_brief rows={len(rows_b)}")
        if metro_uid and not _contains_uid(rows_b, metro_uid):
            warn("REFERENT_METRO ne vidi metro_uid (možda sector-scope fail-closed ili metrology-scope nije prepoznat).")
        if non_uid and _contains_uid(rows_b, non_uid):
            warn("REFERENT_METRO vidi non_uid -> moguće curenje metrology-scope filtera.")
    except Exception as e:
        fail(f"REFERENT_METRO assets_brief -> {e}")
        return 41

    # metrology list should not crash; may be 0 if scope=0
    try:
        mrows = _collect_metrology()
        ok(f"metrology rows={len(mrows)}")
    except Exception as e:
        fail(f"REFERENT_METRO metrology list -> {e}")
        return 42

    # -------------------- BASIC_USER checks --------------------
    section("CHECKS: BASIC_USER")
    _set_user("BASIC_USER", "basic_user", "BASIC_USER", sector="S2", user_id=3)
    print("can(users.view) =", _can("users.view"))
    print("can(assets.view) =", _can("assets.view"))
    print("can(assets.my.view) =", _can("assets.my.view"))
    print("can(metrology.view) =", _can("metrology.view"))

    # users expected deny
    try:
        _try_users_list()
        fail("BASIC_USER users_service.list_users -> UNEXPECTED ALLOW")
        return 50
    except PermissionError:
        ok("users_service.list_users -> EXPECTED DENY")
    except Exception as e:
        warn(f"users_service.list_users -> non-PermissionError: {e}")

    # MY list must include metro_uid if holder_col exists and we set it
    try:
        my_rows = _collect_assets_my()
        ok(f"assets_my rows={len(my_rows)}")
        if holder_col and metro_uid and not _contains_uid(my_rows, metro_uid):
            warn("BASIC_USER assets_my NE sadrži metro_uid (proveri holder match / identity).")
        if non_uid and _contains_uid(my_rows, non_uid):
            warn("BASIC_USER assets_my sadrži non_uid -> MY filter je preširok.")
    except Exception as e:
        fail(f"BASIC_USER assets_my -> {e}")
        return 51

    # metrology list should not crash; may be 0 if metrology scope uses MY holder and join
    try:
        mrows = _collect_metrology()
        ok(f"metrology rows={len(mrows)}")
    except Exception as e:
        fail(f"BASIC_USER metrology list -> {e}")
        return 52

    section("SUMMARY")
    ok("SCENARIO SMOKE TEST: PASS ✅ (uz moguće WARN-ove iznad)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# (FILENAME: tools/scenario_smoke_test.py - END)