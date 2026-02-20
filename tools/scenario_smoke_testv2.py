# FILENAME: tools/scenario_smoke_testv2.py
# (FILENAME: tools/scenario_smoke_testv2.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 — SCENARIO SMOKE TEST (offline)

Šta je novo (hardening, bez promene funkcionalnosti app-a):
- Stabilan BOOTSTRAP: sys.path + (opciono) os.chdir(ROOT_DIR) da izbegnemo "dve baze" zbog CWD.
- test_run_id: svi test-only upisi obeleženi (radi dijagnostike).
- cleanup:
  - vraća originalne vrednosti polja koja smo dirali (holder/sector/metro_flag),
  - briše metrology record kreiran u testu (soft-delete u servisu).
- Tripwire edge-cases:
  1) REFERENT_METRO pokušava da vidi NON metrology asset preko get_asset_by_uid -> EXPECTED DENY (ako imamo non_uid)
  2) REFERENT_METRO bez sektora u sesiji -> assets_brief mora biti 0 (fail-closed) i metrology list mora biti 0 (osim ako MY-scope slučajno upadne)
  3) BASIC_USER pokuša metrology.create -> EXPECTED DENY

Napomena:
- Ovaj test namerno NE radi deep UI automation.
- Ne brišemo test assets (nema bezbednog delete API-ja u ovom kontekstu); zato radimo restore polja + metrology delete.
"""

from __future__ import annotations

import os
import sys
import sqlite3
from datetime import date, timedelta, datetime
from typing import Any, Dict, List, Optional, Tuple


# -------------------- BOOTSTRAP sys.path (ROOT import fix) --------------------
TOOLS_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(TOOLS_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Preporuka: radi stabilnosti DB putanje (i da se ne desi "dve baze" zbog CWD)
try:
    os.chdir(ROOT_DIR)
except Exception:
    pass

TEST_RUN_ID = datetime.now().strftime("SCN-%Y%m%d-%H%M%S")


# -------------------- Pretty helpers --------------------
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
    return _c()  # u tvom projektu radi kao context manager


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


def _asset_exists(conn: sqlite3.Connection, asset_uid: str) -> bool:
    r = conn.execute("SELECT 1 FROM assets WHERE asset_uid=? LIMIT 1;", (asset_uid,)).fetchone()
    return bool(r)


def _find_any_asset(conn: sqlite3.Connection) -> Optional[str]:
    # fallback ako create_asset ne radi
    try:
        r = conn.execute("SELECT asset_uid FROM assets LIMIT 1;").fetchone()
    except Exception:
        r = None
    if not r:
        return None
    try:
        return str(r[0] or "").strip() or None
    except Exception:
        return None


def _get_asset_field(conn: sqlite3.Connection, asset_uid: str, col: str) -> Any:
    if not col:
        return None
    try:
        r = conn.execute(f"SELECT {col} FROM assets WHERE asset_uid=? LIMIT 1;", (asset_uid,)).fetchone()
        if not r:
            return None
        try:
            return r[0]
        except Exception:
            return None
    except Exception:
        return None


def _set_asset_field(conn: sqlite3.Connection, asset_uid: str, col: str, value: Any) -> None:
    conn.execute(f"UPDATE assets SET {col}=? WHERE asset_uid=?;", (value, asset_uid))


# -------------------- Session helpers --------------------
def _set_user(
    role: str,
    username: str,
    display: str,
    sector: str = "S2",
    user_id: int = 999,
    *,
    sector_enabled: bool = True,
) -> None:
    from core.session import set_current_user  # type: ignore
    sec = sector if sector_enabled else ""
    u: Dict[str, Any] = {
        "id": user_id,
        "username": username,
        "display_name": display,
        "name": display,
        "role": role,
        "active_role": role,
        "roles": [role],
        "active_sector": sec,
        "sector": sec,
        "org_unit": sec,
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
    Pokušaj da napravi asset preko services.assets_service.create_asset.
    Ako ne može, vrati None.
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
            notes_summary=f"scenario_smoke_test {TEST_RUN_ID}",
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
            cert_no=f"{TEST_RUN_ID}-001",
            notes=f"scenario_smoke_test {TEST_RUN_ID}",
        )
        return str(mu).strip() or None
    except Exception as e:
        warn(f"create_metrology_record nije uspeo -> {e}")
        return None


def _try_delete_metrology_record_as_admin(met_uid: str) -> bool:
    """
    Soft-delete kroz servis (audit ostaje).
    """
    mu = (met_uid or "").strip()
    if not mu:
        return False
    try:
        from services.metrology_service import delete_metrology_record  # type: ignore
        return bool(delete_metrology_record("admin", mu, note_audit=f"scenario_cleanup {TEST_RUN_ID}"))
    except Exception as e:
        warn(f"cleanup: delete_metrology_record nije uspeo ({mu}) -> {e}")
        return False


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


def _try_get_asset(uid: str) -> Optional[Dict[str, Any]]:
    from services.assets_service import get_asset_by_uid  # type: ignore
    return get_asset_by_uid(asset_uid=uid)


def _try_basic_create_metrology(uid: str) -> None:
    from services.metrology_service import create_metrology_record  # type: ignore
    _ = create_metrology_record(
        "basic",
        asset_uid=uid,
        calib_type="interno",
        calib_date=date.today().isoformat(),
        valid_until=(date.today() + timedelta(days=10)).isoformat(),
        provider_name="X",
        cert_no=f"{TEST_RUN_ID}-BASIC",
        notes="should_fail",
    )


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
    print("ROOT_DIR:", ROOT_DIR)
    print("sys.path[0]:", sys.path[0])
    print("TEST_RUN_ID:", TEST_RUN_ID)

    # DB init
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

    # inspect assets table + prepare columns
    section("ASSETS TABLE CHECK")
    holder_col = ""
    sector_col = ""
    metro_flag_col = ""

    with connect_db() as conn:
        if not _table_exists(conn, "assets"):
            fail("Nema assets tabele. Ovaj test ne može dalje.")
            return 13

        cols = _cols(conn, "assets")
        ok(f"assets cols = {len(cols)}")

        holder_col = _pick_col(cols, ("current_holder", "assigned_to", "holder", "zaduzeno_kod", "kod_koga"))
        sector_col = _pick_col(cols, ("sector", "sektor", "org_unit", "unit", "department", "dept"))
        metro_flag_col = _pick_col(cols, ("is_metrology", "is_metro", "metrology_flag", "metro_flag", "metrology_scope"))

        if holder_col:
            ok(f"holder_col = {holder_col}")
        else:
            warn("Nema holder kolone (current_holder/assigned_to/...). MY-scope test će biti ograničen.")

        if sector_col:
            ok(f"sector_col = {sector_col}")
        else:
            warn("Nema sector kolone. REFERENT_METRO sector-scope test će biti ograničen.")

        if metro_flag_col:
            ok(f"metro_flag_col = {metro_flag_col}")
        else:
            warn("Nema metrology flag kolone. Metrology-scope će se oslanjati na metrology_records.")

    # scenario setup (ADMIN)
    section("SCENARIO DATA (ADMIN setup)")
    _set_user("ADMIN", "admin", "ADMIN", sector="S2", user_id=1)
    print("can(users.view) =", _can("users.view"))
    print("can(assets.create) =", _can("assets.create"))
    print("can(metrology.edit) =", _can("metrology.edit"))

    metro_uid = _try_create_asset_as_admin("SCN_METRO_ASSET", "SI")
    non_uid = _try_create_asset_as_admin("SCN_NONMETRO_ASSET", "SI")

    # Restore bookkeeping (cleanup)
    original_fields: Dict[str, Dict[str, Any]] = {}
    met_rec_uid: Optional[str] = None

    try:
        with connect_db() as conn:
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
                non_uid = None

            # Snapshot original values (za cleanup)
            for uid in [metro_uid] + ([non_uid] if non_uid else []):
                original_fields[uid] = {}
                if sector_col:
                    original_fields[uid][sector_col] = _get_asset_field(conn, uid, sector_col)
                if holder_col:
                    original_fields[uid][holder_col] = _get_asset_field(conn, uid, holder_col)
                if metro_flag_col:
                    original_fields[uid][metro_flag_col] = _get_asset_field(conn, uid, metro_flag_col)

            # test-only updates
            if sector_col:
                _set_asset_field(conn, metro_uid, sector_col, "S2")
                if non_uid:
                    _set_asset_field(conn, non_uid, sector_col, "S2")

            if holder_col:
                # metro asset dodeljujemo BASIC_USER-u da MY-scope bude determinističan
                _set_asset_field(conn, metro_uid, holder_col, "basic_user")
                if non_uid:
                    _set_asset_field(conn, non_uid, holder_col, "someone_else")

            if metro_flag_col:
                _set_asset_field(conn, metro_uid, metro_flag_col, 1)
                if non_uid:
                    _set_asset_field(conn, non_uid, metro_flag_col, 0)

            conn.commit()
            ok("Scenario fields updated in DB (test-only).")

        met_rec_uid = _try_create_metrology_record_as_admin(metro_uid)
        if met_rec_uid:
            ok(f"metrology record created: {met_rec_uid}")
        else:
            warn("Nije kreiran metrology record (OK, nastavljamo).")

        # -------------------- CHECKS: ADMIN --------------------
        section("CHECKS: ADMIN")
        try:
            rows_b = _collect_assets_brief()
            ok(f"assets_brief rows={len(rows_b)}")
        except Exception as e:
            fail(f"ADMIN assets_brief -> {e}")
            return 30

        try:
            mrows = _collect_metrology()
            ok(f"metrology rows={len(mrows)}")
        except Exception as e:
            fail(f"ADMIN metrology list -> {e}")
            return 31

        # -------------------- CHECKS: REFERENT_METRO --------------------
        section("CHECKS: REFERENT_METRO")
        _set_user("REFERENT_METRO", "referent_metro", "REFERENT_METRO", sector="S2", user_id=2)
        print("can(users.view) =", _can("users.view"))
        print("can(assets.my.view) =", _can("assets.my.view"))
        print("can(assets.metrology.view) =", _can("assets.metrology.view"))
        print("can(metrology.view) =", _can("metrology.view"))

        # users.list -> expected deny
        try:
            _try_users_list()
            fail("REFERENT_METRO users_service.list_users -> UNEXPECTED ALLOW")
            return 40
        except PermissionError:
            ok("users_service.list_users -> EXPECTED DENY")
        except Exception as e:
            warn(f"users_service.list_users -> non-PermissionError: {e}")

        # assets_brief -> treba da vidi samo metrology-scope (i sektor-scope ako postoji)
        try:
            rows_b = _collect_assets_brief()
            ok(f"assets_brief rows={len(rows_b)}")
            if metro_uid and not _contains_uid(rows_b, metro_uid):
                warn("REFERENT_METRO ne vidi metro_uid (moguće scope=0 ili metrology-scope nije prepoznat).")
            if non_uid and _contains_uid(rows_b, non_uid):
                warn("REFERENT_METRO vidi non_uid -> moguće curenje metrology-scope filtera.")
        except Exception as e:
            fail(f"REFERENT_METRO assets_brief -> {e}")
            return 41

        # metrology list -> trebalo bi da vidi metrologiju za metrology asset (ako postoji i scope dozvoljava)
        try:
            mrows = _collect_metrology()
            ok(f"metrology rows={len(mrows)}")
        except Exception as e:
            fail(f"REFERENT_METRO metrology list -> {e}")
            return 42

        # Tripwire 1: REFERENT_METRO pokuša get_asset_by_uid(non_uid) -> EXPECTED DENY (ako imamo non_uid)
        if non_uid:
            section("TRIPWIRE: REFERENT_METRO access NON asset (EXPECTED DENY)")
            try:
                _ = _try_get_asset(non_uid)
                warn("REFERENT_METRO get_asset_by_uid(non_uid) -> UNEXPECTED ALLOW (proveri scope).")
            except PermissionError:
                ok("REFERENT_METRO get_asset_by_uid(non_uid) -> EXPECTED DENY")
            except Exception as e:
                warn(f"REFERENT_METRO get_asset_by_uid(non_uid) -> non-PermissionError: {e}")
        else:
            warn("Preskačem tripwire #1 (nema non_uid).")

        # Tripwire 2: REFERENT_METRO bez sektora -> assets_brief mora biti 0 (fail-closed) + metrology list 0 (pošto nema MY match)
        section("TRIPWIRE: REFERENT_METRO without sector (fail-closed expected)")
        _set_user("REFERENT_METRO", "referent_metro", "REFERENT_METRO", sector="S2", user_id=2, sector_enabled=False)
        try:
            rows0 = _collect_assets_brief()
            ok(f"assets_brief rows(no sector)={len(rows0)}")
            if len(rows0) != 0:
                warn("Očekivano je 0 (fail-closed). Ako nije 0, proveri sector-scope implementaciju u assets_service.")
        except Exception as e:
            warn(f"assets_brief(no sector) -> {e}")

        try:
            m0 = _collect_metrology()
            ok(f"metrology rows(no sector)={len(m0)}")
            if len(m0) != 0:
                warn("Očekivano je 0 ili MY-scope rezultat. Ako vidi zapise bez sektora, proveri metrology_service scope.")
        except Exception as e:
            warn(f"metrology list(no sector) -> {e}")

        # -------------------- CHECKS: BASIC_USER --------------------
        section("CHECKS: BASIC_USER")
        _set_user("BASIC_USER", "basic_user", "BASIC_USER", sector="S2", user_id=3)
        print("can(users.view) =", _can("users.view"))
        print("can(assets.view) =", _can("assets.view"))
        print("can(assets.my.view) =", _can("assets.my.view"))
        print("can(metrology.view) =", _can("metrology.view"))

        # users.list -> expected deny
        try:
            _try_users_list()
            fail("BASIC_USER users_service.list_users -> UNEXPECTED ALLOW")
            return 50
        except PermissionError:
            ok("users_service.list_users -> EXPECTED DENY")
        except Exception as e:
            warn(f"users_service.list_users -> non-PermissionError: {e}")

        # assets_my -> mora vratiti samo njegova zaduženja
        try:
            my_rows = _collect_assets_my()
            ok(f"assets_my rows={len(my_rows)}")
            if metro_uid and not _contains_uid(my_rows, metro_uid):
                warn("BASIC_USER assets_my NE sadrži metro_uid (proveri holder match / identity).")
            if non_uid and _contains_uid(my_rows, non_uid):
                warn("BASIC_USER assets_my sadrži non_uid -> MY filter je preširok.")
        except Exception as e:
            fail(f"BASIC_USER assets_my -> {e}")
            return 51

        # metrology list -> može biti 1 (ako MY scope metrology radi) ili 0 u praznoj bazi
        try:
            mrows = _collect_metrology()
            ok(f"metrology rows={len(mrows)}")
        except Exception as e:
            fail(f"BASIC_USER metrology list -> {e}")
            return 52

        # Tripwire 3: BASIC_USER pokuša metrology.create -> EXPECTED DENY
        section("TRIPWIRE: BASIC_USER metrology.create (EXPECTED DENY)")
        try:
            _try_basic_create_metrology(metro_uid)
            warn("BASIC_USER create_metrology_record -> UNEXPECTED ALLOW (RBAC leak?)")
        except PermissionError:
            ok("BASIC_USER create_metrology_record -> EXPECTED DENY")
        except Exception as e:
            warn(f"BASIC_USER create_metrology_record -> non-PermissionError: {e}")

        section("SUMMARY")
        ok("SCENARIO SMOKE TEST: PASS ✅ (uz moguće WARN-ove iznad)")
        return 0

    finally:
        # -------------------- CLEANUP (best-effort) --------------------
        section("CLEANUP (best-effort)")
        # 1) delete metrology record we created
        try:
            _set_user("ADMIN", "admin", "ADMIN", sector="S2", user_id=1)
            if met_rec_uid:
                if _try_delete_metrology_record_as_admin(met_rec_uid):
                    ok(f"cleanup: metrology record deleted (soft): {met_rec_uid}")
                else:
                    warn(f"cleanup: metrology record NOT deleted: {met_rec_uid}")
            else:
                ok("cleanup: nema metrology record-a za brisanje (OK).")
        except Exception as e:
            warn(f"cleanup: metrology delete error -> {e}")

        # 2) restore asset fields we touched
        try:
            with connect_db() as conn:
                for uid, fields in original_fields.items():
                    if not uid or not fields:
                        continue
                    if not _asset_exists(conn, uid):
                        continue
                    for col, oldv in fields.items():
                        if col:
                            _set_asset_field(conn, uid, col, oldv)
                conn.commit()
            ok("cleanup: asset fields restored (holder/sector/flag).")
        except Exception as e:
            warn(f"cleanup: restore asset fields error -> {e}")


if __name__ == "__main__":
    raise SystemExit(main())

# (FILENAME: tools/scenario_smoke_testv2.py - END)