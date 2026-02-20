# FILENAME: tools/scenario_smoke_testv3.py
# (FILENAME: tools/scenario_smoke_testv3.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 — SCENARIO SMOKE TEST v3 (offline)

FIX v3.1:
- Test više NE očekuje da BASIC_USER metrology_my vrati isključivo scenario asset_uid.
  U realnoj bazi korisnik može već imati više "mojih" sredstava sa metrology zapisima.
- Umesto toga:
  (1) metrology_my MORA da sadrži scenario MY met_uid
  (2) metrology_my NE SME da sadrži scenario OTHER met_uid
  (3) (bonus) svaki red u metrology_my mora imati asset čiji holder matchuje BASIC_USER (ako postoji holder kolona)

Ostalo:
- DB init + ensure schemas
- Kreira 2 test sredstva (1 "MY_METRO", 1 "OTHER_METRO") kao ADMIN (ako može)
- Direktno u DB (test-only) setuje holder/sector/metrology flag (ako kolone postoje)
- Ubaci po 1 metrology zapis za oba sredstva (ako može)
- Proveri očekivanja za ADMIN / REFERENT_METRO / BASIC_USER
- Cleanup (best-effort): soft-delete metrology zapisa + restore polja na assetima
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

TEST_RUN_ID = "SCN-" + datetime.now().strftime("%Y%m%d-%H%M%S")

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
    from core.db import connect_db as _c  # type: ignore
    return _c()


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


def _set_asset_field(conn: sqlite3.Connection, asset_uid: str, col: str, value: Any) -> None:
    conn.execute(f"UPDATE assets SET {col}=? WHERE asset_uid=?;", (value, asset_uid))


def _get_asset_field(conn: sqlite3.Connection, asset_uid: str, col: str) -> Any:
    try:
        r = conn.execute(f"SELECT {col} FROM assets WHERE asset_uid=? LIMIT 1;", (asset_uid,)).fetchone()
        if not r:
            return None
        return r[0]
    except Exception:
        return None


def _soft_delete_metrology(conn: sqlite3.Connection, met_uid: str) -> None:
    try:
        conn.execute("UPDATE metrology_records SET is_deleted=1 WHERE met_uid=?;", (met_uid,))
    except Exception:
        pass


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


def _identity_candidates_basic_user() -> List[str]:
    """
    Minimalni MY identiteti za BASIC_USER u ovom testu.
    (Ne oslanjamo se na internu metrology_service implementaciju.)
    """
    # matchujemo ono što test postavlja u session:
    # username=basic_user, display/name=BASIC_USER, id=3
    raw = ["basic_user", "BASIC_USER", "3", "user#3"]
    out: List[str] = []
    seen = set()
    for x in raw:
        s = str(x).strip().casefold()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _holder_matches_basic_user(holder: Any) -> bool:
    h = ("" if holder is None else str(holder)).strip().casefold()
    if not h:
        return False
    cands = _identity_candidates_basic_user()
    for c in cands:
        if h == c:
            return True
    # tolerantno: ako je holder tekst tipa "Basic User (3)" i sl.
    for c in cands:
        if c and c in h:
            return True
    return False


# -------------------- Scenario primitives --------------------
def _try_create_asset_as_admin(name: str, category: str, status: str = "active") -> Optional[str]:
    try:
        from services.assets_service import create_asset  # type: ignore
        uid = create_asset(
            actor="admin",
            name=name,
            category=category,
            status=status,
            assigned_to="",
            location="",
            notes_summary=f"scenario_smoke_testv3 {TEST_RUN_ID}",
        )
        if uid and str(uid).strip():
            return str(uid).strip()
    except Exception as e:
        warn(f"create_asset nije uspeo ({name}) -> {e}")
    return None


def _try_create_metrology_record_as_admin(asset_uid: str, cert_no: str) -> Optional[str]:
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
            cert_no=cert_no,
            notes=f"scenario_smoke_testv3 {TEST_RUN_ID}",
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


def _collect_metrology_my() -> List[Dict[str, Any]]:
    from services.metrology_service import list_metrology_records_my  # type: ignore
    return list_metrology_records_my(limit=200) or []


def _try_users_list() -> None:
    from services.users_service import list_users  # type: ignore
    _ = list_users(limit=5)


def _contains_uid(rows: List[Dict[str, Any]], uid: str) -> bool:
    u = (uid or "").strip()
    for r in rows:
        if isinstance(r, dict) and str(r.get("asset_uid") or "").strip() == u:
            return True
    return False


def _contains_met_uid(rows: List[Dict[str, Any]], met_uid: str) -> bool:
    mu = (met_uid or "").strip()
    for r in rows:
        if isinstance(r, dict) and str(r.get("met_uid") or "").strip() == mu:
            return True
    return False


def main() -> int:
    section("BazaS2 — SCENARIO SMOKE TEST v3 (offline)")
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

    # inspect assets table
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

    # scenario setup
    section("SCENARIO DATA (ADMIN setup)")
    _set_user("ADMIN", "admin", "ADMIN", sector="S2", user_id=1)
    print("can(users.view) =", _can("users.view"))
    print("can(assets.create) =", _can("assets.create"))
    print("can(metrology.edit) =", _can("metrology.edit"))

    my_uid = _try_create_asset_as_admin(f"SCN3_MY_METRO_ASSET_{TEST_RUN_ID}", "SI")
    other_uid = _try_create_asset_as_admin(f"SCN3_OTHER_METRO_ASSET_{TEST_RUN_ID}", "SI")

    # backup original fields (restore u cleanup)
    backups: Dict[str, Dict[str, Any]] = {}

    my_met_uid: Optional[str] = None
    other_met_uid: Optional[str] = None

    with connect_db() as conn:
        # fallback ako create_asset ne radi
        if not my_uid:
            my_uid = _find_any_asset(conn)
            warn(f"Koristim postojeći asset kao my_uid: {my_uid}")
        if not other_uid:
            other_uid = _find_any_asset(conn)
            warn(f"Koristim postojeći asset kao other_uid: {other_uid}")

        if not my_uid or not _asset_exists(conn, my_uid):
            fail("Nemam my_uid za test.")
            return 20
        if not other_uid or not _asset_exists(conn, other_uid):
            fail("Nemam other_uid za test.")
            return 21

        # backup pre izmena
        for uid in (my_uid, other_uid):
            backups[uid] = {}
            if holder_col:
                backups[uid][holder_col] = _get_asset_field(conn, uid, holder_col)
            if sector_col:
                backups[uid][sector_col] = _get_asset_field(conn, uid, sector_col)
            if metro_flag_col:
                backups[uid][metro_flag_col] = _get_asset_field(conn, uid, metro_flag_col)

        # test-only updates
        if sector_col:
            _set_asset_field(conn, my_uid, sector_col, "S2")
            _set_asset_field(conn, other_uid, sector_col, "S2")

        # holder: BASIC_USER vidi "my_uid", NE sme "other_uid"
        if holder_col:
            _set_asset_field(conn, my_uid, holder_col, "basic_user")
            _set_asset_field(conn, other_uid, holder_col, "someone_else")
        else:
            warn("Nema holder kolone => MY test neće biti pouzdan (preskočićemo strict holder proveru).")

        # flag oba kao metrology (ako kolona postoji)
        if metro_flag_col:
            _set_asset_field(conn, my_uid, metro_flag_col, 1)
            _set_asset_field(conn, other_uid, metro_flag_col, 1)

        conn.commit()
        ok("Scenario fields updated in DB (test-only).")

    # kreiraj metrology record za oba
    my_met_uid = _try_create_metrology_record_as_admin(my_uid, cert_no=f"SCN3-MY-{TEST_RUN_ID}")
    other_met_uid = _try_create_metrology_record_as_admin(other_uid, cert_no=f"SCN3-OTHER-{TEST_RUN_ID}")
    if my_met_uid:
        ok(f"metrology record created (MY): {my_met_uid}")
    else:
        warn("Nije kreiran MY metrology record (test će biti ograničen).")
    if other_met_uid:
        ok(f"metrology record created (OTHER): {other_met_uid}")
    else:
        warn("Nije kreiran OTHER metrology record (test će biti ograničen).")

    # ADMIN checks
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

    # REFERENT_METRO checks
    section("CHECKS: REFERENT_METRO")
    _set_user("REFERENT_METRO", "referent_metro", "REFERENT_METRO", sector="S2", user_id=2)
    print("can(users.view) =", _can("users.view"))
    print("can(assets.my.view) =", _can("assets.my.view"))
    print("can(assets.metrology.view) =", _can("assets.metrology.view"))
    print("can(metrology.view) =", _can("metrology.view"))
    try:
        _try_users_list()
        fail("REFERENT_METRO users_service.list_users -> UNEXPECTED ALLOW")
        return 40
    except PermissionError:
        ok("users_service.list_users -> EXPECTED DENY")
    except Exception as e:
        warn(f"users_service.list_users -> non-PermissionError: {e}")

    try:
        rows_b = _collect_assets_brief()
        ok(f"assets_brief rows={len(rows_b)}")
    except Exception as e:
        fail(f"REFERENT_METRO assets_brief -> {e}")
        return 41

    try:
        mrows = _collect_metrology()
        ok(f"metrology rows={len(mrows)}")
    except Exception as e:
        fail(f"REFERENT_METRO metrology list -> {e}")
        return 42

    # BASIC_USER checks (+ MY metrology tripwire)
    section("CHECKS: BASIC_USER + MY METROLOGY TRIPWIRE (fixed expectations)")
    _set_user("BASIC_USER", "basic_user", "BASIC_USER", sector="S2", user_id=3)
    print("can(users.view) =", _can("users.view"))
    print("can(assets.view) =", _can("assets.view"))
    print("can(assets.my.view) =", _can("assets.my.view"))
    print("can(metrology.view) =", _can("metrology.view"))

    try:
        _try_users_list()
        fail("BASIC_USER users_service.list_users -> UNEXPECTED ALLOW")
        return 50
    except PermissionError:
        ok("users_service.list_users -> EXPECTED DENY")
    except Exception as e:
        warn(f"users_service.list_users -> non-PermissionError: {e}")

    # assets_my (postojeći)
    try:
        my_rows = _collect_assets_my()
        ok(f"assets_my rows={len(my_rows)}")
        if holder_col:
            if my_uid and not _contains_uid(my_rows, my_uid):
                fail("BASIC_USER assets_my NE sadrži my_uid (MY scope holder match nije prošao).")
                return 51
            if other_uid and _contains_uid(my_rows, other_uid):
                fail("BASIC_USER assets_my sadrži other_uid (MY filter je preširok).")
                return 52
        else:
            warn("Preskačem strict assets_my proveru (nema holder kolone).")
    except Exception as e:
        fail(f"BASIC_USER assets_my -> {e}")
        return 53

    # metrology (postojeći list_metrology_records)
    try:
        mrows = _collect_metrology()
        ok(f"metrology rows={len(mrows)}")
    except Exception as e:
        fail(f"BASIC_USER metrology list -> {e}")
        return 54

    # ✅ NOVO: metrology MY API — ispravna očekivanja
    try:
        mm = _collect_metrology_my()
        ok(f"metrology_my rows={len(mm)}")

        # (1) mora da sadrži MY met_uid (ako je kreiran)
        if my_met_uid and not _contains_met_uid(mm, my_met_uid):
            fail("BASIC_USER metrology_my NE sadrži MY met_uid (list_metrology_records_my fail).")
            return 55

        # (2) ne sme da sadrži OTHER met_uid (ako je kreiran)
        if other_met_uid and _contains_met_uid(mm, other_met_uid):
            fail("BASIC_USER metrology_my sadrži OTHER met_uid (curenje MY metrology scope-a).")
            return 56

        # (3) bonus: svaki rezultat mora biti stvarno MY po holder koloni (ako postoji)
        if holder_col:
            with connect_db() as conn:
                for r in mm:
                    if not isinstance(r, dict):
                        continue
                    au = str(r.get("asset_uid") or "").strip()
                    if not au:
                        continue
                    h = _get_asset_field(conn, au, holder_col)
                    if not _holder_matches_basic_user(h):
                        fail(
                            f"BASIC_USER metrology_my sadrži zapis za asset_uid={au} "
                            f"čiji holder nije MY (holder={h!r})."
                        )
                        return 57
        else:
            warn("Preskačem holder-validaciju metrology_my (nema holder kolone).")

    except PermissionError as e:
        fail(f"BASIC_USER metrology_my -> UNEXPECTED DENY: {e}")
        return 58
    except Exception as e:
        fail(f"BASIC_USER metrology_my -> {e}")
        return 59

    section("SUMMARY")
    ok("SCENARIO SMOKE TEST v3: PASS ✅ (MY metrology radi kako treba)")

    # -------------------- CLEANUP (best-effort) --------------------
    section("CLEANUP (best-effort)")
    try:
        with connect_db() as conn:
            if my_met_uid:
                _soft_delete_metrology(conn, my_met_uid)
                ok(f"cleanup: metrology record deleted (soft): {my_met_uid}")
            if other_met_uid:
                _soft_delete_metrology(conn, other_met_uid)
                ok(f"cleanup: metrology record deleted (soft): {other_met_uid}")

            for uid, b in backups.items():
                for col, oldv in b.items():
                    try:
                        _set_asset_field(conn, uid, col, oldv)
                    except Exception:
                        pass
            conn.commit()
            ok("cleanup: asset fields restored (holder/sector/flag).")
    except Exception as e:
        warn(f"cleanup warning -> {e}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# (FILENAME: tools/scenario_smoke_testv3.py - END)