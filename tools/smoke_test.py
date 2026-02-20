# FILENAME: tools/smoke_test.py
# (FILENAME: tools/smoke_test.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — tools/smoke_test.py

Smoke test (READ-ONLY):
- Proverava da svi moduli vide ISTU SQLite bazu (nema "dve baze" problem).
- Proverava da se schema tabele vide (users/assets/metrology).
- Proverava RBAC/permisije po userima (best-effort, zavisi od core.session/can).
- Testira ključne service pozive bez UI:
  - users_service.list_users / list_user_roles
  - assets_service.list_assets_brief / get_asset_by_uid (ako dozvoljeno)
  - metrology_service.list_metrology_records (ako dozvoljeno)

Ne menja bazu (SELECT only).
"""

from __future__ import annotations

import argparse
import sys
import traceback
from typing import Any, Dict, List, Optional, Tuple


# ------------------------ Console helpers ------------------------
def ok(msg: str) -> None:
    print(f"[ OK ] {msg}")


def warn(msg: str) -> None:
    print(f"[WARN] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")


def info(msg: str) -> None:
    print(f"       {msg}")


def hr() -> None:
    print("-" * 78)


def _safe_import(path: str):
    try:
        mod = __import__(path, fromlist=["*"])
        return mod
    except Exception as e:
        return e


def _db_file_of_conn(conn) -> str:
    """
    SQLite canonical path: PRAGMA database_list -> name='main'
    """
    try:
        rows = conn.execute("PRAGMA database_list;").fetchall()
        # rows: (seq, name, file)
        for r in rows:
            try:
                name = r[1]
                file_ = r[2]
            except Exception:
                continue
            if str(name) == "main":
                return str(file_ or "")
        # fallback: first row
        if rows:
            try:
                return str(rows[0][2] or "")
            except Exception:
                pass
    except Exception:
        pass
    return ""


def _table_exists(conn, name: str) -> bool:
    try:
        r = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
            (name,),
        ).fetchone()
        return bool(r)
    except Exception:
        return False


def _list_tables(conn) -> List[str]:
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name COLLATE NOCASE;"
        ).fetchall()
        return [str(r[0]) for r in rows if r and str(r[0] or "").strip()]
    except Exception:
        return []


# ------------------------ Session helpers ------------------------
def _try_set_current_user(user: Optional[Dict[str, Any]]) -> bool:
    try:
        from core.session import set_current_user  # type: ignore
        set_current_user(user)  # type: ignore[arg-type]
        return True
    except Exception:
        return False


def _try_can(perm: str) -> Optional[bool]:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return None


def _try_actor_name() -> str:
    try:
        from core.session import actor_name  # type: ignore
        return (actor_name() or "").strip() or "user"
    except Exception:
        return "user"


def _normalize_role(s: Any) -> str:
    return str(s or "").strip().upper()


# ------------------------ Pick user by permission ------------------------
def _pick_user_for_any_perm(users: List[Dict[str, Any]], perms: List[str]) -> Optional[Dict[str, Any]]:
    """
    Probaj svakog user-a: set_current_user + can(perm). Vraća prvog koji ima bar 1 perm.
    """
    if not users:
        return None
    if not _try_set_current_user({}):
        return None

    for u in users:
        if not isinstance(u, dict):
            continue
        if not _try_set_current_user(u):
            continue
        for p in perms:
            v = _try_can(p)
            if v is True:
                return u
    return None


def _user_label(u: Dict[str, Any]) -> str:
    un = (u.get("username") or u.get("user") or u.get("login") or "").strip()
    dn = (u.get("display_name") or u.get("name") or u.get("full_name") or "").strip()
    rid = str(u.get("id") or u.get("user_id") or "").strip()
    ar = _normalize_role(u.get("active_role") or u.get("role") or u.get("user_role"))
    sec = (u.get("active_sector") or u.get("sector") or u.get("org_unit") or "").strip()
    who = dn or un or f"User#{rid or '?'}"
    extra = []
    if un and un.lower() not in who.lower():
        extra.append(un)
    if rid:
        extra.append(f"id={rid}")
    if ar:
        extra.append(f"role={ar}")
    if sec:
        extra.append(f"sector={sec}")
    return f"{who} ({', '.join(extra)})" if extra else who


# ------------------------ Main checks ------------------------
def check_db_path_consistency(verbose: bool = False) -> Tuple[bool, str]:
    """
    Proveri da core.db.connect_db i services.assets_service._sqlite_connect vide isti fajl.
    """
    try:
        from core.db import connect_db  # type: ignore
    except Exception as e:
        return False, f"Ne mogu import core.db.connect_db: {e}"

    try:
        import services.assets_service as assets_service  # type: ignore
    except Exception as e:
        return False, f"Ne mogu import services.assets_service: {e}"

    c1 = None
    c2 = None
    try:
        # core.db.connect_db može biti contextmanager ili connection
        obj = connect_db()
        if hasattr(obj, "__enter__") and hasattr(obj, "__exit__"):
            with obj as conn:
                c1_path = _db_file_of_conn(conn)
        else:
            conn = obj
            c1_path = _db_file_of_conn(conn)
            try:
                conn.close()
            except Exception:
                pass

        c2 = assets_service._sqlite_connect()
        c2_path = _db_file_of_conn(c2)

        if verbose:
            info(f"core.db.connect_db -> {c1_path}")
            info(f"assets_service._sqlite_connect -> {c2_path}")

        if (c1_path or "").strip() and (c2_path or "").strip() and (c1_path.strip() == c2_path.strip()):
            return True, f"Ista DB putanja: {c1_path}"
        return False, f"Različita DB putanja! core={c1_path} vs assets_service={c2_path}"
    except Exception as e:
        return False, f"Exception u DB consistency check: {e}"
    finally:
        try:
            if c2 is not None:
                c2.close()
        except Exception:
            pass


def check_tables(verbose: bool = False) -> Tuple[bool, List[str]]:
    try:
        from core.db import connect_db  # type: ignore
    except Exception:
        return False, ["Ne mogu import core.db.connect_db"]

    required = ["users", "assets", "metrology_records", "metrology_audit"]
    msgs: List[str] = []

    obj = connect_db()
    try:
        if hasattr(obj, "__enter__") and hasattr(obj, "__exit__"):
            with obj as conn:
                tables = _list_tables(conn)
        else:
            conn = obj
            tables = _list_tables(conn)
            try:
                conn.close()
            except Exception:
                pass
    except Exception as e:
        return False, [f"Ne mogu otvoriti DB: {e}"]

    if verbose:
        info(f"Tabele: {', '.join(tables[:30])}{' ...' if len(tables) > 30 else ''}")

    ok_all = True
    for t in required:
        if t in tables:
            msgs.append(f"OK table: {t}")
        else:
            ok_all = False
            msgs.append(f"MISSING table: {t}")

    return ok_all, msgs


def check_users_service(verbose: bool = False) -> Tuple[bool, List[Dict[str, Any]]]:
    try:
        from services.users_service import list_users, list_user_roles  # type: ignore
    except Exception as e:
        fail(f"Import users_service nije uspeo: {e}")
        return False, []

    users: List[Dict[str, Any]] = []
    try:
        try:
            users = list_users(active_only=True, limit=500)
        except TypeError:
            users = list_users()
    except Exception as e:
        fail(f"users_service.list_users pukao: {e}")
        return False, []

    if not users:
        warn("Nema user-a u bazi (users_service vratio prazno).")
        return True, []

    ok(f"Učitani korisnici: {len(users)}")
    if verbose:
        for u in users[:10]:
            info(f"- { _user_label(u) }")

    # best-effort: role list za prvog
    try:
        rr = list_user_roles(users[0])
        if isinstance(rr, list):
            if verbose:
                info(f"Primer list_user_roles(prvi): {rr}")
    except Exception:
        pass

    return True, users


def check_permissions_matrix(users: List[Dict[str, Any]], verbose: bool = False) -> None:
    perms = [
        "assets.view",
        "assets.create",
        "assets.my.view",
        "assets.metrology.view",
        "metrology.view",
        "metrology.edit",
        "metrology.manage",
        "users.view",
        "settings.view",
        "assignments.view",
        "assignments.create",
        "audit.view",
    ]

    can0 = _try_can("settings.view")
    if can0 is None:
        warn("core.session.can nije dostupan (ne mogu da izračunam permisije u testu).")
        return

    hr()
    print("RBAC matrica (prvih 10 user-a):")
    hr()

    for u in users[:10]:
        if not _try_set_current_user(u):
            warn("Ne mogu set_current_user (preskačem RBAC matrica).")
            return

        flags = []
        for p in perms:
            v = _try_can(p)
            if v is True:
                flags.append(p)
        label = _user_label(u)
        print(f"- {label}")
        if flags:
            print(f"    perms: {', '.join(flags)}")
        else:
            print("    perms: (nema / ili RBAC fail-closed)")
    hr()


def check_assets_calls(users: List[Dict[str, Any]], verbose: bool = False) -> None:
    try:
        import services.assets_service as assets_service  # type: ignore
    except Exception as e:
        fail(f"Import assets_service nije uspeo: {e}")
        return

    # Kandidati po scenarijima
    u_full = _pick_user_for_any_perm(users, ["assets.view"])
    u_my = _pick_user_for_any_perm(users, ["assets.my.view"])
    u_metro = _pick_user_for_any_perm(users, ["assets.metrology.view"])

    hr()
    print("Assets service testovi:")
    hr()

    def run_for_user(u: Optional[Dict[str, Any]], title: str) -> None:
        if not u:
            warn(f"{title}: nema user-a koji ima potrebne perm-ove.")
            return
        if not _try_set_current_user(u):
            warn(f"{title}: set_current_user nije dostupan.")
            return

        label = _user_label(u)
        info(f"{title}: {label}")

        # list_assets_brief
        try:
            rows = assets_service.list_assets_brief(limit=50)
            ok(f"{title}: list_assets_brief -> {len(rows)} rows")
        except PermissionError as pe:
            warn(f"{title}: list_assets_brief PermissionError: {pe}")
            return
        except Exception as e:
            fail(f"{title}: list_assets_brief error: {e}")
            if verbose:
                print(traceback.format_exc())
            return

        # get_asset_by_uid: uzmi prvi asset_uid iz brief liste (ako postoji)
        try:
            uid = ""
            if rows and isinstance(rows, list):
                for r in rows:
                    if isinstance(r, dict) and str(r.get("asset_uid") or "").strip():
                        uid = str(r.get("asset_uid")).strip()
                        break
            if not uid:
                warn(f"{title}: nema asset_uid u rezultatu (možda prazna baza) — preskačem get_asset_by_uid.")
                return

            one = assets_service.get_asset_by_uid(asset_uid=uid)
            if one and isinstance(one, dict):
                ok(f"{title}: get_asset_by_uid({uid}) -> OK")
            else:
                warn(f"{title}: get_asset_by_uid({uid}) -> None/empty")
        except PermissionError as pe:
            warn(f"{title}: get_asset_by_uid PermissionError: {pe}")
        except Exception as e:
            fail(f"{title}: get_asset_by_uid error: {e}")
            if verbose:
                print(traceback.format_exc())

    run_for_user(u_full, "FULL (assets.view)")
    run_for_user(u_my, "MY (assets.my.view)")
    run_for_user(u_metro, "METRO (assets.metrology.view)")


def check_metrology_calls(users: List[Dict[str, Any]], verbose: bool = False) -> None:
    try:
        import services.metrology_service as metrology_service  # type: ignore
    except Exception as e:
        fail(f"Import metrology_service nije uspeo: {e}")
        return

    u_view = _pick_user_for_any_perm(users, ["metrology.view", "metrology.manage"])
    u_edit = _pick_user_for_any_perm(users, ["metrology.edit", "metrology.manage"])

    hr()
    print("Metrology service testovi (READ-ONLY):")
    hr()

    def run_list(u: Optional[Dict[str, Any]], title: str) -> None:
        if not u:
            warn(f"{title}: nema user-a koji ima metrology.view/manage.")
            return
        if not _try_set_current_user(u):
            warn(f"{title}: set_current_user nije dostupan.")
            return

        label = _user_label(u)
        info(f"{title}: {label}")

        try:
            rows = metrology_service.list_metrology_records(q="", limit=50, warn_days=30, include_deleted=False)
            ok(f"{title}: list_metrology_records -> {len(rows)} rows")
            if verbose and rows:
                r0 = rows[0]
                try:
                    info(f"Primer: met_uid={r0.get('met_uid')} asset_uid={r0.get('asset_uid')} status={r0.get('status')}")
                except Exception:
                    pass
        except PermissionError as pe:
            warn(f"{title}: PermissionError: {pe}")
        except Exception as e:
            fail(f"{title}: error: {e}")
            if verbose:
                print(traceback.format_exc())

    run_list(u_view, "VIEW (metrology.view)")
    run_list(u_edit, "EDIT (metrology.edit) — samo list (read-only test)")


def main() -> int:
    ap = argparse.ArgumentParser(description="BazaS2 smoke test (offline, read-only).")
    ap.add_argument("--verbose", action="store_true", help="više detalja u output-u")
    args = ap.parse_args()

    verbose = bool(args.verbose)

    hr()
    print("BazaS2 SMOKE TEST (offline, read-only)")
    hr()

    # 1) DB path consistency
    ok1, msg1 = check_db_path_consistency(verbose=verbose)
    if ok1:
        ok(msg1)
    else:
        fail(msg1)

    # 2) Tables
    ok2, msgs = check_tables(verbose=verbose)
    for m in msgs:
        if m.startswith("OK table"):
            ok(m)
        else:
            warn(m)  # tabele mogu biti migracije; ovo je upozorenje, ne hard fail

    # 3) Users service
    ok3, users = check_users_service(verbose=verbose)
    if not ok3:
        fail("users_service test FAIL (ne mogu dalje).")
        return 2

    if not users:
        warn("Nema korisnika — preskačem RBAC/assets/metrology testove.")
        return 0

    # 4) RBAC matrix (best-effort)
    check_permissions_matrix(users, verbose=verbose)

    # 5) Assets tests
    check_assets_calls(users, verbose=verbose)

    # 6) Metrology tests (read-only)
    check_metrology_calls(users, verbose=verbose)

    hr()
    ok("Smoke test završen.")
    hr()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# (FILENAME: tools/smoke_test.py - END)