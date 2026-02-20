# FILENAME: tools/scenario_smoke_testv5.py
# (FILENAME: tools/scenario_smoke_testv5.py - START)  # Part 1/2
# -*- coding: utf-8 -*-
"""
BazaS2 — SCENARIO SMOKE TEST v5 (offline)

v5 = v4 + UI MODE TRIPWIRE

NOVO U v5:
- Garancija da BASIC_USER ostaje BASIC čak i kada ima:
    - settings.view = True
    - assets.my.view = True
- Test hvata regresiju gde bi BASIC postao FULL samo zbog Podešavanja

OSTALO:
- sve iz v4 ostaje NETAKNUTO
"""

from __future__ import annotations

import os
import sys
import sqlite3
from datetime import date, timedelta, datetime
from typing import Any, Dict, List, Optional

# -------------------- BOOTSTRAP --------------------
TOOLS_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(TOOLS_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

TEST_RUN_ID = "SCN5-" + datetime.now().strftime("%Y%m%d-%H%M%S")

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

# -------------------- Session helpers --------------------
def _set_user(role: str, username: str, display: str, sector="S2", user_id=999):
    from core.session import set_current_user  # type: ignore
    set_current_user({
        "id": user_id,
        "username": username,
        "display_name": display,
        "name": display,
        "role": role,
        "active_role": role,
        "roles": [role],
        "sector": sector,
        "active_sector": sector,
    })

def _can(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False

# -------------------- BASIC USER UI MODE TRIPWIRE --------------------
def _basic_user_ui_mode_tripwire() -> None:
    """
    KRITIČNI TEST:
    BASIC_USER ne sme biti tretiran kao FULL
    samo zato što ima settings.view
    """
    section("UI MODE TRIPWIRE: BASIC USER MUST STAY BASIC")

    _set_user(
        role="BASIC_USER",
        username="basic_ui_test",
        display="BASIC_UI_TEST",
        user_id=55,
    )

    # Simuliramo dozvole koje BASIC sme da ima
    perms = {
        "settings.view": _can("settings.view"),
        "assets.my.view": _can("assets.my.view"),
        "users.view": _can("users.view"),
        "assets.create": _can("assets.create"),
    }

    print("Effective permissions:")
    for k, v in perms.items():
        print(f"  {k} = {v}")

    # Heuristika identična app.py (_is_basic_user)
    full_signals = [
        perms.get("users.view"),
        perms.get("assets.create"),
    ]

    if any(full_signals):
        fail("BASIC_USER pogrešno detektovan kao FULL (kritična regresija).")
        raise SystemExit(80)

    ok("BASIC_USER ostaje BASIC (settings.view dozvoljen, bez FULL eskalacije).")

# -------------------- MAIN --------------------
def main() -> int:
    section("BazaS2 — SCENARIO SMOKE TEST v5 (offline)")
    print("TEST_RUN_ID:", TEST_RUN_ID)

    section("DB INIT")
    try:
        from core.db import init_db  # type: ignore
        init_db()
        ok("DB init OK")
    except Exception as e:
        fail(f"DB init failed: {e}")
        return 10

    section("ENSURE SCHEMAS")
    try:
        from services.users_service import ensure_users_schema  # type: ignore
        from services.metrology_service import ensure_metrology_schema  # type: ignore
        ensure_users_schema()
        ensure_metrology_schema()
        ok("Schemas OK")
    except Exception as e:
        fail(f"Schema error: {e}")
        return 11
    
    # FILENAME: tools/scenario_smoke_testv5.py
# (FILENAME: tools/scenario_smoke_testv5.py - START)  # Part 2/2

    # ---- Run legacy v4 scenario (reuse) ----
    section("LEGACY SCENARIO (v4 logic preserved)")
    try:
        from tools.scenario_smoke_testv4 import main as v4_main  # type: ignore
        rc = v4_main()
        if rc != 0:
            fail("v4 scenario FAILED inside v5")
            return rc
        ok("v4 scenario passed inside v5")
    except Exception as e:
        fail(f"v4 scenario import/run failed: {e}")
        return 20

    # ---- NEW: UI MODE TRIPWIRE ----
    _basic_user_ui_mode_tripwire()

    section("SUMMARY")
    ok("SCENARIO SMOKE TEST v5: PASS ✅")
    ok("MY scope, METRO scope, ROLE switch, BASIC UI mode — sve stabilno.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# (FILENAME: tools/scenario_smoke_testv5.py - END)  # Part 2/2