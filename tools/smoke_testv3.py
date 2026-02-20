# FILENAME: tools/smoke_testv3.py
# (FILENAME: tools/smoke_testv3.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 — SMOKE TEST V3 (offline, all-in-one)

Šta radi:
- Bootstrap sys.path (da radi kad se pokrene iz tools foldera)
- Učita i pokrene:
    1) tools.full_smoke_testv2 (main())
    2) tools.scenario_smoke_testv2 (main())
- Hvata exceptione, sabira rezultate, ispisuje SUMMARY i vraća exit code:
    - 0 => sve PASS
    - 1 => nešto FAIL

Napomena:
- Ne dupliramo logiku testova (izbegavamo divergence). V3 je “orchestrator”.
- Ako promeniš naziv fajlova v2 testova, menjaj konstante ispod.
"""

from __future__ import annotations

import os
import sys
import time
import traceback
import importlib
from dataclasses import dataclass
from typing import Optional, Tuple


# -------------------- CONFIG --------------------
FULL_TEST_MOD = "tools.full_smoke_testv2"
SCENARIO_TEST_MOD = "tools.scenario_smoke_testv2"


# -------------------- BOOTSTRAP sys.path --------------------
TOOLS_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(TOOLS_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


def _section(title: str) -> None:
    print("\n" + "-" * 78)
    print(title)
    print("-" * 78 + "\n")


def _fmt_exc(e: BaseException) -> str:
    return "".join(traceback.format_exception(type(e), e, e.__traceback__))


@dataclass
class TestRun:
    name: str
    module: str
    ok: bool
    exit_code: int
    duration_s: float
    detail: str = ""


def _call_test_main(module_name: str) -> Tuple[int, str]:
    """
    Uvezi modul i pozovi main() ako postoji.
    Očekujemo da main() vrati int exit code (0 PASS, !=0 FAIL).
    """
    try:
        mod = importlib.import_module(module_name)
    except Exception as e:
        return 99, f"IMPORT FAIL: {module_name}\n{_fmt_exc(e)}"

    main = getattr(mod, "main", None)
    if not callable(main):
        return 98, f"NO main() in {module_name} (expected a callable main())"

    try:
        rc = main()
        try:
            rc_int = int(rc)
        except Exception:
            rc_int = 1
        return rc_int, ""
    except SystemExit as se:
        # neki testovi rade raise SystemExit(main())
        code = getattr(se, "code", 1)
        try:
            return int(code), ""
        except Exception:
            return 1, f"SystemExit with non-int code: {code!r}"
    except Exception as e:
        return 97, f"EXCEPTION in {module_name}.main()\n{_fmt_exc(e)}"


def _run_one(name: str, module_name: str) -> TestRun:
    _section(f"RUN: {name}")
    print("Module:", module_name)
    print("ROOT_DIR:", ROOT_DIR)
    print("PYTHON:", sys.version.replace("\n", " "))

    t0 = time.perf_counter()
    rc, detail = _call_test_main(module_name)
    dt = time.perf_counter() - t0

    ok = (rc == 0)
    if ok:
        print(f"\n[ OK ] {name}: PASS ✅  (rc={rc}, {dt:.2f}s)")
    else:
        print(f"\n[FAIL] {name}: FAIL ❌  (rc={rc}, {dt:.2f}s)")
        if detail:
            print("\n--- DETAIL ---")
            print(detail)

    return TestRun(
        name=name,
        module=module_name,
        ok=ok,
        exit_code=rc,
        duration_s=dt,
        detail=detail or "",
    )


def main() -> int:
    _section("BazaS2 — SMOKE TEST V3 (offline) — ALL-IN-ONE")

    runs = []
    runs.append(_run_one("FULL SMOKE TEST v2", FULL_TEST_MOD))
    runs.append(_run_one("SCENARIO SMOKE TEST v2", SCENARIO_TEST_MOD))

    _section("SUMMARY (V3)")
    all_ok = True
    total = 0.0
    for r in runs:
        total += float(r.duration_s or 0.0)
        status = "PASS ✅" if r.ok else "FAIL ❌"
        print(f"- {r.name}: {status}  (rc={r.exit_code}, {r.duration_s:.2f}s, mod={r.module})")
        if not r.ok:
            all_ok = False

    print(f"\nTotal duration: {total:.2f}s")
    if all_ok:
        print("\n[ OK ] SMOKE TEST V3: PASS ✅ (sve prošlo)")
        return 0

    print("\n[FAIL] SMOKE TEST V3: FAIL ❌ (vidi gore)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

# (FILENAME: tools/smoke_testv3.py - END)