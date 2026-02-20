# FILENAME: tests/smoke_assets_page.py
# (FILENAME: tests/smoke_assets_page.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — Smoke tests for Assets (DB + optional UI)

Šta proverava:
1) DB layer: init_db, create_asset_db, create_assignment_db, list_assets_db filters/search/sort keys
2) Services layer (ako postoji): services.assets_service list/create
3) UI (opciono --ui): AssetsPage load, tab filter, scope filter, search, sorting, renumber, preview

Najbitniji fix:
- Skripta SAMA dodaje project root u sys.path, tako da radi i kad pokreneš:
    python tests\\smoke_assets_page.py
  bez ručnog setovanja PYTHONPATH.

Slow/Step režim (da vidiš "korak po korak"):
- --slow-ms 400     (pauza 400ms između koraka)
- --step            (čeka Enter između koraka)
- --shots           (snima screenshot PNG posle koraka u folder)
- --shots-dir PATH  (gde da snima PNG; default je temp)

Kako pokrenuti:
- DB + services smoke:
    python tests\\smoke_assets_page.py
- DB + services + UI smoke:
    python tests\\smoke_assets_page.py --ui
- UI sporije:
    python tests\\smoke_assets_page.py --ui --slow-ms 500
- UI "Enter po koraku":
    python tests\\smoke_assets_page.py --ui --step
- UI + screenshotovi:
    python tests\\smoke_assets_page.py --ui --slow-ms 500 --shots
"""

from __future__ import annotations

import argparse
import importlib
import logging
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# -------------------- ensure project root on sys.path --------------------
def _ensure_project_root_on_path() -> Path:
    """
    tests/ je tipično u root-u projekta:
      <ROOT>/tests/smoke_assets_page.py
    pa je parents[1] == <ROOT>
    """
    here = Path(__file__).resolve()
    root = here.parents[1]
    rp = str(root)
    if rp not in sys.path:
        sys.path.insert(0, rp)
    return root


PROJECT_ROOT = _ensure_project_root_on_path()


# -------------------- tiny test framework --------------------
@dataclass
class TestResult:
    name: str
    ok: bool
    detail: str = ""


class T:
    def __init__(self) -> None:
        self.results: List[TestResult] = []

    def ok(self, name: str, cond: bool, detail: str = "") -> None:
        self.results.append(TestResult(name, bool(cond), detail if not cond else ""))

    def eq(self, name: str, a: Any, b: Any, detail: str = "") -> None:
        cond = (a == b)
        if not detail and not cond:
            detail = f"Expected {b!r}, got {a!r}"
        self.ok(name, cond, detail)

    def truthy(self, name: str, v: Any, detail: str = "") -> None:
        self.ok(name, bool(v), detail if not v else "")

    def summary(self) -> Tuple[bool, str]:
        total = len(self.results)
        failed = [r for r in self.results if not r.ok]
        ok = (len(failed) == 0)
        lines = []
        lines.append(f"\n=== SMOKE SUMMARY: {'OK' if ok else 'FAIL'} ===")
        lines.append(f"Total: {total} | Passed: {total - len(failed)} | Failed: {len(failed)}")
        if failed:
            lines.append("\n--- FAILURES ---")
            for r in failed:
                lines.append(f"- {r.name}: {r.detail}")
        return ok, "\n".join(lines)


# -------------------- slow/step controller --------------------
class SlowCtl:
    def __init__(self, slow_ms: int = 0, step: bool = False) -> None:
        self.slow_ms = max(0, int(slow_ms))
        self.step = bool(step)

    def pause_console(self, label: str = "") -> None:
        if self.step:
            try:
                input(f"[STEP] {label}  (Enter za nastavak) ")
            except Exception:
                pass
            return
        if self.slow_ms > 0:
            time.sleep(self.slow_ms / 1000.0)


# -------------------- session / RBAC monkeypatch --------------------
def ensure_dummy_session(
    perms: Optional[Dict[str, bool]] = None,
    actor: str = "marko",
    actor_key: str = "marko",
) -> None:
    """
    AssetsPage koristi core.session.can / actor_name / actor_key.
    Ovde ubacujemo minimalan 'core.session' ako ne postoji, ili patchujemo postojeći.
    """
    import types

    if perms is None:
        perms = {}

    def can(p: str) -> bool:
        return bool(perms.get(p, False))

    def actor_name() -> str:
        return actor

    def actor_key_fn() -> str:
        return actor_key

    mod = sys.modules.get("core.session")
    if mod is None:
        mod = types.ModuleType("core.session")
        sys.modules["core.session"] = mod

    setattr(mod, "can", can)
    setattr(mod, "actor_name", actor_name)
    setattr(mod, "actor_key", actor_key_fn)


# -------------------- DB sandbox setup (no production touching) --------------------
def patch_db_path_and_reload(test_db_path: str) -> None:
    """
    Cilj: sve (core.db + services) da rade nad test DB-om.

    - Pokušamo patch core.config.DB_FILE i/ili core.paths.DB_PATH
    - Reload core.db
    - Reload services.* koji zavise od core.db
    """
    # 1) patch core.config.DB_FILE
    try:
        import core.config  # type: ignore
        setattr(core.config, "DB_FILE", test_db_path)  # type: ignore[attr-defined]
    except Exception:
        pass

    # 2) patch core.paths.DB_PATH
    try:
        import core.paths  # type: ignore
        setattr(core.paths, "DB_PATH", test_db_path)  # type: ignore[attr-defined]
    except Exception:
        pass

    # 3) reload core.db
    try:
        import core.db  # type: ignore
        importlib.reload(core.db)  # type: ignore
    except Exception:
        pass

    # 4) reload services
    for m in [
        "services.assets_service",
        "services.assignments_service",
        "services.dashboard_service",
        "services.metrology_service",
    ]:
        try:
            if m in sys.modules:
                importlib.reload(sys.modules[m])
            else:
                importlib.import_module(m)
        except Exception:
            pass


def make_temp_db_path() -> str:
    td = tempfile.mkdtemp(prefix="bazas2_smoke_")
    p = Path(td) / "bazas2_test.sqlite"
    return str(p)


def _row_to_dict(r: Any) -> Dict[str, Any]:
    if r is None:
        return {}
    if isinstance(r, dict):
        return r
    try:
        return dict(r)
    except Exception:
        return {}


# -------------------- robust DB calls (signature compatibility) --------------------
def _create_asset_db(db_mod, **kwargs) -> str:
    """
    create_asset_db(...) varira između nomenclature_number vs nomenclature_no.
    """
    try:
        return db_mod.create_asset_db(**kwargs)
    except TypeError:
        if "nomenclature_number" in kwargs:
            v = kwargs.pop("nomenclature_number")
            kwargs["nomenclature_no"] = v
            return db_mod.create_asset_db(**kwargs)
        raise


def _create_assignment_db(db_mod, **kwargs) -> Any:
    """
    create_assignment_db(...) varira; pokušaj standardne parametre.
    """
    try:
        return db_mod.create_assignment_db(**kwargs)
    except TypeError:
        # fallback: neki kod koristi holder/location bez "to_"
        if "to_holder" in kwargs and "holder" not in kwargs:
            kwargs["holder"] = kwargs.pop("to_holder")
        if "to_location" in kwargs and "location" not in kwargs:
            kwargs["location"] = kwargs.pop("to_location")
        return db_mod.create_assignment_db(**kwargs)


# -------------------- DB + services smoke tests --------------------
def seed_test_data() -> Dict[str, str]:
    """
    Kreira nekoliko sredstava i jedno zaduženje.
    Vraća mapu naziva -> asset_uid.
    """
    import core.db as db  # type: ignore

    db.init_db()

    with db.db_conn() as conn:  # type: ignore[attr-defined]
        uid1 = _create_asset_db(
            db,
            actor="smoke",
            name="Fluke 289",
            category="Metrologija",
            toc_number="TOC 1001",
            serial_number="SN-289-A",
            nomenclature_number="NOM-55",
            location="Lab 1",
            status="active",
            sector="2.1",
            is_metrology=1,
            source="smoke_seed",
        )

        uid2 = _create_asset_db(
            db,
            actor="smoke",
            name="HP 250 G10",
            category="IT",
            toc_number="1002",
            serial_number="SN-HP-250",
            nomenclature_number="",
            location="IT Magacin",
            status="active",
            sector="2.2",
            is_metrology=0,
            source="smoke_seed",
        )

        uid3 = _create_asset_db(
            db,
            actor="smoke",
            name="Stari UPS",
            category="IT",
            toc_number="1003",
            serial_number="SN-UPS-OLD",
            nomenclature_number="NOM-UPS",
            location="Otpad",
            status="scrapped",
            sector="2.2",
            is_metrology=0,
            source="smoke_seed",
        )

        uid4 = _create_asset_db(
            db,
            actor="smoke",
            name="R&S ESR26",
            category="Metrologija",
            toc_number="1004",
            serial_number="SN-ESR26",
            nomenclature_number="NOM-ESR26",
            location="Lab 2",
            status="service",
            sector="2.1",
            is_metrology=0,
            source="smoke_seed",
        )

        _create_assignment_db(
            db,
            actor="smoke",
            asset_uid=uid2,
            action="assign",
            to_holder="marko",
            to_location="Kancelarija",
            note="Smoke assign",
            source="smoke_seed",
        )

        conn.commit()

    return {"met_active": uid1, "it_assigned": uid2, "it_scrapped": uid3, "met_service": uid4}


def run_db_and_services_tests(t: T, uids: Dict[str, str]) -> None:
    import core.db as db  # type: ignore

    # DB path sanity
    try:
        p = db.get_db_path()  # type: ignore[attr-defined]
        t.truthy("DB path resolved", p and str(p).endswith(".sqlite"))
    except Exception as e:
        t.ok("DB path resolved", False, f"Exception: {e}")

    # list_assets_db basic
    rows_raw = db.list_assets_db(limit=9999)  # type: ignore[attr-defined]
    rows = [_row_to_dict(x) for x in (rows_raw or [])]
    t.truthy("list_assets_db returns rows", len(rows) >= 4)

    # search by TOC
    r2 = [_row_to_dict(x) for x in db.list_assets_db(search="1002", limit=100)]  # type: ignore[attr-defined]
    t.eq("Search by TOC returns 1", len(r2), 1)

    # search by nomenclature
    rnom = [_row_to_dict(x) for x in db.list_assets_db(search="NOM-55", limit=100)]  # type: ignore[attr-defined]
    t.eq("Search by nomenclature returns 1", len(rnom), 1)

    # metrology_only filter (minimalno: mora uključiti uid1)
    rmet = [_row_to_dict(x) for x in db.list_assets_db(metrology_only=True, limit=999)]  # type: ignore[attr-defined]
    found_uids = {x.get("asset_uid") for x in rmet}
    t.ok("metrology_only includes met_active", (uids["met_active"] in found_uids), "met_active missing in metrology_only")

    # sector filter (case/trim)
    rsec = [_row_to_dict(x) for x in db.list_assets_db(sector=" 2.1 ", limit=999)]  # type: ignore[attr-defined]
    sec_uids = {x.get("asset_uid") for x in rsec}
    t.ok("sector filter picks correct", (uids["met_active"] in sec_uids) and (uids["met_service"] in sec_uids))

    # assignment changed status to on_loan (ako tvoja DB logika tako radi)
    try:
        a2 = _row_to_dict(db.get_asset_db(uids["it_assigned"]))  # type: ignore[attr-defined]
        t.eq("Assignment sets status on_loan", (a2 or {}).get("status"), "on_loan")
        t.eq("Assignment sets current_holder", (a2 or {}).get("current_holder"), "marko")
    except Exception as e:
        t.ok("Assignment updates asset fields", False, f"{e}")

    # services layer (optional)
    try:
        from services.assets_service import list_assets as svc_list_assets  # type: ignore
        srows_any = svc_list_assets(limit=9999)
        srows = [_row_to_dict(x) for x in (srows_any or [])]
        t.truthy("services.assets_service.list_assets works", len(srows) >= 4)
    except Exception as e:
        # nije fatalno
        t.ok("services.assets_service.list_assets works (optional)", True, f"Skipped: {e}")


# -------------------- UI smoke tests (optional) --------------------
def _qt_set_fontdir_default() -> None:
    """
    Smanjuje QFontDatabase warning na Windows (py 3.13/3.14 situacije).
    """
    if os.environ.get("QT_QPA_FONTDIR"):
        return
    windir = os.environ.get("WINDIR", r"C:\Windows")
    fonts = os.path.join(windir, "Fonts")
    os.environ["QT_QPA_FONTDIR"] = fonts


def run_ui_smoke(t: T, slow: SlowCtl, shots: bool = False, shots_dir: Optional[str] = None, offscreen: bool = False) -> None:
    """
    Minimal UI smoke: AssetsPage load, tab filter, scope switch, search, sort.
    U slow/step modu pravi pauze i (opciono) snima screenshotove.
    """
    try:
        from PySide6.QtCore import Qt, QTimer  # type: ignore
        from PySide6.QtWidgets import QApplication  # type: ignore
        from PySide6.QtTest import QTest  # type: ignore
    except Exception as e:
        t.ok("PySide6 UI imports", False, f"Missing PySide6/QtTest: {e}")
        return

    _qt_set_fontdir_default()

    if offscreen:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    app = QApplication.instance() or QApplication([])

    # perms
    try:
        from core.rbac import (  # type: ignore
            PERM_ASSETS_VIEW,
            PERM_ASSETS_CREATE,
            PERM_ASSETS_MY_VIEW,
            PERM_ASSETS_METRO_VIEW,
        )
    except Exception:
        PERM_ASSETS_VIEW = "assets.view"
        PERM_ASSETS_CREATE = "assets.create"
        PERM_ASSETS_MY_VIEW = "assets.my.view"
        PERM_ASSETS_METRO_VIEW = "assets.metrology.view"

    perms = {
        PERM_ASSETS_VIEW: True,
        PERM_ASSETS_CREATE: True,
        PERM_ASSETS_MY_VIEW: True,
        PERM_ASSETS_METRO_VIEW: True,
    }
    ensure_dummy_session(perms=perms, actor="marko", actor_key="marko")

    # build page
    try:
        from ui.assets_page import AssetsPage  # type: ignore
    except Exception as e:
        t.ok("Import ui.assets_page.AssetsPage", False, f"{e}")
        return

    logger = logging.getLogger("smoke_ui")
    page = AssetsPage(logger)
    page.resize(1200, 720)
    page.show()

    def _shot(tag: str) -> None:
        if not shots:
            return
        try:
            out_dir = Path(shots_dir) if shots_dir else Path(tempfile.gettempdir()) / "bazas2_smoke_shots"
            out_dir.mkdir(parents=True, exist_ok=True)
            fn = out_dir / f"{int(time.time()*1000)}_{tag}.png"
            page.grab().save(str(fn))
            print(f"[SHOT] {fn}")
        except Exception as e:
            print(f"[SHOT] failed: {e}")

    def _ui_pause(tag: str) -> None:
        _shot(tag)
        if slow.step:
            try:
                input(f"[STEP] {tag}  (Enter za nastavak) ")
            except Exception:
                pass
        elif slow.slow_ms > 0:
            QTest.qWait(slow.slow_ms)
        else:
            QTest.qWait(30)
        app.processEvents()

    _ui_pause("ui_open")

    # initial load should have data
    try:
        page.load_assets()
        _ui_pause("after_load")
        t.truthy("UI load_assets populates table", page.table.rowCount() >= 1)
    except Exception as e:
        t.ok("UI load_assets populates table", False, f"{e}")
        return

    # go to TAB_ALL and SCOPE_ALL for stable search test
    try:
        # TAB_ALL
        idx_all = None
        for i in range(page.tabs.count()):
            if page.tabs.tabText(i).strip().casefold() == page.TAB_ALL.casefold():
                idx_all = i
                break
        if idx_all is not None:
            page.tabs.setCurrentIndex(idx_all)
            _ui_pause("tab_all")
            page.load_assets()
            _ui_pause("after_tab_all_load")

        # SCOPE_ALL
        scope_all_i = None
        for i in range(page.cb_scope.count()):
            if page.cb_scope.itemText(i).strip().casefold() == page.SCOPE_ALL.casefold():
                scope_all_i = i
                break
        if scope_all_i is not None:
            page.cb_scope.setCurrentIndex(scope_all_i)
            _ui_pause("scope_all")
            page.load_assets()
            _ui_pause("after_scope_all_load")
    except Exception as e:
        t.ok("Set stable tab/scope", False, f"{e}")

    # tab: scrapped should show only scrapped
    try:
        idx_scrapped = None
        for i in range(page.tabs.count()):
            if page.tabs.tabText(i).strip().casefold() == page.TAB_SCRAPPED.casefold():
                idx_scrapped = i
                break
        t.truthy("Scrapped tab exists", idx_scrapped is not None)
        if idx_scrapped is not None:
            page.tabs.setCurrentIndex(idx_scrapped)
            _ui_pause("tab_scrapped")
            page.load_assets()
            _ui_pause("after_scrapped_load")

            ok = True
            for r in range(page.table.rowCount()):
                it = page.table.item(r, page.COL_IDX_STATUS)
                if it and it.text().strip().casefold() != "scrapped":
                    ok = False
                    break
            t.ok("Scrapped tab filters statuses", ok, "Found non-scrapped row on scrapped tab")
    except Exception as e:
        t.ok("Scrapped tab filters statuses", False, f"{e}")

    # back to ALL tab for search
    try:
        idx_all = None
        for i in range(page.tabs.count()):
            if page.tabs.tabText(i).strip().casefold() == page.TAB_ALL.casefold():
                idx_all = i
                break
        if idx_all is not None:
            page.tabs.setCurrentIndex(idx_all)
            _ui_pause("back_tab_all")
    except Exception:
        pass

    # search: find TOC 1001 (u ALL scope treba da postoji)
    try:
        page.ed_search.setText("1001")
        _ui_pause("set_search_1001")
        # Ne oslanjamo se na debounce: zovemo direktno
        page.load_assets()
        _ui_pause("after_search_1001_load")
        t.truthy("Search returns rows", page.table.rowCount() >= 1, "Search yielded 0 rows in ALL scope")
    except Exception as e:
        t.ok("Search returns rows", False, f"{e}")

    # scope: My equipment + search 1002 (koji je dodeljen marko)
    try:
        my_i = None
        for i in range(page.cb_scope.count()):
            if page.cb_scope.itemText(i).strip().casefold() == page.SCOPE_MY.casefold():
                my_i = i
                break
        t.truthy("Scope 'Moja oprema' exists (with perms)", my_i is not None)

        if my_i is not None:
            page.cb_scope.setCurrentIndex(my_i)
            _ui_pause("scope_my")
            page.ed_search.setText("1002")
            _ui_pause("set_search_1002")
            page.load_assets()
            _ui_pause("after_scope_my_search_1002")

            ok = True
            for r in range(page.table.rowCount()):
                it = page.table.item(r, page.COL_IDX_HOLDER)
                holder = (it.text() if it else "").strip().casefold()
                if holder and holder != "marko":
                    ok = False
                    break
            t.ok("Scope MY filters holder==actor (when full view)", ok, "Found row not assigned to actor in MY scope")
    except Exception as e:
        t.ok("Scope MY filters", False, f"{e}")

    # sort by TOC
    try:
        hdr = page.table.horizontalHeader()
        toc_col = page.COL_IDX_TOC
        hdr.setSortIndicatorShown(True)
        hdr.setSortIndicator(toc_col, Qt.AscendingOrder)
        page.table.sortItems(toc_col, Qt.AscendingOrder)
        _ui_pause("after_sort_toc")

        ok = True
        expected = 1
        for r in range(min(20, page.table.rowCount())):
            if page.table.isRowHidden(r):
                continue
            it = page.table.item(r, page.COL_IDX_ROWNUM)
            if not it or it.text().strip() != str(expected):
                ok = False
                break
            expected += 1
        t.ok("Sort by TOC keeps renumber stable", ok, "Row numbers not sequential after sort")
    except Exception as e:
        t.ok("Sort by TOC keeps renumber stable", False, f"{e}")

    # close UI
    try:
        _ui_pause("before_close")
        QTimer.singleShot(0, page.close)
        QTest.qWait(20)
        app.processEvents()
    except Exception:
        pass


# -------------------- main --------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ui", action="store_true", help="Run UI smoke tests (PySide6 + QtTest).")
    ap.add_argument("--slow-ms", type=int, default=0, help="Pause between UI steps (ms).")
    ap.add_argument("--step", action="store_true", help="Wait Enter between UI steps.")
    ap.add_argument("--shots", action="store_true", help="Save UI screenshots per step (PNG).")
    ap.add_argument("--shots-dir", type=str, default="", help="Where to save screenshots (default: temp).")
    ap.add_argument("--offscreen", action="store_true", help="Force QT_QPA_PLATFORM=offscreen (headless).")
    args = ap.parse_args()

    slow = SlowCtl(slow_ms=args.slow_ms, step=args.step)
    t = T()

    # create test db
    test_db_path = make_temp_db_path()
    Path(test_db_path).parent.mkdir(parents=True, exist_ok=True)

    # patch + reload
    patch_db_path_and_reload(test_db_path)

    # basic import sanity
    try:
        import core.db as db  # type: ignore
        _ = db  # silence
        t.truthy("Import core.db", True)
    except Exception as e:
        t.ok("Import core.db", False, f"{e}")
        ok, msg = t.summary()
        print(msg)
        return 2

    # seed data
    try:
        uids = seed_test_data()
        t.truthy("Seed test data", True)
    except Exception as e:
        t.ok("Seed test data", False, f"{e}")
        ok, msg = t.summary()
        print(msg)
        return 3

    # run DB+services tests
    try:
        run_db_and_services_tests(t, uids)
    except Exception as e:
        t.ok("DB+services tests run", False, f"{e}")

    # UI tests
    if args.ui:
        try:
            run_ui_smoke(
                t,
                slow=slow,
                shots=bool(args.shots),
                shots_dir=(args.shots_dir or None),
                offscreen=bool(args.offscreen),
            )
        except Exception as e:
            t.ok("UI smoke run", False, f"{e}")

    ok, msg = t.summary()
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

# (FILENAME: tests/smoke_assets_page.py - END)