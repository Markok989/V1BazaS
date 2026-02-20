# core/selfcheck.py
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — core/selfcheck.py
Self-check zavisnosti + offline auto-install iz vendor/wheels (bez interneta).
"""

# -------------------------
# [POČETAK] FAJL: core/selfcheck.py
# -------------------------

from __future__ import annotations

import sys
import json
import subprocess
import traceback
import logging
from dataclasses import dataclass
from typing import List, Tuple, Optional

from .config import LOGS_DIR, WHEELS_DIR


@dataclass
class Dependency:
    import_name: str
    pip_name: str
    min_version: Optional[str] = None


REQUIRED_DEPS: List[Dependency] = [
    Dependency("PySide6", "PySide6", None),
    Dependency("openpyxl", "openpyxl", None),
    Dependency("docx", "python-docx", None),
    Dependency("reportlab", "reportlab", None),
]


def try_import(module_name: str) -> Tuple[bool, Optional[str]]:
    try:
        mod = __import__(module_name)
        ver = getattr(mod, "__version__", None)
        return True, ver
    except Exception:
        return False, None


def have_pip() -> bool:
    try:
        import pip  # noqa: F401
        return True
    except Exception:
        return False


def dependency_report(logger: logging.Logger) -> dict:
    report = {"ok": [], "missing": [], "meta": {"python": sys.version, "exe": sys.executable}}
    for dep in REQUIRED_DEPS:
        ok, ver = try_import(dep.import_name)
        if ok:
            report["ok"].append({"import": dep.import_name, "pip": dep.pip_name, "version": ver})
        else:
            report["missing"].append({"import": dep.import_name, "pip": dep.pip_name, "min_version": dep.min_version})
    logger.info(f"Deps OK: {len(report['ok'])}, missing: {len(report['missing'])}")
    return report


def save_selfcheck_report(logger: logging.Logger, report: dict) -> None:
    try:
        path = LOGS_DIR / "selfcheck_report.json"
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info(f"Self-check report snimljen: {path.name}")
    except Exception as e:
        logger.error(f"Ne mogu da snimim selfcheck_report.json: {e}")


def run_pip_install_offline(logger: logging.Logger, packages: List[str]) -> Tuple[bool, str]:
    """
    Instalira isključivo iz vendor/wheels:
    --no-index + --find-links vendor/wheels
    """
    if not packages:
        return True, "Nothing to install."

    if not WHEELS_DIR.exists():
        return False, f"Missing wheels directory: {WHEELS_DIR}"

    cmd = [
        sys.executable, "-m", "pip", "install",
        "--no-index",
        "--find-links", str(WHEELS_DIR),
        "--upgrade",
    ] + packages

    logger.info("Pokušavam offline pip install iz vendor/wheels ...")
    logger.info("CMD: " + " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        ok = (proc.returncode == 0)
        if ok:
            logger.info("Offline install OK.")
        else:
            logger.error("Offline install FAIL.")
            logger.error(out.strip())
        return ok, out.strip()
    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"pip install exception: {e}")
        logger.error(tb)
        return False, tb


def self_check_and_fix(logger: logging.Logger, auto_fix: bool = True) -> bool:
    logger.info("Pokrećem self-check...")

    if not have_pip():
        logger.warning("pip nije dostupan u ovom Python okruženju. Auto-install neće raditi.")
        rep = dependency_report(logger)
        save_selfcheck_report(logger, rep)
        return len(rep["missing"]) == 0

    rep1 = dependency_report(logger)
    save_selfcheck_report(logger, rep1)

    if not rep1["missing"]:
        logger.info("Self-check: sve biblioteke prisutne.")
        return True

    if not auto_fix:
        logger.warning("Auto-fix je isključen. Ne instaliram ništa.")
        return False

    missing_pips = [m["pip"] for m in rep1["missing"]]
    ok, out = run_pip_install_offline(logger, missing_pips)

    (LOGS_DIR / "pip_install_last.txt").write_text(out or "", encoding="utf-8")

    if not ok:
        logger.error("Neuspela offline instalacija. Proveri vendor/wheels (.whl fajlovi).")
        return False

    rep2 = dependency_report(logger)
    save_selfcheck_report(logger, rep2)

    if rep2["missing"]:
        logger.error("Neke biblioteke i dalje fale posle instalacije.")
        return False

    logger.info("Self-check + auto-install: OK.")
    return True

# -------------------------
# [KRAJ] FAJL: core/selfcheck.py
# -------------------------