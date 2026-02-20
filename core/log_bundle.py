# FILENAME: core/log_bundle.py
# (FILENAME: core/log_bundle.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — core/log_bundle.py
Kreira ZIP paket za dijagnostiku (log bundle).

Ne menja ništa u postojećem sistemu — samo helper koji možeš kasnije
da zakačiš na dugme (npr. Settings/Napredno).

Šta pakuje (best-effort):
- data/logs/app.log + rotacije (app.log.1, app.log.2...)
- data/logs/errors.log + rotacije
- data/logs/selfcheck_report.json (ako postoji)
- data/logs/pip_install_last.txt (ako postoji)
- mali bundle_info.json (verzija, run_id, timestamp, putanje)
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .config import APP_NAME, APP_VERSION, LOGS_DIR
from .logger import get_run_id


def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _safe_add(zf: zipfile.ZipFile, src: Path, arcname: str) -> None:
    try:
        if src.exists() and src.is_file():
            zf.write(src, arcname=arcname)
    except Exception:
        pass


def _collect_rotations(base: Path) -> List[Path]:
    """
    Vrati listu: base + base.1 + base.2 ... (koliko god postoji).
    RotatingFileHandler tipično koristi sufiks .1, .2...
    """
    out: List[Path] = []
    try:
        if base.exists():
            out.append(base)
        # probaj 1..50 (dovoljno, a bez loop-a do besvesti)
        for i in range(1, 51):
            p = Path(str(base) + f".{i}")
            if p.exists():
                out.append(p)
            else:
                # čim pukne niz, prekidamo (najčešći slučaj)
                if i >= 3:
                    break
    except Exception:
        pass
    return out


def create_log_bundle(out_dir: Optional[Path] = None) -> Path:
    """
    Kreira bundle ZIP i vraća putanju do zip fajla.
    Default out_dir: data/logs/bundles

    Ne baca izuzetak (fail-safe): u najgorem slučaju vraća putanju gde bi bio zip.
    """
    run_id = get_run_id()
    bundles_dir = (out_dir or (LOGS_DIR / "bundles"))
    try:
        bundles_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    zip_path = bundles_dir / f"bazas2_logbundle_{_now_stamp()}_run-{run_id}.zip"

    # Fajlovi koje ciljamo
    app_log = LOGS_DIR / "app.log"
    err_log = LOGS_DIR / "errors.log"
    selfcheck = LOGS_DIR / "selfcheck_report.json"
    pip_last = LOGS_DIR / "pip_install_last.txt"

    info = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "run_id": run_id,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "logs_dir": str(LOGS_DIR),
        "included": [],
    }

    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # app.log + rotacije
            for p in _collect_rotations(app_log):
                arc = f"logs/{p.name}"
                _safe_add(zf, p, arc)
                info["included"].append(arc)

            # errors.log + rotacije
            for p in _collect_rotations(err_log):
                arc = f"logs/{p.name}"
                _safe_add(zf, p, arc)
                info["included"].append(arc)

            # selfcheck / pip
            if selfcheck.exists():
                arc = f"logs/{selfcheck.name}"
                _safe_add(zf, selfcheck, arc)
                info["included"].append(arc)

            if pip_last.exists():
                arc = f"logs/{pip_last.name}"
                _safe_add(zf, pip_last, arc)
                info["included"].append(arc)

            # info json (uvek)
            try:
                zf.writestr("bundle_info.json", json.dumps(info, ensure_ascii=False, indent=2))
            except Exception:
                pass

    except Exception:
        # fail-safe: ništa, samo vraćamo planiranu putanju
        return zip_path

    return zip_path

# (FILENAME: core/log_bundle.py - END)