# [START] FILENAME: core/backup.py
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — core/backup.py

Backup/Restore (ZIP) bitnih delova (V1):
- data/ (templates, images, logs, ...)
- db/ (ako postoji)
- SQLite baza (DB_FILE)

Cilj:
1) Restore baze BEZ restart-a (HOT restore) — SQLite backup API
2) FULL Restore (baza + data) — pouzdano preko "restore on next start" (managed restart)

Napomene:
- Backup NE pakuje:
  - data/backups/*.zip (da ne pravi spiralu)
  - data/tmp_restore/
  - data/restore_pending/
  - __pycache__ i *.pyc
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional

from core.config import DB_FILE


# -------------------------
# Helpers
# -------------------------

def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _safe_rel(path: Path, root: Path) -> str:
    return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")


def _resolve_db_path(root: Path) -> Path:
    db_path = Path(DB_FILE)
    if not db_path.is_absolute():
        db_path = (root / db_path).resolve()
    return db_path


def _pending_dir(root: Path) -> Path:
    return root / "data" / "restore_pending"


def _tmp_restore_dir(root: Path) -> Path:
    return root / "data" / "tmp_restore"


def _backups_dir(root: Path) -> Path:
    return root / "data" / "backups"


def _gather_paths(root: Path) -> List[Path]:
    """
    Šta se pakuje u backup:
    - data/
    - db/ (ako postoji)
    - DB_FILE (ako je van data/db)
    - optional: README / CHANGELOG
    """
    paths: List[Path] = []

    data_dir = root / "data"
    if data_dir.exists():
        paths.append(data_dir)

    db_dir = root / "db"
    if db_dir.exists():
        paths.append(db_dir)

    db_path = _resolve_db_path(root)
    if db_path.exists():
        paths.append(db_path)

    for extra in ["README.md", "CHANGELOG.md"]:
        p = root / extra
        if p.exists():
            paths.append(p)

    return paths


def _should_skip_file(file_path: Path, root: Path, target_zip: Path) -> bool:
    fp = file_path.resolve()
    tz = target_zip.resolve()
    if fp == tz:
        return True

    try:
        rel = fp.relative_to(root.resolve())
        rel_str = str(rel).replace("\\", "/")
    except Exception:
        rel_str = ""

    if rel_str.startswith("data/tmp_restore/"):
        return True

    if rel_str.startswith("data/restore_pending/"):
        return True

    if rel_str.startswith("data/backups/") and rel_str.lower().endswith(".zip"):
        return True

    if "/__pycache__/" in f"/{rel_str}/":
        return True

    if rel_str.lower().endswith(".pyc"):
        return True

    return False


def _retry(op_name: str, fn, retries: int = 8, delay_s: float = 0.15, backoff: float = 1.6):
    """
    Windows-friendly retry (AV/Explorer lock itd.)
    """
    last_exc = None
    d = delay_s
    for _ in range(retries):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            time.sleep(d)
            d *= backoff
    raise RuntimeError(f"{op_name} failed after retries: {last_exc}") from last_exc


def _validate_zip(zip_path: Path) -> Tuple[bool, str]:
    if not zip_path.exists():
        return False, "ZIP fajl ne postoji."

    if not zipfile.is_zipfile(zip_path):
        try:
            size = zip_path.stat().st_size
        except Exception:
            size = -1
        return False, f"Fajl nije validan ZIP (verovatno korumpiran). Veličina: {size} B"

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            names = z.namelist()
            if not names:
                return False, "ZIP je prazan."

            has_any = (
                any(n.startswith("data/") for n in names)
                or any(n.startswith("db/") for n in names)
                or any(n.lower().endswith(".sqlite") for n in names)
            )
            if not has_any:
                return False, "ZIP ne izgleda kao BazaS2 backup (nema data/, db/ ili .sqlite)."

    except Exception as e:
        return False, f"Ne mogu da otvorim ZIP: {e}"

    return True, "OK"


# -------------------------
# BACKUP
# -------------------------

def create_backup_zip(target_zip: Path) -> Tuple[int, List[str]]:
    """
    Pravi ZIP backup. Vraća (broj fajlova, lista upisanih rel putanja).
    """
    root = _app_root()
    target_zip = target_zip.resolve()
    target_zip.parent.mkdir(parents=True, exist_ok=True)

    included: List[str] = []
    file_count = 0

    paths = _gather_paths(root)

    with zipfile.ZipFile(target_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in paths:
            p = p.resolve()
            if p.is_dir():
                for f in p.rglob("*"):
                    if not f.is_file():
                        continue
                    if _should_skip_file(f, root, target_zip):
                        continue
                    rel = _safe_rel(f, root)
                    z.write(f, arcname=rel)
                    included.append(rel)
                    file_count += 1
            elif p.is_file():
                if _should_skip_file(p, root, target_zip):
                    continue
                rel = _safe_rel(p, root)
                z.write(p, arcname=rel)
                included.append(rel)
                file_count += 1

        manifest = {
            "created_at": _now_stamp(),
            "file_count": file_count,
            "db_file": str(_resolve_db_path(root)),
            "notes": "BazaS2 offline backup (data + db + sqlite).",
        }
        z.writestr("backup_manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        included.append("backup_manifest.json")

    return file_count, included


# -------------------------
# HOT RESTORE (DB only, no restart)
# -------------------------

def _find_db_in_extracted(root_extracted: Path, expected_rel: str) -> Optional[Path]:
    """
    Pokušava da nađe DB fajl u raspakovanom ZIP-u.
    1) expected_rel (npr data/db/bazas2.sqlite)
    2) fallback: prvi *.sqlite u arhivi
    """
    candidate = root_extracted / expected_rel
    if candidate.exists() and candidate.is_file():
        return candidate

    sqlite_files = list(root_extracted.rglob("*.sqlite"))
    if sqlite_files:
        # uzmi najverovatniji: najdublji / ili najveći
        sqlite_files.sort(key=lambda p: p.stat().st_size if p.exists() else 0, reverse=True)
        return sqlite_files[0]
    return None


def hot_restore_db_from_zip(zip_path: Path) -> Tuple[bool, str]:
    """
    Restore SAMO baze bez restart-a, koristeći SQLite backup API.

    Radi ovako:
    - Validira ZIP
    - Extract u data/tmp_restore/
    - Locira DB u extracted content
    - src_conn.backup(dst_conn) -> prepis sadržaja
    - integrity_check
    """
    root = _app_root()
    zip_path = zip_path.resolve()

    ok, msg = _validate_zip(zip_path)
    if not ok:
        return False, msg

    tmp_dir = _tmp_restore_dir(root)
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir, ignore_errors=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(tmp_dir)
    except Exception as e:
        return False, f"Ne mogu da raspakujem ZIP: {e}"

    expected_rel = _safe_rel(_resolve_db_path(root), root)
    src_db = _find_db_in_extracted(tmp_dir, expected_rel)
    if not src_db:
        return False, "U ZIP-u ne nalazim .sqlite bazu (nema šta da restore-ujem)."

    dst_db = _resolve_db_path(root)
    dst_db.parent.mkdir(parents=True, exist_ok=True)

    try:
        # src read-only, dst normal
        src_conn = sqlite3.connect(f"file:{src_db.as_posix()}?mode=ro", uri=True)
        dst_conn = sqlite3.connect(dst_db.as_posix())

        # malo strpljenja ako nešto drži write lock
        dst_conn.execute("PRAGMA busy_timeout=2500;")
        dst_conn.execute("PRAGMA journal_mode=WAL;")
        dst_conn.execute("PRAGMA synchronous=NORMAL;")

        # backup sadržaja
        src_conn.backup(dst_conn)

        # integrity check
        cur = dst_conn.execute("PRAGMA integrity_check;")
        res = cur.fetchone()
        if not res or str(res[0]).lower() != "ok":
            raise RuntimeError(f"DB integrity_check nije OK: {res}")

        dst_conn.commit()
        src_conn.close()
        dst_conn.close()

        shutil.rmtree(tmp_dir, ignore_errors=True)
        return True, "HOT Restore baze uspeo (bez restart-a)."
    except Exception as e:
        return False, f"HOT Restore baze nije uspeo: {e}"


# -------------------------
# FULL RESTORE (managed restart)
# -------------------------

def stage_full_restore(zip_path: Path) -> Tuple[bool, str, Path]:
    """
    Zakazuje FULL restore na sledeći start (Windows-safe):
    - Validira zip
    - Kopira zip u data/restore_pending/pending_restore.zip
    - Upisuje meta json

    Vraća: (ok, msg, pending_zip_path)
    """
    root = _app_root()
    zip_path = zip_path.resolve()

    ok, msg = _validate_zip(zip_path)
    if not ok:
        return False, msg, Path("")

    pdir = _pending_dir(root)
    pdir.mkdir(parents=True, exist_ok=True)

    pending_zip = pdir / "pending_restore.zip"
    pending_meta = pdir / "pending_restore.json"

    try:
        shutil.copy2(zip_path, pending_zip)
        meta = {
            "created_at": _now_stamp(),
            "original_zip": str(zip_path),
            "pending_zip": str(pending_zip),
            "type": "FULL",
        }
        pending_meta.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        return False, f"Ne mogu da zakazem restore: {e}", Path("")

    return True, "FULL restore je zakazan za sledeći start aplikacije.", pending_zip


def _copy_tree_over(src_root: Path, dst_root: Path) -> Tuple[int, List[str]]:
    """
    Copy fajlova iz src_root u dst_root (overwrite).
    Vraća: (count, list_relpaths)
    """
    copied = 0
    rels: List[str] = []

    for src in src_root.rglob("*"):
        if src.is_dir():
            continue
        rel = src.relative_to(src_root)
        dst = dst_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)

        def _do_copy():
            # probaj prvo unlink ako postoji
            if dst.exists():
                try:
                    dst.unlink()
                except Exception:
                    pass
            shutil.copy2(src, dst)

        _retry(f"copy {rel}", _do_copy)
        copied += 1
        rels.append(str(rel).replace("\\", "/"))

    return copied, rels


def full_restore_from_zip(zip_path: Path) -> Tuple[bool, str, Path]:
    """
    FULL restore:
    1) validacija
    2) safety backup trenutnog stanja
    3) extract u data/tmp_restore
    4) copy over u root (overwrite)
    5) post-check integriteta baze
    """
    root = _app_root()
    zip_path = zip_path.resolve()

    ok, msg = _validate_zip(zip_path)
    if not ok:
        return False, msg, Path("")

    backups = _backups_dir(root)
    backups.mkdir(parents=True, exist_ok=True)
    safety_zip = backups / f"auto_pre_restore_{_now_stamp()}.zip"

    # safety backup
    try:
        create_backup_zip(safety_zip)
    except Exception as e:
        return False, f"Restore stopiran: ne mogu da napravim safety backup: {e}", Path("")

    # extract
    tmp_dir = _tmp_restore_dir(root)
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir, ignore_errors=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(tmp_dir)
    except Exception as e:
        return False, f"Ne mogu da raspakujem ZIP: {e}", safety_zip

    # copy over u root
    try:
        copied, _ = _copy_tree_over(tmp_dir, root)
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception as e:
        return False, f"Restore nije uspeo: {e}\nSafety backup: {safety_zip}", safety_zip

    # post-check
    try:
        db_path = _resolve_db_path(root)
        if db_path.exists():
            conn = sqlite3.connect(db_path.as_posix())
            conn.execute("PRAGMA busy_timeout=2500;")
            cur = conn.execute("PRAGMA integrity_check;")
            res = cur.fetchone()
            conn.close()
            if not res or str(res[0]).lower() != "ok":
                return False, f"Restore završen, ali integrity_check nije OK: {res}\nSafety backup: {safety_zip}", safety_zip
    except Exception as e:
        return False, f"Restore završen, ali post-check nije uspeo: {e}\nSafety backup: {safety_zip}", safety_zip

    return True, f"FULL restore OK. Kopirano fajlova: {copied}. Safety backup: {safety_zip}", safety_zip


def apply_pending_full_restore() -> Tuple[bool, bool, str]:
    """
    Pozvati na startu aplikacije PRE otvaranja DB-a.
    Ako postoji pending_restore.zip, izvrši FULL restore i obriše pending.

    Vraća: (did_apply, ok, msg)
    """
    root = _app_root()
    pdir = _pending_dir(root)
    pending_zip = pdir / "pending_restore.zip"

    if not pending_zip.exists():
        return False, True, "No pending restore."

    ok, msg, safety = full_restore_from_zip(pending_zip)

    if ok:
        try:
            shutil.rmtree(pdir, ignore_errors=True)
        except Exception:
            pass
        return True, True, msg

    # ako nije uspelo, NE brišemo pending, da može opet ili da se uzme log
    details = msg
    if safety:
        details += f"\nSafety backup: {safety}"
    details += "\n\nTip: zatvori sve što može da drži fajlove (Explorer u tom folderu, DB browser, antivirus scan) pa pokušaj ponovo."
    return True, False, details

# [END] FILENAME: core/backup.py