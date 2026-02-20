# [START] FILENAME: core/attachments_store.py
# -*- coding: utf-8 -*-

from __future__ import annotations

import hashlib
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Union


@dataclass
class StoredFile:
    rel_path: str
    sha256: str
    size_bytes: int
    original_name: str


def _sanitize_filename(name: str, max_len: int = 120) -> str:
    name = (name or "").strip()
    if not name:
        return "file"
    name = os.path.basename(name)
    name = re.sub(r"[^\w\.\-\(\)\s]+", "_", name, flags=re.UNICODE)
    name = re.sub(r"\s+", " ", name).strip()

    if len(name) > max_len:
        p = Path(name)
        ext = p.suffix
        stem = p.stem[: max_len - len(ext) - 1]
        name = f"{stem}{ext}"
    return name or "file"


def _sha256_file(src: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with src.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def store_copy_file(app_root: Union[Path, str], src_path: str, *, override_now: Optional[datetime] = None) -> StoredFile:
    # ✅ Stabilnost: prihvati i str i Path
    app_root = Path(app_root).expanduser().resolve()

    src = Path(src_path).expanduser().resolve()
    if not src.exists() or not src.is_file():
        raise FileNotFoundError(f"Ne postoji fajl: {src}")

    now = override_now or datetime.now()
    year = f"{now.year:04d}"
    month = f"{now.month:02d}"

    store_root = app_root / "data" / "files" / year / month
    store_root.mkdir(parents=True, exist_ok=True)

    sha = _sha256_file(src)
    original = _sanitize_filename(src.name)
    dst_name = f"{sha}__{original}"
    dst = store_root / dst_name

    if not dst.exists():
        shutil.copy2(str(src), str(dst))

    # ✅ Ako iz nekog razloga relative_to ne uspe (npr. različit drive), fallback na as_posix pod data/files
    try:
        rel_path = dst.relative_to(app_root).as_posix()
    except Exception:
        rel_path = str(Path("data") / "files" / year / month / dst_name).replace("\\", "/")

    return StoredFile(
        rel_path=rel_path,
        sha256=sha,
        size_bytes=dst.stat().st_size,
        original_name=original
    )


# [END] FILENAME: core/attachments_store.py