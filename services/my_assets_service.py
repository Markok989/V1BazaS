# FILENAME: services/my_assets_service.py
# (FILENAME: services/my_assets_service.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/my_assets_service.py

MY Assets servis (V1.2+):
- list_my_assets(): vraća sredstva koja trenutno DUŽI ulogovani korisnik (self-scope)
- tolerantno mapiranje kolona assets tabele (razne šeme)
- RBAC (service-level, fail-closed):
    - assets.my.view -> dozvola za čitanje "Moja oprema"
Napomena:
- self-scope: ne prima "username" parametar (uzimamo identitet iz session-a)
- 100% offline (SQLite preko core.db.connect_db)
"""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Set

# Prefer centralizovani DB konektor (isti DB kao ostatak sistema)
try:
    from core.db import connect_db  # type: ignore
except Exception:  # pragma: no cover
    connect_db = None  # type: ignore

try:
    from core.rbac import PERM_ASSETS_MY_VIEW  # type: ignore
except Exception:  # pragma: no cover
    PERM_ASSETS_MY_VIEW = "assets.my.view"


# -------------------- RBAC helpers (FAIL-CLOSED) --------------------
def _safe_can(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _must(perm: str) -> None:
    if not _safe_can(perm):
        raise PermissionError(f"RBAC: nemaš pravo ({perm}).")


# -------------------- session identity helpers --------------------
def _get_current_user_dict() -> Dict[str, Any]:
    try:
        from core.session import get_current_user  # type: ignore
        return dict(get_current_user() or {})
    except Exception:
        return {}


def _actor_name_safe() -> str:
    try:
        from core.session import actor_name  # type: ignore
        return (actor_name() or "").strip()
    except Exception:
        return ""


def _actor_key_safe() -> str:
    try:
        from core.session import actor_key  # type: ignore
        return (actor_key() or "").strip()
    except Exception:
        return ""


def _norm(s: Any) -> str:
    return ("" if s is None else str(s)).strip().casefold()


def _identity_candidates() -> List[str]:
    """
    Kandidati identiteta za poređenje sa assets.current_holder.
    Pokriva: username, display_name, id, actor_key/name, itd.
    """
    u = _get_current_user_dict()
    cand: List[str] = []

    ak = _actor_key_safe()
    if ak:
        cand.append(ak)

    an = _actor_name_safe()
    if an:
        cand.append(an)

    for k in ("username", "login", "email", "display_name", "name", "full_name", "user"):
        v = u.get(k)
        if v:
            cand.append(str(v))

    for k in ("id", "user_id", "uid"):
        v = u.get(k)
        if v is not None and str(v).strip():
            cand.append(str(v).strip())

    out: List[str] = []
    seen: Set[str] = set()
    for c in cand:
        cc = _norm(c)
        if cc and cc not in seen:
            seen.add(cc)
            out.append(cc)
    return out


def _holder_matches_me(holder_value: Any) -> bool:
    h = _norm(holder_value)
    if not h:
        return False
    cands = _identity_candidates()
    for c in cands:
        if h == c:
            return True
    # tolerantno (nekad se upisuje "Ime Prezime (username)")
    for c in cands:
        if c and (c in h or h in c):
            return True
    return False


# -------------------- DB helpers --------------------
def _row_to_dict(row: Any, cols: List[str]) -> Dict[str, Any]:
    if row is None:
        return {}
    try:
        keys = list(row.keys())  # type: ignore[attr-defined]
        return {k: row[k] for k in keys}
    except Exception:
        pass
    try:
        seq = list(row)
        if cols and len(seq) == len(cols):
            return {cols[i]: seq[i] for i in range(len(cols))}
    except Exception:
        pass
    return {}


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
        (name,),
    ).fetchone()
    return bool(r)


def _cols(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
        return [r[1] for r in rows]
    except Exception:
        return []


def _pick(cols: List[str], *names: str) -> str:
    for n in names:
        if n in cols:
            return n
    return ""


def _connect():
    if connect_db is None:
        raise RuntimeError("core.db.connect_db nije dostupan.")
    return connect_db()


# -------------------- Public API --------------------
def list_my_assets(limit: int = 5000) -> List[Dict[str, Any]]:
    """
    Vraća listu sredstava koja trenutno duži ulogovani korisnik.
    RBAC: assets.my.view
    """
    _must(PERM_ASSETS_MY_VIEW)

    lim = int(limit or 0)
    if lim <= 0:
        lim = 5000

    with _connect() as conn:
        # fail-closed: ako nema assets tabele -> prazno
        if not _table_exists(conn, "assets"):
            return []

        cols = _cols(conn, "assets")
        if "asset_uid" not in cols:
            return []

        c_uid = "asset_uid"
        c_name = _pick(cols, "name", "asset_name")
        c_cat = _pick(cols, "category", "cat")
        c_toc = _pick(cols, "toc_number", "toc")
        c_sn = _pick(cols, "serial_number", "serial", "sn")
        c_status = _pick(cols, "status", "state")
        c_loc = _pick(cols, "location", "loc")
        c_holder = _pick(cols, "current_holder", "assigned_to", "holder", "zaduzeno_kod", "kod_koga")
        c_upd = _pick(cols, "updated_at", "modified_at", "updated")

        sel: List[str] = [c_uid]
        for c in (c_name, c_cat, c_toc, c_sn, c_status, c_loc, c_holder, c_upd):
            if c and c not in sel:
                sel.append(c)

        sql = f"SELECT {', '.join(sel)} FROM assets"
        # ne filtriramo u SQL jer holder može biti u različitim kolonama/formatima;
        # filtriramo u Python-u (tolerantno + fail-closed)
        rows = conn.execute(sql).fetchall()

        out: List[Dict[str, Any]] = []
        for r in rows:
            d = _row_to_dict(r, sel)
            holder_val = d.get(c_holder, "") if c_holder else ""
            if not _holder_matches_me(holder_val):
                continue

            out.append(
                {
                    "asset_uid": str(d.get(c_uid, "") or "").strip(),
                    "name": str(d.get(c_name, "") or "").strip() if c_name else "",
                    "category": str(d.get(c_cat, "") or "").strip() if c_cat else "",
                    "toc_number": str(d.get(c_toc, "") or "").strip() if c_toc else "",
                    "serial_number": str(d.get(c_sn, "") or "").strip() if c_sn else "",
                    "status": str(d.get(c_status, "") or "").strip() if c_status else "",
                    "location": str(d.get(c_loc, "") or "").strip() if c_loc else "",
                    "current_holder": str(holder_val or "").strip(),
                    "updated_at": str(d.get(c_upd, "") or "").strip() if c_upd else "",
                }
            )

            if len(out) >= lim:
                break

        return out

# (FILENAME: services/my_assets_service.py - END)
# FILENAME: services/my_assets_service.py