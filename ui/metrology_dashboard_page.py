# FILENAME: ui/metrology_dashboard_page.py
# (FILENAME: ui/metrology_dashboard_page.py - START PART 1/6)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/metrology_dashboard_page.py

Hardening (bez menjanja izgleda i postojećih funkcija):
- ✅ Scope filtriranje na SQL nivou (ALL/SECTOR/MY) — sprečava curenje.
- ✅ Metrologija prikazuje SAMO sredstva koja imaju metrology flag (assets.is_metrology=1).
  * Ako kolona ne postoji u legacy bazi: fallback je "samo ona koja imaju metrology record" (bez curenja).
- ✅ Status "NEPOZNATO" ako nije unet datum etaloniranja (calib_date je prazno),
  čak i ako valid_until postoji (po zahtevu).
- ✅ DB konekcija: više ne koristimo `with connect_db() as conn` (to ne zatvara konekciju),
  nego db_conn() (ako postoji) ili ručno zatvaranje (fail-safe).
- Izgled (QSS), kolone, filteri, chip bar, status tint, sort, context menu: ostaje isto.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QRect  # type: ignore
from PySide6.QtGui import QColor, QBrush, QPainter  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QAbstractItemView,
    QComboBox,
    QCheckBox,
    QFrame,
    QMenu,
    QHeaderView,
    QSizePolicy,
    QToolButton,
    QStyledItemDelegate,
    QStyle,
    QStyleOptionViewItem,
)

log = logging.getLogger(__name__)

# -------------------- SR date/time display (FAIL-SAFE for this page) --------------------
try:
    from ui.utils.datetime_fmt import fmt_dt_sr as _base_fmt_dt_sr, fmt_date_sr as _base_fmt_date_sr  # type: ignore
except Exception:
    _base_fmt_dt_sr = None
    _base_fmt_date_sr = None

_RE_SR_DATE_ANY = re.compile(r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{4})\.?\s*$")
_RE_SR_DT_ANY = re.compile(r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{4})\.?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*$")

_RE_ISO_DATE_ANY = re.compile(r"^\s*(\d{4})[-/\.](\d{1,2})[-/\.](\d{1,2})\s*$")
_RE_ISO_DT_ANY = re.compile(r"^\s*(\d{4})[-/\.](\d{1,2})[-/\.](\d{1,2})[ T](\d{1,2}):(\d{2})(?::(\d{2}))?.*$")

# ident hardening (defanzivno — kolone dolaze iz PRAGMA, ali bolje je da ne rizikujemo)
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _is_safe_ident(name: str) -> bool:
    try:
        return bool(name) and bool(_IDENT_RE.match(str(name)))
    except Exception:
        return False


def _is_sentinel_date_iso(s: str) -> bool:
    ss = (s or "").strip()
    return ss in ("9999-12-31", "9999-12-30")


def _sr_date(y: int, m: int, d: int) -> str:
    return f"{d:02d}.{m:02d}.{y:04d}"


def _sr_dt(y: int, m: int, d: int, hh: int, mm: int) -> str:
    return f"{d:02d}.{m:02d}.{y:04d} {hh:02d}:{mm:02d}"


def fmt_date_sr(x: Any) -> str:
    s = ("" if x is None else str(x)).strip()
    if not s:
        return ""
    if _is_sentinel_date_iso(s):
        return "—"

    msr = _RE_SR_DATE_ANY.match(s)
    if msr:
        try:
            d, m, y = int(msr.group(1)), int(msr.group(2)), int(msr.group(3))
            return _sr_date(y, m, d)
        except Exception:
            return s

    try:
        if callable(_base_fmt_date_sr):
            out = str(_base_fmt_date_sr(s) or "").strip()
            if out and _RE_SR_DATE_ANY.match(out):
                return out
            if out:
                s = out
    except Exception:
        pass

    mi = _RE_ISO_DATE_ANY.match(s)
    if mi:
        try:
            y, mo, da = int(mi.group(1)), int(mi.group(2)), int(mi.group(3))
            if y == 9999 and mo == 12 and da == 31:
                return "—"
            return _sr_date(y, mo, da)
        except Exception:
            return s

    midt = _RE_ISO_DT_ANY.match(s)
    if midt:
        try:
            y, mo, da = int(midt.group(1)), int(midt.group(2)), int(midt.group(3))
            if y == 9999 and mo == 12 and da == 31:
                return "—"
            return _sr_date(y, mo, da)
        except Exception:
            return s

    return s


def fmt_dt_sr(x: Any) -> str:
    s = ("" if x is None else str(x)).strip()
    if not s:
        return ""
    if _is_sentinel_date_iso(s):
        return "—"

    msr = _RE_SR_DT_ANY.match(s)
    if msr:
        try:
            d, m, y = int(msr.group(1)), int(msr.group(2)), int(msr.group(3))
            hh, mm = int(msr.group(4)), int(msr.group(5))
            return _sr_dt(y, m, d, hh, mm)
        except Exception:
            return s

    msrd = _RE_SR_DATE_ANY.match(s)
    if msrd:
        try:
            d, m, y = int(msrd.group(1)), int(msrd.group(2)), int(msrd.group(3))
            return _sr_date(y, m, d)
        except Exception:
            return s

    try:
        if callable(_base_fmt_dt_sr):
            out = str(_base_fmt_dt_sr(s) or "").strip()
            if out and (_RE_SR_DT_ANY.match(out) or _RE_SR_DATE_ANY.match(out)):
                return out
            if out:
                s = out
    except Exception:
        pass

    mi = _RE_ISO_DT_ANY.match(s)
    if mi:
        try:
            y, mo, da = int(mi.group(1)), int(mi.group(2)), int(mi.group(3))
            if y == 9999 and mo == 12 and da == 31:
                return "—"
            hh, mm = int(mi.group(4)), int(mi.group(5))
            return _sr_dt(y, mo, da, hh, mm)
        except Exception:
            return s

    mid = _RE_ISO_DATE_ANY.match(s)
    if mid:
        try:
            y, mo, da = int(mid.group(1)), int(mid.group(2)), int(mid.group(3))
            if y == 9999 and mo == 12 and da == 31:
                return "—"
            return _sr_date(y, mo, da)
        except Exception:
            return s

    return s


def _dash_display_for_date_iso(raw_iso: str) -> str:
    s = (raw_iso or "").strip()
    if not s or _is_sentinel_date_iso(s):
        return "—"
    out = fmt_date_sr(s)
    return out if out else "—"


def _dash_display_for_dt_iso(raw_iso_dt: str) -> str:
    s = (raw_iso_dt or "").strip()
    if not s or _is_sentinel_date_iso(s):
        return "—"
    out = fmt_dt_sr(s)
    return out if out else "—"


def _truncate_middle(s: str, left: int = 12, right: int = 6) -> str:
    ss = (s or "").strip()
    if not ss:
        return ""
    if len(ss) <= (left + right + 1):
        return ss
    return f"{ss[:left]}…{ss[-right:]}"


# -------------------- table copy utils (best-effort) --------------------
try:
    from ui.utils.table_copy import (  # type: ignore
        wire_table_selection_plus_copy,
        wire_table_header_plus_copy,
        copy_selected_cells,
    )
except Exception:  # pragma: no cover
    wire_table_selection_plus_copy = None
    wire_table_header_plus_copy = None

    def copy_selected_cells(tbl: QTableWidget) -> None:
        return


# -------------------- RBAC helpers (UI-level, fail-closed) --------------------
try:
    from core.rbac import PERM_METRO_VIEW  # type: ignore
except Exception:  # pragma: no cover
    PERM_METRO_VIEW = "metrology.view"


def _can(perm: str) -> bool:
    try:
        from core.session import can  # type: ignore
        return bool(can(perm))
    except Exception:
        return False


def _get_current_user_dict() -> Dict[str, Any]:
    try:
        from core.session import get_current_user  # type: ignore
        return dict(get_current_user() or {})
    except Exception:
        return {}


def _active_role_safe() -> str:
    try:
        from core.session import active_role  # type: ignore
        r = str(active_role() or "").strip().upper()
        if r:
            return r
    except Exception:
        pass
    u = _get_current_user_dict()
    return str(u.get("active_role") or u.get("role") or u.get("user_role") or "READONLY").strip().upper()


def _current_sector_safe() -> str:
    try:
        from core.session import current_sector  # type: ignore
        s = str(current_sector() or "").strip()
        if s:
            return s
    except Exception:
        pass
    u = _get_current_user_dict()
    return str(u.get("active_sector") or u.get("sector") or u.get("org_unit") or u.get("unit") or "").strip()


def _effective_scope_from_session() -> str:
    try:
        from core.session import effective_scope  # type: ignore
        return str(effective_scope() or "").strip().upper()
    except Exception:
        return ""


def _actor_name_safe() -> str:
    """
    BITNO: ne vraćamo placeholder "user" za identitet.
    Ako ne znamo ko si -> "" (fail-closed za MY filter).
    """
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
    seen = set()
    for c in cand:
        cc = _norm(c)
        if cc and cc not in seen:
            seen.add(cc)
            out.append(cc)
    return out


_TOKEN_SPLIT_RE = re.compile(r"[^0-9a-zA-Z\u0106\u0107\u010c\u010d\u0160\u0161\u017d\u017e\u0110\u0111]+")


def _tokens(s: str) -> List[str]:
    ss = _norm(s)
    if not ss:
        return []
    return [t for t in _TOKEN_SPLIT_RE.split(ss) if t]


def _holder_matches_me(holder_value: Any, *, cands: Optional[List[str]] = None) -> bool:
    """
    Client-side filter ("Samo moja sredstva"):
    - prvo exact match (casefold)
    - zatim token match (kandidat >=4 znaka) da izbegnemo lažna poklapanja
    """
    h = _norm(holder_value)
    if not h:
        return False
    ccands = cands if cands is not None else _identity_candidates()
    if not ccands:
        return False

    for c in ccands:
        if h == c:
            return True

    ht = set(_tokens(h))
    if not ht:
        return False

    for c in ccands:
        if len(c) < 4:
            continue
        if c in ht:
            return True
    return False


def _copy_text_to_clipboard(text: str) -> None:
    try:
        from PySide6.QtWidgets import QApplication  # type: ignore
        QApplication.clipboard().setText(text or "")
    except Exception:
        pass


def _wire_table_copy(table: QTableWidget) -> None:
    try:
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
    except Exception:
        pass

    try:
        if wire_table_selection_plus_copy is not None:
            wire_table_selection_plus_copy(table)
            return
    except Exception:
        pass

    try:
        if wire_table_header_plus_copy is not None:
            wire_table_header_plus_copy(table)
    except Exception:
        pass


# -------------------- DB helpers --------------------
def _db_path_fallback() -> str:
    """
    Jedno mesto za DB path (sprečava “dve baze”).
    Preferiraj core.db.get_db_path (resolve), pa core.config.DB_FILE.
    """
    try:
        from core.db import get_db_path  # type: ignore
        p = str(get_db_path() or "").strip()
        if p:
            return p
    except Exception:
        pass
    try:
        from core.config import DB_FILE  # type: ignore
        return str(DB_FILE)
    except Exception:
        return "data/db/bazas2.sqlite"

# (FILENAME: ui/metrology_dashboard_page.py - END PART 1/6)

# FILENAME: ui/metrology_dashboard_page.py
# (FILENAME: ui/metrology_dashboard_page.py - START PART 2/6)

@contextmanager
def _connect_db():
    """
    UVEK zatvara konekciju:
    - prefer core.db.db_conn() (siguran CM)
    - fallback: core.db.connect_db() + manual close (NE koristimo ga kao CM)
    - last resort: sqlite3.connect(DB_FILE)
    """
    # 1) Prefer db_conn (zatvara konekciju)
    try:
        from core.db import db_conn  # type: ignore
        with db_conn() as conn:
            try:
                conn.row_factory = sqlite3.Row
            except Exception:
                pass
            yield conn
        return
    except Exception:
        pass

    # 2) connect_db exists but is NOT a closing CM -> close manually
    try:
        from core.db import connect_db  # type: ignore
        conn = connect_db()
        try:
            try:
                conn.row_factory = sqlite3.Row
            except Exception:
                pass
            yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return
    except Exception:
        pass

    # 3) Last resort sqlite3 direct
    conn2 = sqlite3.connect(_db_path_fallback(), timeout=5.0)
    try:
        conn2.row_factory = sqlite3.Row
    except Exception:
        pass
    try:
        try:
            conn2.execute("PRAGMA busy_timeout=2500;")
            conn2.execute("PRAGMA foreign_keys=ON;")
        except Exception:
            pass
        yield conn2
    finally:
        try:
            conn2.close()
        except Exception:
            pass


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    if not name:
        return False
    try:
        r = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
            (name,),
        ).fetchone()
        return bool(r)
    except Exception:
        return False


def _cols(conn: sqlite3.Connection, table: str) -> List[str]:
    # table name mora biti safe ident (PRAGMA ne prima parametar)
    if not _is_safe_ident(table):
        return []
    try:
        rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
        out: List[str] = []
        for r in rows:
            try:
                out.append(str(r["name"]))
            except Exception:
                try:
                    out.append(str(r[1]))
                except Exception:
                    pass
        return out
    except Exception:
        return []


def _pick_col(cols: List[str], candidates: Tuple[str, ...]) -> str:
    s = set(cols or [])
    for c in candidates:
        if c in s:
            return c
    return ""


def _role_is_sector_pref(role: str) -> bool:
    r = (role or "").strip().upper()
    return r in ("SECTOR_ADMIN", "REFERENT_IT", "REFERENT_OS", "REFERENT_METRO")


def _resolve_scope_for_dashboard(conn: sqlite3.Connection, *, col_sector: str, col_holder: str) -> str:
    """
    Scope resolve (bez menjanja UI):
    - Session scope je primarni (ALL/SECTOR/MY)
    - ALL samo ADMIN
    - Sector-role preferira SECTOR kad je tehnički moguće (sector kolona + current_sector)
    - Ako SECTOR nije moguće -> MY (ako je moguće), inače MY (pa će predicate postati 0=1)
    """
    role = _active_role_safe()
    sc = _effective_scope_from_session()

    if sc == "ALL" and role != "ADMIN":
        sc = "SECTOR"
    if sc not in ("ALL", "SECTOR", "MY"):
        sc = "MY"

    if role == "ADMIN":
        return "ALL" if sc == "ALL" else sc

    # micro-opt: candidates računamo jednom
    cands = _identity_candidates()
    sector_ok = bool(col_sector) and bool(_current_sector_safe())
    my_ok = bool(col_holder) and bool(cands)

    if _role_is_sector_pref(role):
        if sector_ok:
            return "SECTOR"
        return "MY" if my_ok else "MY"

    if sc == "SECTOR":
        return "SECTOR" if sector_ok else ("MY" if my_ok else "MY")
    if sc == "MY":
        return "MY" if my_ok else "MY"
    return "MY" if my_ok else "MY"


def _scope_where_and_params(
    conn: sqlite3.Connection,
    *,
    scope: str,
    col_sector: str,
    col_holder: str,
) -> Tuple[str, List[Any]]:
    """
    Vraća SQL WHERE dodatak (string koji počinje sa AND...) + params.
    Fail-closed: ako fali identitet/kolone -> AND 0=1.
    """
    sc = (scope or "").strip().upper()

    # hardening: kolone idu u f-string
    if sc == "SECTOR" and col_sector and (not _is_safe_ident(col_sector)):
        return " AND 0=1", []
    if sc == "MY" and col_holder and (not _is_safe_ident(col_holder)):
        return " AND 0=1", []

    if sc == "ALL":
        return "", []

    if sc == "SECTOR":
        sec = _current_sector_safe()
        if not (col_sector and sec):
            return " AND 0=1", []
        return f" AND LOWER(TRIM(COALESCE(a.{col_sector},''))) = LOWER(TRIM(?))", [sec]

    # MY
    cands = _identity_candidates()
    if not (col_holder and cands):
        return " AND 0=1", []

    ors: List[str] = []
    params: List[Any] = []
    for c in cands:
        ors.append(f"LOWER(TRIM(COALESCE(a.{col_holder},''))) = ?")
        params.append(c)
    return " AND (" + " OR ".join(ors) + ")", params


def _met_status(calib_date_iso: str, valid_until_iso: str, warn_days: int) -> str:
    """
    NOVO (po zahtevu):
    - ako calib_date nije unet -> NEPOZNATO
    - inače status po valid_until
    """
    cd = (calib_date_iso or "").strip()
    if not cd:
        return "NEPOZNATO"

    vu = (valid_until_iso or "").strip()
    if not vu or _is_sentinel_date_iso(vu):
        return "NEPOZNATO"

    try:
        y, m, d = [int(x) for x in vu.split("-")]
        vu_date = date(y, m, d)
    except Exception:
        return "NEPOZNATO"

    today = date.today()
    if vu_date < today:
        return "ISTEKLO"

    try:
        wd = int(warn_days)
    except Exception:
        wd = 30
    if wd < 0:
        wd = 0

    if (vu_date - today).days <= wd:
        return "ISTIČE"
    return "OK"


@dataclass
class MetroDashRow:
    rb: Optional[int]
    asset_uid: str
    name: str
    category: str
    holder: str
    sector: str
    location: str
    last_assigned_at: str
    met_uid: str
    calib_date: str  # ✅ treba za status recalculation kad warn_days promeniš
    valid_until: str
    status: str


def _fetch_dashboard_rows(warn_days: int = 30) -> List[MetroDashRow]:
    """
    VAŽNO:
    - SQL scope-aware (sprečava curenje)
    - prikazuje samo assets sa metrology flag (is_metrology=1) ako postoji kolona,
      inače fallback: samo assets koji imaju bar jedan metrology record (bez curenja).
    - status = NEPOZNATO ako calib_date nije unet.
    """
    with _connect_db() as conn:
        if not _table_exists(conn, "assets") or not _table_exists(conn, "metrology_records"):
            return []

        a_cols = _cols(conn, "assets")
        m_cols = _cols(conn, "metrology_records")

        col_rb = _pick_col(a_cols, ("rb", "RB", "rownum", "row_no", "redni_broj"))
        col_uid = _pick_col(a_cols, ("asset_uid", "uid"))
        col_name = _pick_col(a_cols, ("name", "naziv", "asset_name"))
        col_cat = _pick_col(a_cols, ("category", "kategorija", "cat"))
        col_holder = _pick_col(a_cols, ("current_holder", "assigned_to", "holder", "zaduzeno_kod", "kod_koga"))
        col_sector = _pick_col(a_cols, ("sector", "sektor", "org_unit", "unit", "department", "dept"))
        col_loc = _pick_col(a_cols, ("location", "lokacija", "loc"))
        col_assigned_at = _pick_col(a_cols, ("last_assigned_at", "assigned_at", "zaduzeno_od", "assigned_time"))
        col_updated = _pick_col(a_cols, ("updated_at", "modified_at", "updated", "last_update"))
        col_asset_status = _pick_col(a_cols, ("status", "asset_status", "state"))

        # ✅ metrology flag kolona (ako postoji)
        col_is_metro = _pick_col(a_cols, ("is_metrology", "is_metro", "metrology_flag", "metro_flag"))

        col_m_asset = _pick_col(m_cols, ("asset_uid",))
        col_m_uid = _pick_col(m_cols, ("met_uid", "uid"))
        col_m_valid = _pick_col(m_cols, ("valid_until",))
        col_m_calib = _pick_col(m_cols, ("calib_date", "calibration_date", "etalon_date"))
        col_m_updated = _pick_col(m_cols, ("updated_at", "modified_at", "updated"))

        # hardening: identi moraju biti safe pre f-string
        for nm in (col_rb, col_uid, col_name, col_cat, col_holder, col_sector, col_loc, col_assigned_at, col_updated, col_asset_status,
                   col_is_metro, col_m_asset, col_m_uid, col_m_valid, col_m_calib, col_m_updated):
            if nm and (not _is_safe_ident(nm)):
                # ako je schema “čudna”, fail-closed
                return []

        if not col_uid or not col_m_asset or not col_m_uid or not col_m_valid:
            return []

        last_time_col = col_assigned_at if col_assigned_at else col_updated
        if last_time_col and (not _is_safe_ident(last_time_col)):
            last_time_col = col_updated if (col_updated and _is_safe_ident(col_updated)) else ""

        # exclude retired/scrapped assets (postojeće ponašanje)
        where_retired = ""
        if col_asset_status:
            where_retired = f"""
              AND NOT (
                LOWER(COALESCE(a.{col_asset_status},'')) LIKE '%rashod%'
                OR LOWER(COALESCE(a.{col_asset_status},'')) LIKE '%otpis%'
                OR LOWER(COALESCE(a.{col_asset_status},'')) IN ('retired','disposed','decommissioned','inactive','archived')
              )
            """

        # scope predicate
        scope = _resolve_scope_for_dashboard(conn, col_sector=col_sector, col_holder=col_holder)
        where_scope, params_scope = _scope_where_and_params(conn, scope=scope, col_sector=col_sector, col_holder=col_holder)

        sel_rb = f"COALESCE(a.{col_rb}, NULL) AS rb," if col_rb else "NULL AS rb,"

        # ✅ metrology-only filter:
        # - ako postoji flag kolona -> enforce flag=1
        # - ako ne postoji -> fallback: samo assets koji imaju metrology record (l.met_uid nije prazan)
        where_metro_only = ""
        if col_is_metro:
            where_metro_only = f" AND COALESCE(a.{col_is_metro},0)=1"

        # CTE: latest metrology record po max valid_until, pa tie-breaker po updated_at
        select_calib = f", COALESCE(mr.{col_m_calib}, '') AS calib_date" if col_m_calib else ", '' AS calib_date"

        sql = f"""
        WITH latest_valid AS (
            SELECT
                {col_m_asset} AS asset_uid,
                MAX(date({col_m_valid})) AS max_vu
            FROM metrology_records
            WHERE COALESCE(is_deleted,0)=0
              AND COALESCE({col_m_valid}, '') <> ''
            GROUP BY {col_m_asset}
        ),
        latest_pick AS (
            SELECT
                mr.{col_m_asset} AS asset_uid,
                mr.{col_m_uid} AS met_uid,
                mr.{col_m_valid} AS valid_until,
                COALESCE(mr.{col_m_updated}, '') AS updated_at
                {select_calib}
            FROM metrology_records mr
            JOIN latest_valid lv
              ON lv.asset_uid = mr.{col_m_asset}
             AND date(mr.{col_m_valid}) = lv.max_vu
            WHERE COALESCE(mr.is_deleted,0)=0
        ),
        latest_one AS (
            SELECT lp.*
            FROM latest_pick lp
            JOIN (
                SELECT asset_uid, MAX(datetime(updated_at)) AS mx
                FROM latest_pick
                GROUP BY asset_uid
            ) t
            ON t.asset_uid = lp.asset_uid AND datetime(lp.updated_at) = t.mx
        )
        SELECT
            {sel_rb}
            a.{col_uid} AS asset_uid,
            COALESCE(a.{col_name}, '') AS name,
            COALESCE(a.{col_cat}, '') AS category,
            COALESCE(a.{col_holder}, '') AS holder,
            COALESCE(a.{col_sector}, '') AS sector,
            COALESCE(a.{col_loc}, '') AS location,
            COALESCE(a.{last_time_col}, '') AS last_assigned_at,
            COALESCE(l.met_uid, '') AS met_uid,
            COALESCE(l.calib_date, '') AS calib_date,
            COALESCE(l.valid_until, '') AS valid_until
        FROM assets a
        LEFT JOIN latest_one l
          ON l.asset_uid = a.{col_uid}
        WHERE 1=1
        {where_retired}
        {where_scope}
        {where_metro_only}
        ;
        """

        try:
            rows = conn.execute(sql, tuple(params_scope)).fetchall()
        except Exception as e:
            try:
                log.exception("Metrology dashboard SQL failed: %s", e)
            except Exception:
                pass
            return []

        out: List[MetroDashRow] = []
        for r in rows:
            asset_uid = str(r["asset_uid"] or "").strip()
            if not asset_uid:
                continue

            met_uid = str(r["met_uid"] or "").strip()

            # ✅ fallback ako nema flag kolone: samo ona koja imaju metrology record (bez curenja)
            if not col_is_metro and (not met_uid):
                continue

            rb_val: Optional[int] = None
            try:
                rv = r["rb"]
                if rv is not None and str(rv).strip() != "":
                    rb_val = int(rv)
            except Exception:
                rb_val = None

            name = str(r["name"] or "").strip()
            category = str(r["category"] or "").strip()
            holder = str(r["holder"] or "").strip()
            sector = str(r["sector"] or "").strip()
            location = str(r["location"] or "").strip()
            last_assigned_at = str(r["last_assigned_at"] or "").strip()
            calib_date = str(r["calib_date"] or "").strip()
            valid_until = str(r["valid_until"] or "").strip()

            st = _met_status(calib_date, valid_until, warn_days)

            out.append(
                MetroDashRow(
                    rb=rb_val,
                    asset_uid=asset_uid,
                    name=name,
                    category=category,
                    holder=holder,
                    sector=sector,
                    location=location,
                    last_assigned_at=last_assigned_at,
                    met_uid=met_uid,
                    calib_date=calib_date,
                    valid_until=valid_until,
                    status=st,
                )
            )

        order_rank = {"ISTEKLO": 0, "ISTIČE": 1, "OK": 2, "NEPOZNATO": 3}

        def _key(x: MetroDashRow):
            vu = x.valid_until or "9999-12-31"
            rbk = x.rb if (x.rb is not None) else 10**12
            return (order_rank.get(x.status, 9), vu, rbk, x.asset_uid)

        out.sort(key=_key)
        return out


def _kpi_counts(rows: List[MetroDashRow]) -> Dict[str, int]:
    c = {"ISTEKLO": 0, "ISTIČE": 0, "OK": 0, "NEPOZNATO": 0, "UKUPNO": 0}
    c["UKUPNO"] = len(rows)
    for r in rows:
        if r.status in c:
            c[r.status] += 1
        else:
            c["NEPOZNATO"] += 1
    return c

# (FILENAME: ui/metrology_dashboard_page.py - END PART 2/6)

# FILENAME: ui/metrology_dashboard_page.py
# (FILENAME: ui/metrology_dashboard_page.py - START PART 3/6)

# Module logger (koristi se u DB delu; OK je i ako je definisan posle funkcija – global lookup je runtime)
log = logging.getLogger(__name__)

# -------------------- THEME (PRO DARK) --------------------
DASH_QSS = """
QWidget#MetroDashRoot { background: #12141a; color: #e7e9f1; font-size: 12px; }
QLabel#title { font-size: 20px; font-weight: 900; }

QLineEdit {
  background: #171a22;
  border: 1px solid #2a3040;
  border-radius: 10px;
  padding: 8px 10px;
}
QLineEdit:focus { border: 1px solid #2e6bff; }

QComboBox {
  background: #171a22;
  border: 1px solid #2a3040;
  border-radius: 10px;
  padding: 6px 10px;
}
QComboBox::drop-down { border: 0px; width: 22px; }
QComboBox QAbstractItemView { background: #171a22; border: 1px solid #2a3040; selection-background-color: #24355f; }

QCheckBox { spacing: 8px; color: #d7dbe6; }
QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #2a3040; background: #171a22; }
QCheckBox::indicator:checked { background: #2e6bff; border: 1px solid #2e6bff; }

QPushButton, QToolButton {
  background: #171a22;
  border: 1px solid #2a3040;
  border-radius: 10px;
  padding: 8px 14px;
}
QPushButton:hover, QToolButton:hover { border: 1px solid #2e6bff; }
QPushButton:pressed, QToolButton:pressed { background: #141724; }
QPushButton:disabled, QToolButton:disabled { color: #7b849c; background: #141724; border: 1px solid #23283a; }

QPushButton#primary {
  background: #2e6bff;
  border: 1px solid #2e6bff;
  color: #ffffff;
  font-weight: 900;
}
QPushButton#primary:hover { background: #255df0; }

QToolButton#StatusBtn {
  padding: 7px 12px;
  border-radius: 12px;
  font-weight: 900;
}
QToolButton#StatusBtn:checked {
  border: 1px solid #3a7bff;
  background: #162547;
}

QToolButton#FocusBtn {
  padding: 7px 12px;
  border-radius: 12px;
  font-weight: 900;
}
QToolButton#FocusBtn:checked {
  border: 1px solid #3a7bff;
  background: #14203b;
}

QToolButton#ColsBtn {
  padding: 7px 12px;
  border-radius: 12px;
  font-weight: 900;
}

QFrame#kpiCard {
  background: #161a24;
  border: 1px solid #2a3040;
  border-radius: 14px;
}
QFrame#kpiCard:hover { border: 1px solid #3a7bff; }
QFrame#kpiAccent { border-radius: 3px; }

QFrame#ChipBar {
  background: #131726;
  border: 1px solid #232a3a;
  border-radius: 12px;
}
QPushButton#ChipX {
  padding: 2px 7px;
  border-radius: 9px;
  font-weight: 900;
  background: #1a1f2f;
  border: 1px solid #2a3040;
}
QPushButton#ChipX:hover { border: 1px solid #3a7bff; }

QTableWidget {
  background: #121624;
  border: 1px solid #2a3040;
  border-radius: 12px;
  gridline-color: #2b3346;
  alternate-background-color: #111a2a;
  selection-background-color: #223a66;
  selection-color: #ffffff;
}
QTableWidget::item {
  padding: 7px 10px;
  border-bottom: 1px solid #1d2434;
  border-right: 1px solid #1d2434;
  color: #d7dbe6;
}
QTableWidget::item:hover { background: #172544; }
QTableWidget::item:selected { background: #223a66; color: #ffffff; }

QHeaderView::section {
  background: #171a22;
  color: #dfe3ee;
  border: 0px;
  border-bottom: 2px solid #2b3346;
  border-right: 1px solid #2b3346;
  padding: 10px 10px;
  font-weight: 900;
}

QScrollBar:vertical {
  background: #0f1116;
  width: 12px;
  margin: 8px 2px 8px 2px;
  border-radius: 6px;
}
QScrollBar::handle:vertical {
  background: #2a3040;
  min-height: 30px;
  border-radius: 6px;
}
QScrollBar::handle:vertical:hover { background: #3a4460; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }

QScrollBar:horizontal {
  background: #0f1116;
  height: 12px;
  margin: 2px 8px 2px 8px;
  border-radius: 6px;
}
QScrollBar::handle:horizontal {
  background: #2a3040;
  min-width: 30px;
  border-radius: 6px;
}
QScrollBar::handle:horizontal:hover { background: #3a7bff; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }
"""


class _KpiCard(QFrame):
    def __init__(self, title: str, accent_color: str, parent=None):
        super().__init__(parent)
        self.setObjectName("kpiCard")
        self.setFixedSize(190, 74)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        self.accent = QFrame()
        self.accent.setObjectName("kpiAccent")
        self.accent.setFixedWidth(6)
        self.accent.setStyleSheet(f"QFrame#kpiAccent {{ background: {accent_color}; }}")

        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(2)

        self.lb_title = QLabel(title)
        self.lb_title.setStyleSheet("font-size: 12px; color: #aab2c5; font-weight: 800;")

        self.lb_value = QLabel("0")
        self.lb_value.setStyleSheet("font-size: 24px; font-weight: 950; color: #ffffff;")

        right.addWidget(self.lb_title)
        right.addWidget(self.lb_value, 1)

        lay.addWidget(self.accent)
        lay.addLayout(right, 1)

    def set_value(self, v: int) -> None:
        try:
            self.lb_value.setText(str(int(v)))
        except Exception:
            self.lb_value.setText("0")


class _SortKeyItem(QTableWidgetItem):
    def __init__(self, text: str, sort_value: Any = None):
        super().__init__(text)
        self._sort_value = sort_value

    def __lt__(self, other) -> bool:
        try:
            a = getattr(self, "_sort_value", None)
            b = getattr(other, "_sort_value", None) if isinstance(other, QTableWidgetItem) else None
            if a is None or b is None:
                return super().__lt__(other)

            try:
                if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                    return a < b
                sa, sb = str(a), str(b)
                if sa.isdigit() and sb.isdigit():
                    return int(sa) < int(sb)
            except Exception:
                pass

            return str(a) < str(b)
        except Exception:
            return super().__lt__(other)


def _status_badge_style(item: QTableWidgetItem, status: str) -> None:
    st = (status or "").strip().upper()

    if st == "ISTEKLO":
        item.setForeground(QBrush(QColor("#ffd0d4")))
    elif st in ("ISTIČE", "ISTICE"):
        item.setForeground(QBrush(QColor("#ffe8b8")))
    elif st == "OK":
        item.setForeground(QBrush(QColor("#c8f7d6")))
    else:
        item.setForeground(QBrush(QColor("#d7dbe6")))

    f = item.font()
    f.setBold(True)
    item.setFont(f)


class _RowStatusTintDelegate(QStyledItemDelegate):
    def __init__(self, table: QTableWidget, status_col: int = 0, accent_px: int = 3):
        super().__init__(table)
        self._tbl = table
        self._status_col = int(status_col)
        self._accent_px = int(accent_px)

        self._palette = {
            "ISTEKLO": (QColor("#ff4d57"), QColor("#241417")),
            "ISTIČE": (QColor("#ffcc00"), QColor("#232013")),
            "ISTICE": (QColor("#ffcc00"), QColor("#232013")),
            "OK": (QColor("#22c55e"), QColor("#142418")),
            "NEPOZNATO": (QColor("#a0a6b6"), QColor("#171a22")),
        }

    def _status_for_row(self, row: int) -> str:
        try:
            it = self._tbl.item(row, self._status_col)
            st = (it.text() if it else "") or ""
            st = st.strip().upper()
            return st if st else "NEPOZNATO"
        except Exception:
            return "NEPOZNATO"

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        try:
            row = int(index.row())
            col = int(index.column())
        except Exception:
            super().paint(painter, option, index)
            return

        st = self._status_for_row(row)
        accent, tint = self._palette.get(st, self._palette["NEPOZNATO"])
        is_selected = bool(option.state & QStyle.State_Selected)

        painter.save()
        if not is_selected:
            painter.fillRect(option.rect, tint)

        # leva akcent traka (na prvoj koloni)
        if col == 0:
            r = QRect(option.rect)
            stripe = QRect(r.left(), r.top(), self._accent_px, r.height())
            painter.fillRect(stripe, accent)

        painter.restore()
        super().paint(painter, option, index)


class _Chip(QFrame):
    def __init__(self, text: str, on_close, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 6, 10, 6)
        lay.setSpacing(8)

        self.lb = QLabel(text)
        self.lb.setStyleSheet("color:#dfe3ee; font-weight:800;")
        lay.addWidget(self.lb)

        self.x = QPushButton("×")
        self.x.setObjectName("ChipX")
        self.x.setFixedSize(24, 22)
        self.x.clicked.connect(on_close)
        lay.addWidget(self.x)

        self.setStyleSheet("""
        QFrame {
          background:#141a2a;
          border: 1px solid #232a3a;
          border-radius: 12px;
        }
        """)


@contextmanager
def _block_signals(*widgets: Any):
    """
    Stabilno blokiranje signala (da ne ostane zaglavljeno ako se desi exception).
    """
    try:
        for w in widgets:
            try:
                w.blockSignals(True)
            except Exception:
                pass
        yield
    finally:
        for w in widgets:
            try:
                w.blockSignals(False)
            except Exception:
                pass


class MetrologyDashboardPage(QWidget):
    COLS = [
        "#",
        "Status", "Važi do", "Met UID",
        "UID", "Naziv", "Kategorija",
        "Nosilac", "Sektor", "Lokacija", "Zaduženo od",
    ]

    C_NO = 0
    C_STATUS = 1
    C_VALID_UNTIL = 2
    C_MET_UID = 3
    C_UID = 4
    C_NAME = 5
    C_CAT = 6
    C_HOLDER = 7
    C_SECTOR = 8
    C_LOC = 9
    C_ASSIGNED = 10

    def __init__(self, logger: logging.Logger, parent=None):
        super().__init__(parent)
        self.setObjectName("MetroDashRoot")
        self.setStyleSheet(DASH_QSS)

        self.logger = logger
        self._rows: List[MetroDashRow] = []
        self._force_default_sort: bool = False

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(10)

        title = QLabel("Metrologija Dashboard")
        title.setObjectName("title")
        top.addWidget(title)
        top.addStretch(1)

        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("Pretraga (UID / naziv / nosilac / sektor / status)...")
        self.ed_search.setClearButtonEnabled(True)
        self.ed_search.setFixedWidth(520)
        top.addWidget(self.ed_search)

        self.lbl_warn = QLabel("Alarm (dana):")
        self.lbl_warn.setStyleSheet("color:#aab2c5; font-weight:700;")
        self.cb_warn = QComboBox()
        self.cb_warn.addItems(["7", "14", "30", "60", "90"])
        self.cb_warn.setCurrentText("30")
        self.cb_warn.setFixedWidth(90)
        top.addWidget(self.lbl_warn)
        top.addWidget(self.cb_warn)

        # ✅ dugme za osvežavanje ostaje
        self.btn_refresh = QPushButton("Osveži")
        self.btn_refresh.setObjectName("primary")
        self.btn_refresh.setFixedWidth(120)
        top.addWidget(self.btn_refresh)

        kpi = QHBoxLayout()
        kpi.setSpacing(12)

        self.kpi_overdue = _KpiCard("Isteklo", "#ff4d57")
        self.kpi_due = _KpiCard("Ističe uskoro", "#ffcc00")
        self.kpi_ok = _KpiCard("Validno", "#22c55e")
        self.kpi_total = _KpiCard("Ukupno", "#3b82f6")

        kpi.addWidget(self.kpi_overdue)
        kpi.addWidget(self.kpi_due)
        kpi.addWidget(self.kpi_ok)
        kpi.addWidget(self.kpi_total)
        kpi.addStretch(1)

        status_row = QHBoxLayout()
        status_row.setSpacing(10)

        self.btn_st_overdue = self._mk_status_btn("Isteklo", "#ff4d57")
        self.btn_st_due = self._mk_status_btn("Ističe", "#ffcc00")
        self.btn_st_ok = self._mk_status_btn("OK", "#22c55e")
        self.btn_st_unknown = self._mk_status_btn("Nepoznato", "#a0a6b6")

        for b in (self.btn_st_overdue, self.btn_st_due, self.btn_st_ok, self.btn_st_unknown):
            b.setChecked(True)

        self.btn_focus = QToolButton()
        self.btn_focus.setObjectName("FocusBtn")
        self.btn_focus.setText("Fokus: samo kritično")
        self.btn_focus.setCheckable(True)
        self.btn_focus.setToolTip("Uključi Isteklo+Ističe, sakrij OK/Nepoznato.")

        self.btn_cols_default = QToolButton()
        self.btn_cols_default.setObjectName("ColsBtn")
        self.btn_cols_default.setText("Kolone: default")
        self.btn_cols_default.setToolTip("Vrati raspored kolona na podrazumevani (samo prikaz).")

        self.btn_filters_reset = QToolButton()
        self.btn_filters_reset.setObjectName("ColsBtn")
        self.btn_filters_reset.setText("Reset filtera")
        self.btn_filters_reset.setToolTip("Vrati pretragu, status filtere, fokus, 'Samo moja' i alarm na default (SVE prikazano).")

        status_row.addWidget(QLabel("Status filteri:"))
        status_row.addWidget(self.btn_st_overdue)
        status_row.addWidget(self.btn_st_due)
        status_row.addWidget(self.btn_st_ok)
        status_row.addWidget(self.btn_st_unknown)
        status_row.addSpacing(10)
        status_row.addWidget(self.btn_focus)
        status_row.addStretch(1)
        status_row.addWidget(self.btn_cols_default)
        status_row.addWidget(self.btn_filters_reset)

        flt = QHBoxLayout()
        flt.setSpacing(14)

        self.ck_my = QCheckBox("Samo moja sredstva")
        flt.addWidget(self.ck_my)
        flt.addStretch(1)

        self.btn_open_asset = QPushButton("Otvori sredstvo")
        self.btn_open_asset.setEnabled(False)
        flt.addWidget(self.btn_open_asset)

        self.btn_open_met_list = QPushButton("Otvori metrologiju (lista)")
        self.btn_open_met_list.setEnabled(False)
        flt.addWidget(self.btn_open_met_list)

        self.chip_wrap = QFrame()
        self.chip_wrap.setObjectName("ChipBar")
        self.chip_wrap.setStyleSheet("""
        QFrame#ChipBar{
          background:#131726;
          border: 1px solid #232a3a;
          border-radius: 12px;
        }
        """)
        self.chip_lay = QHBoxLayout(self.chip_wrap)
        self.chip_lay.setContentsMargins(10, 8, 10, 8)
        self.chip_lay.setSpacing(8)

        self.lb_chips_title = QLabel("Aktivni filteri:")
        self.lb_chips_title.setStyleSheet("color:#aab2c5; font-weight:900;")
        self.chip_lay.addWidget(self.lb_chips_title)
        self.chip_lay.addStretch(1)
        self.chip_wrap.setVisible(False)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("color: #2a3040;")

        self.tbl = QTableWidget(0, len(self.COLS))
        self.tbl.setHorizontalHeaderLabels(self.COLS)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setShowGrid(True)
        self.tbl.setGridStyle(Qt.SolidLine)
        self.tbl.verticalHeader().setVisible(False)

        self.tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tbl.setSortingEnabled(True)

        try:
            self.tbl.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
            self.tbl.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        except Exception:
            pass

        hdr = self.tbl.horizontalHeader()
        hdr.setDefaultAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        hdr.setFixedHeight(38)
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)
        hdr.setSectionsMovable(True)
        hdr.setSectionsClickable(True)
        hdr.setSortIndicatorShown(True)

        self.tbl.verticalHeader().setDefaultSectionSize(32)

        self.tbl.setColumnWidth(self.C_NO, 58)
        self.tbl.setColumnWidth(self.C_STATUS, 120)
        self.tbl.setColumnWidth(self.C_VALID_UNTIL, 110)
        self.tbl.setColumnWidth(self.C_MET_UID, 180)
        self.tbl.setColumnWidth(self.C_UID, 150)
        self.tbl.setColumnWidth(self.C_NAME, 320)
        self.tbl.setColumnWidth(self.C_CAT, 120)
        self.tbl.setColumnWidth(self.C_HOLDER, 160)
        self.tbl.setColumnWidth(self.C_SECTOR, 90)
        self.tbl.setColumnWidth(self.C_LOC, 140)
        self.tbl.setColumnWidth(self.C_ASSIGNED, 160)

        _wire_table_copy(self.tbl)
        self.tbl.setItemDelegate(_RowStatusTintDelegate(self.tbl, status_col=self.C_STATUS, accent_px=3))

        self.tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tbl.customContextMenuRequested.connect(self._on_context_menu)
        self.tbl.itemSelectionChanged.connect(self._sync_buttons)
        self.tbl.cellDoubleClicked.connect(self._on_double_click)

        self.lb_rbac = QLabel("")
        self.lb_rbac.setStyleSheet("color: #ff7b7b; font-weight: 800;")
        self.lb_rbac.setVisible(False)
        self.lb_rbac.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        main = QVBoxLayout(self)
        main.setContentsMargins(16, 14, 16, 16)
        main.setSpacing(12)
        main.addLayout(top)
        main.addLayout(kpi)
        main.addLayout(status_row)
        main.addLayout(flt)
        main.addWidget(self.chip_wrap)
        main.addWidget(sep)
        main.addWidget(self.lb_rbac)
        main.addWidget(self.tbl, 1)

        # wiring
        self.btn_refresh.clicked.connect(self.refresh)
        self.ed_search.textChanged.connect(self._apply_filter)
        self.ed_search.returnPressed.connect(self._focus_first_row)
        self.cb_warn.currentIndexChanged.connect(self._apply_filter)
        self.ck_my.stateChanged.connect(self._apply_filter)

        for b in (self.btn_st_overdue, self.btn_st_due, self.btn_st_ok, self.btn_st_unknown):
            b.toggled.connect(self._on_status_toggle)

        self.btn_focus.toggled.connect(self._on_focus_toggle)
        self.btn_cols_default.clicked.connect(self._reset_columns_default)
        self.btn_filters_reset.clicked.connect(self._reset_filters_default)

        self.btn_open_asset.clicked.connect(self._open_asset)
        self.btn_open_met_list.clicked.connect(self._open_metrology_list)

        self._apply_rbac()
        self.refresh()

# (FILENAME: ui/metrology_dashboard_page.py - END PART 3/6)

# FILENAME: ui/metrology_dashboard_page.py
# (FILENAME: ui/metrology_dashboard_page.py - START PART 4/6)

    # -------------------- UI builders --------------------
    def _mk_status_btn(self, text: str, color_hex: str) -> QToolButton:
        b = QToolButton()
        b.setObjectName("StatusBtn")
        b.setText(text)
        b.setCheckable(True)
        b.setToolButtonStyle(Qt.ToolButtonTextOnly)
        b.setStyleSheet(f"""
        QToolButton#StatusBtn {{
          border: 1px solid #2a3040;
        }}
        QToolButton#StatusBtn:checked {{
          border: 1px solid {color_hex};
          background: rgba(46,107,255,0.18);
        }}
        """)
        return b

    def _reset_columns_default(self) -> None:
        """Stabilniji restore ordera (bez vizuelne promene, samo tačnost)."""
        try:
            hdr = self.tbl.horizontalHeader()
            # cilj: vizuelni indeks = logički indeks (default mapping)
            for target_visual in range(hdr.count()):
                logical = target_visual
                cur_visual = hdr.visualIndex(logical)
                if cur_visual != target_visual:
                    hdr.moveSection(cur_visual, target_visual)
        except Exception:
            pass

    def _reset_filters_default(self) -> None:
        """Reset filtera: vrati UI kontrole na default tako da se opet vidi SVE."""
        with _block_signals(
            self.btn_st_overdue, self.btn_st_due, self.btn_st_ok, self.btn_st_unknown,
            self.btn_focus, self.ck_my, self.cb_warn, self.ed_search
        ):
            self.btn_focus.setChecked(False)
            self.btn_st_overdue.setChecked(True)
            self.btn_st_due.setChecked(True)
            self.btn_st_ok.setChecked(True)
            self.btn_st_unknown.setChecked(True)

            self.ck_my.setChecked(False)
            self.ed_search.setText("")
            self.cb_warn.setCurrentText("30")

        self._force_default_sort = True
        self._apply_filter()

    # -------------------- RBAC --------------------
    def _apply_rbac(self) -> None:
        ok = _can(PERM_METRO_VIEW)
        for w in (
            self.tbl, self.ed_search, self.cb_warn, self.ck_my, self.btn_refresh,
            self.btn_st_overdue, self.btn_st_due, self.btn_st_ok, self.btn_st_unknown, self.btn_focus,
            self.btn_cols_default, self.btn_filters_reset,
            self.btn_open_asset, self.btn_open_met_list,
        ):
            try:
                w.setEnabled(ok)
            except Exception:
                pass

        if not ok:
            try:
                self.tbl.setRowCount(0)
            except Exception:
                pass
            self.lb_rbac.setText("RBAC: nemaš pravo da vidiš metrologija dashboard (metrology.view).")
            self.lb_rbac.setVisible(True)
        else:
            self.lb_rbac.setVisible(False)

    # -------------------- helpers --------------------
    def _warn_days(self) -> int:
        try:
            return int(self.cb_warn.currentText())
        except Exception:
            return 30

    def _selected_asset_uid(self) -> str:
        r = self.tbl.currentRow()
        if r < 0:
            return ""
        it = self.tbl.item(r, self.C_UID)
        return it.text().strip() if it else ""

    def _selected_met_uid(self) -> str:
        r = self.tbl.currentRow()
        if r < 0:
            return ""
        it = self.tbl.item(r, self.C_MET_UID)
        return it.toolTip().strip() if (it and it.toolTip().strip()) else (it.text().strip() if it else "")

    def _sync_buttons(self) -> None:
        has = self.tbl.currentRow() >= 0
        try:
            self.btn_open_asset.setEnabled(has)
            self.btn_open_met_list.setEnabled(has)
        except Exception:
            pass

    def _enabled_statuses(self) -> set:
        st = set()
        if self.btn_st_overdue.isChecked():
            st.add("ISTEKLO")
        if self.btn_st_due.isChecked():
            st.add("ISTIČE")
            st.add("ISTICE")
        if self.btn_st_ok.isChecked():
            st.add("OK")
        if self.btn_st_unknown.isChecked():
            st.add("NEPOZNATO")
        return st

    def _focus_first_row(self) -> None:
        try:
            if self.tbl.rowCount() > 0:
                self.tbl.setCurrentCell(0, 0)
                self.tbl.setFocus()
        except Exception:
            pass

    def _apply_default_sort(self) -> None:
        """
        Default sort: status kolona (SortKeyItem ima stabilan status_sort ključ).
        """
        try:
            self.tbl.sortItems(self.C_STATUS, Qt.AscendingOrder)
            self.tbl.horizontalHeader().setSortIndicator(self.C_STATUS, Qt.AscendingOrder)
        except Exception:
            pass

    # -------------------- toggles --------------------
    def _on_focus_toggle(self, checked: bool) -> None:
        if checked:
            with _block_signals(self.btn_st_overdue, self.btn_st_due, self.btn_st_ok, self.btn_st_unknown):
                self.btn_st_overdue.setChecked(True)
                self.btn_st_due.setChecked(True)
                self.btn_st_ok.setChecked(False)
                self.btn_st_unknown.setChecked(False)
        self._apply_filter()

    def _on_status_toggle(self, _checked: bool) -> None:
        # ako fokus više nije “kritično only”, isključi fokus toggle
        if self.btn_focus.isChecked():
            crit = (
                self.btn_st_overdue.isChecked()
                and self.btn_st_due.isChecked()
                and (not self.btn_st_ok.isChecked())
                and (not self.btn_st_unknown.isChecked())
            )
            if not crit:
                with _block_signals(self.btn_focus):
                    self.btn_focus.setChecked(False)
        self._apply_filter()

    # -------------------- data load --------------------
    def refresh(self) -> None:
        self._apply_rbac()
        if not _can(PERM_METRO_VIEW):
            return

        try:
            self._rows = _fetch_dashboard_rows(warn_days=self._warn_days())
        except Exception as e:
            self._rows = []
            try:
                QMessageBox.critical(self, "Greška", f"Ne mogu da učitam dashboard.\n\n{e}")
            except Exception:
                pass
            return

        c = _kpi_counts(self._rows)
        self.kpi_overdue.set_value(c.get("ISTEKLO", 0))
        self.kpi_due.set_value(c.get("ISTIČE", 0))
        self.kpi_ok.set_value(c.get("OK", 0))
        self.kpi_total.set_value(c.get("UKUPNO", 0))

        self._force_default_sort = True
        self._apply_filter()

    # -------------------- filtering + chips --------------------
    def _apply_filter(self) -> None:
        if not _can(PERM_METRO_VIEW):
            return

        warn_days = self._warn_days()
        q = (self.ed_search.text() or "").strip().casefold()
        only_my = bool(self.ck_my.isChecked())
        enabled_statuses = self._enabled_statuses()

        # micro-opt: candidates računamo jednom
        my_cands = _identity_candidates() if only_my else None

        rows: List[MetroDashRow] = []
        for r in (self._rows or []):
            # status sada zavisi od calib_date + valid_until
            st = _met_status(r.calib_date, r.valid_until, warn_days)
            rr = MetroDashRow(**{**r.__dict__, "status": st})

            st_key = (rr.status or "").strip().upper() or "NEPOZNATO"
            if st_key not in enabled_statuses:
                continue

            if only_my and not _holder_matches_me(rr.holder, cands=my_cands):
                continue

            if q:
                hay = " ".join([
                    rr.asset_uid, rr.name, rr.category,
                    rr.holder, rr.sector, rr.location,
                    rr.status, rr.met_uid, rr.valid_until, rr.last_assigned_at
                ]).casefold()
                if q not in hay:
                    continue

            rows.append(rr)

        self._render(rows)
        self._refresh_chips()

    def _clear_chip_row(self) -> None:
        # struktura: [title][chips...][stretch] -> brišemo samo chip widgete
        try:
            while self.chip_lay.count() > 2:
                item = self.chip_lay.takeAt(1)
                w = item.widget() if item is not None else None
                if w is not None:
                    w.deleteLater()
        except Exception:
            pass

    def _refresh_chips(self) -> None:
        self._clear_chip_row()

        chips: List[Tuple[str, Any]] = []

        try:
            all_status = (
                self.btn_st_overdue.isChecked()
                and self.btn_st_due.isChecked()
                and self.btn_st_ok.isChecked()
                and self.btn_st_unknown.isChecked()
            )
        except Exception:
            all_status = True

        if not all_status:
            if self.btn_st_overdue.isChecked():
                chips.append(("Isteklo", lambda: self.btn_st_overdue.setChecked(False)))
            if self.btn_st_due.isChecked():
                chips.append(("Ističe", lambda: self.btn_st_due.setChecked(False)))
            if self.btn_st_ok.isChecked():
                chips.append(("OK", lambda: self.btn_st_ok.setChecked(False)))
            if self.btn_st_unknown.isChecked():
                chips.append(("Nepoznato", lambda: self.btn_st_unknown.setChecked(False)))

        if self.btn_focus.isChecked():
            chips.append(("Fokus: kritično", lambda: self.btn_focus.setChecked(False)))

        if self.ck_my.isChecked():
            chips.append(("Samo moja", lambda: self.ck_my.setChecked(False)))

        s_txt = (self.ed_search.text() or "").strip()
        if s_txt:
            chips.append((f'Pretraga: "{s_txt}"', lambda: self.ed_search.setText("")))

        wd = self._warn_days()
        if wd != 30:
            chips.append((f"Alarm: {wd} dana", lambda: self.cb_warn.setCurrentText("30")))

        for text, fn in chips:
            try:
                self.chip_lay.insertWidget(self.chip_lay.count() - 1, _Chip(text, fn, self.chip_wrap))
            except Exception:
                pass

        try:
            self.chip_wrap.setVisible(len(chips) > 0)
        except Exception:
            pass

    # -------------------- rendering --------------------
    def _render(self, rows: List[MetroDashRow]) -> None:
        order_rank = {"ISTEKLO": 0, "ISTIČE": 1, "ISTICE": 1, "OK": 2, "NEPOZNATO": 3}

        try:
            self.tbl.setSortingEnabled(False)
            self.tbl.setUpdatesEnabled(False)
            self.tbl.setRowCount(0)

            for rr in rows:
                i = self.tbl.rowCount()
                self.tbl.insertRow(i)

                base_bg = QBrush(QColor("#121624" if (i % 2 == 0) else "#111a2a"))

                rb_text = ""
                rb_sort: Any = 10**12
                if rr.rb is not None:
                    rb_text = str(rr.rb)
                    try:
                        rb_sort = int(rr.rb)
                    except Exception:
                        rb_sort = rr.rb

                st_key = (rr.status or "").strip().upper() or "NEPOZNATO"
                rank = int(order_rank.get(st_key, 9))

                vu_raw = (rr.valid_until or "").strip()
                vu_sort = vu_raw if (vu_raw and not _is_sentinel_date_iso(vu_raw)) else "9999-12-31"
                vu_disp = _dash_display_for_date_iso(vu_raw)

                asg_raw = (rr.last_assigned_at or "").strip()
                asg_disp = _dash_display_for_dt_iso(asg_raw)

                met_raw = (rr.met_uid or "").strip()
                met_disp = _truncate_middle(met_raw, left=14, right=6)

                # status sort key stabilan (rank + valid_until + rb + uid)
                status_sort = f"{rank}|{vu_sort}|{str(rb_sort).zfill(12)}|{rr.asset_uid}"

                display_vals = [
                    rb_text,
                    rr.status,
                    vu_disp,
                    met_disp,
                    rr.asset_uid,
                    rr.name,
                    rr.category,
                    rr.holder,
                    rr.sector,
                    rr.location,
                    asg_disp,
                ]

                sort_vals = [
                    rb_sort,
                    status_sort,
                    vu_sort,
                    met_raw or "",
                    rr.asset_uid or "",
                    rr.name or "",
                    rr.category or "",
                    rr.holder or "",
                    rr.sector or "",
                    rr.location or "",
                    asg_raw or "",
                ]

                for cc, v in enumerate(display_vals):
                    item = _SortKeyItem(str(v), sort_vals[cc])
                    item.setBackground(base_bg)

                    if cc == self.C_ASSIGNED:
                        item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                    elif cc in (self.C_NO, self.C_STATUS, self.C_VALID_UNTIL, self.C_MET_UID, self.C_UID, self.C_SECTOR, self.C_LOC):
                        item.setTextAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
                    else:
                        item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)

                    # tooltips: raw vrednosti (precizno kopiranje)
                    if cc == self.C_VALID_UNTIL and vu_raw:
                        item.setToolTip(vu_raw)
                    elif cc == self.C_ASSIGNED and asg_raw:
                        item.setToolTip(asg_raw)
                    elif cc == self.C_MET_UID and met_raw:
                        item.setToolTip(met_raw)

                    if cc == self.C_STATUS:
                        _status_badge_style(item, rr.status)

                    self.tbl.setItem(i, cc, item)

        finally:
            try:
                self.tbl.setUpdatesEnabled(True)
                self.tbl.setSortingEnabled(True)
            except Exception:
                pass

        self._sync_buttons()

        if self._force_default_sort:
            self._force_default_sort = False
            self._apply_default_sort()

# (FILENAME: ui/metrology_dashboard_page.py - END PART 4/6)

# FILENAME: ui/metrology_dashboard_page.py
# (FILENAME: ui/metrology_dashboard_page.py - START PART 5/6)

    # -------------------- actions (ne diramo logiku, samo stabilno) --------------------
    def _open_asset(self) -> None:
        asset_uid = self._selected_asset_uid()
        if not asset_uid:
            return
        try:
            from ui.asset_detail_dialog import AssetDetailDialog  # type: ignore
            dlg = AssetDetailDialog(asset_uid, self)
            dlg.exec()
        except Exception as e:
            try:
                QMessageBox.information(self, "Info", f"Ne mogu da otvorim detalje sredstva.\n\n{e}")
            except Exception:
                pass

    def _open_metrology_details(self) -> None:
        met_uid = self._selected_met_uid()
        if not met_uid:
            try:
                QMessageBox.information(self, "Info", "Nema metrologija zapisa (met_uid je prazan).")
            except Exception:
                pass
            return
        try:
            from ui.metrology_page import MetrologyDetailsDialog  # type: ignore
            dlg = MetrologyDetailsDialog(met_uid, parent=self, warn_days=self._warn_days())
            dlg.exec()
        except Exception as e:
            try:
                QMessageBox.information(self, "Info", f"Ne mogu da otvorim detalje metrologije.\n\n{e}")
            except Exception:
                pass

    def _open_metrology_list(self) -> None:
        asset_uid = self._selected_asset_uid()
        if not asset_uid:
            return
        try:
            from ui.my_assets_page import MetrologyForAssetDialog  # type: ignore
            dlg = MetrologyForAssetDialog(asset_uid, warn_days=self._warn_days(), parent=self)
            dlg.exec()
        except Exception as e:
            try:
                QMessageBox.information(self, "Info", f"Ne mogu da otvorim listu metrologije.\n\n{e}")
            except Exception:
                pass

    def _on_double_click(self, _r: int, c: int) -> None:
        # status/valid/met_uid kolone vode u metrologiju
        if c in (self.C_STATUS, self.C_VALID_UNTIL, self.C_MET_UID):
            if self._selected_met_uid():
                self._open_metrology_details()
            else:
                self._open_metrology_list()
            return
        self._open_asset()

    def _on_context_menu(self, pos) -> None:
        try:
            it = self.tbl.itemAt(pos)
            if it is not None:
                self.tbl.setCurrentCell(it.row(), it.column())

            cur = self.tbl.currentItem()
            cell_text = cur.text() if cur else ""

            uid = self._selected_asset_uid()
            met_uid = self._selected_met_uid()

            menu = QMenu(self)
            act_copy_cell = menu.addAction("Kopiraj ćeliju")
            act_copy_sel = menu.addAction("Kopiraj selekciju (TSV)")
            menu.addSeparator()

            act_copy_uid = menu.addAction("Kopiraj Asset UID") if uid else None
            act_copy_met = menu.addAction("Kopiraj Met UID") if met_uid else None

            menu.addSeparator()
            act_open_asset = menu.addAction("Otvori sredstvo") if uid else None
            act_open_met_details = menu.addAction("Otvori metrologiju (detalji)") if met_uid else None
            act_open_met_list = menu.addAction("Otvori metrologiju (lista)") if uid else None

            chosen = menu.exec(self.tbl.viewport().mapToGlobal(pos))

            if chosen == act_copy_cell:
                _copy_text_to_clipboard(cell_text)
                return
            if chosen == act_copy_sel:
                copy_selected_cells(self.tbl)
                return

            if act_copy_uid is not None and chosen == act_copy_uid:
                _copy_text_to_clipboard(uid)
                return
            if act_copy_met is not None and chosen == act_copy_met:
                _copy_text_to_clipboard(met_uid)
                return

            if act_open_asset is not None and chosen == act_open_asset:
                self._open_asset()
                return
            if act_open_met_details is not None and chosen == act_open_met_details:
                self._open_metrology_details()
                return
            if act_open_met_list is not None and chosen == act_open_met_list:
                self._open_metrology_list()
                return

        except Exception:
            # context menu je best-effort, bez rušenja UI-a
            return

# (FILENAME: ui/metrology_dashboard_page.py - END PART 5/6)

# FILENAME: ui/metrology_dashboard_page.py
# (FILENAME: ui/metrology_dashboard_page.py - START PART 6/6)

# Public exports (da importovi budu čisti i stabilni)
__all__ = ["MetrologyDashboardPage"]

# (FILENAME: ui/metrology_dashboard_page.py - END PART 6/6)