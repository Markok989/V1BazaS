# FILENAME: services/dashboard_service.py
# --- START PART 1/2 (services/dashboard_service.py) ---
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — services/dashboard_service.py

Dashboard metrike (V1) sa scope kontrolom (ALL / SECTOR / MY).

Princip (anti-"curenje"):
- Jedan izvor istine za scope: core.session.effective_scope() => ALL | SECTOR | MY
- ALL je dozvoljen samo ADMIN-u (fail-safe).
- SECTOR koristi sector iz session-a + sektor kolonu iz DB (fail-closed ako nešto fali).
- MY koristi self-scope (actor iz session-a; ne verujemo parametru).

RBAC:
- KPI/Assets: assets.view
- Assignments: assignments.view
- Metrology alarms: metrology.view + (metrology.manage ili fallback metrology.edit)
  * Dodatno: kada je scope=ALL, metrology alarms zahtevaju manage (backstop).

SQLite:
- Izbegavamo dinamičke datetime modifiere preko f-string.
- Za overdue koristimo julianday razliku.
"""

from __future__ import annotations

import re
import sqlite3
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.config import DB_FILE
from services._rbac_guard import require_perm, require_login, current_actor

DEFAULT_OVERDUE_DAYS = 30
DEFAULT_MET_WARN_DAYS = 30

# hard caps (anti-abuse / stabilnost)
_MAX_LIMIT = 5000
_MIN_LIMIT = 1
_MAX_DAYS = 3650  # ~10 godina, više od ovoga je ionako besmisleno za dashboard

try:
    from core.rbac import (
        PERM_ASSETS_VIEW,
        PERM_ASSIGN_VIEW,
        PERM_METRO_VIEW,
        PERM_METRO_EDIT,
        PERM_METRO_MANAGE,
    )  # type: ignore
except Exception:  # pragma: no cover
    PERM_ASSETS_VIEW = "assets.view"
    PERM_ASSIGN_VIEW = "assignments.view"
    PERM_METRO_VIEW = "metrology.view"
    PERM_METRO_EDIT = "metrology.edit"
    PERM_METRO_MANAGE = "metrology.manage"


# -------------------- DB helpers --------------------

def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _resolve_db_path() -> Path:
    db_path = Path(DB_FILE)
    if not db_path.is_absolute():
        db_path = (_app_root() / db_path).resolve()
    return db_path


@contextmanager
def _connect_db():
    db_path = _resolve_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path.as_posix())
    try:
        conn.execute("PRAGMA busy_timeout=2500;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    try:
        r = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
            (name,),
        ).fetchone()
        return bool(r)
    except Exception:
        return False


def _ensure_metrology_schema_safe() -> None:
    """
    Metrologija tabela može da ne postoji (ako user nikad nije ušao u Metrologiju).
    Lazy import izbegava circular import.
    """
    try:
        from services.metrology_service import ensure_metrology_schema  # type: ignore
        ensure_metrology_schema()
    except Exception:
        pass


# -------------------- sanitizers --------------------

_ident_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _qident(name: str) -> str:
    """
    Quote identifier safely for SQLite.
    We allow only [A-Za-z_][A-Za-z0-9_]* to avoid injection via weird column names.
    Returns empty string if invalid -> fail-closed upstream.
    """
    n = (name or "").strip()
    if not n or not _ident_re.match(n):
        return ""
    return f'"{n}"'


def _safe_int(x: Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _clamp_limit(limit: Any, default: int) -> int:
    lim = _safe_int(limit, default)
    if lim < _MIN_LIMIT:
        lim = default
    if lim > _MAX_LIMIT:
        lim = _MAX_LIMIT
    return lim


def _clamp_days(days: Any, default: int) -> int:
    d = _safe_int(days, default)
    if d <= 0:
        d = default
    if d > _MAX_DAYS:
        d = _MAX_DAYS
    return d


def _my_actor(_actor_param: str) -> str:
    """
    MY scope mora biti "self-scope":
    - tražimo da korisnik bude prijavljen
    - actor uzimamo iz session-a (ne verujemo parametru)
    """
    require_login("MY scope")
    return current_actor()


def _assets_holder_col(conn: sqlite3.Connection) -> str:
    """Tolerantno pronalazi kolonu za holder u assets (current_holder ili holder)."""
    try:
        if not _table_exists(conn, "assets"):
            return ""
        cols = [r[1] for r in conn.execute("PRAGMA table_info(assets);").fetchall()]
        for cand in ("current_holder", "holder"):
            if cand in cols:
                return cand
    except Exception:
        pass
    return ""


def _assets_sector_col(conn: sqlite3.Connection) -> str:
    """
    Pronalazi kolonu u assets tabeli koja predstavlja sektor/jedinicu.
    Kandidati:
      sector, sector_id, sector_code, org_unit, unit, department, dept, section, sektor
    """
    try:
        if not _table_exists(conn, "assets"):
            return ""
        cols = [r[1] for r in conn.execute("PRAGMA table_info(assets);").fetchall()]
        for cand in (
            "sector", "sector_id", "sector_code", "org_unit",
            "unit", "department", "dept", "section", "sektor"
        ):
            if cand in cols:
                return cand
    except Exception:
        pass
    return ""


def _can_metro_alarms_fail_closed(scope: str) -> bool:
    """
    Metrologija alarmi:
    - scope=ALL  -> samo metrology.manage (strogo, backstop)
    - scope!=ALL -> metrology.manage OR metrology.edit (fallback)
    FAIL-CLOSED: ako ne mogu da proverim -> False.
    """
    try:
        from core.session import can  # type: ignore
        if (scope or "").upper() == "ALL":
            return bool(can(PERM_METRO_MANAGE))
        return bool(can(PERM_METRO_MANAGE)) or bool(can(PERM_METRO_EDIT))
    except Exception:
        return False


# -------------------- SCOPE (ALL / SECTOR / MY) --------------------

def _effective_scope_safe() -> str:
    """
    Jedini izvor istine: core.session.effective_scope().
    Fail-safe: ako scope=ALL a user nije ADMIN -> SECTOR.
    """
    try:
        from core.session import effective_scope, active_role  # type: ignore
        sc = (effective_scope() or "").strip().upper()
        role = (active_role() or "").strip().upper()
        if sc == "ALL" and role != "ADMIN":
            return "SECTOR"
        if sc in ("ALL", "SECTOR", "MY"):
            return sc
    except Exception:
        pass
    return "MY"  # safest fallback


def _sector_value_safe() -> str:
    try:
        from core.session import current_sector  # type: ignore
        return str(current_sector() or "").strip()
    except Exception:
        return ""


def _scope_where_assets(conn: sqlite3.Connection, actor_for_my: str, alias: str = "a") -> Tuple[str, List[Any]]:
    """
    Vraća (WHERE fragment bez 'WHERE', params) za assets po scope-u.
    alias: SQL alias za assets tabelu (default "a")
    FAIL-CLOSED za SECTOR kad nemamo sektor ili kolonu.
    """
    sc = _effective_scope_safe()
    a = (alias or "a").strip() or "a"

    if sc == "ALL":
        return "1=1", []

    if sc == "MY":
        holder_col = _assets_holder_col(conn)
        qcol = _qident(holder_col)
        if qcol:
            return f"COALESCE({a}.{qcol},'') = ?", [actor_for_my]
        # fallback: MY bez holder kolone -> fail-closed ovde
        return "1=0", []

    # SECTOR
    sector_val = _sector_value_safe()
    sector_col = _assets_sector_col(conn)
    qcol = _qident(sector_col)
    if not sector_val or not qcol:
        return "1=0", []
    return f"COALESCE({a}.{qcol},'') = ?", [sector_val]


# -------------------- GLOBAL / SCOPED API --------------------

def get_kpi_counts() -> Dict[str, int]:
    """
    KPI brojači za assets.
    RBAC: assets.view
    Scope:
      - ALL: sve
      - SECTOR: samo sektor
      - MY: moja sredstva
        * ako nema holder kolone -> fallback preko assignments "last_event"
    """
    require_perm(PERM_ASSETS_VIEW, "dashboard.get_kpi_counts")

    with _connect_db() as conn:
        if not _table_exists(conn, "assets"):
            return {"total": 0, "active": 0, "on_loan": 0, "service": 0, "scrapped": 0}

        sc = _effective_scope_safe()
        actor = _my_actor("") if sc == "MY" else ""
        where_frag, params = _scope_where_assets(conn, actor_for_my=actor, alias="a")

        # MY fallback: ako je fail-closed jer nema holder kolone, pokušaj preko assignments
        if sc == "MY" and where_frag == "1=0":
            if not _table_exists(conn, "assignments"):
                return {"total": 0, "active": 0, "on_loan": 0, "service": 0, "scrapped": 0}

            sql_fb = """
            WITH last_event AS (
                SELECT
                    asg.asset_uid,
                    asg.action AS last_action,
                    COALESCE(asg.to_holder,'') AS last_to_holder,
                    asg.created_at AS last_created_at
                FROM assignments asg
                WHERE asg.created_at = (
                    SELECT MAX(created_at) FROM assignments WHERE asset_uid = asg.asset_uid
                )
            ),
            held AS (
                SELECT asset_uid
                FROM last_event
                WHERE last_action IN ('assign','transfer')
                  AND last_to_holder = ?
            )
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN COALESCE(a.status,'')='active' THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN COALESCE(a.status,'')='on_loan' THEN 1 ELSE 0 END) AS on_loan,
                SUM(CASE WHEN COALESCE(a.status,'')='service' THEN 1 ELSE 0 END) AS service,
                SUM(CASE WHEN COALESCE(a.status,'')='scrapped' THEN 1 ELSE 0 END) AS scrapped
            FROM held h
            LEFT JOIN assets a ON a.asset_uid = h.asset_uid;
            """
            row = conn.execute(sql_fb, (actor,)).fetchone()
            return {
                "total": int(row[0] or 0),
                "active": int(row[1] or 0),
                "on_loan": int(row[2] or 0),
                "service": int(row[3] or 0),
                "scrapped": int(row[4] or 0),
            }

        sql = f"""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN COALESCE(status,'')='active' THEN 1 ELSE 0 END) AS active,
            SUM(CASE WHEN COALESCE(status,'')='on_loan' THEN 1 ELSE 0 END) AS on_loan,
            SUM(CASE WHEN COALESCE(status,'')='service' THEN 1 ELSE 0 END) AS service,
            SUM(CASE WHEN COALESCE(status,'')='scrapped' THEN 1 ELSE 0 END) AS scrapped
        FROM assets a
        WHERE {where_frag};
        """
        row = conn.execute(sql, tuple(params)).fetchone()

    return {
        "total": int((row[0] or 0) if row else 0),
        "active": int((row[1] or 0) if row else 0),
        "on_loan": int((row[2] or 0) if row else 0),
        "service": int((row[3] or 0) if row else 0),
        "scrapped": int((row[4] or 0) if row else 0),
    }


def list_overdue_assignments(days: int = DEFAULT_OVERDUE_DAYS, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Overdue = poslednje zaduženje (assign/transfer) starije od N dana.
    RBAC: assignments.view
    Scope:
      - ALL: sve
      - SECTOR: samo assets u mom sektoru (join assets)
      - MY: samo moja sredstva (self-scope)
        * ako nema holder kolone -> fallback preko assignments last_event
    """
    require_perm(PERM_ASSIGN_VIEW, "dashboard.list_overdue_assignments")

    days_i = _clamp_days(days, DEFAULT_OVERDUE_DAYS)
    lim = _clamp_limit(limit, 50)

    with _connect_db() as conn:
        if (not _table_exists(conn, "assets")) or (not _table_exists(conn, "assignments")):
            return []

        sc = _effective_scope_safe()
        actor = _my_actor("") if sc == "MY" else ""

        where_assets, params_assets = _scope_where_assets(conn, actor_for_my=actor, alias="a")

        # MY fallback: ako nema holder kolone, filtriraj po last_to_holder (assignments)
        if sc == "MY" and where_assets == "1=0":
            sql_my = """
            WITH last_event AS (
                SELECT
                    a.asset_uid AS asset_uid,
                    a.name AS asset_name,
                    a.location AS location,
                    asg.action AS last_action,
                    COALESCE(asg.to_holder,'') AS last_to_holder,
                    asg.created_at AS last_created_at
                FROM assets a
                JOIN assignments asg ON asg.asset_uid = a.asset_uid
                WHERE asg.created_at = (
                    SELECT MAX(created_at) FROM assignments WHERE asset_uid = a.asset_uid
                )
            )
            SELECT
                asset_uid, asset_name, location, last_action, last_to_holder, last_created_at
            FROM last_event
            WHERE last_action IN ('assign','transfer')
              AND last_to_holder = ?
              AND (julianday('now') - julianday(last_created_at)) >= ?
            ORDER BY datetime(last_created_at) ASC
            LIMIT ?;
            """
            rows = conn.execute(sql_my, (actor, float(days_i), int(lim))).fetchall()
        else:
            sql = f"""
            WITH last_event AS (
                SELECT
                    a.asset_uid AS asset_uid,
                    a.name AS asset_name,
                    a.location AS location,
                    asg.action AS last_action,
                    COALESCE(asg.to_holder,'') AS last_to_holder,
                    asg.created_at AS last_created_at
                FROM assets a
                JOIN assignments asg ON asg.asset_uid = a.asset_uid
                WHERE asg.created_at = (
                    SELECT MAX(created_at) FROM assignments WHERE asset_uid = a.asset_uid
                )
                  AND ({where_assets})
            )
            SELECT
                asset_uid, asset_name, location, last_action, last_to_holder, last_created_at
            FROM last_event
            WHERE last_action IN ('assign','transfer')
              AND (julianday('now') - julianday(last_created_at)) >= ?
            ORDER BY datetime(last_created_at) ASC
            LIMIT ?;
            """
            rows = conn.execute(sql, tuple(params_assets + [float(days_i), int(lim)])).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "asset_uid": r[0],
                "asset_name": r[1],
                "location": r[2],
                "last_action": r[3],
                "last_to_holder": r[4],
                "last_created_at": r[5],
            }
        )
    return out


def list_recent_assignments(limit: int = 20) -> List[Dict[str, Any]]:
    """
    Poslednje aktivnosti zaduženja.
    RBAC: assignments.view
    Scope:
      - ALL: sve
      - SECTOR: samo assets u mom sektoru (join assets)
      - MY: samo gde sam učesnik (from/to == actor)
    """
    require_perm(PERM_ASSIGN_VIEW, "dashboard.list_recent_assignments")
    lim = _clamp_limit(limit, 20)

    with _connect_db() as conn:
        if not _table_exists(conn, "assignments"):
            return []

        sc = _effective_scope_safe()

        if sc == "MY":
            a = _my_actor("")
            sql = """
            SELECT
                asg.created_at,
                asg.asset_uid,
                COALESCE(a.name, '') AS asset_name,
                asg.action,
                COALESCE(asg.from_holder,'') AS from_holder,
                COALESCE(asg.to_holder,'') AS to_holder
            FROM assignments asg
            LEFT JOIN assets a ON a.asset_uid = asg.asset_uid
            WHERE COALESCE(asg.from_holder,'') = ?
               OR COALESCE(asg.to_holder,'') = ?
            ORDER BY datetime(asg.created_at) DESC
            LIMIT ?;
            """
            rows = conn.execute(sql, (a, a, lim)).fetchall()
        else:
            if not _table_exists(conn, "assets"):
                return []
            where_assets, params_assets = _scope_where_assets(conn, actor_for_my="", alias="a")
            sql = f"""
            SELECT
                asg.created_at,
                asg.asset_uid,
                COALESCE(a.name, '') AS asset_name,
                asg.action,
                COALESCE(asg.from_holder,'') AS from_holder,
                COALESCE(asg.to_holder,'') AS to_holder
            FROM assignments asg
            LEFT JOIN assets a ON a.asset_uid = asg.asset_uid
            WHERE ({where_assets})
            ORDER BY datetime(asg.created_at) DESC
            LIMIT ?;
            """
            rows = conn.execute(sql, tuple(params_assets + [lim])).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "created_at": r[0],
                "asset_uid": r[1],
                "asset_name": r[2],
                "action": r[3],
                "from_holder": r[4],
                "to_holder": r[5],
            }
        )
    return out

# --- END PART 1/2 (services/dashboard_service.py) ---

# FILENAME: services/dashboard_service.py
# --- START PART 2/2 (services/dashboard_service.py) ---

def get_metrology_alarm_counts(warn_days: int = DEFAULT_MET_WARN_DAYS) -> Dict[str, int]:
    """
    Brojači metrologija alarma.
    RBAC: metrology.view + (metrology.manage/edit) uz posebnu politiku:
      - scope=ALL  -> samo metrology.manage (strogo)
      - scope!=ALL -> metrology.manage OR metrology.edit (fallback)

    Scope:
      - ALL: sve (samo admin/manage)
      - SECTOR: samo assets u mom sektoru
      - MY: samo sredstva koja dužim (holder kolona ili assignments fallback)
    """
    require_perm(PERM_METRO_VIEW, "dashboard.get_metrology_alarm_counts")

    sc = _effective_scope_safe()
    if not _can_metro_alarms_fail_closed(sc):
        raise PermissionError("RBAC: nemaš pravo za metrologija alarme (metrology.manage/edit).")

    wd = _clamp_days(warn_days, DEFAULT_MET_WARN_DAYS)

    _ensure_metrology_schema_safe()
    today_iso = date.today().isoformat()

    with _connect_db() as conn:
        if not _table_exists(conn, "metrology_records"):
            return {"expired": 0, "expiring": 0}

        # SECTOR/MY zahtevaju assets da bi filtrirali scope
        if sc in ("SECTOR", "MY"):
            if not _table_exists(conn, "assets"):
                return {"expired": 0, "expiring": 0}

            actor = _my_actor("") if sc == "MY" else ""
            where_assets, params_assets = _scope_where_assets(conn, actor_for_my=actor, alias="a")

            # MY fallback (bez holder kolone): držimo self-scope preko assignments last_event
            if sc == "MY" and where_assets == "1=0":
                if not _table_exists(conn, "assignments"):
                    return {"expired": 0, "expiring": 0}

                sql_my = """
                WITH last_event AS (
                    SELECT
                        asg.asset_uid,
                        asg.action AS last_action,
                        COALESCE(asg.to_holder,'') AS last_to_holder,
                        asg.created_at AS last_created_at
                    FROM assignments asg
                    WHERE asg.created_at = (
                        SELECT MAX(created_at) FROM assignments WHERE asset_uid = asg.asset_uid
                    )
                ),
                held AS (
                    SELECT asset_uid
                    FROM last_event
                    WHERE last_action IN ('assign','transfer')
                      AND last_to_holder = ?
                )
                SELECT
                    SUM(CASE WHEN date(mr.valid_until) < date(?) THEN 1 ELSE 0 END) AS expired,
                    SUM(CASE
                            WHEN date(mr.valid_until) >= date(?)
                             AND date(mr.valid_until) <= date(?, '+' || ? || ' day')
                            THEN 1 ELSE 0 END) AS expiring
                FROM metrology_records mr
                JOIN held h ON h.asset_uid = mr.asset_uid
                WHERE mr.is_deleted=0
                  AND COALESCE(mr.valid_until,'') <> '';
                """
                row = conn.execute(sql_my, (actor, today_iso, today_iso, today_iso, int(wd))).fetchone()
                return {"expired": int(row[0] or 0), "expiring": int(row[1] or 0)}

            # SECTOR fail-closed ako nemamo sektor kolonu/vrednost
            if where_assets == "1=0":
                return {"expired": 0, "expiring": 0}

            sql = f"""
            SELECT
                SUM(CASE WHEN date(mr.valid_until) < date(?) THEN 1 ELSE 0 END) AS expired,
                SUM(CASE
                        WHEN date(mr.valid_until) >= date(?)
                         AND date(mr.valid_until) <= date(?, '+' || ? || ' day')
                        THEN 1 ELSE 0 END) AS expiring
            FROM metrology_records mr
            JOIN assets a ON a.asset_uid = mr.asset_uid
            WHERE mr.is_deleted=0
              AND COALESCE(mr.valid_until,'') <> ''
              AND ({where_assets});
            """
            row = conn.execute(sql, tuple([today_iso, today_iso, today_iso, int(wd)] + params_assets)).fetchone()
            return {"expired": int(row[0] or 0), "expiring": int(row[1] or 0)}

        # ALL (strogo već provereno: manage-only)
        sql_all = """
        SELECT
            SUM(CASE WHEN date(valid_until) < date(?) THEN 1 ELSE 0 END) AS expired,
            SUM(CASE
                    WHEN date(valid_until) >= date(?)
                     AND date(valid_until) <= date(?, '+' || ? || ' day')
                    THEN 1 ELSE 0 END) AS expiring
        FROM metrology_records
        WHERE is_deleted=0
          AND COALESCE(valid_until,'') <> '';
        """
        row = conn.execute(sql_all, (today_iso, today_iso, today_iso, int(wd))).fetchone()

    return {"expired": int(row[0] or 0), "expiring": int(row[1] or 0)}


def list_metrology_alarms(warn_days: int = DEFAULT_MET_WARN_DAYS, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Lista metrologija alarma.
    RBAC: metrology.view + (metrology.manage/edit) uz posebnu politiku:
      - scope=ALL  -> samo metrology.manage (strogo)
      - scope!=ALL -> metrology.manage OR metrology.edit (fallback)

    Scope:
      - ALL: sve (samo admin/manage)
      - SECTOR: samo assets u mom sektoru
      - MY: samo sredstva koja dužim (holder kolona ili assignments fallback)
    """
    require_perm(PERM_METRO_VIEW, "dashboard.list_metrology_alarms")

    sc = _effective_scope_safe()
    if not _can_metro_alarms_fail_closed(sc):
        raise PermissionError("RBAC: nemaš pravo za metrologija alarme (metrology.manage/edit).")

    wd = _clamp_days(warn_days, DEFAULT_MET_WARN_DAYS)
    lim = _clamp_limit(limit, 50)

    _ensure_metrology_schema_safe()
    today_iso = date.today().isoformat()

    with _connect_db() as conn:
        if not _table_exists(conn, "metrology_records"):
            return []

        # SECTOR/MY zahtevaju assets za filtriranje scope
        if sc in ("SECTOR", "MY"):
            if not _table_exists(conn, "assets"):
                return []

            actor = _my_actor("") if sc == "MY" else ""
            where_assets, params_assets = _scope_where_assets(conn, actor_for_my=actor, alias="a")

            # MY fallback (bez holder kolone): self-scope preko assignments last_event
            if sc == "MY" and where_assets == "1=0":
                if not _table_exists(conn, "assignments"):
                    return []

                sql_my = """
                WITH last_event AS (
                    SELECT
                        asg.asset_uid,
                        asg.action AS last_action,
                        COALESCE(asg.to_holder,'') AS last_to_holder,
                        asg.created_at AS last_created_at
                    FROM assignments asg
                    WHERE asg.created_at = (
                        SELECT MAX(created_at) FROM assignments WHERE asset_uid = asg.asset_uid
                    )
                ),
                held AS (
                    SELECT asset_uid
                    FROM last_event
                    WHERE last_action IN ('assign','transfer')
                      AND last_to_holder = ?
                )
                SELECT
                    mr.met_uid,
                    mr.asset_uid,
                    mr.calib_type,
                    COALESCE(mr.valid_until,'') AS valid_until,
                    COALESCE(mr.provider_name,'') AS provider_name,
                    COALESCE(mr.cert_no,'') AS cert_no,
                    COALESCE(mr.updated_at,'') AS updated_at,
                    CASE
                        WHEN date(mr.valid_until) < date(?) THEN 'ISTEKLO'
                        WHEN date(mr.valid_until) >= date(?)
                         AND date(mr.valid_until) <= date(?, '+' || ? || ' day')
                        THEN 'ISTICE'
                        ELSE 'OK'
                    END AS status
                FROM metrology_records mr
                JOIN held h ON h.asset_uid = mr.asset_uid
                WHERE mr.is_deleted=0
                  AND COALESCE(mr.valid_until,'') <> ''
                  AND (
                        date(mr.valid_until) < date(?)
                        OR (date(mr.valid_until) >= date(?)
                            AND date(mr.valid_until) <= date(?, '+' || ? || ' day'))
                      )
                ORDER BY
                    CASE WHEN status='ISTEKLO' THEN 0 ELSE 1 END,
                    date(valid_until) ASC,
                    datetime(updated_at) DESC
                LIMIT ?;
                """
                rows = conn.execute(
                    sql_my,
                    (
                        actor,
                        today_iso, today_iso, today_iso, int(wd),
                        today_iso, today_iso, today_iso, int(wd),
                        int(lim),
                    ),
                ).fetchall()
            else:
                if where_assets == "1=0":
                    return []

                sql = f"""
                SELECT
                    mr.met_uid,
                    mr.asset_uid,
                    mr.calib_type,
                    COALESCE(mr.valid_until,'') AS valid_until,
                    COALESCE(mr.provider_name,'') AS provider_name,
                    COALESCE(mr.cert_no,'') AS cert_no,
                    COALESCE(mr.updated_at,'') AS updated_at,
                    CASE
                        WHEN date(mr.valid_until) < date(?) THEN 'ISTEKLO'
                        WHEN date(mr.valid_until) >= date(?)
                         AND date(mr.valid_until) <= date(?, '+' || ? || ' day')
                        THEN 'ISTICE'
                        ELSE 'OK'
                    END AS status
                FROM metrology_records mr
                JOIN assets a ON a.asset_uid = mr.asset_uid
                WHERE mr.is_deleted=0
                  AND COALESCE(mr.valid_until,'') <> ''
                  AND (
                        date(mr.valid_until) < date(?)
                        OR (date(mr.valid_until) >= date(?)
                            AND date(mr.valid_until) <= date(?, '+' || ? || ' day'))
                      )
                  AND ({where_assets})
                ORDER BY
                    CASE WHEN status='ISTEKLO' THEN 0 ELSE 1 END,
                    date(valid_until) ASC,
                    datetime(updated_at) DESC
                LIMIT ?;
                """
                rows = conn.execute(
                    sql,
                    tuple(
                        [
                            today_iso, today_iso, today_iso, int(wd),
                            today_iso, today_iso, today_iso, int(wd),
                        ] + params_assets + [int(lim)]
                    ),
                ).fetchall()

        else:
            # ALL (strogo manage-only već provereno)
            sql_all = """
            SELECT
                met_uid,
                asset_uid,
                calib_type,
                COALESCE(valid_until,'') AS valid_until,
                COALESCE(provider_name,'') AS provider_name,
                COALESCE(cert_no,'') AS cert_no,
                COALESCE(updated_at,'') AS updated_at,
                CASE
                    WHEN date(valid_until) < date(?) THEN 'ISTEKLO'
                    WHEN date(valid_until) >= date(?)
                     AND date(valid_until) <= date(?, '+' || ? || ' day')
                    THEN 'ISTICE'
                    ELSE 'OK'
                END AS status
            FROM metrology_records
            WHERE is_deleted=0
              AND COALESCE(valid_until,'') <> ''
              AND (
                    date(valid_until) < date(?)
                    OR (date(valid_until) >= date(?)
                        AND date(valid_until) <= date(?, '+' || ? || ' day'))
                  )
            ORDER BY
                CASE WHEN status='ISTEKLO' THEN 0 ELSE 1 END,
                date(valid_until) ASC,
                datetime(updated_at) DESC
            LIMIT ?;
            """
            rows = conn.execute(
                sql_all,
                (today_iso, today_iso, today_iso, int(wd), today_iso, today_iso, today_iso, int(wd), int(lim)),
            ).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "met_uid": r[0],
                "asset_uid": r[1],
                "calib_type": r[2],
                "valid_until": r[3],
                "provider_name": r[4],
                "cert_no": r[5],
                "updated_at": r[6],
                "status": r[7],
            }
        )
    return out


# -------------------- Compatibility MY-API (kept; tightened, anti-leak) --------------------
# Napomena: UI može i dalje da koristi ove pozive. Ove funkcije su self-scope (actor iz session-a).

def get_my_kpi_counts(actor: str) -> Dict[str, int]:
    a = _my_actor(actor)
    with _connect_db() as conn:
        if not _table_exists(conn, "assets"):
            return {"total": 0, "active": 0, "on_loan": 0, "service": 0, "scrapped": 0}

        holder_col = _assets_holder_col(conn)
        qcol = _qident(holder_col)
        if qcol:
            sql = f"""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN COALESCE(status,'')='active' THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN COALESCE(status,'')='on_loan' THEN 1 ELSE 0 END) AS on_loan,
                SUM(CASE WHEN COALESCE(status,'')='service' THEN 1 ELSE 0 END) AS service,
                SUM(CASE WHEN COALESCE(status,'')='scrapped' THEN 1 ELSE 0 END) AS scrapped
            FROM assets
            WHERE COALESCE({qcol},'') = ?;
            """
            row = conn.execute(sql, (a,)).fetchone()
            return {
                "total": int(row[0] or 0),
                "active": int(row[1] or 0),
                "on_loan": int(row[2] or 0),
                "service": int(row[3] or 0),
                "scrapped": int(row[4] or 0),
            }

        # fallback: preko assignments last_event
        if not _table_exists(conn, "assignments"):
            return {"total": 0, "active": 0, "on_loan": 0, "service": 0, "scrapped": 0}

        sql = """
        WITH last_event AS (
            SELECT
                asg.asset_uid,
                asg.action AS last_action,
                COALESCE(asg.to_holder,'') AS last_to_holder,
                asg.created_at AS last_created_at
            FROM assignments asg
            WHERE asg.created_at = (
                SELECT MAX(created_at) FROM assignments WHERE asset_uid = asg.asset_uid
            )
        ),
        held AS (
            SELECT asset_uid
            FROM last_event
            WHERE last_action IN ('assign','transfer')
              AND last_to_holder = ?
        )
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN COALESCE(a.status,'')='active' THEN 1 ELSE 0 END) AS active,
            SUM(CASE WHEN COALESCE(a.status,'')='on_loan' THEN 1 ELSE 0 END) AS on_loan,
            SUM(CASE WHEN COALESCE(a.status,'')='service' THEN 1 ELSE 0 END) AS service,
            SUM(CASE WHEN COALESCE(a.status,'')='scrapped' THEN 1 ELSE 0 END) AS scrapped
        FROM held h
        LEFT JOIN assets a ON a.asset_uid = h.asset_uid;
        """
        row = conn.execute(sql, (a,)).fetchone()

    return {
        "total": int(row[0] or 0),
        "active": int(row[1] or 0),
        "on_loan": int(row[2] or 0),
        "service": int(row[3] or 0),
        "scrapped": int(row[4] or 0),
    }


def list_my_overdue_assets(actor: str, days: int = DEFAULT_OVERDUE_DAYS, limit: int = 50) -> List[Dict[str, Any]]:
    a = _my_actor(actor)
    days_i = _clamp_days(days, DEFAULT_OVERDUE_DAYS)
    lim = _clamp_limit(limit, 50)

    with _connect_db() as conn:
        if (not _table_exists(conn, "assets")) or (not _table_exists(conn, "assignments")):
            return []

        holder_col = _assets_holder_col(conn)
        qcol = _qident(holder_col)

        # Ako imamo holder kolonu: držimo se nje kao "current state",
        # ali NE forsiramo last_to_holder=a (da ne sakrijemo nekonzistentna stanja).
        holder_filter = f"COALESCE(a.{qcol},'') = ?" if qcol else "1=1"

        sql = f"""
        WITH last_event AS (
            SELECT
                a.asset_uid AS asset_uid,
                a.name AS asset_name,
                a.location AS location,
                asg.action AS last_action,
                COALESCE(asg.to_holder,'') AS last_to_holder,
                asg.created_at AS last_created_at
            FROM assets a
            JOIN assignments asg ON asg.asset_uid = a.asset_uid
            WHERE {holder_filter}
              AND asg.created_at = (
                SELECT MAX(created_at) FROM assignments WHERE asset_uid = a.asset_uid
              )
        )
        SELECT
            asset_uid, asset_name, location, last_action, last_to_holder, last_created_at
        FROM last_event
        WHERE last_action IN ('assign','transfer')
          AND (julianday('now') - julianday(last_created_at)) >= ?
          {"" if qcol else "AND last_to_holder = ?"}
        ORDER BY datetime(last_created_at) ASC
        LIMIT ?;
        """

        params: List[Any] = []
        if qcol:
            params.append(a)
            params.append(float(days_i))
        else:
            params.append(float(days_i))
            params.append(a)
        params.append(int(lim))

        rows = conn.execute(sql, tuple(params)).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "asset_uid": r[0],
                "asset_name": r[1],
                "location": r[2],
                "last_action": r[3],
                "last_to_holder": r[4],
                "last_created_at": r[5],
            }
        )
    return out


def list_my_recent_assignments(actor: str, limit: int = 20) -> List[Dict[str, Any]]:
    a = _my_actor(actor)
    lim = _clamp_limit(limit, 20)

    sql = """
    SELECT
        asg.created_at,
        asg.asset_uid,
        COALESCE(a.name, '') AS asset_name,
        asg.action,
        COALESCE(asg.from_holder,'') AS from_holder,
        COALESCE(asg.to_holder,'') AS to_holder
    FROM assignments asg
    LEFT JOIN assets a ON a.asset_uid = asg.asset_uid
    WHERE COALESCE(asg.from_holder,'') = ?
       OR COALESCE(asg.to_holder,'') = ?
    ORDER BY datetime(asg.created_at) DESC
    LIMIT ?;
    """

    with _connect_db() as conn:
        if not _table_exists(conn, "assignments"):
            return []
        rows = conn.execute(sql, (a, a, lim)).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "created_at": r[0],
                "asset_uid": r[1],
                "asset_name": r[2],
                "action": r[3],
                "from_holder": r[4],
                "to_holder": r[5],
            }
        )
    return out


def list_my_assets(actor: str, limit: int = 2000) -> List[Dict[str, Any]]:
    a = _my_actor(actor)
    lim = _clamp_limit(limit, 2000)

    with _connect_db() as conn:
        if not _table_exists(conn, "assets"):
            return []

        holder_col = _assets_holder_col(conn)
        qcol = _qident(holder_col)

        if qcol:
            last_dt = "(SELECT MAX(created_at) FROM assignments WHERE asset_uid=a.asset_uid)" if _table_exists(conn, "assignments") else "''"
            sql = f"""
            SELECT
                a.asset_uid,
                COALESCE(a.name,'') AS name,
                COALESCE(a.category,'') AS category,
                COALESCE(a.location,'') AS location,
                COALESCE(a.status,'') AS status,
                COALESCE({last_dt}, '') AS last_assigned_at
            FROM assets a
            WHERE COALESCE(a.{qcol},'') = ?
            ORDER BY COALESCE(a.name,''), a.asset_uid
            LIMIT ?;
            """
            rows = conn.execute(sql, (a, lim)).fetchall()
        else:
            if not _table_exists(conn, "assignments"):
                return []
            sql = """
            WITH last_event AS (
                SELECT
                    asg.asset_uid,
                    asg.action AS last_action,
                    COALESCE(asg.to_holder,'') AS last_to_holder,
                    asg.created_at AS last_created_at
                FROM assignments asg
                WHERE asg.created_at = (
                    SELECT MAX(created_at) FROM assignments WHERE asset_uid = asg.asset_uid
                )
            )
            SELECT
                a.asset_uid,
                COALESCE(a.name,'') AS name,
                COALESCE(a.category,'') AS category,
                COALESCE(a.location,'') AS location,
                COALESCE(a.status,'') AS status,
                le.last_created_at
            FROM assets a
            JOIN last_event le ON le.asset_uid = a.asset_uid
            WHERE le.last_action IN ('assign','transfer')
              AND le.last_to_holder = ?
            ORDER BY COALESCE(a.name,''), a.asset_uid
            LIMIT ?;
            """
            rows = conn.execute(sql, (a, lim)).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "asset_uid": r[0],
                "name": r[1],
                "category": r[2],
                "location": r[3],
                "status": r[4],
                "last_assigned_at": r[5] or "",
            }
        )
    return out


def get_my_metrology_alarm_counts(actor: str, warn_days: int = DEFAULT_MET_WARN_DAYS) -> Dict[str, int]:
    a = _my_actor(actor)
    wd = _clamp_days(warn_days, DEFAULT_MET_WARN_DAYS)

    _ensure_metrology_schema_safe()
    today_iso = date.today().isoformat()

    with _connect_db() as conn:
        if not _table_exists(conn, "metrology_records") or not _table_exists(conn, "assets"):
            return {"expired": 0, "expiring": 0}

        holder_col = _assets_holder_col(conn)
        qcol = _qident(holder_col)
        if not qcol:
            # fallback bez holder kolone je namerno fail-closed u MY-compat API (izbegavamo pogrešne MY rezultate)
            return {"expired": 0, "expiring": 0}

        sql = f"""
        SELECT
            SUM(CASE WHEN date(mr.valid_until) < date(?) THEN 1 ELSE 0 END) AS expired,
            SUM(CASE
                    WHEN date(mr.valid_until) >= date(?)
                     AND date(mr.valid_until) <= date(?, '+' || ? || ' day')
                    THEN 1 ELSE 0 END) AS expiring
        FROM metrology_records mr
        JOIN assets a ON a.asset_uid = mr.asset_uid
        WHERE mr.is_deleted=0
          AND COALESCE(mr.valid_until,'') <> ''
          AND COALESCE(a.{qcol},'') = ?;
        """
        row = conn.execute(sql, (today_iso, today_iso, today_iso, int(wd), a)).fetchone()
        return {"expired": int(row[0] or 0), "expiring": int(row[1] or 0)}


def list_my_metrology_alarms(actor: str, warn_days: int = DEFAULT_MET_WARN_DAYS, limit: int = 50) -> List[Dict[str, Any]]:
    a = _my_actor(actor)
    wd = _clamp_days(warn_days, DEFAULT_MET_WARN_DAYS)
    lim = _clamp_limit(limit, 50)

    _ensure_metrology_schema_safe()
    today_iso = date.today().isoformat()

    with _connect_db() as conn:
        if not _table_exists(conn, "metrology_records") or not _table_exists(conn, "assets"):
            return []

        holder_col = _assets_holder_col(conn)
        qcol = _qident(holder_col)
        if not qcol:
            return []

        sql = f"""
        SELECT
            mr.met_uid,
            mr.asset_uid,
            mr.calib_type,
            COALESCE(mr.valid_until,'') AS valid_until,
            COALESCE(mr.provider_name,'') AS provider_name,
            COALESCE(mr.cert_no,'') AS cert_no,
            COALESCE(mr.updated_at,'') AS updated_at,
            CASE
                WHEN date(mr.valid_until) < date(?) THEN 'ISTEKLO'
                WHEN date(mr.valid_until) >= date(?)
                 AND date(mr.valid_until) <= date(?, '+' || ? || ' day')
                THEN 'ISTICE'
                ELSE 'OK'
            END AS status
        FROM metrology_records mr
        JOIN assets a ON a.asset_uid = mr.asset_uid
        WHERE mr.is_deleted=0
          AND COALESCE(mr.valid_until,'') <> ''
          AND COALESCE(a.{qcol},'') = ?
          AND (
                date(mr.valid_until) < date(?)
                OR (date(mr.valid_until) >= date(?)
                    AND date(mr.valid_until) <= date(?, '+' || ? || ' day'))
              )
        ORDER BY
            CASE WHEN status='ISTEKLO' THEN 0 ELSE 1 END,
            date(valid_until) ASC,
            datetime(updated_at) DESC
        LIMIT ?;
        """
        rows = conn.execute(
            sql,
            (today_iso, today_iso, today_iso, int(wd), a, today_iso, today_iso, today_iso, int(wd), int(lim)),
        ).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "met_uid": r[0],
                "asset_uid": r[1],
                "calib_type": r[2],
                "valid_until": r[3],
                "provider_name": r[4],
                "cert_no": r[5],
                "updated_at": r[6],
                "status": r[7],
            }
        )
    return out


# (FILENAME: services/dashboard_service.py - END)
# --- END PART 2/2 (services/dashboard_service.py) ---