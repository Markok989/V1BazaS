# FILENAME: ui/utils/datetime_fmt.py
# (FILENAME: ui/utils/datetime_fmt.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/utils/datetime_fmt.py

Centralni formatteri za prikaz datuma/vremena u UI.
✅ SR format: DD.MM.YYYY
✅ 24h format: DD.MM.YYYY HH:MM

Kompatibilnost:
- Zadržane pomoćne funkcije koje UI već koristi:
  - sr_to_iso_date()
  - iso_to_sr_masked()

Tolerantno parsiranje prihvata i:
- 2026-2-1, 2026/02/01, 2026.02.01
- 2026-02-01 7:05, 2026-02-01 07:05:33, 2026-02-01T07:05:33Z
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Optional, Tuple


# -------------------- regex helpers --------------------
_RE_SR_DATE = re.compile(r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{4})\.?\s*$")
_RE_SR_DT = re.compile(r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{4})\.?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*$")

_RE_ISO_DATE_FLEX = re.compile(r"^\s*(\d{4})[-/\.](\d{1,2})[-/\.](\d{1,2})\s*$")

# YYYY-MM-DD[ T]HH:MM[:SS][.ms][Z|+HH:MM]
_RE_ISO_DT_FLEX = re.compile(
    r"^\s*(\d{4})[-/\.](\d{1,2})[-/\.](\d{1,2})"
    r"[ T](\d{1,2}):(\d{2})(?::(\d{2}))?"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s*$"
)


# -------------------- internal formatters --------------------
def _fmt_sr_date(d: date) -> str:
    return f"{d.day:02d}.{d.month:02d}.{d.year:04d}"


def _fmt_sr_dt(dt: datetime) -> str:
    # 24h, bez sekundi (preglednije u tabelama)
    return f"{dt.day:02d}.{dt.month:02d}.{dt.year:04d} {dt.hour:02d}:{dt.minute:02d}"


def _safe_make_datetime(y: int, mo: int, da: int, hh: int = 0, mm: int = 0, ss: int = 0) -> Optional[datetime]:
    try:
        return datetime(int(y), int(mo), int(da), int(hh), int(mm), int(ss))
    except Exception:
        return None


def _parse_sr(s: str) -> Tuple[Optional[datetime], bool]:
    """
    Parse SR format:
    - DD.MM.YYYY (date_only=True)
    - DD.MM.YYYY HH:MM(:SS) (date_only=False)
    """
    ss = (s or "").strip()
    if not ss:
        return (None, False)

    mdt = _RE_SR_DT.match(ss)
    if mdt:
        d, mo, y = int(mdt.group(1)), int(mdt.group(2)), int(mdt.group(3))
        hh, mm = int(mdt.group(4)), int(mdt.group(5))
        sec = int(mdt.group(6) or 0)
        return (_safe_make_datetime(y, mo, d, hh, mm, sec), False)

    md = _RE_SR_DATE.match(ss)
    if md:
        d, mo, y = int(md.group(1)), int(md.group(2)), int(md.group(3))
        return (_safe_make_datetime(y, mo, d, 0, 0, 0), True)

    return (None, False)


def _parse_iso_like(s: str) -> Tuple[Optional[datetime], bool]:
    """
    Parse ISO-like flexible:
    - YYYY-M-D / YYYY/MM/DD / YYYY.MM.DD (date_only=True)
    - ... + time (date_only=False)
    """
    ss = (s or "").strip()
    if not ss:
        return (None, False)

    # date-only (flex)
    md = _RE_ISO_DATE_FLEX.match(ss)
    if md and not _RE_ISO_DT_FLEX.match(ss):
        y, mo, da = int(md.group(1)), int(md.group(2)), int(md.group(3))
        return (_safe_make_datetime(y, mo, da, 0, 0, 0), True)

    # datetime (flex)
    if _RE_ISO_DT_FLEX.match(ss):
        # pokušaj fromisoformat (posle malog normalizovanja)
        try:
            ss2 = ss.replace("Z", "+00:00")
            if "T" not in ss2 and " " in ss2:
                ss2 = ss2.replace(" ", "T", 1)
            # fromisoformat ne voli '/', '.' u datumu -> zamenimo u '-'
            ss2 = ss2.replace("/", "-").replace(".", "-")
            dt = datetime.fromisoformat(ss2)
            return (dt, False)
        except Exception:
            # ručni fallback bez TZ
            try:
                s3 = ss.replace("T", " ").strip()
                s3 = s3.replace("/", "-").replace(".", "-")
                parts = s3.split()
                dpart = parts[0]
                tpart = parts[1] if len(parts) > 1 else "00:00:00"

                y, mo, da = [int(x) for x in dpart.split("-")]
                tt = tpart.split(":")
                hh = int(tt[0]) if len(tt) > 0 else 0
                mm = int(tt[1]) if len(tt) > 1 else 0
                sec_raw = tt[2] if len(tt) > 2 else "0"
                # skini tz / ms iz sekundi dela
                sec = int(re.split(r"[^\d]", sec_raw)[0] or "0")
                return (_safe_make_datetime(y, mo, da, hh, mm, sec), False)
            except Exception:
                return (None, False)

    return (None, False)


# -------------------- PUBLIC: display helpers --------------------
def fmt_date_sr(x: Any) -> str:
    """
    UI prikaz datuma: DD.MM.YYYY
    """
    if x is None:
        return ""
    if isinstance(x, date) and not isinstance(x, datetime):
        return _fmt_sr_date(x)
    if isinstance(x, datetime):
        return _fmt_sr_date(x.date())

    s = str(x).strip()
    if not s:
        return ""

    # SR -> normalize
    dt_sr, _date_only_sr = _parse_sr(s)
    if dt_sr is not None:
        return _fmt_sr_date(dt_sr.date())

    # ISO-like -> SR
    dt_iso, _date_only_iso = _parse_iso_like(s)
    if dt_iso is not None:
        return _fmt_sr_date(dt_iso.date())

    return s


def fmt_dt_sr(x: Any) -> str:
    """
    UI prikaz datuma+vremena: DD.MM.YYYY HH:MM (24h)
    - Ako je input samo datum, vraća samo datum (bez 00:00).
    """
    if x is None:
        return ""
    if isinstance(x, datetime):
        return _fmt_sr_dt(x)
    if isinstance(x, date) and not isinstance(x, datetime):
        return _fmt_sr_date(x)

    s = str(x).strip()
    if not s:
        return ""

    # SR parse
    dt_sr, date_only_sr = _parse_sr(s)
    if dt_sr is not None:
        return _fmt_sr_date(dt_sr.date()) if date_only_sr else _fmt_sr_dt(dt_sr)

    # ISO parse
    dt_iso, date_only_iso = _parse_iso_like(s)
    if dt_iso is not None:
        return _fmt_sr_date(dt_iso.date()) if date_only_iso else _fmt_sr_dt(dt_iso)

    return s


# -------------------- PUBLIC: widget compatibility helpers --------------------
def sr_to_iso_date(x: Any) -> str:
    """
    Pretvori SR datum (DD.MM.YYYY) u ISO (YYYY-MM-DD).
    - Ako je već ISO date-like, normalizuje u YYYY-MM-DD.
    - Ako je invalid/prazno, vrati "".
    """
    if x is None:
        return ""
    s = str(x).strip()
    if not s:
        return ""

    # prvo SR
    dt_sr, _date_only = _parse_sr(s)
    if dt_sr is not None:
        return f"{dt_sr.year:04d}-{dt_sr.month:02d}-{dt_sr.day:02d}"

    # onda ISO-like date (bez vremena)
    md = _RE_ISO_DATE_FLEX.match(s)
    if md and not _RE_ISO_DT_FLEX.match(s):
        try:
            y, mo, da = int(md.group(1)), int(md.group(2)), int(md.group(3))
            if _safe_make_datetime(y, mo, da) is None:
                return ""
            return f"{y:04d}-{mo:02d}-{da:02d}"
        except Exception:
            return ""

    return ""


def iso_to_sr_masked(x: Any) -> str:
    """
    Pretvori ISO datum/datetime u SR prikaz (DD.MM.YYYY) za mask input.
    - Ako je već SR, normalizuje.
    - Ako je invalid/prazno, vrati "".
    """
    if x is None:
        return ""
    s = str(x).strip()
    if not s:
        return ""

    dt_sr, _date_only_sr = _parse_sr(s)
    if dt_sr is not None:
        return _fmt_sr_date(dt_sr.date())

    dt_iso, _date_only_iso = _parse_iso_like(s)
    if dt_iso is not None:
        return _fmt_sr_date(dt_iso.date())

    return ""

# (FILENAME: ui/utils/datetime_fmt.py - END)