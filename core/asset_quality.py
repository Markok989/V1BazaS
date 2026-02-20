# FILENAME: core/asset_quality.py
# (FILENAME: core/asset_quality.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — core/asset_quality.py

Asset Data Quality (soft-obavezna polja, bez blokiranja unosa):
- Centralizovana logika: šta fali, nivo ozbiljnosti, score.
- UI koristi ovo za:
  - banner "nedostaje X polja"
  - checklist panel u detalju sredstva
  - status u listi sredstava (kompletno / nepotpuno)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# -------------------- helpers --------------------
def _s(v: Any) -> str:
    try:
        return str(v or "")
    except Exception:
        return ""


def _norm_ws(s: str) -> str:
    # trim + collapse whitespace (ali ne diramo crtice i sl.)
    parts = (s or "").strip().split()
    return " ".join(parts)


def normalize_nomenklaturni_broj(value: Any) -> str:
    """
    Nomenklaturni broj:
    - dozvoljava: brojeve, slova, crtice, razmake, duži tekst
    - tretira se kao string
    - standardizacija: trim + collapse whitespace
    """
    return _norm_ws(_s(value))


def _get_any(asset: Dict[str, Any], keys: Tuple[str, ...]) -> Any:
    for k in keys:
        if k in asset:
            return asset.get(k)
    return None


def _is_missing(v: Any) -> bool:
    if v is None:
        return True
    if isinstance(v, str):
        return len(v.strip()) == 0
    return False


# -------------------- rules --------------------
@dataclass(frozen=True)
class FieldRule:
    code: str
    label: str
    severity: str  # "warn" | "critical"
    keys: Tuple[str, ...]


DEFAULT_RULES: List[FieldRule] = [
    # ✅ ovo je tvoj novi zahtev
    FieldRule(
        code="nomenklaturni_broj",
        label="Nomenklaturni broj",
        severity="warn",
        keys=("nomenklaturni_broj", "nomenklaturni", "nom_broj", "nomenclature_no", "nomenclature_number"),
    ),

    # Dodatni "quality" signali (ne blokiraju, samo pomažu)
    FieldRule(
        code="serial",
        label="Serijski broj",
        severity="warn",
        keys=("serial_number", "serial", "sn", "serijski_broj", "ser_broj"),
    ),
    FieldRule(
        code="location",
        label="Lokacija",
        severity="warn",
        keys=("location", "lokacija", "loc"),
    ),
    FieldRule(
        code="toc",
        label="TOC broj",
        severity="warn",
        keys=("toc", "toc_number", "toc_broj"),
    ),
    FieldRule(
        code="name",
        label="Naziv",
        severity="critical",
        keys=("name", "naziv", "asset_name", "title"),
    ),
]


def compute_asset_quality(asset: Dict[str, Any], rules: Optional[List[FieldRule]] = None) -> Dict[str, Any]:
    """
    Returns:
      {
        "missing": [{"code","label","severity"}...],
        "missing_warn": [...],
        "missing_critical": [...],
        "score": int 0..100,
        "level": "ok"|"warn"|"critical",
        "summary": "Nedostaje: ...",
        "missing_count": int,
        "total_checks": int,
      }
    """
    rr = rules or DEFAULT_RULES

    missing: List[Dict[str, str]] = []
    missing_warn: List[Dict[str, str]] = []
    missing_critical: List[Dict[str, str]] = []

    total = 0
    present = 0

    for r in rr:
        total += 1
        v = _get_any(asset, r.keys)
        if r.code == "nomenklaturni_broj":
            v = normalize_nomenklaturni_broj(v)
        if _is_missing(v):
            item = {"code": r.code, "label": r.label, "severity": r.severity}
            missing.append(item)
            if r.severity == "critical":
                missing_critical.append(item)
            else:
                missing_warn.append(item)
        else:
            present += 1

    # score: jednostavno (kasnije možeš fino da ga “težinski” doteraš)
    score = 100
    if total > 0:
        score = int(round((present / total) * 100))

    if missing_critical:
        level = "critical"
    elif missing_warn:
        level = "warn"
    else:
        level = "ok"

    if missing:
        labels = ", ".join([m["label"] for m in missing[:6]])
        more = ""
        if len(missing) > 6:
            more = f" (+{len(missing) - 6})"
        summary = f"Nedostaje: {labels}{more}"
    else:
        summary = "Sredstvo je kompletno."

    return {
        "missing": missing,
        "missing_warn": missing_warn,
        "missing_critical": missing_critical,
        "score": score,
        "level": level,
        "summary": summary,
        "missing_count": len(missing),
        "total_checks": total,
    }


def quality_badge(level: str) -> str:
    """
    Tekstualni badge (UI može da koristi emoji ili ikonicu).
    """
    lv = (level or "").strip().lower()
    if lv == "ok":
        return "🟢 Kompletno"
    if lv == "critical":
        return "🔴 Kritično"
    return "🟡 Nepotpuno"

# (FILENAME: core/asset_quality.py - END)
# FILENAME: core/asset_quality.py