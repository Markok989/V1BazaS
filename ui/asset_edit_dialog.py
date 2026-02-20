# FILENAME: ui/asset_edit_dialog.py
# (FILENAME: ui/asset_edit_dialog.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/asset_edit_dialog.py

AssetEditDialog:
- Modal dijalog za izmenu ključnih polja sredstva
- Ne forsira obavezna polja (V1), ali omogućava unos/brisanje vrednosti
- RBAC fail-safe: bez prava -> Save je disabled + poruka
- SQLite update sa tolerantnim mapiranjem kolona (različite šeme baze)

Napomena:
- 100% offline
- Ne zavisi od assets_service (direktno DB preko DB_FILE / core.db ako postoji)
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QVBoxLayout,
)

from core.config import DB_FILE
from core.session import actor_name, can

# (Optional) assets edit perm (projekti nekad imaju različita imena)
try:
    from core.rbac import PERM_ASSETS_EDIT  # type: ignore
except Exception:  # pragma: no cover
    PERM_ASSETS_EDIT = "assets.edit"

log = logging.getLogger(__name__)


def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _resolve_db_path() -> Path:
    p = Path(DB_FILE)
    if not p.is_absolute():
        p = (_app_root() / p).resolve()
    return p


def _try_table_exists(conn: sqlite3.Connection, table: str) -> bool:
    try:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (table,))
        return cur.fetchone() is not None
    except Exception:
        return False


def _table_cols(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return [str(r[1]) for r in cur.fetchall()]
    except Exception:
        return []


def _pick_col(cols: List[str], *cands: str) -> str:
    s = set(cols)
    for c in cands:
        if c in s:
            return c
    return ""


def _can_asset_edit() -> bool:
    """Fail-safe RBAC: dovoljno je da prođe bilo koji poznat edit/manage perm."""
    try:
        if bool(can(PERM_ASSETS_EDIT)):
            return True
    except Exception:
        pass

    for p in ("assets.update", "assets.manage", "assets.write", "assets.edit", "assets.change_status"):
        try:
            if bool(can(p)):
                return True
        except Exception:
            continue
    return False


def _open_conn() -> sqlite3.Connection:
    """Prefer core.db.connect_db ako postoji, inače fallback na DB_FILE."""
    try:
        from core.db import connect_db as _connect_db  # type: ignore
    except Exception:
        _connect_db = None  # type: ignore

    if _connect_db is not None:
        try:
            return _connect_db()
        except Exception:
            pass

    db_path = _resolve_db_path()
    return sqlite3.connect(db_path.as_posix())


def update_asset_fields(asset_uid: str, updates: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Upis u assets tabelu:
    - tolerantno mapiranje na kolone u DB
    - dozvoljava brisanje vrednosti (prazan string)
    - best-effort updated_at
    """
    uid = (asset_uid or "").strip()
    if not uid:
        return False, "Nema asset_uid."

    if not updates:
        return True, "Nema promena."

    conn = _open_conn()
    try:
        if not _try_table_exists(conn, "assets"):
            return False, "Ne postoji tabela 'assets' u bazi."

        cols = _table_cols(conn, "assets")
        if "asset_uid" not in cols:
            return False, "Tabela 'assets' nema kolonu 'asset_uid'."

        # Map standard polja -> stvarne kolone
        col_map = {
            "name": _pick_col(cols, "name", "asset_name"),
            "category": _pick_col(cols, "category", "cat"),
            "toc_number": _pick_col(cols, "toc_number", "toc"),
            "serial_number": _pick_col(cols, "serial_number", "serial"),
            "nomenclature_no": _pick_col(
                cols,
                "nomenclature_no", "nomenclature_number", "nomencl_no",
                "nomenklaturni_broj", "nomenkl_broj", "nomenklatura",
                "nom_no", "nom_number", "nomenclature",
            ),
            "inventory_no": _pick_col(cols, "inventory_no", "inv_no", "inventarski_broj"),
            "sector": _pick_col(cols, "sector", "sektor", "org_unit", "unit", "department", "dept", "section"),
            "location": _pick_col(cols, "location", "loc"),
            "current_holder": _pick_col(cols, "current_holder", "holder", "assigned_to"),
            "vendor": _pick_col(cols, "vendor", "manufacturer", "maker"),
            "model": _pick_col(cols, "model", "device_model"),
            "notes": _pick_col(cols, "notes", "note", "napomena", "opis"),
            "is_metrology": _pick_col(cols, "is_metrology", "is_metro", "metrology_flag", "metro_flag", "metrology_scope"),
        }
        col_updated = _pick_col(cols, "updated_at", "modified_at", "updated")

        set_parts: List[str] = []
        vals: List[Any] = []
        skipped: List[str] = []

        for key, val in updates.items():
            col = col_map.get(key, "")
            if not col:
                skipped.append(key)
                continue

            if key == "is_metrology":
                try:
                    v = 1 if int(val or 0) == 1 else 0
                except Exception:
                    v = 0
                set_parts.append(f"{col}=?")
                vals.append(v)
            else:
                set_parts.append(f"{col}=?")
                vals.append(val)

        if col_updated:
            set_parts.append(f"{col_updated}=?")
            vals.append(datetime.now().isoformat(timespec="seconds"))

        if not set_parts:
            return False, "Ni jedno polje nije moglo da se upiše (kolone ne postoje u DB)."

        sql = f"UPDATE assets SET {', '.join(set_parts)} WHERE asset_uid=?"
        vals.append(uid)

        cur = conn.execute(sql, tuple(vals))
        conn.commit()

        if cur.rowcount <= 0:
            return False, "Sredstvo nije pronađeno (nema update)."

        msg = "Snimljeno."
        if skipped:
            msg += f" Preskočeno (nema kolona u DB): {', '.join(skipped)}"
        return True, msg

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        log.debug("update_asset_fields error", exc_info=True)
        return False, str(e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


class AssetEditDialog(QDialog):
    def __init__(self, asset_uid: str, initial: Optional[Dict[str, Any]] = None, parent=None):
        super().__init__(parent)
        self.setModal(True)

        self.asset_uid = (asset_uid or "").strip()
        self.initial = initial or {}

        self.setWindowTitle(f"Izmeni sredstvo — {self.asset_uid}")
        self.resize(560, 560)

        root = QVBoxLayout(self)

        info = QLabel(
            "Izmeni podatke i klikni Snimi.\n"
            "Polja nisu hard-obavezna (V1), ali prazna polja daju upozorenje u detaljima sredstva."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color:#666;")
        root.addWidget(info)

        form = QFormLayout()
        root.addLayout(form)

        def _init_text(key: str) -> str:
            return str(self.initial.get(key, "") or "")

        self.ed_name = QLineEdit(_init_text("name"))
        self.ed_cat = QLineEdit(_init_text("category"))
        self.ed_toc = QLineEdit(_init_text("toc_number"))
        self.ed_nom = QLineEdit(_init_text("nomenclature_no"))
        self.ed_sn = QLineEdit(_init_text("serial_number"))
        self.ed_inv = QLineEdit(_init_text("inventory_no"))
        self.ed_sector = QLineEdit(_init_text("sector"))
        self.ed_loc = QLineEdit(_init_text("location"))
        self.ed_holder = QLineEdit(_init_text("current_holder"))
        self.ed_vendor = QLineEdit(_init_text("vendor"))
        self.ed_model = QLineEdit(_init_text("model"))

        self.cb_metro = QCheckBox("Metrologija (flag)")
        try:
            self.cb_metro.setChecked(int(self.initial.get("is_metrology", 0) or 0) == 1)
        except Exception:
            self.cb_metro.setChecked(False)

        self.ed_notes = QPlainTextEdit(_init_text("notes"))
        self.ed_notes.setFixedHeight(120)

        form.addRow("Naziv", self.ed_name)
        form.addRow("Kategorija", self.ed_cat)
        form.addRow("TOC", self.ed_toc)
        form.addRow("Nomenklaturni broj", self.ed_nom)
        form.addRow("Serijski broj", self.ed_sn)
        form.addRow("Inventarski broj", self.ed_inv)
        form.addRow("Sektor", self.ed_sector)
        form.addRow("Lokacija", self.ed_loc)
        form.addRow("Zaduženo kod", self.ed_holder)
        form.addRow("Proizvođač", self.ed_vendor)
        form.addRow("Model", self.ed_model)
        form.addRow("", self.cb_metro)
        form.addRow("Napomena/Opis", self.ed_notes)

        self.btns = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.btns.button(QDialogButtonBox.Save).setText("Snimi")     # type: ignore
        self.btns.button(QDialogButtonBox.Cancel).setText("Otkaži")  # type: ignore
        root.addWidget(self.btns)

        self.btns.accepted.connect(self._on_save)
        self.btns.rejected.connect(self.reject)

        # RBAC
        if not _can_asset_edit():
            self.btns.button(QDialogButtonBox.Save).setEnabled(False)  # type: ignore
            QMessageBox.warning(self, "Zabranjeno", "Nemaš pravo da menjaš podatke sredstava.")

    def _on_save(self) -> None:
        if not _can_asset_edit():
            QMessageBox.warning(self, "Zabranjeno", "Nemaš pravo da menjaš podatke sredstava.")
            return

        updates: Dict[str, Any] = {
            "name": (self.ed_name.text() or "").strip(),
            "category": (self.ed_cat.text() or "").strip(),
            "toc_number": (self.ed_toc.text() or "").strip(),
            "nomenclature_no": (self.ed_nom.text() or "").strip(),
            "serial_number": (self.ed_sn.text() or "").strip(),
            "inventory_no": (self.ed_inv.text() or "").strip(),
            "sector": (self.ed_sector.text() or "").strip(),
            "location": (self.ed_loc.text() or "").strip(),
            "current_holder": (self.ed_holder.text() or "").strip(),
            "vendor": (self.ed_vendor.text() or "").strip(),
            "model": (self.ed_model.text() or "").strip(),
            "notes": (self.ed_notes.toPlainText() or "").strip(),
            "is_metrology": 1 if self.cb_metro.isChecked() else 0,
        }

        ok, msg = update_asset_fields(self.asset_uid, updates)
        if not ok:
            QMessageBox.critical(self, "Greška", f"Ne mogu da sačuvam.\n\n{msg}")
            return

        QMessageBox.information(self, "OK", msg)
        self.accept()

# (FILENAME: ui/asset_edit_dialog.py - END)