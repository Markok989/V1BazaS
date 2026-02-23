# FILENAME: ui/asset_edit_dialog.py
# (FILENAME: ui/asset_edit_dialog.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/asset_edit_dialog.py

AssetEditDialog (revizija):
- UVEK pre-popunjava trenutne vrednosti iz DB (ako initial nije prosleđen ili je nepotpun)
- Snima samo stvarne promene (PATCH), da mala izmena ne “pregazi” ostala polja
- I dalje dozvoljava brisanje: korisnik obriše sadržaj polja -> snimi se prazno
- RBAC fail-safe: bez prava -> Save disabled + jasna poruka u dijalogu (bez “spam” warning-a)
- SQLite update sa tolerantnim mapiranjem kolona (različite šeme baze)
- Identifikatori (kolone) se bezbedno quoting-uju

Napomena:
- 100% offline
- Ne zavisi od assets_service (direktno DB preko DB_FILE / core.db.connect_db ako postoji)
"""

from __future__ import annotations

import logging
import re
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

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _resolve_db_path() -> Path:
    p = Path(DB_FILE)
    if not p.is_absolute():
        p = (_app_root() / p).resolve()
    return p


def _q_ident(name: str) -> str:
    """
    Quote SQLite identifikator.
    Koristimo ga za kolone koje dolaze iz PRAGMA table_info (dakle iz DB).
    """
    n = str(name or "").replace('"', '""')
    return f'"{n}"'


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _safe_str(v: Any) -> str:
    return ("" if v is None else str(v)).strip()


def _try_table_exists(conn: sqlite3.Connection, table: str) -> bool:
    try:
        cur = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (table,),
        )
        return cur.fetchone() is not None
    except Exception:
        return False


def _table_cols(conn: sqlite3.Connection, table: str) -> List[str]:
    if not table or not _IDENT_RE.match(table):
        return []
    try:
        cur = conn.execute(f"PRAGMA table_info({_q_ident(table)})")
        return [str(r[1]) for r in cur.fetchall()]
    except Exception:
        return []


def _pick_col(cols: List[str], *cands: str) -> str:
    s = set(cols or [])
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
    """
    Prefer core.db.connect_db ako postoji, inače fallback na DB_FILE.
    Napomena: connect_db u projektu često podešava WAL/busy_timeout; koristimo ga kad možemo.
    """
    try:
        from core.db import connect_db as _connect_db  # type: ignore
    except Exception:
        _connect_db = None  # type: ignore

    if _connect_db is not None:
        try:
            conn = _connect_db()
            try:
                conn.row_factory = sqlite3.Row
            except Exception:
                pass
            return conn
        except Exception:
            pass

    db_path = _resolve_db_path()
    conn2 = sqlite3.connect(db_path.as_posix())
    try:
        conn2.row_factory = sqlite3.Row
    except Exception:
        pass
    try:
        conn2.execute("PRAGMA busy_timeout=2500;")
        conn2.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass
    return conn2


def _build_assets_col_map(cols: List[str]) -> Dict[str, str]:
    """
    Standard polja (UI) -> stvarne kolone u DB (tolerantno).
    Prazno znači: kolona ne postoji u toj šemi baze.
    """
    return {
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
        "_updated_at": _pick_col(cols, "updated_at", "modified_at", "updated"),
    }


def read_asset_for_edit(asset_uid: str) -> Tuple[Dict[str, Any], str]:
    """
    Čita trenutne vrednosti iz DB i vraća standardizovan dict.
    Vraća (data, err). err="" kad je sve ok.
    """
    uid = (asset_uid or "").strip()
    if not uid:
        return {}, "Nema asset_uid."

    conn = _open_conn()
    try:
        if not _try_table_exists(conn, "assets"):
            return {}, "Ne postoji tabela 'assets' u bazi."
        cols = _table_cols(conn, "assets")
        if "asset_uid" not in cols:
            return {}, "Tabela 'assets' nema kolonu 'asset_uid'."

        cmap = _build_assets_col_map(cols)

        # select samo postojeće kolone
        sel_cols = ["asset_uid"]
        for k, c in cmap.items():
            if k.startswith("_"):
                continue
            if c:
                sel_cols.append(c)
        if cmap.get("_updated_at"):
            sel_cols.append(cmap["_updated_at"])

        sel_sql = ", ".join(_q_ident(c) for c in sel_cols)
        row = conn.execute(
            f"SELECT {sel_sql} FROM assets WHERE asset_uid=? LIMIT 1",
            (uid,),
        ).fetchone()
        if not row:
            return {}, "Sredstvo nije pronađeno u bazi."

        # row može biti sqlite3.Row ili tuple
        def _get(col: str) -> Any:
            try:
                if isinstance(row, sqlite3.Row):
                    return row[col]  # type: ignore[index]
            except Exception:
                pass
            try:
                idx = sel_cols.index(col)
                return row[idx]  # type: ignore[index]
            except Exception:
                return None

        out: Dict[str, Any] = {"asset_uid": uid}
        for key, col in cmap.items():
            if key.startswith("_"):
                continue
            if col:
                out[key] = _get(col)
            else:
                out[key] = ""

        if cmap.get("_updated_at"):
            out["_updated_at"] = _get(cmap["_updated_at"])  # type: ignore[index]
        else:
            out["_updated_at"] = ""

        # normalizacija bool flag-a
        out["is_metrology"] = 1 if _safe_int(out.get("is_metrology", 0), 0) == 1 else 0

        # string trim
        for k in ("name", "category", "toc_number", "serial_number", "nomenclature_no", "inventory_no",
                  "sector", "location", "current_holder", "vendor", "model", "notes"):
            out[k] = _safe_str(out.get(k, ""))

        return out, ""
    except Exception as e:
        log.debug("read_asset_for_edit failed", exc_info=True)
        return {}, str(e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def update_asset_fields(asset_uid: str, updates: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Upis u assets tabelu (PATCH):
    - updates sadrži SAMO polja koja treba menjati
    - tolerantno mapiranje na kolone u DB
    - dozvoljava brisanje vrednosti (prazan string) kad je to u updates
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

        cmap = _build_assets_col_map(cols)
        col_updated = cmap.get("_updated_at", "")

        set_parts: List[str] = []
        vals: List[Any] = []
        skipped: List[str] = []

        for key, val in updates.items():
            col = cmap.get(key, "")
            if not col:
                skipped.append(key)
                continue

            if key == "is_metrology":
                v = 1 if _safe_int(val, 0) == 1 else 0
                set_parts.append(f"{_q_ident(col)}=?")
                vals.append(v)
            else:
                set_parts.append(f"{_q_ident(col)}=?")
                # ovde namerno dozvoljavamo "" (brisanje)
                vals.append("" if val is None else val)

        if col_updated:
            set_parts.append(f"{_q_ident(col_updated)}=?")
            vals.append(datetime.now().isoformat(timespec="seconds"))

        if not set_parts:
            return False, "Ni jedno polje nije moglo da se upiše (kolone ne postoje u DB)."

        sql = f"UPDATE assets SET {', '.join(set_parts)} WHERE asset_uid=?"
        vals.append(uid)

        cur = conn.execute(sql, tuple(vals))
        conn.commit()

        if getattr(cur, "rowcount", 0) <= 0:
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
    """
    UI dijalog za izmenu.
    Ključna stvar: dijalog sam učitava trenutne vrednosti iz DB i upisuje samo promene.
    """

    def __init__(self, asset_uid: str, initial: Optional[Dict[str, Any]] = None, parent=None):
        super().__init__(parent)
        self.setModal(True)

        self.asset_uid = (asset_uid or "").strip()
        self.initial = dict(initial or {})

        self.setWindowTitle(f"Izmeni sredstvo — {self.asset_uid}")
        self.resize(580, 600)

        # trenutne vrednosti (iz DB) + eventualni initial overlay
        self._current: Dict[str, Any] = {}
        self._current_err: str = ""

        root = QVBoxLayout(self)

        self.lb_rbac = QLabel("")
        self.lb_rbac.setWordWrap(True)
        self.lb_rbac.setStyleSheet("color:#b00020; font-weight:700;")
        self.lb_rbac.hide()
        root.addWidget(self.lb_rbac)

        info = QLabel(
            "Izmeni podatke i klikni Snimi.\n"
            "Dijalog pre-popunjava trenutne vrednosti iz baze.\n"
            "Snimaju se samo promene (PATCH), pa mala izmena ne dira ostala polja.\n"
            "Brisanje je moguće: obriši sadržaj polja i snimi."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color:#666;")
        root.addWidget(info)

        self._load_current_values()

        form = QFormLayout()
        root.addLayout(form)

        def cur_text(key: str) -> str:
            # initial overlay ima prioritet samo ako je data vrednost (npr. pre-supply iz nekog UI-ja)
            if key in self.initial and self.initial.get(key) is not None:
                return _safe_str(self.initial.get(key))
            return _safe_str(self._current.get(key, ""))

        # Widgets
        self.ed_name = QLineEdit(cur_text("name"))
        self.ed_cat = QLineEdit(cur_text("category"))
        self.ed_toc = QLineEdit(cur_text("toc_number"))
        self.ed_nom = QLineEdit(cur_text("nomenclature_no"))
        self.ed_sn = QLineEdit(cur_text("serial_number"))
        self.ed_inv = QLineEdit(cur_text("inventory_no"))
        self.ed_sector = QLineEdit(cur_text("sector"))
        self.ed_loc = QLineEdit(cur_text("location"))
        self.ed_holder = QLineEdit(cur_text("current_holder"))
        self.ed_vendor = QLineEdit(cur_text("vendor"))
        self.ed_model = QLineEdit(cur_text("model"))

        self.cb_metro = QCheckBox("Metrologija (flag)")
        try:
            init_flag = self.initial.get("is_metrology", None)
            if init_flag is None:
                init_flag = self._current.get("is_metrology", 0)
            self.cb_metro.setChecked(_safe_int(init_flag, 0) == 1)
        except Exception:
            self.cb_metro.setChecked(False)

        self.ed_notes = QPlainTextEdit(cur_text("notes"))
        self.ed_notes.setFixedHeight(140)

        # placeholders (UX sitnice, bez promene logike)
        self.ed_toc.setPlaceholderText("TOC broj (npr. 123-456)")
        self.ed_nom.setPlaceholderText("Nomenklaturni broj")
        self.ed_sn.setPlaceholderText("Serijski broj")
        self.ed_inv.setPlaceholderText("Inventarski broj")
        self.ed_sector.setPlaceholderText("Sektor / jedinica")
        self.ed_loc.setPlaceholderText("Lokacija")
        self.ed_holder.setPlaceholderText("Zaduženo kod (nosilac)")

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
        try:
            self.btns.button(QDialogButtonBox.Save).setText("Snimi")     # type: ignore
            self.btns.button(QDialogButtonBox.Cancel).setText("Otkaži")  # type: ignore
        except Exception:
            pass
        root.addWidget(self.btns)

        self.btns.accepted.connect(self._on_save)
        self.btns.rejected.connect(self.reject)

        self._apply_rbac_and_state()

    def _load_current_values(self) -> None:
        if not self.asset_uid:
            self._current, self._current_err = {}, "Nema asset_uid."
            return

        data, err = read_asset_for_edit(self.asset_uid)
        self._current = data or {}
        self._current_err = err or ""

    def _apply_rbac_and_state(self) -> None:
        can_edit = _can_asset_edit()

        if self._current_err:
            # Ako ne možemo ni da učitamo sredstvo, nema smisla snimati.
            self.lb_rbac.setText(f"Ne mogu da učitam trenutno stanje sredstva.\n\n{self._current_err}")
            self.lb_rbac.show()
            can_edit = False

        if not _can_asset_edit():
            self.lb_rbac.setText("RBAC: nemaš pravo da menjaš podatke sredstava.")
            self.lb_rbac.show()

        try:
            self.btns.button(QDialogButtonBox.Save).setEnabled(bool(can_edit))  # type: ignore
        except Exception:
            pass

    def _gather_new_values(self) -> Dict[str, Any]:
        return {
            "name": _safe_str(self.ed_name.text()),
            "category": _safe_str(self.ed_cat.text()),
            "toc_number": _safe_str(self.ed_toc.text()),
            "nomenclature_no": _safe_str(self.ed_nom.text()),
            "serial_number": _safe_str(self.ed_sn.text()),
            "inventory_no": _safe_str(self.ed_inv.text()),
            "sector": _safe_str(self.ed_sector.text()),
            "location": _safe_str(self.ed_loc.text()),
            "current_holder": _safe_str(self.ed_holder.text()),
            "vendor": _safe_str(self.ed_vendor.text()),
            "model": _safe_str(self.ed_model.text()),
            "notes": _safe_str(self.ed_notes.toPlainText()),
            "is_metrology": 1 if self.cb_metro.isChecked() else 0,
        }

    def _diff_updates(self, new_vals: Dict[str, Any]) -> Dict[str, Any]:
        """
        PATCH logika:
        - vraća samo polja koja su stvarno promenjena u odnosu na trenutno stanje (self._current)
        - prazno polje je validna promena (brisanje) samo ako je pre toga bilo nešto
        """
        cur = self._current or {}
        out: Dict[str, Any] = {}

        for k, v in new_vals.items():
            if k == "is_metrology":
                if _safe_int(v, 0) != _safe_int(cur.get(k, 0), 0):
                    out[k] = 1 if _safe_int(v, 0) == 1 else 0
                continue

            nv = _safe_str(v)
            cv = _safe_str(cur.get(k, ""))

            if nv != cv:
                out[k] = nv  # nv može biti "" => brisanje

        return out

    def _on_save(self) -> None:
        if not _can_asset_edit():
            QMessageBox.warning(self, "Zabranjeno", "Nemaš pravo da menjaš podatke sredstava.")
            return
        if not self.asset_uid:
            QMessageBox.warning(self, "Greška", "Nema asset_uid.")
            return

        new_vals = self._gather_new_values()
        updates = self._diff_updates(new_vals)

        if not updates:
            QMessageBox.information(self, "Info", "Nema promena za snimanje.")
            self.accept()
            return

        ok, msg = update_asset_fields(self.asset_uid, updates)
        if not ok:
            QMessageBox.critical(self, "Greška", f"Ne mogu da sačuvam.\n\n{msg}")
            return

        QMessageBox.information(self, "OK", msg)
        self.accept()

# (FILENAME: ui/asset_edit_dialog.py - END)