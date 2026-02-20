# FILENAME: ui/new_asset_dialog.py
# (FILENAME: ui/new_asset_dialog.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/new_asset_dialog.py
"Novo sredstvo" dijalog (prošli dizajn + TOGGLE Napredno):
- Osnovno + Identifikacija + Zaduženje&Lokacija
- Toggle "Napredno" (sektor/jedinica, metrology flag, napomene)
- "Kome ide" = editable combobox + autocomplete iz postojećih korisnika (fail-safe fallback)
- Ako je "Kome ide" popunjeno: automatski predlog status=on_loan (i zaključava status dok je popunjeno)

HARDENING (sector-scope):
- Ako je aktivna uloga SECTOR_ADMIN:
  * sektor je AUTO iz sesije (current_sector)
  * sektor polje je zaključano (ne može ručni unos)
  * values() fail-safe override: uvek vraća sesijski sektor
Napomena:
- UI je fail-closed za punjenje liste zaposlenih: ako ne može da učita, ostaje ručni unos.
- Samo vraća values(); AssetsPage odlučuje da li će praviti assignment.
"""
from __future__ import annotations
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLabel,
    QLineEdit,
    QComboBox,
    QCheckBox,
    QTextEdit,
    QDialogButtonBox,
    QToolButton,
    QWidget,
    QMessageBox,
    QCompleter,
)

from core.config import DB_FILE


# -------------------- RBAC/session helpers (fail-soft) --------------------
def _current_sector_best_effort() -> str:
    try:
        from core.session import current_sector  # type: ignore
        return str(current_sector() or "").strip()
    except Exception:
        return ""


def _is_sector_admin_best_effort() -> bool:
    """
    True ako je aktivna uloga (effective_role) == SECTOR_ADMIN.
    Fail-soft: ako ne možemo da utvrdimo, vraćamo False (ne zaključavamo).
    """
    try:
        from core.session import get_current_user  # type: ignore
        from core.rbac import effective_role  # type: ignore
        u = get_current_user() or {}
        r = str(effective_role(u)).strip().upper()
        return r == "SECTOR_ADMIN"
    except Exception:
        return False


# -------------------- DB fallback helpers --------------------
def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _resolve_db_path() -> Path:
    p = Path(DB_FILE)
    if not p.is_absolute():
        p = (_app_root() / p).resolve()
    return p


def _connect_db() -> sqlite3.Connection:
    db_path = _resolve_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path.as_posix())
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=2500;")
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    try:
        r = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
            (name,),
        ).fetchone()
        return bool(r)
    except Exception:
        return False


def _load_employees_fail_safe(limit: int = 2000) -> List[str]:
    """
    Pokušaj da učita listu zaposlenih/korisnika:
    1) services.users_service.list_users_brief (ako postoji)
    2) DB tabela users (ako postoji) -> display_name/name/full_name/username/login/email
    Ako sve pukne: [] (ručni unos).
    """
    # 1) service layer (prefer brief)
    try:
        from services.users_service import list_users_brief  # type: ignore

        rows = list_users_brief(limit=int(limit)) or []
        out: List[str] = []
        for r in rows:
            if isinstance(r, dict):
                nm = (
                    str(
                        r.get("display_name")
                        or r.get("full_name")
                        or r.get("name")
                        or r.get("username")
                        or r.get("login")
                        or r.get("email")
                        or ""
                    ).strip()
                )
            else:
                nm = str(r or "").strip()
            if nm:
                k = nm.casefold()
                if not any(x.casefold() == k for x in out):
                    out.append(nm)
        return out
    except Exception:
        pass

    # 2) DB fallback
    try:
        conn = _connect_db()
        try:
            if not _table_exists(conn, "users"):
                return []
            cols = [str(x["name"]) for x in conn.execute("PRAGMA table_info(users);").fetchall()]
            cand = [c for c in ["display_name", "full_name", "name", "username", "login", "email"] if c in cols]
            if not cand:
                return []
            col = cand[0]
            rows = conn.execute(
                f"SELECT COALESCE(TRIM({col}), '') AS v FROM users "
                f"WHERE COALESCE(TRIM({col}), '') <> '' "
                f"ORDER BY LOWER(TRIM({col})) ASC LIMIT ?;",
                (int(limit),),
            ).fetchall()
            out: List[str] = []
            seen = set()
            for rr in rows:
                v = (rr["v"] if isinstance(rr, sqlite3.Row) else rr[0]) or ""
                v = str(v).strip()
                if not v:
                    continue
                k = v.casefold()
                if k not in seen:
                    seen.add(k)
                    out.append(v)
            return out
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception:
        return []


# -------------------- UI --------------------
@dataclass
class NewAssetValues:
    name: str
    category: str
    toc_number: str
    serial_number: str
    location: str
    status: str
    sector: str
    is_metrology: int
    assignee: str  # "kome ide"
    assign_note: str
    asset_note: str


class NewAssetDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Novo sredstvo")
        self.resize(720, 520)

        # sektor-lock state
        self._is_sector_admin = bool(_is_sector_admin_best_effort())
        self._session_sector = _current_sector_best_effort()

        # ---------- Osnovno ----------
        self.ed_name = QLineEdit()
        self.ed_name.setPlaceholderText("npr. Fluke 289 / Laptop HP 250 G10 / ...")

        self.cb_category = QComboBox()
        self.cb_category.addItems(["IT", "Metrologija", "OS", "SI", "Zalihe", "Ostalo"])

        self.cb_status = QComboBox()
        self.cb_status.addItems(["active", "on_loan", "service", "scrapped"])

        # ---------- Identifikacija ----------
        self.ed_toc = QLineEdit()
        self.ed_toc.setPlaceholderText("npr. TOC 1234 ili 1234")

        self.ed_serial = QLineEdit()
        self.ed_serial.setPlaceholderText("Serijski broj (ako postoji)")

        # ---------- Zaduženje & lokacija ----------
        self.ed_location = QLineEdit()
        self.ed_location.setPlaceholderText("npr. 2.1 laboratorija / kancelarija / magacin ...")

        self.cb_assignee = QComboBox()
        self.cb_assignee.setEditable(True)
        self.cb_assignee.setInsertPolicy(QComboBox.NoInsert)
        try:
            self.cb_assignee.setPlaceholderText("Kome ide (započni kucanje)")
        except Exception:
            pass

        self.ed_assign_note = QLineEdit()
        self.ed_assign_note.setPlaceholderText("Napomena za zaduženje (opciono)")

        # ---------- Napredno (toggle) ----------
        self.ed_sector = QLineEdit()
        self.ed_sector.setPlaceholderText("npr. 2.1 / 2.2 / Trošarina / ...")

        self.cb_is_metro = QCheckBox("Metrologija (scope flag)")
        self.cb_is_metro.setToolTip("Ako je čekirano: assets.is_metrology=1 (ulazi u metrology-scope).")

        self.txt_note = QTextEdit()
        self.txt_note.setPlaceholderText("Dodatne napomene o sredstvu (opciono).")
        self.txt_note.setFixedHeight(90)

        # ✅ HARDEN: sector-admin => sector locked to session
        if self._is_sector_admin:
            if self._session_sector:
                self.ed_sector.setText(self._session_sector)
            self.ed_sector.setReadOnly(True)
            self.ed_sector.setEnabled(False)
            self.ed_sector.setToolTip("SECTOR_ADMIN: sektor je zaključan na tvoj sektor (iz sesije).")
        else:
            # prefiliuj sektor iz sesije ako postoji (ali ostaje izmenjivo za ADMIN/global)
            if self._session_sector:
                self.ed_sector.setText(self._session_sector)

        # ---------- Load employees (fail-safe) ----------
        try:
            names = _load_employees_fail_safe(limit=2000)
        except Exception:
            names = []

        self.cb_assignee.addItem("")
        for nm in (names or []):
            self.cb_assignee.addItem(nm)

        try:
            comp = QCompleter(names or [], self)
            comp.setCaseSensitivity(Qt.CaseInsensitive)
            try:
                comp.setFilterMode(Qt.MatchContains)  # type: ignore[attr-defined]
            except Exception:
                pass
            comp.setCompletionMode(QCompleter.PopupCompletion)
            le = self.cb_assignee.lineEdit()
            if le is not None:
                le.setCompleter(comp)
            else:
                self.cb_assignee.setCompleter(comp)
        except Exception:
            pass

        # AUTO: ako kategorija Metrologija -> čekiraj flag
        def _sync_metro_flag():
            try:
                is_m = (self.cb_category.currentText().strip().casefold() == "metrologija")
                if is_m:
                    self.cb_is_metro.setChecked(True)
            except Exception:
                pass

        self.cb_category.currentIndexChanged.connect(_sync_metro_flag)
        _sync_metro_flag()

        # AUTO: ako "Kome ide" ima vrednost -> status on_loan + lock
        def _sync_status_by_assignee():
            try:
                a = (self.cb_assignee.currentText() or "").strip()
                if a:
                    self.cb_status.setCurrentText("on_loan")
                    self.cb_status.setEnabled(False)
                else:
                    self.cb_status.setEnabled(True)
            except Exception:
                pass

        self.cb_assignee.currentTextChanged.connect(_sync_status_by_assignee)
        _sync_status_by_assignee()

        # ---------- Layout ----------
        root = QVBoxLayout(self)
        title = QLabel("Unos novog sredstva")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        root.addWidget(title)

        row2 = QHBoxLayout()
        root.addLayout(row2)

        left = QFormLayout()
        left.setLabelAlignment(Qt.AlignRight)
        left.addRow("Naziv *", self.ed_name)
        left.addRow("Kategorija *", self.cb_category)
        left.addRow("Status", self.cb_status)
        w_left = QWidget()
        w_left.setLayout(left)
        w_left.setMinimumWidth(320)

        right = QFormLayout()
        right.setLabelAlignment(Qt.AlignRight)
        right.addRow("TOC broj", self.ed_toc)
        right.addRow("Serijski broj", self.ed_serial)
        w_right = QWidget()
        w_right.setLayout(right)
        w_right.setMinimumWidth(320)

        row2.addWidget(w_left, 1)
        row2.addWidget(w_right, 1)

        mid = QFormLayout()
        mid.setLabelAlignment(Qt.AlignRight)
        mid.addRow("Lokacija", self.ed_location)
        mid.addRow("Kome ide", self.cb_assignee)
        mid.addRow("Napomena (zaduženje)", self.ed_assign_note)
        w_mid = QWidget()
        w_mid.setLayout(mid)
        root.addWidget(w_mid)

        self.btn_adv = QToolButton()
        self.btn_adv.setText("Napredno")
        self.btn_adv.setCheckable(True)
        self.btn_adv.setChecked(False)
        self.btn_adv.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        try:
            self.btn_adv.setArrowType(Qt.RightArrow)
        except Exception:
            pass
        root.addWidget(self.btn_adv)

        self.adv = QWidget()
        adv_form = QFormLayout(self.adv)
        adv_form.setLabelAlignment(Qt.AlignRight)
        adv_form.addRow("Sektor/Jedinica", self.ed_sector)
        adv_form.addRow("", self.cb_is_metro)
        adv_form.addRow("Napomena (sredstvo)", self.txt_note)
        self.adv.setVisible(False)
        root.addWidget(self.adv)

        def _toggle_adv(on: bool):
            self.adv.setVisible(bool(on))
            try:
                self.btn_adv.setArrowType(Qt.DownArrow if on else Qt.RightArrow)
            except Exception:
                pass

        self.btn_adv.toggled.connect(_toggle_adv)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._on_ok)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def _on_ok(self):
        if not self.ed_name.text().strip():
            QMessageBox.warning(self, "Validacija", "Naziv je obavezan.")
            return
        if not self.cb_category.currentText().strip():
            QMessageBox.warning(self, "Validacija", "Kategorija je obavezna.")
            return

        # ✅ HARDEN: ako sector admin i nema sektora u sesiji -> fail-closed
        if self._is_sector_admin and (not self._session_sector):
            QMessageBox.warning(
                self,
                "Validacija",
                "Ne mogu da odredim sektor iz sesije (SECTOR_ADMIN). "
                "Uloguj se ponovo ili proveri podešavanja profila.",
            )
            return

        self.accept()

    def values(self) -> Dict[str, Any]:
        is_m = 1 if self.cb_is_metro.isChecked() else 0

        # ✅ HARDEN: fail-safe override za sector admin
        sector_val = (self.ed_sector.text() or "").strip()
        if self._is_sector_admin:
            sector_val = (self._session_sector or "").strip()

        return {
            "name": self.ed_name.text().strip(),
            "category": self.cb_category.currentText().strip(),
            "toc_number": self.ed_toc.text().strip(),
            "serial_number": self.ed_serial.text().strip(),
            "location": self.ed_location.text().strip(),
            "status": self.cb_status.currentText().strip(),
            "sector": sector_val,
            "is_metrology": int(is_m),
            "assignee": (self.cb_assignee.currentText() or "").strip(),
            "assign_note": (self.ed_assign_note.text() or "").strip(),
            "asset_note": (self.txt_note.toPlainText() or "").strip(),
        }

# (FILENAME: ui/new_asset_dialog.py - END)
# END FILENAME: ui/new_asset_dialog.py