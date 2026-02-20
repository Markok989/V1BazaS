# FILENAME: ui/users_page.py
# (FILENAME: ui/users_page.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/users_page.py

STANDARD tabela (pilot #3 — Korisnici):
- Redni broj (# / Rb) kao prva kolona (uvek vidljiva)
- Sortiranje klikom na header (uvek ON)
- Drag&Drop kolona po headeru (redosled se pamti kroz wire_columns)
- Filter/search iznad tabele (TableToolsBar)
- Ctrl+C kopiranje kao TSV (header + selekcija)

Promene (V1.x):
- Sortiranje je UVEK uključeno (nema više toggle).
- NEMA Drag&Drop redova (samo kolone preko header DnD).
- Dodata kolona "Policy" (badge): "MORA PROMENA" / "OK" (must_change_creds).
- RBAC fail-closed: ako nema users.view, UI se zaključa i ne učitava.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Optional, List, Tuple, Any

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtGui import QColor, QBrush, QFont  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QMessageBox,
    QAbstractItemView, QDialog, QTableWidgetItem, QTableWidget
)

from core.session import can
from core.rbac import PERM_USERS_VIEW, PERM_USERS_MANAGE

from services.users_service import (
    ensure_users_schema,
    list_users,
)

from ui.user_detail_dialog import UserDetailDialog

from ui.columns_dialog import ColSpec
from ui.utils.table_columns import wire_columns

# ✅ STANDARD copy: header persist + Ctrl+C TSV
from ui.utils.table_copy import wire_table_header_plus_copy

# ✅ global tools: search (bez sort toggle-a).
from ui.utils.table_search_sort import TableToolsBar, TableToolsConfig


def _safe_can(perm: str) -> bool:
    try:
        return bool(can(perm))
    except Exception:
        return False


def _warn(parent: QWidget, text: str, title: str = "Upozorenje") -> None:
    QMessageBox.warning(parent, title, text)


# -------------------- DATE PARSE + DISPLAY (UI) --------------------
_RE_ISO_DT = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?\s*$")
_RE_SR_DT = re.compile(r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{4})(?:\.\s*|\s+)?(?:(\d{1,2}):(\d{2})(?::(\d{2}))?)?\s*$")


def _try_parse_dt(s: str) -> Optional[datetime]:
    t = (s or "").strip()
    if not t:
        return None

    m = _RE_ISO_DT.match(t)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hh = int(m.group(4) or 0)
        mm = int(m.group(5) or 0)
        ss = int(m.group(6) or 0)
        try:
            return datetime(y, mo, d, hh, mm, ss)
        except Exception:
            return None

    m = _RE_SR_DT.match(t)
    if m:
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hh = int(m.group(4) or 0)
        mm = int(m.group(5) or 0)
        ss = int(m.group(6) or 0)
        try:
            return datetime(y, mo, d, hh, mm, ss)
        except Exception:
            return None

    try:
        tt = t.replace("Z", "")
        return datetime.fromisoformat(tt)
    except Exception:
        return None


def _fmt_dt_sr(value: Any) -> str:
    s = ("" if value is None else str(value)).strip()
    if not s:
        return "—"
    dt = _try_parse_dt(s)
    if not dt:
        return s
    return dt.strftime("%d.%m.%Y %H:%M:%S")


# -------------------- SMART SORT --------------------
def _try_parse_number(s: str) -> Optional[float]:
    t = (s or "").strip()
    if not t:
        return None

    t2 = re.sub(r"[^\d\-\+\., ]", "", t).strip()
    if not t2:
        return None

    t2 = t2.replace(" ", "")

    if "," in t2 and "." in t2:
        t2 = t2.replace(".", "").replace(",", ".")
    elif "," in t2 and "." not in t2:
        t2 = t2.replace(",", ".")

    try:
        return float(t2)
    except Exception:
        return None


def _smart_key(text: str) -> Tuple[int, Any]:
    s = (text or "").strip()

    dt = _try_parse_dt(s)
    if dt is not None:
        return (0, dt.timestamp())

    n = _try_parse_number(s)
    if n is not None:
        return (1, n)

    return (2, s.casefold())


class SmartItem(QTableWidgetItem):
    def __init__(self, text: str, *, sort_key: Optional[Tuple[int, Any]] = None) -> None:
        super().__init__(text)
        self._k = sort_key if sort_key is not None else _smart_key(text)

    def __lt__(self, other: "QTableWidgetItem") -> bool:  # type: ignore[override]
        try:
            if isinstance(other, SmartItem):
                return self._k < other._k
        except Exception:
            pass
        try:
            return _smart_key(self.text()) < _smart_key(other.text())
        except Exception:
            return super().__lt__(other)


def _item(text: Any, *, sort_key: Optional[Tuple[int, Any]] = None) -> SmartItem:
    return SmartItem(str(text or ""), sort_key=sort_key)


def _dt_item(raw: Any) -> SmartItem:
    s = ("" if raw is None else str(raw)).strip()
    disp = _fmt_dt_sr(s)
    dt = _try_parse_dt(s)
    if dt is not None:
        return _item(disp, sort_key=(0, dt.timestamp()))
    return _item(disp, sort_key=(9, disp.casefold()))


def _rb_item(n: int) -> SmartItem:
    it = _item(str(int(n)), sort_key=(0, int(n)))
    it.setTextAlignment(Qt.AlignCenter)
    return it


def _active_badge(active: bool) -> SmartItem:
    txt = "AKTIVAN" if active else "NEAKTIVAN"
    it = _item(txt, sort_key=(0, 1 if active else 0))
    it.setTextAlignment(Qt.AlignCenter)

    f = QFont()
    f.setBold(True)
    it.setFont(f)

    if active:
        it.setForeground(QBrush(QColor("#FFFFFF")))
        it.setBackground(QBrush(QColor("#2E7D32")))
    else:
        it.setForeground(QBrush(QColor("#FFFFFF")))
        it.setBackground(QBrush(QColor("#C62828")))
    return it


def _policy_badge(must_change: bool) -> SmartItem:
    """
    must_change_creds badge:
    - True  -> "MORA PROMENA" (crveno)
    - False -> "OK" (zeleno)
    """
    txt = "MORA PROMENA" if must_change else "OK"
    it = _item(txt, sort_key=(0, 1 if must_change else 0))
    it.setTextAlignment(Qt.AlignCenter)

    f = QFont()
    f.setBold(True)
    it.setFont(f)

    if must_change:
        it.setForeground(QBrush(QColor("#FFFFFF")))
        it.setBackground(QBrush(QColor("#B71C1C")))
    else:
        it.setForeground(QBrush(QColor("#FFFFFF")))
        it.setBackground(QBrush(QColor("#1B5E20")))
    return it


def _split_name_guess(display_name: str) -> Tuple[str, str, str]:
    s = (display_name or "").strip()
    if not s:
        return "", "", ""

    if "," in s:
        parts = [p.strip() for p in s.split(",") if p.strip()]
        if len(parts) >= 2:
            return parts[0], "", parts[1]

    parts = [p for p in s.split() if p.strip()]
    if len(parts) >= 2:
        prezime = parts[0]
        ime = " ".join(parts[1:])
        return prezime, "", ime

    return "", "", s


class UsersPage(QWidget):
    """
    Users page:
    - Search (filter) iznad tabele
    - Sort (smart) po kolonama (uvek ON)
    - Kolone dugme: izbor vidljivih + redosled + reset default
    - Dupli klik -> detalji
    """

    def __init__(self, logger: logging.Logger, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.logger = logger

        ensure_users_schema()

        self._can_view = _safe_can(PERM_USERS_VIEW)
        self._can_manage = _safe_can(PERM_USERS_MANAGE)

        root = QVBoxLayout(self)

        # header/actions
        top = QHBoxLayout()
        self.lbl = QLabel("Korisnici")
        top.addWidget(self.lbl, 1)

        self.btn_refresh = QPushButton("Osveži")
        self.btn_add = QPushButton("Novi")
        self.btn_details = QPushButton("Detalji")
        self.btn_columns = QPushButton("Kolone")

        for b in [self.btn_refresh, self.btn_columns, self.btn_add, self.btn_details]:
            top.addWidget(b)

        root.addLayout(top)

        self.lb_rbac = QLabel("")
        self.lb_rbac.setWordWrap(True)
        self.lb_rbac.hide()
        root.addWidget(self.lb_rbac)

        # table
        self.tbl = QTableWidget()
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)

        # ✅ STANDARD: sort uvek ON
        self.tbl.setSortingEnabled(True)
        self.tbl.horizontalHeader().setSortIndicatorShown(True)

        # ✅ STANDARD: drag&drop kolona po headeru
        hdr = self.tbl.horizontalHeader()
        hdr.setSectionsMovable(True)
        hdr.setSectionsClickable(True)
        try:
            hdr.setDragEnabled(True)  # type: ignore[attr-defined]
        except Exception:
            pass

        # +1 kolona: Rb, +1 kolona: Policy
        self.tbl.setColumnCount(19)
        self.tbl.setHorizontalHeaderLabels([
            "Rb",
            "Aktivan",
            "Username",
            "Prezime",
            "Ime oca",
            "Ime",
            "Prikazno ime",
            "Sektor",
            "Lokacija",
            "Čin/Status",
            "Primarna rola",
            "Role",
            "JMBG",
            "Email",
            "Telefon",
            "Kreiran",
            "Ažuriran",
            "Login",
            "Policy",
        ])

        self.tbl.cellDoubleClicked.connect(self._open_details_from_double_click)

        # tools bar (filter UI, bez sort toggle-a)
        cfg = TableToolsConfig(
            placeholder="Pretraga… (prezime/ime/jmbg/username/sektor/rola/lokacija/email/telefon/kreiran/ažuriran/login/policy)",
            show_sort_toggle=False,
            default_sort_enabled=True,
            filter_columns=None,
        )
        self.tools = TableToolsBar(self.tbl, cfg, parent=self)
        root.addWidget(self.tools)

        root.addWidget(self.tbl, 1)

        # ✅ STANDARD copy: header + Ctrl+C TSV
        try:
            wire_table_header_plus_copy(self.tbl)  # type: ignore[misc]
        except Exception:
            pass

        # ✅ Kolone specs (ključ stabilan)
        self._col_specs: List[ColSpec] = [
            ColSpec(key="rb", label="Rb", default_visible=True, default_width=60),
            ColSpec(key="is_active", label="Aktivan", default_visible=True, default_width=90),
            ColSpec(key="username", label="Username", default_visible=True, default_width=140),
            ColSpec(key="last_name", label="Prezime", default_visible=True, default_width=160),
            ColSpec(key="father_name", label="Ime oca", default_visible=True, default_width=140),
            ColSpec(key="first_name", label="Ime", default_visible=True, default_width=160),
            ColSpec(key="display_name", label="Prikazno ime", default_visible=True, default_width=220),
            ColSpec(key="sector", label="Sektor", default_visible=True, default_width=140),
            ColSpec(key="location", label="Lokacija", default_visible=True, default_width=160),
            ColSpec(key="title", label="Čin/Status", default_visible=True, default_width=150),
            ColSpec(key="primary_role", label="Primarna rola", default_visible=True, default_width=140),
            ColSpec(key="roles", label="Role", default_visible=True, default_width=200),
            ColSpec(key="jmbg", label="JMBG", default_visible=True, default_width=140),
            ColSpec(key="email", label="Email", default_visible=True, default_width=200),
            ColSpec(key="phone", label="Telefon", default_visible=True, default_width=140),
            ColSpec(key="created_at", label="Kreiran", default_visible=True, default_width=160),
            ColSpec(key="updated_at", label="Ažuriran", default_visible=True, default_width=160),
            ColSpec(key="login", label="Login", default_visible=True, default_width=110),
            ColSpec(key="must_change_creds", label="Policy", default_visible=True, default_width=140),
        ]

        # ✅ wiring "Kolone" + header DnD + autosave
        self._apply_cols_users = wire_columns(
            self, self.tbl, self.btn_columns, "users_table_v1", self._col_specs
        )

        # ✅ renumeracija Rb posle sortiranja
        try:
            hdr.sortIndicatorChanged.connect(lambda _i, _o: self._renumber_rows())
        except Exception:
            pass

        # signals
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_add.clicked.connect(self._add_user)
        self.btn_details.clicked.connect(self._edit_user)

        # perms -> UI
        self._apply_rbac()

        # init
        if self._can_view:
            self.refresh()

    def _apply_rbac(self) -> None:
        self.btn_add.setEnabled(bool(self._can_manage))
        self.btn_details.setEnabled(bool(self._can_view))
        self.btn_columns.setEnabled(bool(self._can_view))
        self.btn_refresh.setEnabled(bool(self._can_view))

        if not self._can_view:
            self.lb_rbac.setText("Nemaš pravo pristupa (users.view).")
            self.lb_rbac.show()
            for w in [self.tbl, self.tools, self.btn_columns, self.btn_details, self.btn_refresh]:
                try:
                    w.setEnabled(False)
                except Exception:
                    pass
        else:
            self.lb_rbac.hide()
            for w in [self.tbl, self.tools]:
                try:
                    w.setEnabled(True)
                except Exception:
                    pass

    def reload(self) -> None:
        self.refresh()

    def _selected_username(self) -> str:
        # username kolona je index 2 (0=Rb, 1=Aktivan, 2=Username)
        try:
            r = self.tbl.currentRow()
            if r < 0:
                return ""
            it = self.tbl.item(r, 2)
            return (it.text() if it else "").strip()
        except Exception:
            return ""

    def _restore_selection_by_username(self, username: str) -> None:
        if not username:
            return
        try:
            for r in range(self.tbl.rowCount()):
                it = self.tbl.item(r, 2)
                if it and it.text().strip() == username:
                    self.tbl.setCurrentCell(r, 2)
                    return
        except Exception:
            pass

    def _renumber_rows(self) -> None:
        """Rb treba da prati trenutni redosled (posle sort/filter)."""
        try:
            rc = self.tbl.rowCount()
            for r in range(rc):
                it = self.tbl.item(r, 0)
                if it is None:
                    it = _rb_item(r + 1)
                    self.tbl.setItem(r, 0, it)
                it.setText(str(r + 1))
                try:
                    it.setData(Qt.UserRole, r + 1)
                except Exception:
                    pass
        except Exception:
            pass

    def refresh(self) -> None:
        if not self._can_view:
            try:
                self.tbl.setRowCount(0)
            except Exception:
                pass
            return

        selected_un = self._selected_username()

        try:
            users = list_users(active_only=False)
        except Exception as e:
            self.tbl.setRowCount(0)
            _warn(self, f"Greška pri učitavanju korisnika:\n{e}")
            return

        # zapamti trenutni sort (kolona + smer)
        sort_col = 2  # default: Username
        sort_order = Qt.AscendingOrder
        try:
            hdr = self.tbl.horizontalHeader()
            sort_col = int(hdr.sortIndicatorSection())
            sort_order = hdr.sortIndicatorOrder()
        except Exception:
            pass

        # tokom punjenja: privremeno isključi sort da ne “skače”
        try:
            self.tbl.setSortingEnabled(False)
        except Exception:
            pass

        self.tbl.setRowCount(len(users))
        for i, u in enumerate(users):
            username = str(u.get("username") or "").strip()
            display = str(u.get("display_name") or "").strip()

            prezime = str(u.get("prezime") or u.get("last_name") or "").strip()
            ime_oca = str(u.get("ime_oca") or u.get("father_name") or "").strip()
            ime = str(u.get("ime") or u.get("first_name") or "").strip()
            if not (prezime or ime or ime_oca):
                p, io, im = _split_name_guess(display)
                prezime = prezime or p
                ime_oca = ime_oca or io
                ime = ime or im

            sector = str(u.get("sector") or u.get("org_unit") or "").strip()
            location = str(u.get("location") or "").strip()
            title = str(u.get("title") or "").strip()

            primary = (str(u.get("primary_role") or u.get("role") or "").strip().upper())
            roles_val = u.get("roles") or []
            if isinstance(roles_val, str):
                roles_txt = roles_val.strip()
            else:
                roles_txt = ", ".join([str(x).strip().upper() for x in roles_val if str(x).strip()])

            jmbg = str(u.get("jmbg") or "").strip()
            email = str(u.get("email") or "").strip()
            phone = str(u.get("phone") or "").strip()

            created_raw = u.get("created_at")
            updated_raw = u.get("updated_at")

            # active (robust)
            raw_active = u.get("is_active")
            if raw_active is None:
                is_active = True
            else:
                try:
                    is_active = int(str(raw_active).strip()) == 1
                except Exception:
                    is_active = str(raw_active).strip().lower() in ("true", "yes", "da", "y")

            # login (fail-soft)
            has_pin = bool(u.get("has_pin")) or bool(str(u.get("pin_hash") or "").strip())
            has_pw = bool(u.get("has_password")) or bool(str(u.get("pass_hash") or "").strip())
            if has_pin and has_pw:
                login_txt = "PIN+Lozinka"
            elif has_pin:
                login_txt = "PIN"
            elif has_pw:
                login_txt = "Lozinka"
            else:
                login_txt = "—"

            # must_change_creds (fail-soft)
            raw_mc = u.get("must_change_creds", 0)
            try:
                must_change = int(str(raw_mc).strip() or "0") != 0
            except Exception:
                must_change = str(raw_mc).strip().lower() in ("true", "yes", "da", "y")

            # 0: Rb (privremeno; posle sort renumerišemo)
            self.tbl.setItem(i, 0, _rb_item(i + 1))

            # 1: Aktivnost badge
            self.tbl.setItem(i, 1, _active_badge(bool(is_active)))

            # 2..18
            row_vals = [
                username,      # 2
                prezime,       # 3
                ime_oca,       # 4
                ime,           # 5
                display,       # 6
                sector,        # 7
                location,      # 8
                title,         # 9
                primary,       # 10
                roles_txt,     # 11
                jmbg,          # 12
                email,         # 13
                phone,         # 14
                None,          # 15 Kreiran
                None,          # 16 Ažuriran
                login_txt,     # 17 Login
                None,          # 18 Policy
            ]

            for c, v in enumerate(row_vals, start=2):
                if c == 15:  # Kreiran
                    self.tbl.setItem(i, c, _dt_item(created_raw))
                elif c == 16:  # Ažuriran
                    self.tbl.setItem(i, c, _dt_item(updated_raw))
                elif c == 18:  # Policy badge
                    self.tbl.setItem(i, c, _policy_badge(must_change))
                else:
                    self.tbl.setItem(i, c, _item(v))

        # ✅ vrati sort + primeni indikator
        try:
            self.tbl.setSortingEnabled(True)
            if 0 <= int(sort_col) < self.tbl.columnCount():
                self.tbl.sortItems(int(sort_col), sort_order)
            else:
                self.tbl.sortItems(2, Qt.AscendingOrder)
        except Exception:
            try:
                self.tbl.setSortingEnabled(True)
            except Exception:
                pass

        # ✅ primeni kolone prefs (redosled/vidljivost/širine)
        try:
            self._apply_cols_users()
        except Exception:
            pass

        # ✅ vrati selekciju (best-effort)
        self._restore_selection_by_username(selected_un)

        # ✅ renumeriši Rb po trenutnom prikazu
        self._renumber_rows()

        # re-primeni filter ako postoji tekst
        try:
            q = self.tools.ed.text()
            if q:
                self.tools._on_text_changed(q)
                self._renumber_rows()
        except Exception:
            pass

    def _add_user(self) -> None:
        if not self._can_manage:
            _warn(self, "Nemaš pravo (users.manage).")
            return

        try:
            dlg = UserDetailDialog(self, self.logger, is_new=True)
        except Exception as e:
            _warn(self, f"Ne mogu da otvorim dijalog:\n{e}")
            return

        if dlg.exec() != QDialog.Accepted:
            return

        self.refresh()

    def _edit_user(self) -> None:
        if not self._can_view:
            _warn(self, "Nemaš pravo (users.view).")
            return

        un = self._selected_username()
        if not un:
            _warn(self, "Prvo izaberi korisnika.")
            return

        try:
            dlg = UserDetailDialog(self, self.logger, username=un, is_new=False)
        except Exception as e:
            _warn(self, f"Ne mogu da otvorim detalje korisnika:\n{e}")
            return

        if dlg.exec() != QDialog.Accepted:
            return

        self.refresh()

    def _open_details_from_double_click(self, _row: int, _col: int) -> None:
        self._edit_user()


# END FILENAME: ui/users_page.py
# (FILENAME: ui/users_page.py - END)