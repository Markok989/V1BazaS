# FILENAME: ui/login_dialog.py
# (FILENAME: ui/login_dialog.py - START)  # Part 1/2
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/login_dialog.py

Prijava (V1) — UX/Sec hardening (bez menjanja osnovne logike), sa izmenom politike rola:
- NEMA multi-role izbora tokom prijave.
- Tokom login-a uvek se bira NAJVEĆA rola korisnika (po core.rbac.pick_highest_role / ROLE_PRIORITY ako postoji).
- UI elementi za izbor uloge su trajno sakriveni (kompatibilnost sa starim QSS/layout-om).

Ostalo zadržano:
- Fokus na username pri otvaranju (ne na password)
- "Primary action" dugme radi kao Next kad secret nije unet, a user ima kredencijale
- Fail-closed resolver typed user (not_found/ambiguous -> stop)
- Rate-limit / cooldown posle više pogrešnih pokušaja (offline, in-memory, po korisniku)
- Best-effort audit: login.success / login.fail (bez upisa tajni)
- Show password toggle
- PIN-only input hardening (digits-only + validator) kad user ima samo PIN
- Uklonjeni duplikati helper funkcija (jedna istina)
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import json
import sqlite3
import time

from PySide6.QtCore import Qt, QEvent, QTimer, QRegularExpression  # type: ignore
from PySide6.QtGui import QRegularExpressionValidator  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QCheckBox,
    QComboBox,
    QCompleter,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from core.config import DB_FILE
from services.users_service import (
    list_users,
    list_user_roles,
    user_has_any_credential,
    verify_user_password,
    verify_user_pin,
)

# ✅ Prefer centralizovani DB konektor (isti DB kao core/db.py)
try:
    from core.db import connect_db as _core_connect_db  # type: ignore
except Exception:  # pragma: no cover
    _core_connect_db = None  # type: ignore

# ✅ RBAC: highest-role picker (ako postoji)
try:
    from core.rbac import pick_highest_role as _rbac_pick_highest_role  # type: ignore
except Exception:  # pragma: no cover
    _rbac_pick_highest_role = None  # type: ignore

# ✅ Optional helpers (ako postoje u users_service.py)
try:
    from services.users_service import normalize_user_for_session, validate_user_role_choice  # type: ignore
except Exception:  # pragma: no cover
    normalize_user_for_session = None  # type: ignore
    validate_user_role_choice = None  # type: ignore


# -------------------- small helpers (single source of truth) --------------------
def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _dedupe_upper(items: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for it in items or []:
        x = str(it or "").strip().upper()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _pick_highest_role(roles: List[str]) -> str:
    """
    Izaberi NAJVEĆU rolu za korisnika.
    - Ako core.rbac.pick_highest_role postoji, koristi njega (source of truth).
    - Inače fallback: prva rola (deterministički, ali slabije).
    """
    rr = _dedupe_upper([str(x or "") for x in (roles or [])]) or ["READONLY"]
    if callable(_rbac_pick_highest_role):
        try:
            r = _rbac_pick_highest_role(rr)
            r = str(r or "").strip().upper()
            return r or "READONLY"
        except Exception:
            pass
    return str(rr[0] or "READONLY").strip().upper() or "READONLY"


# -------------------- App paths (offline) --------------------
def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _resolve_db_path() -> Path:
    p = Path(DB_FILE)
    return p if p.is_absolute() else (_app_root() / p).resolve()


# -------------------- Login state (remember last user) --------------------
_MAX_STATE_BYTES = 32_768  # hard limit (DoS-safe)


def _settings_dir() -> Path:
    return _app_root() / "data" / "settings"


def _login_state_file() -> Path:
    return _settings_dir() / "login_state.json"


def _load_login_state() -> Dict[str, Any]:
    """
    Fail-safe: vraća {} na svaku grešku.
    Limitira veličinu fajla da izbegnemo "neko ubacio 200MB JSON".
    """
    try:
        fp = _login_state_file()
        if not fp.exists():
            return {}
        try:
            if fp.stat().st_size > _MAX_STATE_BYTES:
                return {}
        except Exception:
            pass
        data = json.loads(fp.read_text(encoding="utf-8") or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_login_state(state: Dict[str, Any]) -> bool:
    try:
        _settings_dir().mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    try:
        fp = _login_state_file()
        tmp = fp.with_suffix(".tmp")
        tmp.write_text(json.dumps(state or {}, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(fp)  # atomic (same filesystem)
        return True
    except Exception:
        return False


# -------------------- DB fallback (login must work even if services layer is broken) --------------------
def _apply_pragmas(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("PRAGMA busy_timeout=2500;")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass


@contextmanager
def _connect_db():
    """
    Login fallback mora da gleda ISTU bazu kao ostatak app-a.
    - ako postoji core.db.connect_db -> koristi njega
    - inače fallback na DB_FILE
    """
    if _core_connect_db is not None:
        obj = None
        try:
            obj = _core_connect_db()

            # sqlite3.Connection ima __enter__/__exit__ ali se NE zatvara automatski,
            # zato ga tretiramo kao plain connection i uvek zatvaramo.
            if isinstance(obj, sqlite3.Connection):
                conn = obj
                _apply_pragmas(conn)
                try:
                    yield conn
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
                return

            # context manager (npr. core.db)
            if hasattr(obj, "__enter__") and hasattr(obj, "__exit__"):
                with obj as conn:
                    if isinstance(conn, sqlite3.Connection):
                        _apply_pragmas(conn)
                    yield conn
                return

            # unknown connection-like
            conn = obj
            try:
                if isinstance(conn, sqlite3.Connection):
                    _apply_pragmas(conn)
                yield conn
            finally:
                try:
                    if hasattr(conn, "close"):
                        conn.close()  # type: ignore[attr-defined]
                except Exception:
                    pass
            return
        except Exception:
            # swallow and fallback to DB_FILE (login should still work)
            try:
                if obj is not None and hasattr(obj, "close"):
                    obj.close()  # type: ignore[attr-defined]
            except Exception:
                pass

    db_path = _resolve_db_path()
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    conn = sqlite3.connect(db_path.as_posix(), timeout=3.0)
    _apply_pragmas(conn)
    try:
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


def _has_any_cred_fast(u: Dict[str, Any]) -> bool:
    # Prefer flags if present (no DB hit)
    if "has_pin" in u or "has_password" in u:
        return bool(u.get("has_pin")) or bool(u.get("has_password"))
    # fallback (DB hit)
    return bool(user_has_any_credential(u))


def _list_users_db_fallback(active_only: bool = True, limit: int = 500) -> List[Dict[str, Any]]:
    lim = _safe_int(limit, 500) or 500
    if lim <= 0:
        lim = 500

    with _connect_db() as conn:
        if not _table_exists(conn, "users"):
            return []
        cols = [r[1] for r in conn.execute("PRAGMA table_info(users);").fetchall()]
        if not cols:
            return []

        def pick(*names: str) -> str:
            for n in names:
                if n in cols:
                    return n
            return ""

        c_id = pick("id", "user_id", "uid")
        c_username = pick("username", "user_name", "login")
        c_display = pick("display_name", "full_name", "name", "ime_prezime")
        c_role = pick("role", "user_role", "uloga")
        c_sector = pick("sector", "sektor", "org_unit", "orgunit", "unit", "department", "dept", "section")
        c_active = pick("is_active", "active", "enabled")
        c_pin_hash = pick("pin_hash", "pin")
        c_pw_hash = pick("pass_hash", "password_hash", "pwd_hash", "pass", "password")

        sel = [c for c in (c_id, c_username, c_display, c_role, c_sector, c_active, c_pin_hash, c_pw_hash) if c]
        if not sel:
            return []

        where = ""
        args: List[Any] = []
        if active_only and c_active:
            where = f"WHERE COALESCE({c_active},1)=1"
        sql = f"SELECT {', '.join(sel)} FROM users {where} LIMIT ?;"
        args.append(lim)
        rows = conn.execute(sql, tuple(args)).fetchall()

    out: List[Dict[str, Any]] = []
    for row in rows:
        rr: Dict[str, Any] = {sel[i]: row[i] for i in range(min(len(sel), len(row)))}

        uid_int = _safe_int(rr.get(c_id), 0) if c_id else 0
        username = str(rr.get(c_username) or "").strip() if c_username else ""
        display = str(rr.get(c_display) or "").strip() if c_display else ""
        role = str(rr.get(c_role) or "").strip().upper() if c_role else ""
        sector = str(rr.get(c_sector) or "").strip() if c_sector else ""

        has_pin = bool(str(rr.get(c_pin_hash) or "").strip()) if c_pin_hash else False
        has_pw = bool(str(rr.get(c_pw_hash) or "").strip()) if c_pw_hash else False

        out.append(
            {
                "id": uid_int,
                "user_id": uid_int,
                "username": username,
                "user": username,
                "display_name": display or username or f"User {uid_int}",
                "role": role,
                "user_role": role,
                "active_role": role,
                "roles": [],  # filled later
                "sector": sector,
                "org_unit": sector,
                "has_pin": bool(has_pin),
                "has_password": bool(has_pw),
                "is_active": True,
            }
        )
    return out


def _roles_for_user_db_fallback(user_id: int, primary_role: str) -> List[str]:
    uid = _safe_int(user_id, 0)
    if uid > 0:
        with _connect_db() as conn:
            if _table_exists(conn, "user_roles"):
                try:
                    rows = conn.execute(
                        "SELECT role FROM user_roles WHERE user_id=? AND is_active=1 ORDER BY role COLLATE NOCASE;",
                        (uid,),
                    ).fetchall()
                    roles = [str(r[0] or "").strip().upper() for r in rows if str(r[0] or "").strip()]
                    ded = _dedupe_upper(roles)
                    if ded:
                        return ded
                except Exception:
                    pass

    pr = str(primary_role or "").strip().upper()
    return [pr] if pr else []


class LoginDialog(QDialog):
    # UX tuning (offline-safe)
    _AUTOSELECT_MIN_CHARS = 3
    _TYPE_DEBOUNCE_MS = 180
    _MAX_USERS = 500

    # Security: rate-limit tuning (in-memory, per user key)
    _FAIL_THRESHOLD = 5
    _COOLDOWN_BASE_SEC = 10
    _COOLDOWN_MAX_SEC = 300

    def __init__(self, parent=None, logger=None):
        super().__init__(parent)
        self.logger = logger

        self.setWindowTitle("BazaS2 — Prijava")
        self.resize(560, 330)

        self._users: List[Dict[str, Any]] = []
        self._selected_user: Optional[Dict[str, Any]] = None

        # NOTE: cache only for real user ids (>0). Avoid collisions on 0/None.
        self._roles_cache: Dict[int, List[str]] = {}

        # typing / focus guards
        self._is_typing_user: bool = False
        self._pending_user_text: str = ""
        self._programmatic_user_index_change: bool = False
        self._caps_lock_on: bool = False

        # initial UX: never auto-focus secret until user interacts
        self._user_interacted: bool = False

        # rate-limit state
        self._fail_count: Dict[str, int] = {}
        self._cooldown_until: Dict[str, float] = {}  # monotonic seconds

        self._type_timer = QTimer(self)
        self._type_timer.setSingleShot(True)
        self._type_timer.timeout.connect(self._apply_typed_user_text)

        self._cooldown_timer = QTimer(self)
        self._cooldown_timer.setInterval(400)
        self._cooldown_timer.timeout.connect(self._refresh_cooldown_ui)

        # ✅ Korisnik: dropdown + editable + autocomplete
        self.cb_user = QComboBox()
        self.cb_user.setEditable(True)
        self.cb_user.setInsertPolicy(QComboBox.NoInsert)
        self.cb_user.setMaxVisibleItems(20)
        le = self.cb_user.lineEdit()
        if le:
            le.setPlaceholderText("Upiši ime/username… ili izaberi iz liste")
            le.setClearButtonEnabled(True)

        # Real-time feedback (bez popupa)
        self.lb_user_feedback = QLabel("")
        self.lb_user_feedback.setWordWrap(True)
        self.lb_user_feedback.setProperty("muted", True)  # token QSS
        self.lb_user_feedback.setStyleSheet("font-size: 11px;")

        # ✅ ULOGA: UI postoji radi kompatibilnosti, ali je trajno sakriven (nema izbora tokom login-a).
        self.lb_role = QLabel("Uloga:")
        self.cb_role = QComboBox()
        self.lb_role.setVisible(False)
        self.cb_role.setVisible(False)

        # ✅ Smart input (PIN ili lozinka)
        self.ed_secret = QLineEdit()
        self.ed_secret.setEchoMode(QLineEdit.Password)
        self.ed_secret.setPlaceholderText("Unesi PIN ili lozinku")
        self.ed_secret.returnPressed.connect(self._on_login)
        self.ed_secret.installEventFilter(self)

        self.chk_show_secret = QCheckBox("Prikaži")
        self.chk_show_secret.toggled.connect(self._toggle_secret_visibility)

        self._pin_validator = QRegularExpressionValidator(QRegularExpression(r"^\d{0,12}$"), self)

        self.lb_caps = QLabel("")
        self.lb_caps.setWordWrap(True)
        self.lb_caps.setVisible(False)
        self.lb_caps.setStyleSheet("font-size: 11px; color: #b45309;")  # best-effort

        self.lb_hint = QLabel("")
        self.lb_hint.setWordWrap(True)

        btn_row = QHBoxLayout()
        self.btn_login = QPushButton("Prijavi se")
        self.btn_cancel = QPushButton("Odustani")
        btn_row.addStretch(1)
        btn_row.addWidget(self.btn_login)
        btn_row.addWidget(self.btn_cancel)

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Prijava (offline)"))
        lay.addSpacing(6)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Korisnik:"), 0)
        row1.addWidget(self.cb_user, 1)
        lay.addLayout(row1)
        lay.addWidget(self.lb_user_feedback)

        row_role = QHBoxLayout()
        row_role.addWidget(self.lb_role, 0)
        row_role.addWidget(self.cb_role, 1)
        lay.addLayout(row_role)

        lay.addWidget(QLabel("PIN / lozinka:"))

        row_secret = QHBoxLayout()
        row_secret.addWidget(self.ed_secret, 1)
        row_secret.addWidget(self.chk_show_secret, 0)
        lay.addLayout(row_secret)

        lay.addWidget(self.lb_caps)
        lay.addWidget(self.lb_hint)
        lay.addStretch(1)
        lay.addLayout(btn_row)

        self.btn_cancel.clicked.connect(self.reject)
        self.btn_login.clicked.connect(self._on_primary_action)

        # commit selection (klik / izbor iz liste)
        self.cb_user.currentIndexChanged.connect(self._on_user_changed)

        # ✅ kada korisnik kuca, NE menjaj fokus; samo pametno selektuj (debounce)
        if le:
            le.textEdited.connect(self._on_user_text_edited)
            le.returnPressed.connect(self._on_user_enter_pressed)  # Enter = Next (ne Login)

        # tab order (UX)
        try:
            if le:
                self.setTabOrder(le, self.ed_secret)
                self.setTabOrder(self.ed_secret, self.btn_login)
                self.setTabOrder(self.btn_login, self.btn_cancel)
        except Exception:
            pass

        self._load_users()
        self._wire_user_autocomplete()
        self._restore_last_login_selection()
        self._sync_ui()

    # -------------------- showEvent: focus username first --------------------
    def showEvent(self, event):  # type: ignore[override]
        try:
            super().showEvent(event)
        finally:
            # Fokus ide na username (korisnik) pri otvaranju — uvek.
            QTimer.singleShot(0, self._focus_user_on_show)

    def _focus_user_on_show(self) -> None:
        try:
            le = self.cb_user.lineEdit()
            if le:
                le.setFocus(Qt.OtherFocusReason)
                try:
                    le.selectAll()
                except Exception:
                    pass
        except Exception:
            pass

    # -------------------- Qt event filter (CapsLock best-effort) --------------------
    def eventFilter(self, obj, event):  # type: ignore[override]
        try:
            if obj is self.ed_secret and event.type() == QEvent.KeyPress:
                try:
                    key = int(event.key())
                except Exception:
                    key = 0
                if key == int(Qt.Key_CapsLock):
                    self._caps_lock_on = not self._caps_lock_on
                    self._update_caps_lock_label()
        except Exception:
            pass
        return super().eventFilter(obj, event)

    def _update_caps_lock_label(self) -> None:
        try:
            if self._caps_lock_on and self.ed_secret.isEnabled():
                self.lb_caps.setText("⚠️ Caps Lock je uključen (best-effort detekcija).")
                self.lb_caps.setVisible(True)
            else:
                self.lb_caps.setVisible(False)
        except Exception:
            pass

    # -------------------- misc helpers --------------------
    def _log(self, msg: str, *args: Any) -> None:
        if not self.logger:
            return
        try:
            self.logger.info(msg, *args)
        except Exception:
            pass

    def _normalize_text(self, s: str) -> str:
        return (s or "").strip().casefold()

    def _make_user_label(self, u: Dict[str, Any]) -> str:
        dn = (u.get("display_name") or u.get("username") or "User").strip()
        role = (u.get("role") or "").strip().upper()
        sector = (u.get("sector") or u.get("org_unit") or "").strip()
        roles = u.get("roles") or []
        has_cred = _has_any_cred_fast(u)
        tag = "✓" if has_cred else "—"
        extra = f", {sector}" if sector else ""
        multi = f" (+{max(0, len(roles) - 1)})" if isinstance(roles, list) and len(roles) > 1 else ""
        un = (u.get("username") or u.get("user") or "").strip()
        if un and un.lower() not in dn.lower():
            dn2 = f"{dn} — {un}"
        else:
            dn2 = dn
        return f"{dn2} ({role}{multi}{extra}) [{tag}]"

    def _wire_user_autocomplete(self) -> None:
        """
        Autocomplete radi nad tekstom item-a u combobox-u (label),
        pa zato u label ubacujemo i username (ako nije već prisutan).
        """
        try:
            model = self.cb_user.model()
            comp = QCompleter(model, self)
            comp.setCaseSensitivity(Qt.CaseInsensitive)
            try:
                comp.setFilterMode(Qt.MatchContains)  # type: ignore[attr-defined]
            except Exception:
                pass
            comp.setCompletionMode(QCompleter.PopupCompletion)
            self.cb_user.setCompleter(comp)
        except Exception:
            pass

    def _typed_user_text(self) -> str:
        try:
            le = self.cb_user.lineEdit()
            return (le.text() if le else "") or ""
        except Exception:
            return ""

    def _restore_last_login_selection(self) -> None:
        """
        Preselect poslednjeg user-a (offline, fail-safe).
        Ne menja logiku prijave – samo UX.
        """
        st = _load_login_state()
        if not st:
            return

        last_uid = st.get("last_user_id")
        last_username = (st.get("last_username") or "").strip()

        idx = -1

        # 1) po ID
        try:
            if last_uid is not None:
                lu = int(last_uid)
                for i, u in enumerate(self._users):
                    uid = _safe_int(u.get("id") or u.get("user_id") or 0, 0)
                    if uid and uid == lu:
                        idx = i
                        break
        except Exception:
            idx = -1

        # 2) po username
        if idx < 0 and last_username:
            t = last_username.casefold()
            for i, u in enumerate(self._users):
                un = (u.get("username") or u.get("user") or "").strip().casefold()
                if un and un == t:
                    idx = i
                    break

        if 0 <= idx < self.cb_user.count():
            self._set_user_index_programmatically(idx, keep_text="")
            self._selected_user = self._get_selected_user()

    def _load_users(self) -> None:
        users: List[Dict[str, Any]] = []
        err: Optional[Exception] = None

        try:
            try:
                users = list_users(active_only=True, limit=self._MAX_USERS)
            except TypeError:
                users = list_users()
        except Exception as e:
            err = e
            users = []

        if not users:
            try:
                users = _list_users_db_fallback(active_only=True, limit=self._MAX_USERS)
                if users:
                    self._log(
                        "LoginDialog: users_service list_users nije dostupan (%s) -> DB fallback OK (%s users).",
                        err, len(users)
                    )
            except Exception as e2:
                users = []
                msg = str(err) if err else ""
                QMessageBox.critical(
                    self,
                    "Greška",
                    f"Ne mogu da učitam korisnike.\n\n{msg}\n\nFallback DB greška:\n{e2}",
                )
                return

        self._users = users
        self._roles_cache.clear()

        self.cb_user.blockSignals(True)
        try:
            self.cb_user.clear()
            for u in self._users:
                uid = _safe_int(u.get("id") or u.get("user_id") or 0, 0)
                self.cb_user.addItem(self._make_user_label(u), uid)
        finally:
            self.cb_user.blockSignals(False)

        self._selected_user = self._users[0] if self._users else None

    # -------------------- matching helpers --------------------
    def _collect_user_fields(self, u: Dict[str, Any]) -> List[str]:
        dn = (u.get("display_name") or "").strip()
        un = (u.get("username") or u.get("user") or "").strip()
        role = (u.get("role") or "").strip()
        sector = (u.get("sector") or u.get("org_unit") or "").strip()
        return [dn, un, role, sector]

    def _find_user_matches(self, text: str) -> List[int]:
        t = self._normalize_text(text)
        if not t:
            return []
        hits: List[int] = []
        for i, u in enumerate(self._users):
            fields = self._collect_user_fields(u)
            label = (self.cb_user.itemText(i) or "").strip()
            hay = " | ".join([label] + fields)
            if t in self._normalize_text(hay):
                hits.append(i)
        return hits

    def _find_user_index_by_text(self, text: str) -> int:
        """
        Vraća indeks u combobox-u koji najbolje odgovara tekstu.
        Koristi se za "strict-ish" mapiranje pri login-u.
        """
        t = self._normalize_text(text)
        if not t:
            return -1

        # exact match na label
        for i in range(self.cb_user.count()):
            it = self._normalize_text(self.cb_user.itemText(i) or "")
            if it == t:
                return i

        # exact match na display_name / username
        for i, u in enumerate(self._users):
            dn = self._normalize_text(u.get("display_name") or "")
            un = self._normalize_text(u.get("username") or u.get("user") or "")
            if t and (t == dn or t == un):
                return i

        # contains match (fallback)
        for i, u in enumerate(self._users):
            dn = self._normalize_text(u.get("display_name") or "")
            un = self._normalize_text(u.get("username") or u.get("user") or "")
            label = self._normalize_text(self.cb_user.itemText(i) or "")
            if t in dn or t in un or t in label:
                return i

        return -1

    def _resolve_typed_user(self, typed: str) -> Tuple[Optional[Dict[str, Any]], int, str]:
        """
        Fail-closed resolver:
        - Ako je typed prazan: vrati trenutno selektovanog user-a (best-effort)
        - Ako typed mapira na tačno jednog user-a: vrati (user, index, "")
        - Ako nema match: (None, -1, "not_found")
        - Ako je nejednoznačno: (None, -1, "ambiguous")
        """
        t = (typed or "").strip()
        if not t:
            u = self._get_selected_user()
            idx = self.cb_user.currentIndex()
            return (u, idx, "")

        idx_strict = self._find_user_index_by_text(t)
        if idx_strict >= 0:
            u = self._users[idx_strict] if 0 <= idx_strict < len(self._users) else self._get_selected_user()
            return (u, idx_strict, "")

        hits = self._find_user_matches(t)
        if not hits:
            return (None, -1, "not_found")
        if len(hits) == 1:
            u = self._users[hits[0]] if 0 <= hits[0] < len(self._users) else None
            return (u, hits[0], "")
        return (None, -1, "ambiguous")

    def _set_user_index_programmatically(self, idx: int, keep_text: str) -> None:
        if idx < 0 or idx >= self.cb_user.count():
            return
        self._programmatic_user_index_change = True
        try:
            self.cb_user.blockSignals(True)
            self.cb_user.setCurrentIndex(idx)
        finally:
            try:
                self.cb_user.blockSignals(False)
            except Exception:
                pass
            self._programmatic_user_index_change = False

        # vrati korisnikov tekst (da caret ostane, i da label ne “pregazi” unos)
        if keep_text is not None:
            try:
                le = self.cb_user.lineEdit()
                if le:
                    le.blockSignals(True)
                    try:
                        le.setText(keep_text)
                        le.setCursorPosition(len(keep_text))
                    finally:
                        le.blockSignals(False)
            except Exception:
                pass

    # -------------------- typing UX --------------------
    def _on_user_text_edited(self, text: str) -> None:
        """
        Dok kuca:
        - ne menjamo fokus (ne “krademo” šifru)
        - debounce + min chars
        - auto-selekcija samo ako je match jedinstven
        """
        self._user_interacted = True
        self._is_typing_user = True
        self._pending_user_text = text or ""
        try:
            self._type_timer.stop()
            self._type_timer.start(int(self._TYPE_DEBOUNCE_MS))
        except Exception:
            self._apply_typed_user_text()

    def _apply_typed_user_text(self) -> None:
        text = self._pending_user_text or ""
        t = (text or "").strip()
        self._is_typing_user = False

        try:
            self.lb_user_feedback.setText("")
        except Exception:
            pass

        if not t:
            self._sync_ui()
            return

        if len(t) < int(self._AUTOSELECT_MIN_CHARS):
            try:
                self.lb_user_feedback.setText(
                    f"Tip: ukucaj bar {self._AUTOSELECT_MIN_CHARS} slova za pametno biranje."
                )
            except Exception:
                pass
            self._sync_ui()
            return

        hits = self._find_user_matches(t)
        if not hits:
            try:
                self.lb_user_feedback.setText("Nema takvog korisnika (izaberi iz liste / autocomplete).")
            except Exception:
                pass
            self._sync_ui()
            return

        if len(hits) == 1:
            # jedinstven match -> selektuj, ali NE prebacuj fokus na šifru
            self._set_user_index_programmatically(hits[0], keep_text=text)
            self._sync_ui()
            return

        try:
            self.lb_user_feedback.setText(f"Nađeno više korisnika ({len(hits)}). Izaberi iz liste/autocomplete.")
        except Exception:
            pass
        self._sync_ui()

    def _on_user_enter_pressed(self) -> None:
        """
        Enter u polju Korisnik:
        - resolve typed -> mora biti jednoznačno (fail-closed)
        - zatim: ako user ima kredencijale -> fokus na šifru
                ako nema kredencijale -> login odmah (kao pre)
        """
        self._user_interacted = True
        typed = self._typed_user_text()
        user, idx, status = self._resolve_typed_user(typed)

        if status == "not_found":
            QMessageBox.warning(self, "Validacija", "Korisnik nije pronađen. Izaberi iz liste (autocomplete).")
            return
        if status == "ambiguous":
            QMessageBox.warning(self, "Validacija", "Nađeno više korisnika. Izaberi tačno jednog iz liste (autocomplete).")
            return
        if not user:
            QMessageBox.warning(self, "Info", "Nema izabranog korisnika.")
            return

        # uskladi selekciju UI-a sa resolved korisnikom (bez krađe fokusa)
        if 0 <= idx < self.cb_user.count():
            self._set_user_index_programmatically(idx, keep_text=typed)

        self._sync_ui()

        if self._user_has_credentials(user):
            self._focus_secret(force=True)
        else:
            self._on_login()

# (FILENAME: ui/login_dialog.py - END)  # Part 1/2

# FILENAME: ui/login_dialog.py
# (FILENAME: ui/login_dialog.py - START)  # Part 2/2

    def _user_has_credentials(self, u: Dict[str, Any]) -> bool:
        has_pin = bool(u.get("has_pin")) if ("has_pin" in u) else False
        has_pw = bool(u.get("has_password")) if ("has_password" in u) else False
        has_cred = (has_pin or has_pw)
        if ("has_pin" not in u) and ("has_password" not in u):
            has_cred = _has_any_cred_fast(u)
        return bool(has_cred)

    def _should_keep_user_focus(self) -> bool:
        """
        Ne kradi fokus dok korisnik aktivno kuca korisnika.
        """
        try:
            le = self.cb_user.lineEdit()
            if le and le.hasFocus():
                return True
        except Exception:
            pass
        return bool(self._is_typing_user)

    def _toggle_secret_visibility(self, on: bool) -> None:
        try:
            self.ed_secret.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        except Exception:
            pass

    def _focus_secret(self, force: bool = False) -> None:
        try:
            if not self.ed_secret.isEnabled():
                return
            # Ne kradi fokus dok user kuca, osim ako je eksplicitno traženo (Enter/Next)
            if (not force) and self._should_keep_user_focus():
                return
            self.ed_secret.setFocus(Qt.OtherFocusReason)
        except Exception:
            pass
        try:
            self.btn_login.setDefault(True)
        except Exception:
            pass

    def _get_selected_user(self) -> Optional[Dict[str, Any]]:
        uid = self.cb_user.currentData()
        uid_int = _safe_int(uid, 0)

        if uid_int:
            for u in self._users:
                u_id = _safe_int(u.get("id") or u.get("user_id") or 0, 0)
                if u_id == uid_int:
                    return u

        # ako je korisnik nešto ukucao, pokušaj match po tekstu
        typed = self._typed_user_text()
        idx = self._find_user_index_by_text(typed)
        if 0 <= idx < len(self._users):
            return self._users[idx]

        return self._users[0] if self._users else None

    def _load_roles_for_user(self, u: Dict[str, Any]) -> List[str]:
        """
        Učitavanje uloga (za highest-role izbor).
        Cache samo kad user_id > 0 (izbegavamo koliziju na 0/None).
        """
        uid = _safe_int(u.get("id") or u.get("user_id") or 0, 0)
        if uid > 0 and uid in self._roles_cache:
            return list(self._roles_cache.get(uid) or [])

        roles = u.get("roles")
        if isinstance(roles, list) and roles:
            ded = _dedupe_upper([str(x or "") for x in roles])
            if ded:
                if uid > 0:
                    self._roles_cache[uid] = ded
                return list(ded)

        # services layer
        try:
            rr = list_user_roles(u)
            if rr:
                ded2 = _dedupe_upper([str(x or "") for x in rr])
                if ded2:
                    if uid > 0:
                        self._roles_cache[uid] = ded2
                    return list(ded2)
        except Exception:
            pass

        pr = str(u.get("role") or "").strip().upper()
        ded3 = _dedupe_upper(_roles_for_user_db_fallback(uid, pr))
        if uid > 0:
            self._roles_cache[uid] = ded3
        return list(ded3)

    def _apply_active_role(self, u: Dict[str, Any]) -> str:
        """
        Postavlja active_role na NAJVEĆU rolu korisnika.
        Vraća izabranu rolu (canonical upper).
        """
        roles = u.get("roles") or []
        if isinstance(roles, list) and roles:
            ded = _dedupe_upper([str(x or "") for x in roles])
            u["roles"] = ded
            chosen = _pick_highest_role(ded)
        else:
            chosen = str(u.get("role") or "READONLY").strip().upper() or "READONLY"

        # Validacija (ako postoji) — ali bez UI izbora: fail-safe fallback
        try:
            if callable(validate_user_role_choice):
                if not validate_user_role_choice(u, chosen):
                    if isinstance(u.get("roles"), list) and u["roles"]:
                        chosen = _pick_highest_role(u["roles"])
                    else:
                        chosen = "READONLY"
        except Exception:
            pass

        u["active_role"] = chosen
        # legacy/compat keys
        u["role"] = chosen
        u["user_role"] = chosen
        u["rbac_role"] = chosen
        u["profile"] = chosen
        return chosen

    def _sync_role_ui(self) -> None:
        """
        UI za izbor uloge je trajno sakriven.
        Ipak, ovde punimo u['roles'] i postavljamo active_role = highest.
        """
        u = self._selected_user
        self.lb_role.setVisible(False)
        self.cb_role.setVisible(False)
        try:
            self.cb_role.clear()
        except Exception:
            pass

        if not u:
            return

        roles = self._load_roles_for_user(u)
        u["roles"] = roles
        self._apply_active_role(u)

    def _on_user_changed(self) -> None:
        """
        Svaka promena korisnika mora da očisti secret (da ne ostane tuđ PIN/lozinka).
        Programatska promena (auto-match) ne sme da krade fokus.
        """
        try:
            self.ed_secret.setText("")
        except Exception:
            pass

        if not self._programmatic_user_index_change:
            self._user_interacted = True

        try:
            self._selected_user = self._get_selected_user()
        except Exception:
            pass

        self._sync_ui()

    # -------------------- rate-limit / cooldown --------------------
    def _user_key(self, u: Optional[Dict[str, Any]]) -> str:
        if not u:
            return "user:unknown"
        uid = _safe_int(u.get("id") or u.get("user_id") or 0, 0)
        if uid > 0:
            return f"user:id:{uid}"
        un = str(u.get("username") or u.get("user") or "").strip().casefold()
        return f"user:un:{un}" if un else "user:unknown"

    def _cooldown_remaining(self, u: Optional[Dict[str, Any]]) -> int:
        key = self._user_key(u)
        until = float(self._cooldown_until.get(key) or 0.0)
        if until <= 0:
            return 0
        now = time.monotonic()
        rem = int(round(until - now))
        return rem if rem > 0 else 0

    def _set_cooldown(self, u: Dict[str, Any], seconds: int) -> None:
        key = self._user_key(u)
        sec = max(1, min(int(seconds), int(self._COOLDOWN_MAX_SEC)))
        self._cooldown_until[key] = time.monotonic() + float(sec)

    def _reset_attempts(self, u: Dict[str, Any]) -> None:
        key = self._user_key(u)
        self._fail_count.pop(key, None)
        self._cooldown_until.pop(key, None)

    def _register_failed_attempt(self, u: Dict[str, Any], reason: str) -> None:
        key = self._user_key(u)
        n = int(self._fail_count.get(key) or 0) + 1
        self._fail_count[key] = n

        cd = 0
        if n >= int(self._FAIL_THRESHOLD):
            # 5->10s, 6->20s, 7->40s ... max 300s
            exp = max(0, n - int(self._FAIL_THRESHOLD))
            cd = min(int(self._COOLDOWN_BASE_SEC) * (2 ** exp), int(self._COOLDOWN_MAX_SEC))
            self._set_cooldown(u, cd)

        # audit (best-effort, bez tajni)
        self._audit_login_event(success=False, u=u, reason=reason, extra={"fail_count": n, "cooldown_sec": cd})

    def _refresh_cooldown_ui(self) -> None:
        # samo refresh, bez popupa
        try:
            self._sync_ui()
        except Exception:
            pass

    # -------------------- audit (best-effort, no secrets) --------------------
    def _audit_login_event(self, success: bool, u: Dict[str, Any], reason: str, extra: Optional[Dict[str, Any]] = None) -> None:
        try:
            from core.db import connect_db, write_audit  # type: ignore
        except Exception:
            return
        if not callable(connect_db) or not callable(write_audit):
            return

        uid = _safe_int(u.get("id") or u.get("user_id") or 0, 0)
        username = str(u.get("username") or u.get("user") or "").strip()
        display_name = str(u.get("display_name") or "").strip()
        role = str(u.get("active_role") or u.get("role") or "").strip().upper()

        payload = dict(
            actor=username or (f"user#{uid}" if uid > 0 else "user"),
            actor_name=display_name or username or "user",
            action="login.success" if success else "login.fail",
            entity="user",
            entity_id=str(uid or ""),
            before_obj=None,
            after_obj={"active_role": role} if success else None,
            extra={
                "source": "ui.login_dialog",
                "reason": str(reason or "").strip(),
                "username": username,
                "role": role,
                **(extra or {}),
            },
        )

        try:
            obj = connect_db()
            if isinstance(obj, sqlite3.Connection):
                conn = obj
                try:
                    write_audit(conn=conn, **payload)  # type: ignore[arg-type]
                    try:
                        conn.commit()
                    except Exception:
                        pass
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
                return

            if hasattr(obj, "__enter__") and hasattr(obj, "__exit__"):
                with obj as conn:
                    write_audit(conn=conn, **payload)  # type: ignore[arg-type]
                    try:
                        conn.commit()
                    except Exception:
                        pass
                return

            conn = obj
            write_audit(conn=conn, **payload)  # type: ignore[arg-type]
            try:
                conn.commit()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
        except Exception:
            return

    # -------------------- UI sync --------------------
    def _apply_secret_mode_constraints(self, u: Dict[str, Any]) -> None:
        """
        PIN-only hardening:
        - digits-only input hints + validator
        - remove validator when password is allowed
        """
        try:
            has_pin = bool(u.get("has_pin")) if ("has_pin" in u) else False
            has_pw = bool(u.get("has_password")) if ("has_password" in u) else False

            if has_pin and (not has_pw):
                self.ed_secret.setValidator(self._pin_validator)
                try:
                    self.ed_secret.setInputMethodHints(Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText)
                except Exception:
                    pass
            else:
                self.ed_secret.setValidator(None)
                try:
                    self.ed_secret.setInputMethodHints(Qt.ImhNoPredictiveText)
                except Exception:
                    pass
        except Exception:
            pass

    def _sync_ui(self) -> None:
        self._selected_user = self._get_selected_user()

        if not self._selected_user:
            self.btn_login.setEnabled(False)
            self.ed_secret.setEnabled(False)
            self.lb_hint.setText("Nema korisnika u bazi.")
            self.lb_role.setVisible(False)
            self.cb_role.setVisible(False)
            self._update_caps_lock_label()
            return

        # Always: roles + highest active role
        self._sync_role_ui()

        u = self._selected_user
        has_cred = self._user_has_credentials(u)

        # typed validation UX (disable when clearly invalid)
        typed = (self._typed_user_text() or "").strip()
        if typed and len(typed) >= int(self._AUTOSELECT_MIN_CHARS):
            _, _, st = self._resolve_typed_user(typed)
            if st in ("not_found", "ambiguous"):
                self.btn_login.setEnabled(False)
                self.ed_secret.setEnabled(False)
                self.lb_hint.setText("Izaberi tačno jednog korisnika (autocomplete/lista).")
                self._update_caps_lock_label()
                return

        # cooldown gate (only relevant if user has credentials)
        if has_cred:
            rem = self._cooldown_remaining(u)
            if rem > 0:
                self.ed_secret.setEnabled(False)
                self.btn_login.setEnabled(False)
                self.lb_hint.setText(f"Previše pokušaja. Sačekaj {rem}s pa probaj ponovo.")
                try:
                    if not self._cooldown_timer.isActive():
                        self._cooldown_timer.start()
                except Exception:
                    pass
                self._update_caps_lock_label()
                # keep focus on user (prevents frustration)
                try:
                    if not self._should_keep_user_focus():
                        le = self.cb_user.lineEdit()
                        if le:
                            le.setFocus(Qt.OtherFocusReason)
                except Exception:
                    pass
                return
            else:
                try:
                    if self._cooldown_timer.isActive():
                        self._cooldown_timer.stop()
                except Exception:
                    pass

        if not has_cred:
            # ulaz bez lozinke
            self.ed_secret.setEnabled(False)
            self.btn_login.setEnabled(True)
            self.btn_login.setText("Uđi")
            self.lb_hint.setText("Ovaj korisnik nema PIN/lozinku — ulaz bez lozinke je dozvoljen (privremeno).")
            self._update_caps_lock_label()
            return

        # ima kredencijale -> traži unos
        self.ed_secret.setEnabled(True)
        self.btn_login.setEnabled(True)

        self._apply_secret_mode_constraints(u)

        has_pin = bool(u.get("has_pin")) if ("has_pin" in u) else False
        has_pw = bool(u.get("has_password")) if ("has_password" in u) else False

        if has_pin and has_pw:
            self.lb_hint.setText("Unesi PIN ili lozinku (oba važe).")
            self.ed_secret.setPlaceholderText("Unesi PIN ili lozinku")
        elif has_pin:
            self.lb_hint.setText("Unesi PIN.")
            self.ed_secret.setPlaceholderText("Unesi PIN")
        elif has_pw:
            self.lb_hint.setText("Unesi lozinku.")
            self.ed_secret.setPlaceholderText("Unesi lozinku")
        else:
            self.lb_hint.setText("Unesi PIN ili lozinku.")
            self.ed_secret.setPlaceholderText("Unesi PIN ili lozinku")

        self._update_caps_lock_label()

        # button text: Next vs Login
        try:
            secret = (self.ed_secret.text() or "").strip()
            self.btn_login.setText("Dalje" if not secret else "Prijavi se")
        except Exception:
            pass

        # Auto-focus secret: dozvoljeno tek kad user interaguje (da prozor ne otvara na password)
        if self._user_interacted and (not self._should_keep_user_focus()):
            self._focus_secret(force=False)

    # -------------------- primary action: Next/Login --------------------
    def _on_primary_action(self) -> None:
        """
        Jedno dugme, pametno ponašanje:
        - Ako user ima kredencijale i secret je prazan -> radi kao "Dalje" (resolve + fokus na secret)
        - Inače -> normalan login
        """
        typed = self._typed_user_text()
        user, _, status = self._resolve_typed_user(typed)
        if status == "not_found":
            QMessageBox.warning(self, "Validacija", "Korisnik nije pronađen. Izaberi korisnika iz liste (autocomplete).")
            return
        if status == "ambiguous":
            QMessageBox.warning(self, "Validacija", "Nađeno više korisnika. Izaberi tačno jednog iz liste (autocomplete).")
            return
        if not user:
            QMessageBox.warning(self, "Info", "Nema izabranog korisnika.")
            return

        if self._user_has_credentials(user):
            secret = (self.ed_secret.text() or "").strip()
            if not secret:
                self._on_user_enter_pressed()
                return

        self._on_login()

    # -------------------- session finalize + login flow --------------------
    def _finalize_user_for_session(self, base_user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Priprema user dict za session:
        - ne mutira original iz self._users (radi se na kopiji)
        - osigurava roles + active_role (highest)
        - opciono poziva normalize_user_for_session ako postoji
        """
        merged = dict(base_user)

        # roles fallback ako nisu već tu
        if not (isinstance(merged.get("roles"), list) and merged.get("roles")):
            try:
                merged["roles"] = self._load_roles_for_user(merged)
            except Exception:
                merged["roles"] = []

        # highest active role
        self._apply_active_role(merged)

        # normalize hook (ako postoji u users_service)
        if callable(normalize_user_for_session):
            try:
                norm = normalize_user_for_session(merged, active_role=merged.get("active_role"))
                if isinstance(norm, dict):
                    return norm
            except Exception:
                pass

        return merged

    def _persist_last_login_state(self, u: Dict[str, Any]) -> None:
        """
        Pamti poslednjeg user-a (offline).
        Best-effort: ne sme da obori login.
        (last_role čuvamo samo radi kompatibilnosti, ali se ne koristi za izbor tokom prijave)
        """
        uid = _safe_int(u.get("id") or u.get("user_id") or 0, 0)
        username = (u.get("username") or u.get("user") or "").strip()
        role = (u.get("active_role") or u.get("role") or "").strip().upper()

        st = _load_login_state()
        st["last_user_id"] = uid
        st["last_username"] = username
        st["last_role"] = role  # compat only
        _save_login_state(st)

    def _wipe_secret(self) -> None:
        try:
            self.ed_secret.setText("")
        except Exception:
            pass

    def _on_login(self) -> None:
        """
        Login:
        - fail-closed resolve typed user (not_found / ambiguous => stop)
        - bez lozinke samo ako user nema kredencijale
        - smart provera: PIN i/ili lozinka (u skladu sa has_pin / has_password)
        - rate-limit: posle više fail-ova, cooldown
        - rola se NE bira u UI: uvek highest
        """
        self._user_interacted = True

        typed = self._typed_user_text()
        user, idx, status = self._resolve_typed_user(typed)

        if status == "not_found":
            QMessageBox.warning(self, "Validacija", "Korisnik nije pronađen. Izaberi korisnika iz liste (autocomplete).")
            return
        if status == "ambiguous":
            QMessageBox.warning(self, "Validacija", "Nađeno više korisnika. Izaberi tačno jednog iz liste (autocomplete).")
            return
        if not user:
            QMessageBox.warning(self, "Info", "Nema izabranog korisnika.")
            return

        # uskladi selekciju UI-a (best-effort)
        if 0 <= idx < self.cb_user.count():
            self._set_user_index_programmatically(idx, keep_text=typed)
            self._selected_user = user
        else:
            self._selected_user = user

        # cooldown gate
        if self._user_has_credentials(user):
            rem = self._cooldown_remaining(user)
            if rem > 0:
                QMessageBox.warning(self, "Sačekaj", f"Previše pokušaja. Sačekaj {rem}s pa probaj ponovo.")
                return

        secret = (self.ed_secret.text() or "").strip()
        has_cred = self._user_has_credentials(user)

        # ✅ Bez lozinke samo kad nema kredencijala
        if not has_cred:
            finalized = self._finalize_user_for_session(user)
            self._selected_user = finalized
            try:
                self._persist_last_login_state(finalized)
            except Exception:
                pass
            self._audit_login_event(success=True, u=finalized, reason="no_credential_login", extra=None)
            self._wipe_secret()
            self.accept()
            return

        if not secret:
            QMessageBox.warning(self, "Validacija", "Unesi PIN ili lozinku.")
            self._focus_secret(force=True)
            return

        ok: Any = False
        merged = dict(user)

        has_pin = bool(user.get("has_pin")) if ("has_pin" in user) else False
        has_pw = bool(user.get("has_password")) if ("has_password" in user) else False

        # PIN first (ako postoji ili nije eksplicitno poznato)
        if has_pin or ("has_pin" not in user):
            try:
                ok = verify_user_pin(user, secret)
            except Exception:
                ok = False

            if ok:
                if isinstance(ok, dict):
                    merged.update(ok)
                finalized = self._finalize_user_for_session(merged)
                self._selected_user = finalized
                self._reset_attempts(user)
                try:
                    self._persist_last_login_state(finalized)
                except Exception:
                    pass
                self._audit_login_event(success=True, u=finalized, reason="pin_ok", extra=None)
                self._wipe_secret()
                self.accept()
                return

        # Password (ako postoji ili nije eksplicitno poznato)
        if has_pw or ("has_password" not in user):
            try:
                ok = verify_user_password(user, secret)
            except Exception:
                ok = False

            if ok:
                if isinstance(ok, dict):
                    merged.update(ok)
                finalized = self._finalize_user_for_session(merged)
                self._selected_user = finalized
                self._reset_attempts(user)
                try:
                    self._persist_last_login_state(finalized)
                except Exception:
                    pass
                self._audit_login_event(success=True, u=finalized, reason="password_ok", extra=None)
                self._wipe_secret()
                self.accept()
                return

        # Fail: register attempt, maybe cooldown
        self._register_failed_attempt(user, reason="bad_secret")

        QMessageBox.warning(self, "Greška", "Pogrešan PIN ili lozinka.")
        try:
            self.ed_secret.selectAll()
            self._focus_secret(force=True)
        except Exception:
            pass

        self._sync_ui()

    def selected_user(self) -> Optional[Dict[str, Any]]:
        return self._selected_user

# (FILENAME: ui/login_dialog.py - END)  # Part 2/2