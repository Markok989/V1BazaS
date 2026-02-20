# FILENAME: ui/user_detail_dialog.py
# (FILENAME: ui/user_detail_dialog.py - START / PART 1 of 3)

from __future__ import annotations

import inspect
import logging
import re
import unicodedata
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from PySide6.QtCore import Qt, QRegularExpression  # type: ignore
from PySide6.QtGui import QStandardItem, QRegularExpressionValidator  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QDialog,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTabWidget,
    QFormLayout,
    QLineEdit,
    QComboBox,
    QPlainTextEdit,
    QCheckBox,
    QListWidget,
    QListWidgetItem,
    QAbstractItemView,
    QDialogButtonBox,
    QMessageBox,
    QGroupBox,
)

from core.session import can
from core.rbac import PERM_USERS_VIEW, PERM_USERS_MANAGE

from services.users_service import (
    ensure_users_schema,
    get_user_by_username,
    list_available_roles,
    set_user_roles,
    create_user,
    update_user_profile,
    set_user_pin,
    clear_user_pin,
    set_user_password,
    clear_user_password,
)

# ---- optional (fail-soft) imports from users_service (newer features) ----
try:
    from services.users_service import (  # type: ignore
        get_user_credential_flags,
        set_user_must_change_creds,
        admin_reset_credentials,
        set_my_pin,
        clear_my_pin,
        set_my_password,
        clear_my_password,
    )
except Exception:  # pragma: no cover
    get_user_credential_flags = None  # type: ignore
    set_user_must_change_creds = None  # type: ignore
    admin_reset_credentials = None  # type: ignore
    set_my_pin = None  # type: ignore
    clear_my_pin = None  # type: ignore
    set_my_password = None  # type: ignore
    clear_my_password = None  # type: ignore

# optional (fail-soft)
try:
    from services.users_service import list_sectors  # type: ignore
except Exception:  # pragma: no cover
    list_sectors = None  # type: ignore

try:
    from services.users_service import list_locations  # type: ignore
except Exception:  # pragma: no cover
    list_locations = None  # type: ignore

try:
    from services.users_service import list_title_groups  # type: ignore
except Exception:  # pragma: no cover
    list_title_groups = None  # type: ignore


_TITLE_HEADER_ROLE = int(Qt.UserRole) + 11

# Inline validation QSS (minimal, da ne ubije globalnu temu)
_INLINE_INVALID_QSS = (
    "border: 2px solid #d32f2f;"
    "border-radius: 6px;"
)


def _safe_can(perm: str) -> bool:
    try:
        return bool(can(perm))
    except Exception:
        return False


def _warn(parent: QWidget, text: str, title: str = "Upozorenje") -> None:
    QMessageBox.warning(parent, title, text)


def _info(parent: QWidget, text: str, title: str = "Info") -> None:
    QMessageBox.information(parent, title, text)


def _ask_yes_no(parent: QWidget, text: str, title: str = "Potvrda") -> bool:
    r = QMessageBox.question(parent, title, text, QMessageBox.Yes | QMessageBox.No)
    return r == QMessageBox.Yes


def _norm_text(s: Any, max_len: int) -> str:
    x = ("" if s is None else str(s)).replace("\n", " ").replace("\r", " ").strip()
    return x[:max_len]


def _dedup_casefold(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        t = str(x or "").strip()
        if not t:
            continue
        k = t.casefold()
        if k in seen:
            continue
        seen.add(k)
        out.append(t)
    return out


def _safe_list(fn, existing: Optional[List[str]] = None, max_len: int = 120) -> List[str]:
    try:
        if callable(fn):
            rr = fn()
            if isinstance(rr, list) and rr:
                return _dedup_casefold([_norm_text(x, max_len) for x in rr])
    except Exception:
        pass
    ex = existing or []
    return _dedup_casefold([_norm_text(x, max_len) for x in ex])


def _combo_add_header(cb: QComboBox, text: str) -> None:
    idx = cb.count()
    cb.addItem(text)
    cb.setItemData(idx, True, _TITLE_HEADER_ROLE)
    try:
        model = cb.model()
        it = model.item(idx)  # type: ignore[attr-defined]
        if isinstance(it, QStandardItem):
            f = it.font()
            f.setBold(True)
            it.setFont(f)
            it.setFlags(Qt.ItemIsEnabled)
    except Exception:
        pass


def _combo_is_header(cb: QComboBox, idx: int) -> bool:
    try:
        return bool(cb.itemData(idx, _TITLE_HEADER_ROLE))
    except Exception:
        return False


def _populate_titles(cb: QComboBox, current_text: str = "") -> None:
    cb.clear()

    groups = []
    try:
        if callable(list_title_groups):
            groups = list_title_groups()  # type: ignore[misc]
    except Exception:
        groups = []

    if not isinstance(groups, list) or not groups:
        groups = [{"group": "Status", "items": ["Vojni službenik"]}]

    for g in groups:
        gname = str(g.get("group") or "").strip()
        items = g.get("items") or []
        if not isinstance(items, list):
            items = []
        items2 = [str(x).strip() for x in items if str(x).strip()]
        if not items2:
            continue

        if gname:
            _combo_add_header(cb, gname)
        for t in items2:
            cb.addItem(t)

        try:
            cb.insertSeparator(cb.count())
        except Exception:
            pass

    cur = (current_text or "").strip()
    if cur:
        j = cb.findText(cur)
        if j >= 0 and (not _combo_is_header(cb, j)):
            cb.setCurrentIndex(j)
            return

    j = cb.findText("Vojni službenik")
    if j >= 0 and (not _combo_is_header(cb, j)):
        cb.setCurrentIndex(j)
        return

    for i in range(cb.count()):
        if _combo_is_header(cb, i):
            continue
        if cb.itemText(i).strip():
            cb.setCurrentIndex(i)
            return


def _slugify_sr(s: str) -> str:
    t = (s or "").strip()
    if not t:
        return ""
    t = unicodedata.normalize("NFKD", t)
    t = "".join(ch for ch in t if not unicodedata.combining(ch))
    t = t.lower()
    t = re.sub(r"[^a-z0-9]+", "", t)
    return t


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


def _validate_jmbg(j: str) -> Optional[str]:
    jj = (j or "").strip()
    if not jj:
        return None
    if not re.fullmatch(r"\d{13}", jj):
        return "JMBG mora imati tačno 13 cifara."
    return None


def _roles_norm_list(roles: Any) -> List[str]:
    out: List[str] = []
    if isinstance(roles, list):
        for x in roles:
            t = str(x or "").strip().upper()
            if t:
                out.append(t)
    seen: Set[str] = set()
    ded: List[str] = []
    for r in out:
        if r not in seen:
            seen.add(r)
            ded.append(r)
    return ded


def _call_with_supported_kwargs(fn, **kwargs):
    """
    Fail-safe: ako servis još nema nova polja, ignoriši ih.
    """
    try:
        sig = inspect.signature(fn)
        allowed = set(sig.parameters.keys())
        filtered = {k: v for k, v in kwargs.items() if k in allowed}
        return fn(**filtered)
    except Exception:
        return fn(**kwargs)


def _get_current_username_best_effort() -> str:
    """
    core.session može imati get_current_user() ili _CURRENT_USER.
    """
    try:
        import core.session as s  # type: ignore
        fn = getattr(s, "get_current_user", None)
        if callable(fn):
            u = fn() or {}
            if isinstance(u, dict):
                return str(u.get("username") or u.get("user") or u.get("login") or "").strip()
            return str(u or "").strip()
        u2 = getattr(s, "_CURRENT_USER", None)
        if isinstance(u2, dict):
            return str(u2.get("username") or u2.get("user") or u2.get("login") or "").strip()
        return str(u2 or "").strip()
    except Exception:
        return ""


def _get_current_sector_best_effort() -> str:
    """
    Best-effort izvlačenje sektora iz sesije.
    Preferiramo core.session.current_sector() ako postoji.
    """
    try:
        from core.session import current_sector  # type: ignore
        if callable(current_sector):
            return str(current_sector() or "").strip()
    except Exception:
        pass

    try:
        import core.session as s  # type: ignore
        fn = getattr(s, "get_current_user", None)
        if callable(fn):
            u = fn() or {}
            if isinstance(u, dict):
                return str(u.get("sector") or u.get("org_unit") or "").strip()
        u2 = getattr(s, "_CURRENT_USER", None)
        if isinstance(u2, dict):
            return str(u2.get("sector") or u2.get("org_unit") or "").strip()
    except Exception:
        pass
    return ""


def _is_sector_admin_best_effort() -> bool:
    """
    Best-effort detekcija aktivne role.
    Preferiramo core.rbac.effective_role(get_current_user()) ako postoji.
    """
    try:
        from core.session import get_current_user  # type: ignore
        from core.rbac import effective_role  # type: ignore
        u = get_current_user() or {}
        r = str(effective_role(u) or "").strip().upper()
        return r == "SECTOR_ADMIN"
    except Exception:
        pass

    try:
        import core.session as s  # type: ignore
        u2 = getattr(s, "_CURRENT_USER", None)
        if isinstance(u2, dict):
            r2 = str(u2.get("role") or u2.get("active_role") or u2.get("user_role") or "").strip().upper()
            return r2 == "SECTOR_ADMIN"
    except Exception:
        pass
    return False


class UserDetailDialog(QDialog):
    """
    Detalji korisnika (tabovi: Profil / Uloge / Bezbednost)

    Inline validacija + pop-up poruke:
    - Inline: crveni border + tooltip na polju (trenutni hint)
    - Pop-up: na Save i na akcijama (kao do sada)

    SECTOR scope UI hardening:
    - Ako je aktivna rola SECTOR_ADMIN:
        * sektor je fiksiran na current_sector()
        * polje sektor je zaključano
        * Save ignoriše UI sektor i uvek koristi session sektor
    """

    def __init__(
        self,
        parent: QWidget,
        logger: logging.Logger,
        *,
        username: Optional[str] = None,
        is_new: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setModal(True)
        self.logger = logger
        self.is_new = bool(is_new)
        self.username_arg = (username or "").strip()

        self._can_manage = _safe_can(PERM_USERS_MANAGE)
        self._can_view = _safe_can(PERM_USERS_VIEW)

        # ✅ aktivna rola / sektor (best-effort)
        self._is_sector_admin = bool(_is_sector_admin_best_effort())
        self._my_sector = _get_current_sector_best_effort().strip()

        # inline validation state
        self._save_attempted = False
        self._orig_styles: Dict[int, str] = {}

        ensure_users_schema()

        self._user: Dict[str, Any] = {}
        if (not self.is_new) and self.username_arg:
            try:
                self._user = get_user_by_username(self.username_arg) or {}
            except Exception as e:
                _warn(self, f"Ne mogu da učitam korisnika:\n{e}")
                self._user = {}

        self._username_touched = False
        self._is_self = False  # popuni se posle load-a

        self._build_ui()
        self._load_initial()
        self._refresh_security_status()
        self._refresh_active_badge()
        self._apply_profile_permissions()
        self._apply_security_permissions()

        # initial inline validation (bez “crvenjenja” required polja dok user nije kliknuo Save)
        self._inline_validate_all()

    # ---------------- inline validation helpers ----------------
    def _log_exc(self, msg: str, exc: Exception) -> None:
        try:
            self.logger.exception("%s: %s", msg, exc)
        except Exception:
            pass

    def _remember_style(self, w: QWidget) -> None:
        key = id(w)
        if key not in self._orig_styles:
            try:
                self._orig_styles[key] = w.styleSheet() or ""
            except Exception:
                self._orig_styles[key] = ""

    def _set_inline_error(self, w: QWidget, msg: str) -> None:
        """
        Inline hint: crveni border + tooltip.
        Ne diramo globalnu temu — dodajemo minimalni QSS samo tom widgetu.
        """
        if w is None:
            return
        try:
            if not msg:
                self._clear_inline_error(w)
                return
            self._remember_style(w)
            base = self._orig_styles.get(id(w), "")
            # izbegni dupliranje
            if _INLINE_INVALID_QSS not in (w.styleSheet() or ""):
                w.setStyleSheet((base + "\n" + _INLINE_INVALID_QSS).strip())
            w.setToolTip(msg)
        except Exception as e:
            self._log_exc("set inline error failed", e)

    def _clear_inline_error(self, w: QWidget) -> None:
        if w is None:
            return
        try:
            base = self._orig_styles.get(id(w))
            if base is not None:
                w.setStyleSheet(base)
            else:
                # fallback: samo skloni invalid QSS ako je ubačen
                ss = w.styleSheet() or ""
                ss = ss.replace(_INLINE_INVALID_QSS, "").strip()
                w.setStyleSheet(ss)
            w.setToolTip("")
        except Exception as e:
            self._log_exc("clear inline error failed", e)

    def _clear_all_inline_errors(self) -> None:
        for w in getattr(self, "_inline_widgets", []):
            try:
                self._clear_inline_error(w)
            except Exception:
                pass

    def _inline_validate_all(self) -> None:
        """
        Validira polja inline (bez pop-up-a).
        Required polja se “crvene” tek posle pokušaja Save (self._save_attempted).
        """
        self._inline_validate_profile()
        self._inline_validate_roles()
        self._inline_validate_security_inputs()

    def _inline_validate_profile(self) -> None:
        # required tek posle save attempt
        last_name = (self.ed_last.text() or "").strip()
        first_name = (self.ed_first.text() or "").strip()

        if self._save_attempted and not last_name:
            self._set_inline_error(self.ed_last, "Prezime je obavezno.")
        else:
            self._clear_inline_error(self.ed_last)

        if self._save_attempted and not first_name:
            self._set_inline_error(self.ed_first, "Ime je obavezno.")
        else:
            self._clear_inline_error(self.ed_first)

        # username: uvek validiraj format (jer utiče na sve)
        u = (self.ed_username.text() or "").strip().casefold()
        if u:
            if re.search(r"\s", u):
                self._set_inline_error(self.ed_username, "Username ne sme imati razmake.")
            elif len(u) < 3:
                self._set_inline_error(self.ed_username, "Username mora imati minimum 3 karaktera.")
            elif len(u) > 50:
                self._set_inline_error(self.ed_username, "Username je predugačak (max 50).")
            elif not re.fullmatch(r"[a-z0-9_.]+", u):
                self._set_inline_error(self.ed_username, "Dozvoljeno: a-z, 0-9, '_' i '.'.")
            else:
                self._clear_inline_error(self.ed_username)
        else:
            if self._save_attempted:
                self._set_inline_error(self.ed_username, "Username je obavezan.")
            else:
                self._clear_inline_error(self.ed_username)

        # jmbg format
        jmbg = (self.ed_jmbg.text() or "").strip()
        jmsg = _validate_jmbg(jmbg)
        if jmsg:
            self._set_inline_error(self.ed_jmbg, jmsg)
        else:
            self._clear_inline_error(self.ed_jmbg)

        # email (light check)
        email = (self.ed_email.text() or "").strip()
        if email and (not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)):
            self._set_inline_error(self.ed_email, "Email format nije validan.")
        else:
            self._clear_inline_error(self.ed_email)

    def _inline_validate_roles(self) -> None:
        if not hasattr(self, "lst_roles"):
            return
        checked = self._checked_roles()
        if self._save_attempted and not checked:
            self._set_inline_error(self.lst_roles, "Čekiraj bar jednu rolu.")
        else:
            self._clear_inline_error(self.lst_roles)

    def _inline_validate_security_inputs(self) -> None:
        # samo ako user nešto kuca (da ne “crveni” prazno)
        pin = (self.ed_new_pin.text() or "").strip()
        if pin:
            if re.fullmatch(r"\d{4,8}", pin):
                self._clear_inline_error(self.ed_new_pin)
            else:
                self._set_inline_error(self.ed_new_pin, "PIN: 4–8 cifara.")
        else:
            self._clear_inline_error(self.ed_new_pin)

        pw = (self.ed_new_pw.text() or "").strip()
        if pw:
            if len(pw) >= 6:
                self._clear_inline_error(self.ed_new_pw)
            else:
                self._set_inline_error(self.ed_new_pw, "Lozinka: minimum 6 karaktera.")
        else:
            self._clear_inline_error(self.ed_new_pw)

    # ---------------- UI ----------------
    def _build_ui(self) -> None:
        self.resize(980, 650)
        root = QVBoxLayout(self)

        header = QHBoxLayout()
        self.lb_title = QLabel("")
        self.lb_title.setStyleSheet("font-size: 20px; font-weight: 700;")
        header.addWidget(self.lb_title, 1)

        self.lb_active_badge = QLabel("")
        self.lb_active_badge.setAlignment(Qt.AlignCenter)
        self.lb_active_badge.setMinimumWidth(130)
        self.lb_active_badge.setStyleSheet("padding: 6px 10px; border-radius: 12px; font-weight: 800;")
        header.addWidget(self.lb_active_badge)
        root.addLayout(header)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        # --- Profil tab ---
        self.tab_profile = QWidget()
        self.tabs.addTab(self.tab_profile, "Profil")
        prof_root = QVBoxLayout(self.tab_profile)

        form = QFormLayout()
        prof_root.addLayout(form)

        self.ed_last = QLineEdit()
        self.ed_last.setPlaceholderText("Prezime")
        form.addRow("Prezime:", self.ed_last)

        self.ed_father = QLineEdit()
        self.ed_father.setPlaceholderText("Ime oca (opciono)")
        form.addRow("Ime oca:", self.ed_father)

        self.ed_first = QLineEdit()
        self.ed_first.setPlaceholderText("Ime")
        form.addRow("Ime:", self.ed_first)

        self.ed_username = QLineEdit()
        self.ed_username.setPlaceholderText("username (auto: prezime+ime)")
        # optional: validator (light) – dozvoljeno samo što i policy
        self.ed_username.setMaxLength(50)
        self.ed_username.setValidator(QRegularExpressionValidator(QRegularExpression(r"[a-z0-9_.]{0,50}"), self))
        form.addRow("Username:", self.ed_username)

        self.cb_sector = QComboBox()
        self.cb_sector.setEditable(True)
        form.addRow("Sektor:", self.cb_sector)

        self.cb_location = QComboBox()
        self.cb_location.setEditable(True)
        form.addRow("Lokacija:", self.cb_location)

        self.cb_title = QComboBox()
        self.cb_title.setEditable(False)
        self.cb_title.currentIndexChanged.connect(self._on_title_changed)
        form.addRow("Čin/Status:", self.cb_title)

        self.ed_jmbg = QLineEdit()
        self.ed_jmbg.setPlaceholderText("13 cifara")
        self.ed_jmbg.setMaxLength(13)
        self.ed_jmbg.setValidator(QRegularExpressionValidator(QRegularExpression(r"\d{0,13}"), self))
        form.addRow("JMBG:", self.ed_jmbg)

        self.ed_email = QLineEdit()
        form.addRow("Email:", self.ed_email)

        self.ed_phone = QLineEdit()
        form.addRow("Telefon:", self.ed_phone)

        self.ed_empno = QLineEdit()
        form.addRow("Broj (mat./ID):", self.ed_empno)

        self.ed_note = QPlainTextEdit()
        self.ed_note.setPlaceholderText("Napomena...")
        self.ed_note.setFixedHeight(90)
        form.addRow("Napomena:", self.ed_note)

        self.chk_active = QCheckBox("Aktivan korisnik")
        prof_root.addWidget(self.chk_active)

        meta_box = QGroupBox("Meta")
        meta_form = QFormLayout(meta_box)

        self.ed_created_at = QLineEdit()
        self.ed_created_at.setReadOnly(True)
        self.ed_created_at.setPlaceholderText("—")
        meta_form.addRow("Kreiran:", self.ed_created_at)

        self.ed_updated_at = QLineEdit()
        self.ed_updated_at.setReadOnly(True)
        self.ed_updated_at.setPlaceholderText("—")
        meta_form.addRow("Ažuriran:", self.ed_updated_at)

        prof_root.addWidget(meta_box)

        # --- Uloge tab ---
        self.tab_roles = QWidget()
        self.tabs.addTab(self.tab_roles, "Uloge")
        roles_root = QVBoxLayout(self.tab_roles)

        box_roles = QGroupBox("Role (čekiraj dodeljene)")
        box_l = QVBoxLayout(box_roles)

        row_pr = QHBoxLayout()
        row_pr.addWidget(QLabel("Primarna rola:"))
        self.cb_primary_role = QComboBox()
        row_pr.addWidget(self.cb_primary_role, 1)
        box_l.addLayout(row_pr)

        self.lst_roles = QListWidget()
        self.lst_roles.setSelectionMode(QAbstractItemView.NoSelection)
        self.lst_roles.itemChanged.connect(self._on_roles_changed)
        box_l.addWidget(self.lst_roles, 1)

        roles_root.addWidget(box_roles, 1)

        # --- Bezbednost tab ---
        self.tab_sec = QWidget()
        self.tabs.addTab(self.tab_sec, "Bezbednost")
        sec_root = QVBoxLayout(self.tab_sec)

        self.lb_login_status = QLabel("")
        self.lb_login_status.setWordWrap(True)
        self.lb_login_status.setStyleSheet("font-weight: 650;")
        sec_root.addWidget(self.lb_login_status)

        self.lb_policy_status = QLabel("")
        self.lb_policy_status.setWordWrap(True)
        self.lb_policy_status.setStyleSheet("font-weight: 700;")
        sec_root.addWidget(self.lb_policy_status)

        hint = QLabel(
            "Napomena: Sistem je offline; u bazi se čuva samo hash. "
            "Ako je uključeno 'Mora promena kredencijala', korisnik treba odmah da promeni PIN/lozinku."
        )
        hint.setWordWrap(True)
        sec_root.addWidget(hint)

        # Admin reset box (fail-soft)
        self.box_admin_reset = QGroupBox("Admin reset")
        ar_l = QHBoxLayout(self.box_admin_reset)
        self.btn_admin_reset = QPushButton("Resetuj kredencijale (privremeno)")
        self.btn_clear_must_change = QPushButton("Skini 'mora promena'")
        ar_l.addWidget(self.btn_admin_reset)
        ar_l.addWidget(self.btn_clear_must_change)
        sec_root.addWidget(self.box_admin_reset)

        # PIN box
        box_pin = QGroupBox("PIN")
        pin_l = QFormLayout(box_pin)
        self.ed_new_pin = QLineEdit()
        self.ed_new_pin.setEchoMode(QLineEdit.Password)
        self.ed_new_pin.setPlaceholderText("4–8 cifara")
        pin_l.addRow("Novi PIN:", self.ed_new_pin)

        row_pin = QHBoxLayout()
        self.btn_set_pin = QPushButton("Postavi PIN")
        self.btn_clear_pin = QPushButton("Obriši PIN")
        row_pin.addWidget(self.btn_set_pin)
        row_pin.addWidget(self.btn_clear_pin)
        pin_l.addRow("", row_pin)
        sec_root.addWidget(box_pin)

        # Password box
        box_pw = QGroupBox("Lozinka")
        pw_l = QFormLayout(box_pw)
        self.ed_new_pw = QLineEdit()
        self.ed_new_pw.setEchoMode(QLineEdit.Password)
        self.ed_new_pw.setPlaceholderText("min 6 karaktera")
        pw_l.addRow("Nova lozinka:", self.ed_new_pw)

        row_pw = QHBoxLayout()
        self.btn_set_pw = QPushButton("Postavi lozinku")
        self.btn_clear_pw = QPushButton("Obriši lozinku")
        row_pw.addWidget(self.btn_set_pw)
        row_pw.addWidget(self.btn_clear_pw)
        pw_l.addRow("", row_pw)
        sec_root.addWidget(box_pw)

        sec_root.addStretch(1)

        self.btn_set_pin.clicked.connect(self._do_set_pin)
        self.btn_clear_pin.clicked.connect(self._do_clear_pin)
        self.btn_set_pw.clicked.connect(self._do_set_pw)
        self.btn_clear_pw.clicked.connect(self._do_clear_pw)
        self.btn_admin_reset.clicked.connect(self._do_admin_reset_creds)
        self.btn_clear_must_change.clicked.connect(self._do_clear_must_change)

        self.btns = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.btns.accepted.connect(self._on_save)
        self.btns.rejected.connect(self.reject)
        root.addWidget(self.btns)

        # widgets list za inline reset (bitno da je posle init-a svih widgeta)
        self._inline_widgets = [
            self.ed_last,
            self.ed_first,
            self.ed_username,
            self.ed_jmbg,
            self.ed_email,
            self.lst_roles,
            self.ed_new_pin,
            self.ed_new_pw,
        ]

        # signals: inline validacija (bez pop-up-a)
        self.chk_active.stateChanged.connect(self._refresh_active_badge)
        self.ed_username.textEdited.connect(self._on_username_edited)
        self.ed_last.textChanged.connect(self._maybe_autofill_username)
        self.ed_first.textChanged.connect(self._maybe_autofill_username)

        self.ed_last.textChanged.connect(lambda _=None: self._inline_validate_all())
        self.ed_first.textChanged.connect(lambda _=None: self._inline_validate_all())
        self.ed_username.textChanged.connect(lambda _=None: self._inline_validate_all())
        self.ed_jmbg.textChanged.connect(lambda _=None: self._inline_validate_all())
        self.ed_email.textChanged.connect(lambda _=None: self._inline_validate_all())
        self.ed_new_pin.textChanged.connect(lambda _=None: self._inline_validate_all())
        self.ed_new_pw.textChanged.connect(lambda _=None: self._inline_validate_all())

# (FILENAME: ui/user_detail_dialog.py - END / PART 1 of 3)

# FILENAME: ui/user_detail_dialog.py
# (FILENAME: ui/user_detail_dialog.py - START / PART 2 of 3)

    # ---------------- permissions / UX ----------------
    def _apply_profile_permissions(self) -> None:
        """
        UX + Security hardening:
        - Ako nema users.manage: dialog je read-only (nema "lažnog" editovanja).
        - Ako nema ni users.view ni users.manage: fail-closed (zatvori).
        """
        try:
            if (not self._can_manage) and (not self._can_view):
                _warn(self, "Nemaš pravo da vidiš korisnike (users.view).")
                self.reject()
                return
        except Exception:
            pass

        # Save dugme: enabled samo za manage
        try:
            b = self.btns.button(QDialogButtonBox.Save)
            if b is not None:
                b.setEnabled(bool(self._can_manage))
                if not self._can_manage:
                    b.setToolTip("Nemaš pravo (users.manage).")
        except Exception:
            pass

        # Read-only mod (view only)
        if not self._can_manage:
            # Profil polja
            for w in (
                self.ed_last,
                self.ed_father,
                self.ed_first,
                self.ed_username,
                self.ed_jmbg,
                self.ed_email,
                self.ed_phone,
                self.ed_empno,
            ):
                try:
                    w.setReadOnly(True)
                except Exception:
                    pass

            try:
                self.ed_note.setReadOnly(True)
            except Exception:
                pass

            try:
                self.chk_active.setEnabled(False)
            except Exception:
                pass

            # Combo polja
            try:
                self.cb_sector.setEnabled(False)
                self.cb_sector.setEditable(False)
            except Exception:
                pass
            try:
                self.cb_location.setEnabled(False)
                self.cb_location.setEditable(False)
            except Exception:
                pass
            try:
                self.cb_title.setEnabled(False)
            except Exception:
                pass

            # Roles
            try:
                self.lst_roles.setEnabled(False)
                self.cb_primary_role.setEnabled(False)
            except Exception:
                pass

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        # mali UX: fokus na prvo logično polje
        try:
            if self.is_new:
                self.ed_last.setFocus(Qt.TabFocusReason)
                self.ed_last.selectAll()
            else:
                self.tabs.setCurrentWidget(self.tab_profile)
        except Exception:
            pass

    # ---------------- load / fill ----------------
    def _load_initial(self) -> None:
        u = dict(self._user or {})

        if self.is_new:
            self.setWindowTitle("Novi korisnik")
            self.lb_title.setText("Novi korisnik")
        else:
            uname = str(u.get("username") or self.username_arg or "").strip()
            self.setWindowTitle(f"Korisnik: {uname or '—'}")
            self.lb_title.setText(f"Korisnik: {uname or '—'}")

        # name parts
        self.ed_last.setText(str(u.get("last_name") or "").strip())
        self.ed_father.setText(str(u.get("father_name") or "").strip())
        self.ed_first.setText(str(u.get("first_name") or "").strip())

        # username
        uname = str(u.get("username") or self.username_arg or "").strip()
        self.ed_username.setText(uname)

        # username behavior: new -> editable + auto; edit -> read-only (bezbednije)
        if self.is_new:
            self.ed_username.setReadOnly(False)
            self._username_touched = False
            self._maybe_autofill_username()
        else:
            self.ed_username.setReadOnly(True)

        # sector / location
        sector_now = str(u.get("sector") or u.get("org_unit") or "").strip()
        location_now = str(u.get("location") or "").strip()

        # ✅ SECTOR_ADMIN: sektor uvek dolazi iz sesije (UI hardening)
        if self._is_sector_admin and self._my_sector:
            sector_now = self._my_sector

        sec_opts = _safe_list(list_sectors, [sector_now] if sector_now else [], 80)
        self.cb_sector.clear()
        for x in sec_opts:
            self.cb_sector.addItem(x)
        if sector_now:
            self.cb_sector.setCurrentText(sector_now)

        loc_opts = _safe_list(list_locations, [location_now] if location_now else [], 120)
        self.cb_location.clear()
        for x in loc_opts:
            self.cb_location.addItem(x)
        if location_now:
            self.cb_location.setCurrentText(location_now)

        # ✅ zaključaj sektor polje za SECTOR_ADMIN (nema izbora/unos)
        if self._is_sector_admin:
            if self._my_sector:
                self.cb_sector.setCurrentText(self._my_sector)
            self.cb_sector.setEnabled(False)
            self.cb_sector.setEditable(False)
            try:
                le = self.cb_sector.lineEdit()
                if le is not None:
                    le.setReadOnly(True)
            except Exception:
                pass

        # title
        title_now = str(u.get("title") or "").strip()
        _populate_titles(self.cb_title, current_text=title_now)

        # jmbg/contact/note
        self.ed_jmbg.setText(str(u.get("jmbg") or "").strip())
        self.ed_email.setText(str(u.get("email") or "").strip())
        self.ed_phone.setText(str(u.get("phone") or "").strip())
        self.ed_empno.setText(str(u.get("employee_no") or "").strip())
        self.ed_note.setPlainText(str(u.get("note") or "").strip())

        # created/updated
        self.ed_created_at.setText(_fmt_dt_sr(u.get("created_at")))
        self.ed_updated_at.setText(_fmt_dt_sr(u.get("updated_at")))

        # active (FIX: 0 ne sme da postane 1 zbog "or 1")
        raw_active = u.get("is_active")
        if raw_active is None:
            is_active = True
        else:
            if isinstance(raw_active, bool):
                is_active = bool(raw_active)
            else:
                try:
                    is_active = int(str(raw_active).strip()) == 1
                except Exception:
                    is_active = str(raw_active).strip().lower() in ("true", "yes", "da", "y")
        self.chk_active.setChecked(bool(is_active))

        # roles
        roles = _roles_norm_list(u.get("roles") or [])
        primary = str(u.get("primary_role") or u.get("role") or "").strip().upper()
        if not primary and roles:
            primary = roles[0]
        if not roles and primary:
            roles = [primary]
        self._fill_roles_ui(roles, primary)

        # self detection (za self-service u Bezbednost tabu)
        target_username = str(u.get("username") or self.username_arg or "").strip()
        me = _get_current_username_best_effort()
        self._is_self = (not self.is_new) and bool(target_username) and (_slugify_sr(me) == _slugify_sr(target_username))

        # posle load-a: inline validacija (bez crvenjenja required dok nema save attempt)
        self._inline_validate_all()

    def _fill_roles_ui(self, roles: List[str], primary: str) -> None:
        roles = _roles_norm_list(roles)
        primary = (primary or "").strip().upper()

        choices: List[str] = []
        try:
            rr = list_available_roles()
            if isinstance(rr, list) and rr:
                choices = [str(x).strip().upper() for x in rr if str(x).strip()]
        except Exception:
            choices = ["ADMIN", "SECTOR_ADMIN", "REFERENT_IT", "REFERENT_METRO", "BASIC_USER", "READONLY"]
        if not choices:
            choices = ["READONLY"]

        self.lst_roles.blockSignals(True)
        self.lst_roles.clear()

        for r in choices:
            it = QListWidgetItem(r)
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Checked if r in roles else Qt.Unchecked)
            self.lst_roles.addItem(it)

        self.lst_roles.blockSignals(False)
        self._rebuild_primary_combo(prefer=primary)

    def _checked_roles(self) -> List[str]:
        out: List[str] = []
        for i in range(self.lst_roles.count()):
            it = self.lst_roles.item(i)
            if it.checkState() == Qt.Checked:
                out.append(str(it.text() or "").strip().upper())
        return _roles_norm_list(out)

    def _rebuild_primary_combo(self, prefer: str = "") -> None:
        prefer = (prefer or "").strip().upper()
        checked = self._checked_roles()

        # UX: ako nema nijedna čekirana (user je odčekirao sve), nemoj nasilno vraćati
        # dok ne klikne Save; Save će ga zaustaviti + inline highlight.
        self.cb_primary_role.blockSignals(True)
        self.cb_primary_role.clear()
        for r in checked:
            self.cb_primary_role.addItem(r)

        if checked:
            if prefer and prefer in checked:
                j = self.cb_primary_role.findText(prefer)
                if j >= 0:
                    self.cb_primary_role.setCurrentIndex(j)
                else:
                    self.cb_primary_role.setCurrentIndex(0)
            else:
                self.cb_primary_role.setCurrentIndex(0)

        self.cb_primary_role.blockSignals(False)

        # inline validate roles kad se menjaju
        self._inline_validate_roles()

    # ---------------- behaviors ----------------
    def _on_roles_changed(self, _item: QListWidgetItem) -> None:
        cur = str(self.cb_primary_role.currentText() or "").strip().upper()
        self._rebuild_primary_combo(prefer=cur)

    def _on_title_changed(self, idx: int) -> None:
        if idx < 0:
            return
        if _combo_is_header(self.cb_title, idx):
            for j in range(idx + 1, self.cb_title.count()):
                if (not _combo_is_header(self.cb_title, j)) and self.cb_title.itemText(j).strip():
                    self.cb_title.setCurrentIndex(j)
                    return
            for j in range(idx - 1, -1, -1):
                if (not _combo_is_header(self.cb_title, j)) and self.cb_title.itemText(j).strip():
                    self.cb_title.setCurrentIndex(j)
                    return

    def _on_username_edited(self, _txt: str) -> None:
        if self.is_new:
            self._username_touched = True
        self._inline_validate_all()

    def _maybe_autofill_username(self) -> None:
        if not self.is_new:
            return
        if self._username_touched:
            return

        ln = _slugify_sr(self.ed_last.text())
        fn = _slugify_sr(self.ed_first.text())
        if not ln or not fn:
            return

        uname = (ln + fn)[:50]
        if uname and (self.ed_username.text() or "").strip() != uname:
            self.ed_username.setText(uname)

    def _refresh_active_badge(self) -> None:
        active = self.chk_active.isChecked()
        if active:
            self.lb_active_badge.setText("AKTIVAN")
            self.lb_active_badge.setStyleSheet(
                "padding: 6px 12px; border-radius: 12px; font-weight: 900;"
                "background-color: #1b5e20; color: #ffffff; border: 2px solid #66bb6a;"
            )
        else:
            self.lb_active_badge.setText("NEAKTIVAN")
            self.lb_active_badge.setStyleSheet(
                "padding: 6px 12px; border-radius: 12px; font-weight: 900;"
                "background-color: #424242; color: #ffffff; border: 2px solid #9e9e9e;"
            )

# (FILENAME: ui/user_detail_dialog.py - END / PART 2 of 3)


# FILENAME: ui/user_detail_dialog.py
# (FILENAME: ui/user_detail_dialog.py - START / PART 3 of 3)

    # ---------------- inline validation helpers (UX + stability) ----------------
    def _remember_style_once(self, w: QWidget) -> None:
        try:
            if w.property("_bzs2_orig_style") is None:
                w.setProperty("_bzs2_orig_style", w.styleSheet() or "")
        except Exception:
            pass

    def _set_invalid(self, w: QWidget, msg: str) -> None:
        self._remember_style_once(w)
        try:
            w.setToolTip(msg or "")
        except Exception:
            pass

        # Fail-soft styling: ne oslanjamo se na global QSS
        try:
            orig = str(w.property("_bzs2_orig_style") or "")
            w.setStyleSheet(orig + " ; border: 2px solid #ff5252; border-radius: 6px;")
        except Exception:
            pass

    def _clear_invalid(self, w: QWidget) -> None:
        try:
            w.setToolTip("")
        except Exception:
            pass
        try:
            orig = str(w.property("_bzs2_orig_style") or "")
            w.setStyleSheet(orig)
        except Exception:
            pass

    def _inline_validate_roles(self) -> bool:
        ok = True
        roles = self._checked_roles()
        if not roles:
            ok = False
            try:
                self._set_invalid(self.lst_roles, "Moraš čekirati bar jednu rolu.")
            except Exception:
                pass
        else:
            try:
                self._clear_invalid(self.lst_roles)
            except Exception:
                pass
        return ok

    def _inline_validate_profile(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        ok = True

        last_name = _norm_text(self.ed_last.text(), 80)
        first_name = _norm_text(self.ed_first.text(), 80)
        username = _norm_text(self.ed_username.text(), 50)
        jmbg = _norm_text(self.ed_jmbg.text(), 13)

        # Prezime
        if not last_name:
            ok = False
            errors.append("Prezime je obavezno.")
            self._set_invalid(self.ed_last, "Prezime je obavezno.")
        else:
            self._clear_invalid(self.ed_last)

        # Ime
        if not first_name:
            ok = False
            errors.append("Ime je obavezno.")
            self._set_invalid(self.ed_first, "Ime je obavezno.")
        else:
            self._clear_invalid(self.ed_first)

        # Username: required + (preporučeno) sanitizacija
        if not username:
            ok = False
            errors.append("Username je obavezan.")
            self._set_invalid(self.ed_username, "Username je obavezan.")
        else:
            # NEW: enforce safe set (alnum only) da izbegnemo edge-case-ove u logovanju
            if self.is_new:
                safe = _slugify_sr(username)
                if safe and safe != username:
                    # ne menjamo potajno bez signala: označi polje + tooltip
                    ok = False
                    errors.append("Username sadrži nedozvoljene karaktere (dozvoljeno: slova i brojevi).")
                    self._set_invalid(
                        self.ed_username,
                        "Nedozvoljeni karakteri. Predlog: koristi samo slova i brojeve "
                        f"(npr. '{safe}').",
                    )
                else:
                    self._clear_invalid(self.ed_username)
            else:
                self._clear_invalid(self.ed_username)

        # JMBG: nije obavezan uvek (može biti prazno), ali ako je unet mora biti validan
        msg = _validate_jmbg(jmbg)
        if msg:
            ok = False
            errors.append(msg)
            self._set_invalid(self.ed_jmbg, msg)
        else:
            self._clear_invalid(self.ed_jmbg)

        return ok, errors

    def _inline_validate_all(self) -> bool:
        ok1, _ = self._inline_validate_profile()
        ok2 = self._inline_validate_roles()
        return bool(ok1 and ok2)

    # ---------------- Security permissions / status ----------------
    def _apply_security_permissions(self) -> None:
        """
        Pravila:
        - New user: bezbednost disabled dok se ne sačuva.
        - Manage: admin može sve.
        - Self (bez manage): ako servis podržava set_my_* onda može za sebe.
        + Uvek pozovi _apply_profile_permissions() (read-only hardening).
        """
        # ✅ harden whole dialog first
        try:
            self._apply_profile_permissions()
        except Exception:
            pass

        if self.is_new:
            self.btn_set_pin.setEnabled(False)
            self.btn_clear_pin.setEnabled(False)
            self.btn_set_pw.setEnabled(False)
            self.btn_clear_pw.setEnabled(False)
            self.box_admin_reset.setVisible(False)
            self.lb_policy_status.setText("Sačuvaj prvo korisnika, pa onda podesi PIN/lozinku.")
            return

        # admin reset box vidljiv samo manage + ako funkcije postoje
        self.box_admin_reset.setVisible(bool(self._can_manage) and callable(admin_reset_credentials))

        # self-service dostupnost
        self_service_ok = bool(self._is_self) and callable(set_my_pin) and callable(set_my_password)

        can_pin_pw = bool(self._can_manage) or self_service_ok
        self.btn_set_pin.setEnabled(can_pin_pw)
        self.btn_clear_pin.setEnabled(can_pin_pw)
        self.btn_set_pw.setEnabled(can_pin_pw)
        self.btn_clear_pw.setEnabled(can_pin_pw)

        # “must change” dugme samo kad ima manage i servis podršku
        try:
            self.btn_clear_must_change.setEnabled(bool(self._can_manage) and callable(set_user_must_change_creds))
        except Exception:
            pass

        if (not self._can_manage) and (not self_service_ok):
            self.lb_policy_status.setText("Bezbednost: nemaš pravo da menjaš PIN/lozinku za ovog korisnika.")

    def _refresh_security_status(self) -> None:
        u = self._user or {}
        un = str(u.get("username") or self.username_arg or "").strip()

        # Best-effort (staro stanje)
        has_pin = bool(u.get("has_pin")) or bool(str(u.get("pin_hash") or "").strip())
        has_pw = bool(u.get("has_password")) or bool(str(u.get("pass_hash") or "").strip())

        must_change = 0
        try:
            must_change = 1 if int(u.get("must_change_creds") or 0) != 0 else 0
        except Exception:
            must_change = 0

        # Ako postoji novi helper u servisu, uzmi ga kao source-of-truth
        if callable(get_user_credential_flags) and un:
            try:
                flags = get_user_credential_flags(un)  # type: ignore[misc]
                if isinstance(flags, dict):
                    has_pin = bool(flags.get("has_pin"))
                    has_pw = bool(flags.get("has_password"))
                    try:
                        must_change = 1 if int(flags.get("must_change_creds", 0) or 0) != 0 else 0
                    except Exception:
                        must_change = 0
            except Exception:
                pass

        # Status tekst
        if has_pin and has_pw:
            txt = "Login metod: PIN + Lozinka"
        elif has_pin:
            txt = "Login metod: PIN"
        elif has_pw:
            txt = "Login metod: Lozinka"
        else:
            txt = "Login metod: — (nije postavljen ni PIN ni lozinka)"
        self.lb_login_status.setText(txt)

        if must_change:
            self.lb_policy_status.setText("POLICY: Mora promena kredencijala ✅")
            self.lb_policy_status.setStyleSheet("font-weight: 900; color: #ff5252;")
        else:
            self.lb_policy_status.setText("POLICY: Nema obavezne promene kredencijala")
            self.lb_policy_status.setStyleSheet("font-weight: 750; color: #69f0ae;")

        # Enable/disable “Skini mora promena”
        try:
            if self.btn_clear_must_change is not None:
                self.btn_clear_must_change.setEnabled(bool(self._can_manage) and callable(set_user_must_change_creds) and bool(must_change))
        except Exception:
            pass

    # ---------------- Security actions ----------------
    def _require_edit_user(self) -> Optional[str]:
        if self.is_new:
            _warn(self, "Sačuvaj prvo novog korisnika, pa onda menjaj bezbednost.")
            return None
        un = str(self._user.get("username") or self.username_arg or "").strip()
        if not un:
            _warn(self, "Neispravan korisnik (prazan username).")
            return None
        return un

    def _do_set_pin(self) -> None:
        un = self._require_edit_user()
        if not un:
            return

        pin = (self.ed_new_pin.text() or "").strip()
        if not re.fullmatch(r"\d{4,8}", pin or ""):
            _warn(self, "PIN mora imati 4–8 cifara.")
            return

        try:
            if self._can_manage:
                set_user_pin(un, pin)
            else:
                if not (self._is_self and callable(set_my_pin)):
                    _warn(self, "Nemaš pravo da menjaš PIN za ovog korisnika.")
                    return
                set_my_pin(pin)  # type: ignore[misc]

            self.ed_new_pin.setText("")
            self._user = get_user_by_username(un) or self._user
            self._refresh_security_status()
            _info(self, "PIN je postavljen.")
        except Exception as e:
            _warn(self, f"Ne mogu da postavim PIN:\n{e}")

    def _do_clear_pin(self) -> None:
        un = self._require_edit_user()
        if not un:
            return

        if not _ask_yes_no(self, "Obrisati PIN korisniku?"):
            return

        try:
            if self._can_manage:
                clear_user_pin(un)
            else:
                if not (self._is_self and callable(clear_my_pin)):
                    _warn(self, "Nemaš pravo da obrišeš PIN za ovog korisnika.")
                    return
                clear_my_pin()  # type: ignore[misc]

            self._user = get_user_by_username(un) or self._user
            self._refresh_security_status()
            _info(self, "PIN je obrisan.")
        except Exception as e:
            _warn(self, f"Ne mogu da obrišem PIN:\n{e}")

    def _do_set_pw(self) -> None:
        un = self._require_edit_user()
        if not un:
            return

        pw = (self.ed_new_pw.text() or "").strip()
        if len(pw) < 6:
            _warn(self, "Lozinka mora imati minimum 6 karaktera.")
            return

        try:
            if self._can_manage:
                set_user_password(un, pw)
            else:
                if not (self._is_self and callable(set_my_password)):
                    _warn(self, "Nemaš pravo da menjaš lozinku za ovog korisnika.")
                    return
                set_my_password(pw)  # type: ignore[misc]

            self.ed_new_pw.setText("")
            self._user = get_user_by_username(un) or self._user
            self._refresh_security_status()
            _info(self, "Lozinka je postavljena.")
        except Exception as e:
            _warn(self, f"Ne mogu da postavim lozinku:\n{e}")

    def _do_clear_pw(self) -> None:
        un = self._require_edit_user()
        if not un:
            return

        if not _ask_yes_no(self, "Obrisati lozinku korisniku?"):
            return

        try:
            if self._can_manage:
                clear_user_password(un)
            else:
                if not (self._is_self and callable(clear_my_password)):
                    _warn(self, "Nemaš pravo da obrišeš lozinku za ovog korisnika.")
                    return
                clear_my_password()  # type: ignore[misc]

            self._user = get_user_by_username(un) or self._user
            self._refresh_security_status()
            _info(self, "Lozinka je obrisana.")
        except Exception as e:
            _warn(self, f"Ne mogu da obrišem lozinku:\n{e}")

    def _do_admin_reset_creds(self) -> None:
        if not self._can_manage:
            _warn(self, "Nemaš pravo (users.manage).")
            return
        if not callable(admin_reset_credentials):
            _warn(self, "Servis nema admin_reset_credentials (nije ažuriran).")
            return

        un = self._require_edit_user()
        if not un:
            return

        if not _ask_yes_no(self, "Resetovaćeš kredencijale korisniku i postaviti 'mora promena'. Nastaviti?"):
            return

        try:
            creds = admin_reset_credentials(un)  # type: ignore[misc]
            lines: List[str] = ["Kredencijali su resetovani (privremeni):", ""]

            if isinstance(creds, dict):
                if creds.get("pin"):
                    lines.append(f"PIN: {creds.get('pin')}")
                if creds.get("password"):
                    lines.append(f"Lozinka: {creds.get('password')}")
            else:
                lines.append("(Servis nije vratio detalje kredencijala.)")

            lines.append("")
            lines.append("Napomena: korisnik mora odmah promeniti ove vrednosti pri prvom logovanju.")

            _info(self, "\n".join(lines), title="Admin reset")
            self._user = get_user_by_username(un) or self._user
            self._refresh_security_status()
        except Exception as e:
            _warn(self, f"Ne mogu da resetujem:\n{e}")

    def _do_clear_must_change(self) -> None:
        if not self._can_manage:
            _warn(self, "Nemaš pravo (users.manage).")
            return
        if not callable(set_user_must_change_creds):
            _warn(self, "Servis nema set_user_must_change_creds (nije ažuriran).")
            return

        un = self._require_edit_user()
        if not un:
            return

        try:
            set_user_must_change_creds(un, False)  # type: ignore[misc]
            self._user = get_user_by_username(un) or self._user
            self._refresh_security_status()
            _info(self, "Skidanje 'mora promena' je uspešno.")
        except Exception as e:
            _warn(self, f"Ne mogu da promenim policy flag:\n{e}")

    # ---------------- Save ----------------
    def _on_save(self) -> None:
        if not self._can_manage:
            _warn(self, "Nemaš pravo (users.manage).")
            return

        # ✅ SECTOR_ADMIN: mora imati sektor iz sesije, nema ručnog unosa
        if self._is_sector_admin:
            if not self._my_sector:
                _warn(
                    self,
                    "Tvoja sesija nema definisan sektor.\n"
                    "Sektorski admin ne može da kreira/menja korisnike bez fiksiranog sektora.\n"
                    "Rešenje: proveri role-switch / login da sektor bude postavljen.",
                )
                return

        # ✅ inline + popup (oboje): prvo označi polja, pa onda daj jasnu poruku
        ok_profile, errors = self._inline_validate_profile()
        ok_roles = self._inline_validate_roles()
        if not (ok_profile and ok_roles):
            # Pop-up ostaje (tvoj zahtev), ali već ima i inline highlight
            _warn(self, "\n".join(errors or ["Proveri označena polja."]))
            # UX: fokus na profil ili role tab
            if not ok_profile:
                self.tabs.setCurrentWidget(self.tab_profile)
            elif not ok_roles:
                self.tabs.setCurrentWidget(self.tab_roles)
            return

        last_name = _norm_text(self.ed_last.text(), 80)
        father_name = _norm_text(self.ed_father.text(), 80)
        first_name = _norm_text(self.ed_first.text(), 80)

        username = _norm_text(self.ed_username.text(), 50)
        if not username:
            # fallback (realno ne bi trebalo zbog validacije)
            username = (_slugify_sr(last_name) + _slugify_sr(first_name))[:50]
            self.ed_username.setText(username)

        # NEW user: enforce safe username (slova+brojevi)
        if self.is_new:
            safe = _slugify_sr(username)
            if safe and safe != username:
                if _ask_yes_no(self, f"Username ima nedozvoljene karaktere.\nPredlog: '{safe}'.\nPrimeni predlog?"):
                    username = safe
                    self.ed_username.setText(username)
                else:
                    _warn(self, "Molim ispravi username (samo slova i brojevi).")
                    self._set_invalid(self.ed_username, "Samo slova i brojevi.")
                    self.tabs.setCurrentWidget(self.tab_profile)
                    return

        jmbg = _norm_text(self.ed_jmbg.text(), 13)
        msg = _validate_jmbg(jmbg)
        if msg:
            self._set_invalid(self.ed_jmbg, msg)
            _warn(self, msg)
            self.tabs.setCurrentWidget(self.tab_profile)
            return

        # sector/location
        sector_ui = _norm_text(self.cb_sector.currentText(), 80)
        location = _norm_text(self.cb_location.currentText(), 120)

        # ✅ SECTOR_ADMIN: ignorisi UI sektor, koristi isključivo session sektor
        sector = self._my_sector if self._is_sector_admin else sector_ui

        ti = self.cb_title.currentIndex()
        if ti >= 0 and _combo_is_header(self.cb_title, ti):
            for i in range(self.cb_title.count()):
                if (not _combo_is_header(self.cb_title, i)) and self.cb_title.itemText(i).strip():
                    self.cb_title.setCurrentIndex(i)
                    break
        title = _norm_text(self.cb_title.currentText(), 120)

        email = _norm_text(self.ed_email.text(), 160)
        phone = _norm_text(self.ed_phone.text(), 80)
        empno = _norm_text(self.ed_empno.text(), 80)
        note = _norm_text(self.ed_note.toPlainText(), 500)

        roles = self._checked_roles()
        if not roles:
            self._set_invalid(self.lst_roles, "Moraš čekirati bar jednu rolu.")
            _warn(self, "Moraš čekirati bar jednu rolu.")
            self.tabs.setCurrentWidget(self.tab_roles)
            return

        primary = _norm_text(self.cb_primary_role.currentText(), 40).upper()
        if not primary:
            primary = roles[0]
        if primary not in roles:
            roles.insert(0, primary)

        is_active = bool(self.chk_active.isChecked())
        display_name = f"{last_name} {first_name}".strip()

        # NEW user: check username uniqueness (fail-fast)
        if self.is_new:
            try:
                existing = get_user_by_username(username)
                if existing:
                    self._set_invalid(self.ed_username, "Username već postoji.")
                    _warn(self, "Username već postoji. Izaberi drugi.")
                    self.tabs.setCurrentWidget(self.tab_profile)
                    return
            except Exception:
                # ako servis ne može da proveri, nastavi (create_user će failovati pa hvatamo)
                pass

        try:
            if self.is_new:
                uid = _call_with_supported_kwargs(
                    create_user,
                    username=username,
                    display_name=display_name,
                    role=primary,
                    pin=None,
                    password=None,
                    sector=sector,
                    location=location,
                    email=email,
                    phone=phone,
                    employee_no=empno,
                    title=title,
                    note=note,
                    last_name=last_name,
                    father_name=father_name,
                    first_name=first_name,
                    jmbg=jmbg,
                )

                # role set (multi-role)
                try:
                    set_user_roles(username, roles, replace=True, primary_role=primary)
                except Exception as e_roles:
                    _warn(
                        self,
                        "Korisnik je kreiran, ali dodela rola nije uspela.\n"
                        f"Detalji:\n{e_roles}",
                        title="Upozorenje",
                    )

                _info(self, f"Korisnik kreiran (ID={uid}).")
                self.accept()
                return

            ok = _call_with_supported_kwargs(
                update_user_profile,
                username=username,
                display_name=display_name,
                role=primary,
                is_active=is_active,
                sector=sector,
                location=location,
                email=email,
                phone=phone,
                employee_no=empno,
                title=title,
                note=note,
                last_name=last_name,
                father_name=father_name,
                first_name=first_name,
                jmbg=jmbg,
            )
            if not ok:
                _warn(self, "Izmena nije uspela.")
                return

            try:
                set_user_roles(username, roles, replace=True, primary_role=primary)
            except Exception as e_roles2:
                _warn(
                    self,
                    "Profil je sačuvan, ali dodela rola nije uspela.\n"
                    f"Detalji:\n{e_roles2}",
                    title="Upozorenje",
                )

            try:
                self._user = get_user_by_username(username) or self._user
            except Exception:
                pass

            self._refresh_security_status()
            self._refresh_active_badge()
            self._apply_security_permissions()

            _info(self, "Sačuvano.")
            self.accept()

        except Exception as e:
            # username duplicate ili drugi DB error
            _warn(self, f"Ne mogu da sačuvam:\n{e}")

# (FILENAME: ui/user_detail_dialog.py - END / PART 3 of 3)
# END FILENAME: ui/user_detail_dialog.py