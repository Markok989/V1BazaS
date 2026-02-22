# FILENAME: app.py
# (FILENAME: app.py - REGEN - START)  [PART 1/2]
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — app.py

KRITIČNO:
- Ne importuj PySide6 / ui.* pre dependency provere.
- Ako PySide6 fali, UI ne može da se podigne.

Dodato / unapređeno:
- Preflight check: kritične + preporučene biblioteke
- Prompt: radi i bez TTY (Tkinter fallback ako postoji)
- Self-check report parsing: ispiše tačno šta fali i nudi OFFLINE install iz WHEELS_DIR
- Kompatibilnost: self_check_and_fix može imati različit potpis u tvojoj bazi koda

UI/UX poboljšanja:
- MainWindow: QSplitter (nav <-> content) + pamćenje splitter stanja
- Dialog policy: Windows-like resize (W+H) + Min/Max dugmad (bez scroll-wrap, bez belila)

REGEN (ovaj patch):
- ✅ "Metrologija Dashboard" je vidljiv SVIMA koji imaju metrology.view,
  u okviru svojih prava (scope se rešava u dashboard modulu).
  ADMIN vidi ALL, sector/admin i referenti SECTOR (ako dostupno), ostali MY (fail-closed).
"""

from __future__ import annotations

import sys
import os
import json
import traceback
import logging
import threading
import subprocess
import importlib.util
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple, Any, Iterable, Set

# ===================== PATH BOOTSTRAP (fix "No module named core") =====================
_PROJECT_ROOT = Path(__file__).resolve().parent
try:
    pr = str(_PROJECT_ROOT)
    if pr and pr not in sys.path:
        sys.path.insert(0, pr)
except Exception:
    pass

# ===================== SAFE IMPORTS (NO PySide6 / NO ui.* HERE) =====================
from core.config import APP_NAME, APP_VERSION, DB_FILE, WHEELS_DIR, LOGS_DIR, ensure_folders  # type: ignore
from core.logger import setup_logging  # type: ignore
from core.selfcheck import self_check_and_fix  # type: ignore
from core.db import init_db  # type: ignore
from core.backup import apply_pending_full_restore  # type: ignore
from core.session import set_current_user, actor_name, can  # type: ignore

from core.rbac import (  # type: ignore
    PERM_ASSETS_CREATE,
    PERM_ASSIGN_CREATE,
    PERM_AUDIT_VIEW,
    PERM_USERS_VIEW,
    PERM_SETTINGS_VIEW,
    PERM_METRO_VIEW,   # ✅ NEW: da možemo da prikažemo Metrologija Dashboard svima sa metrology.view
)

from services.users_service import ensure_users_schema  # type: ignore

# ===================== GLOBAL CRASH/LOGGING HOOKS =====================
_HOOKS_INSTALLED = False
_ORIG_SYS_EXCEPTHOOK = sys.excepthook
_FAULT_FILE_HANDLE = None
_QT_MSG_HANDLER_INSTALLED = False


def _safe_mkdir(p: str) -> None:
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        pass


def _write_crash_report(logger: logging.Logger, title: str, exc_info=None) -> None:
    """Best-effort crash report. Nikad ne sme da sruši app."""
    try:
        _safe_mkdir(str(LOGS_DIR))
        fp = Path(LOGS_DIR) / "crash_last.txt"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pid = os.getpid()
        th = threading.current_thread().name

        lines = [
            f"[{now}] {title}",
            f"APP={APP_NAME} v={APP_VERSION}",
            f"PID={pid} THREAD={th}",
            f"DB_FILE={DB_FILE}",
            "",
        ]
        if exc_info:
            lines.append("EXCEPTION:")
            lines.append("".join(traceback.format_exception(*exc_info)))
        else:
            lines.append("EXCEPTION: (n/a)")

        fp.write_text("\n".join(lines), encoding="utf-8", errors="ignore")
    except Exception:
        try:
            logger.error("Crash report write failed.", exc_info=True)
        except Exception:
            pass


def _install_exception_hooks(logger: logging.Logger) -> None:
    """sys/thread hooks + faulthandler; Qt handler ide tek kad PySide6 postoji."""
    global _HOOKS_INSTALLED, _FAULT_FILE_HANDLE
    if _HOOKS_INSTALLED:
        return
    _HOOKS_INSTALLED = True

    def _sys_hook(exc_type, exc, tb):
        try:
            logger.critical("UNHANDLED EXCEPTION (sys.excepthook)", exc_info=(exc_type, exc, tb))
        except Exception:
            pass
        try:
            _write_crash_report(logger, "UNHANDLED EXCEPTION (sys.excepthook)", exc_info=(exc_type, exc, tb))
        except Exception:
            pass
        try:
            _ORIG_SYS_EXCEPTHOOK(exc_type, exc, tb)
        except Exception:
            pass

    sys.excepthook = _sys_hook

    if hasattr(threading, "excepthook"):
        _orig_thread_hook = threading.excepthook

        def _thread_hook(args):
            try:
                logger.critical(
                    f"UNHANDLED THREAD EXCEPTION thread={getattr(args.thread, 'name', '?')}",
                    exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
                )
            except Exception:
                pass
            try:
                _write_crash_report(
                    logger,
                    f"UNHANDLED THREAD EXCEPTION thread={getattr(args.thread, 'name', '?')}",
                    exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
                )
            except Exception:
                pass
            try:
                _orig_thread_hook(args)
            except Exception:
                pass

        threading.excepthook = _thread_hook

    try:
        import faulthandler  # stdlib
        _safe_mkdir(str(LOGS_DIR))
        fh_path = Path(LOGS_DIR) / "faulthandler.log"
        _FAULT_FILE_HANDLE = open(fh_path, "a", encoding="utf-8", buffering=1)
        faulthandler.enable(file=_FAULT_FILE_HANDLE, all_threads=True)
        try:
            logger.info(f"Faulthandler enabled: {fh_path}")
        except Exception:
            pass
    except Exception:
        pass


# ===================== DEPENDENCY / INSTALL HELPERS =====================
def _module_exists(module_name: str) -> bool:
    """True ako import spec postoji (bez importovanja)."""
    try:
        return importlib.util.find_spec(module_name) is not None
    except Exception:
        return False


def _pip_available() -> bool:
    try:
        return importlib.util.find_spec("pip") is not None
    except Exception:
        return False


def _prompt_yes_no(prompt: str, default_no: bool = True) -> bool:
    # 1) TTY
    try:
        if sys.stdin and sys.stdin.isatty():
            suffix = " [y/N]: " if default_no else " [Y/n]: "
            try:
                ans = input(prompt + suffix).strip().lower()
            except Exception:
                return False
            if not ans:
                return (not default_no)
            return ans in ("y", "yes", "da", "d")
    except Exception:
        pass

    # 2) Tkinter fallback
    try:
        import tkinter as tk  # type: ignore
        from tkinter import messagebox  # type: ignore

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        try:
            res = messagebox.askyesno(APP_NAME, prompt, parent=root)
        except Exception:
            res = False
        try:
            root.destroy()
        except Exception:
            pass
        return bool(res)
    except Exception:
        return False


def _pip_install_offline_from_wheels(
    logger: logging.Logger,
    requirements: List[str],
    wheels_dir: Path,
) -> Tuple[bool, str]:
    reqs = [r.strip() for r in (requirements or []) if str(r).strip()]
    if not reqs:
        return True, "No requirements to install."

    if not _pip_available():
        return False, "pip nije dostupan u ovom Python okruženju (ne mogu da pokrenem install)."

    wheels_dir = Path(wheels_dir)
    if not wheels_dir.exists():
        return False, f"WHEELS_DIR ne postoji: {wheels_dir}"

    cmd = [
        sys.executable, "-m", "pip", "install",
        "--no-index",
        "--find-links", str(wheels_dir),
        "--disable-pip-version-check",
        "--no-input",
        *reqs,
    ]
    try:
        _safe_mkdir(str(LOGS_DIR))
        log_fp = Path(LOGS_DIR) / "pip_install_last.txt"
        with open(log_fp, "w", encoding="utf-8", errors="ignore") as f:
            f.write("CMD: " + " ".join(cmd) + "\n\n")
            proc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, cwd=str(_PROJECT_ROOT))
        ok = (proc.returncode == 0)
        msg = f"pip install {'OK' if ok else 'FAILED'} (exit={proc.returncode}). Log: {log_fp}"
        try:
            (logger.info if ok else logger.error)(msg)
        except Exception:
            pass
        return ok, msg
    except Exception as e:
        return False, f"pip install error: {e}"


@dataclass(frozen=True)
class DepSpec:
    module: str
    requirement: str
    critical: bool = True
    note: str = ""


def _dependency_plan() -> List[DepSpec]:
    return [
        DepSpec(module="PySide6", requirement="PySide6", critical=True, note="UI framework"),
        DepSpec(module="openpyxl", requirement="openpyxl", critical=False, note="Excel import/export"),
        DepSpec(module="docx", requirement="python-docx", critical=False, note="Word (.docx) templates"),
        DepSpec(module="reportlab", requirement="reportlab", critical=False, note="PDF export"),
    ]


def _missing_from_plan(plan: Iterable[DepSpec]) -> Tuple[List[DepSpec], List[DepSpec]]:
    missing_critical: List[DepSpec] = []
    missing_optional: List[DepSpec] = []
    for d in (plan or []):
        try:
            if not _module_exists(d.module):
                (missing_critical if d.critical else missing_optional).append(d)
        except Exception:
            continue
    return missing_critical, missing_optional


def _format_missing_deps(missing: List[DepSpec], title: str) -> str:
    if not missing:
        return ""
    lines = [title]
    for d in missing:
        note = f" — {d.note}" if d.note else ""
        lines.append(f" - {d.requirement} (import: {d.module}){note}")
    return "\n".join(lines)


def _preflight_dependencies(logger: logging.Logger) -> bool:
    plan = _dependency_plan()
    missing_critical, missing_optional = _missing_from_plan(plan)

    if not missing_critical and not missing_optional:
        return True

    msg_parts: List[str] = []
    if missing_critical:
        msg_parts.append(_format_missing_deps(missing_critical, "Nedostaju KRITIČNE biblioteke:"))
    if missing_optional:
        msg_parts.append(_format_missing_deps(missing_optional, "Nedostaju PREPORUČENE biblioteke (app može da radi, ali neke opcije neće):"))

    msg_parts.append("")
    msg_parts.append(f"Offline instalacija se radi iz: {WHEELS_DIR}")
    msg_parts.append("U taj folder ubaci odgovarajuće .whl pakete (i njihove dependencies).")
    msg = "\n".join([p for p in msg_parts if p])

    try:
        logger.error(msg)
    except Exception:
        pass

    if missing_critical:
        reqs = [d.requirement for d in missing_critical]
        if _prompt_yes_no("Nedostaju kritične biblioteke. Da li želiš da pokušam OFFLINE instalaciju sada?", default_no=True):
            ok, out = _pip_install_offline_from_wheels(logger, reqs, Path(WHEELS_DIR))
            if not ok:
                print(msg)
                print(out)
                return False
            still = [d for d in missing_critical if not _module_exists(d.module)]
            if still:
                print(msg)
                print("I dalje nedostaje:", ", ".join([d.requirement for d in still]))
                return False
        else:
            print(msg)
            print("Instalacija nije pokrenuta (nema potvrde).")
            return False

    if missing_optional:
        reqs2 = [d.requirement for d in missing_optional]
        if _prompt_yes_no("Želiš li da instaliram i preporučene biblioteke (OFFLINE) iz WHEELS_DIR?", default_no=True):
            _pip_install_offline_from_wheels(logger, reqs2, Path(WHEELS_DIR))

    return True


def show_fatal_message(title: str, message: str) -> None:
    if _module_exists("PySide6"):
        try:
            from PySide6.QtWidgets import QApplication as _QApp, QMessageBox as _QMsg  # type: ignore
            _app = _QApp.instance() or _QApp(sys.argv)
            _QMsg.critical(None, title, message)
            return
        except Exception:
            pass
    print(f"[FATAL] {title}\n{message}", file=sys.stderr)


def _extract_missing_from_selfcheck_report(logger: logging.Logger) -> List[str]:
    fp = Path(LOGS_DIR) / "selfcheck_report.json"
    if not fp.exists():
        return []

    try:
        raw = fp.read_text(encoding="utf-8", errors="ignore").strip()
        if not raw:
            return []
        data = json.loads(raw)
    except Exception:
        try:
            logger.warning("Ne mogu da parsiram selfcheck_report.json (nije validan JSON).")
        except Exception:
            pass
        return []

    KEYS = {
        "missing", "missing_packages", "missing_package", "missing_modules", "missing_module",
        "pip_missing", "pip_missing_packages", "requirements_missing", "deps_missing",
        "not_installed", "not_found",
    }

    found: Set[str] = set()

    def _add_val(v: Any) -> None:
        if v is None:
            return
        if isinstance(v, str):
            s = v.strip()
            if s:
                found.add(s)
            return
        if isinstance(v, (list, tuple, set)):
            for x in v:
                _add_val(x)
            return
        if isinstance(v, dict):
            for kk in ("pkg", "package", "name", "requirement", "module"):
                try:
                    sv = v.get(kk)
                    if isinstance(sv, str) and sv.strip():
                        found.add(sv.strip())
                except Exception:
                    pass

    def _walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = str(k).strip().lower()
                if kl in KEYS:
                    _add_val(v)
                _walk(v)
        elif isinstance(obj, list):
            for x in obj:
                _walk(x)

    _walk(data)

    out = sorted({s for s in found if s and len(s) <= 120})
    cleaned: List[str] = []
    seen = set()
    for s in out:
        ss = s.strip()
        if not ss:
            continue
        key = ss.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(ss)
    return cleaned


def _install_qt_message_handler(logger: logging.Logger) -> None:
    global _QT_MSG_HANDLER_INSTALLED
    if _QT_MSG_HANDLER_INSTALLED:
        return
    if not _module_exists("PySide6"):
        return
    try:
        from PySide6.QtCore import QtMsgType, qInstallMessageHandler  # type: ignore

        def _qt_msg_handler(mode, context, message):
            try:
                if mode == QtMsgType.QtDebugMsg:
                    lvl, tag = logging.DEBUG, "QT_DEBUG"
                elif mode == QtMsgType.QtInfoMsg:
                    lvl, tag = logging.INFO, "QT_INFO"
                elif mode == QtMsgType.QtWarningMsg:
                    lvl, tag = logging.WARNING, "QT_WARN"
                elif mode == QtMsgType.QtCriticalMsg:
                    lvl, tag = logging.ERROR, "QT_CRIT"
                elif mode == QtMsgType.QtFatalMsg:
                    lvl, tag = logging.CRITICAL, "QT_FATAL"
                else:
                    lvl, tag = logging.INFO, "QT"

                loc = ""
                try:
                    f = getattr(context, "file", "") or ""
                    line = getattr(context, "line", 0) or 0
                    fn = getattr(context, "function", "") or ""
                    if f or fn:
                        loc = f" ({f}:{line} {fn})"
                except Exception:
                    loc = ""

                logger.log(lvl, f"{tag}: {message}{loc}")
            except Exception:
                pass

        qInstallMessageHandler(_qt_msg_handler)
        _QT_MSG_HANDLER_INSTALLED = True
    except Exception:
        pass


def _run_selfcheck(logger: logging.Logger, auto_fix: bool) -> bool:
    try:
        return bool(self_check_and_fix(logger, auto_fix=bool(auto_fix)))  # type: ignore
    except TypeError:
        pass
    try:
        return bool(self_check_and_fix(logger, fix=bool(auto_fix)))  # type: ignore
    except TypeError:
        pass
    try:
        return bool(self_check_and_fix(logger))  # type: ignore
    except Exception:
        try:
            logger.exception("self_check_and_fix failed")
        except Exception:
            pass
        return False


_LAST_LOGIN_USER: Optional[object] = None


def _remember_login_user(u: Optional[object]) -> None:
    global _LAST_LOGIN_USER
    _LAST_LOGIN_USER = u


def _uget(u: object, key: str, default=None):
    if u is None:
        return default
    try:
        if isinstance(u, dict):
            return u.get(key, default)
        return getattr(u, key, default)
    except Exception:
        return default


def _extract_role_from_user(u: Optional[object]) -> Optional[str]:
    if u is None:
        return None

    for k in ("is_admin", "admin", "is_superuser", "superuser"):
        v = _uget(u, k, None)
        try:
            if bool(v):
                return "ADMIN"
        except Exception:
            pass

    for k in ("is_basic", "basic", "is_basic_user"):
        v = _uget(u, k, None)
        try:
            if bool(v):
                return "BASIC_USER"
        except Exception:
            pass

    for k in ("active_role", "role", "rbac_role", "user_role", "profile", "user_type", "type", "ui_mode", "mode"):
        v = _uget(u, k, None)
        if not v:
            continue
        try:
            if isinstance(v, dict):
                for kk in ("name", "code", "role", "profile", "id"):
                    vv = v.get(kk)
                    if vv:
                        return str(vv)
                continue
            return str(v)
        except Exception:
            continue

    return None


def _extract_username_like(u: Optional[object]) -> Optional[str]:
    if u is None:
        return None
    keys = ("username", "login", "user", "email", "account", "name", "full_name", "display_name")
    for k in keys:
        v = _uget(u, k, None)
        if v:
            try:
                return str(v)
            except Exception:
                pass
    return None


def _actor_name() -> str:
    return actor_name()


def _current_role_safe() -> str:
    try:
        from core.session import current_role  # type: ignore
        return str(current_role() or "").strip()
    except Exception:
        return ""


def _list_roles_safe() -> List[str]:
    try:
        from core.session import list_user_roles  # type: ignore
        rr = list_user_roles()
        out: List[str] = []
        seen = set()
        for x in rr:
            s = str(x or "").strip().upper()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        return out
    except Exception:
        return []


def _set_active_role_safe(new_role: str, source: str = "ui_mainwindow_role_switch") -> bool:
    try:
        from core.session import set_active_role  # type: ignore
        set_active_role(str(new_role or "").strip(), source=source, audit=True)
        return True
    except Exception:
        return False


def _sync_last_login_user_from_session() -> None:
    global _LAST_LOGIN_USER
    try:
        from core.session import get_current_user  # type: ignore
        su = get_current_user() or {}
        if not su:
            return
        _LAST_LOGIN_USER = dict(su)
    except Exception:
        pass


def _apply_global_theme(app, logger: logging.Logger) -> None:
    try:
        from ui.theme.theme_manager import apply_saved_theme as apply_theme_from_settings  # type: ignore
        apply_theme_from_settings(app)
        try:
            logger.info("Theme applied (saved theme).")
        except Exception:
            pass
    except Exception as e:
        try:
            logger.warning(f"Theme apply skipped: {e}")
        except Exception:
            pass

# (FILENAME: app.py - REGEN - END)  [PART 1/2]

# FILENAME: app.py
# (FILENAME: app.py - REGEN - START)  [PART 2/2]

def start_ui(logger: logging.Logger) -> None:
    from PySide6.QtWidgets import (  # type: ignore
        QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel,
        QListWidget, QStackedWidget, QPushButton, QDialog, QMessageBox, QComboBox,
        QSizePolicy, QLayout, QSplitter
    )
    from PySide6.QtCore import Qt, QObject, QEvent, QTimer, QSettings, QByteArray  # type: ignore

    def _install_dialog_responsiveness_policy(app: QApplication, logger: logging.Logger) -> None:
        """
        Cilj: SVI naknadni prozori (QDialog) da se ponašaju kao normalan Windows prozor:
        - Resize po širini i visini (W + H)
        - Maximize i Minimize dugmad (cel ekran / normal)
        - Bez "belila": ne ubacujemo scroll-wrap i ne pravimo layout transplant

        Preskačemo:
        - LoginDialog (osetljiv)
        - QMessageBox (sistemske poruke)
        """
        try:
            settings = QSettings("BazaS2", APP_NAME)

            class _DialogPolicy(QObject):
                def __init__(self, parent=None):
                    super().__init__(parent)

                def _cls_name(self, dlg: QDialog) -> str:
                    try:
                        return dlg.metaObject().className()
                    except Exception:
                        return dlg.__class__.__name__

                def _should_skip(self, dlg: QDialog) -> bool:
                    try:
                        if bool(dlg.property("_bz_no_policy")):
                            return True
                    except Exception:
                        pass

                    try:
                        if isinstance(dlg, QMessageBox):
                            return True
                    except Exception:
                        pass

                    cn = (self._cls_name(dlg) or "").lower()
                    if "logindialog" in cn or cn == "login":
                        return True
                    return False

                def _dlg_key(self, dlg: QDialog) -> str:
                    cls = self._cls_name(dlg) or dlg.__class__.__name__
                    obj = ""
                    try:
                        obj = str(dlg.objectName() or "").strip()
                    except Exception:
                        obj = ""
                    return f"ui/dialogs/{cls}{('/' + obj) if obj else ''}"

                def _apply_windows_like_flags(self, dlg: QDialog) -> None:
                    try:
                        flags = dlg.windowFlags()
                        try:
                            flags &= ~Qt.MSWindowsFixedSizeDialogHint
                        except Exception:
                            pass

                        flags |= Qt.WindowSystemMenuHint
                        flags |= Qt.WindowMinMaxButtonsHint
                        flags |= Qt.WindowCloseButtonHint

                        dlg.setWindowFlags(flags)
                    except Exception:
                        pass

                def _unlock_size(self, dlg: QDialog) -> None:
                    try:
                        dlg.setSizeGripEnabled(True)
                    except Exception:
                        pass

                    try:
                        lay = dlg.layout()
                        if lay is not None:
                            try:
                                lay.setSizeConstraint(QLayout.SetNoConstraint)
                            except Exception:
                                pass
                    except Exception:
                        pass

                    try:
                        if dlg.minimumHeight() == dlg.maximumHeight():
                            dlg.setMaximumHeight(16777215)
                        if dlg.minimumWidth() == dlg.maximumWidth():
                            dlg.setMaximumWidth(16777215)
                    except Exception:
                        pass

                    try:
                        dlg.setMinimumSize(240, 160)
                    except Exception:
                        pass

                    try:
                        dlg.setMaximumSize(16777215, 16777215)
                    except Exception:
                        pass

                    try:
                        dlg.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                    except Exception:
                        pass

                def _restore_geometry(self, dlg: QDialog) -> None:
                    key = self._dlg_key(dlg) + "/geometry"

                    def _do():
                        try:
                            val = settings.value(key, None)
                            if isinstance(val, (QByteArray, bytes)):
                                ba = val if isinstance(val, QByteArray) else QByteArray(val)
                                if ba and len(ba) > 12:
                                    dlg.restoreGeometry(ba)
                        except Exception:
                            pass

                    QTimer.singleShot(0, _do)

                def _save_geometry(self, dlg: QDialog) -> None:
                    try:
                        key = self._dlg_key(dlg) + "/geometry"
                        settings.setValue(key, dlg.saveGeometry())
                        try:
                            settings.sync()
                        except Exception:
                            pass
                    except Exception:
                        pass

                def eventFilter(self, obj, ev):  # type: ignore[override]
                    try:
                        if not isinstance(obj, QDialog):
                            return False
                        if self._should_skip(obj):
                            return False

                        et = ev.type()

                        if et == QEvent.Polish:
                            self._apply_windows_like_flags(obj)
                            self._unlock_size(obj)
                            return False

                        if et == QEvent.Show:
                            self._restore_geometry(obj)
                            self._unlock_size(obj)
                            return False

                        if et == QEvent.Resize:
                            self._unlock_size(obj)
                            return False

                        if et in (QEvent.Hide, QEvent.Close):
                            self._save_geometry(obj)
                            return False

                    except Exception:
                        pass
                    return False

            pol = _DialogPolicy(app)
            app.installEventFilter(pol)
            try:
                setattr(app, "_bz_dialog_policy", pol)
            except Exception:
                pass

            try:
                logger.info("Dialog policy: ON (Windows-like resize W+H + Min/Max + geometry persist).")
            except Exception:
                pass

        except Exception as e:
            try:
                logger.warning(f"Dialog policy skipped: {e}")
            except Exception:
                pass

    # UI imports tek sad (posle PySide6)
    try:
        from ui.login_dialog import LoginDialog  # type: ignore
        from ui.audit_page import AuditPage  # type: ignore
        from ui.settings_page import SettingsPage  # type: ignore
        from ui.metrology_page import MetrologyPage  # type: ignore
        from ui.users_page import UsersPage  # type: ignore
        from ui.assets_page import AssetsPage  # type: ignore
        from ui.assignments_page import AssignmentsPage  # type: ignore
        from ui.dashboard_page import DashboardPage  # type: ignore
        from ui.my_assets_page import MyAssetsPage  # type: ignore
    except Exception as e:
        tb = traceback.format_exc()
        _write_crash_report(logger, "UI import failed", exc_info=sys.exc_info())
        show_fatal_message("BazaS2 — UI import error", f"Ne mogu da importujem UI module.\n\n{e}\n\n{tb}")
        raise

    # METRO dashboard: fail-safe stub
    _metro_err: Optional[str] = None
    try:
        from ui.metrology_dashboard_page import MetrologyDashboardPage  # type: ignore
    except Exception as e:
        _metro_err = str(e)

        class MetrologyDashboardPage(QWidget):  # type: ignore
            def __init__(self, logger: logging.Logger, parent=None):
                super().__init__(parent)
                lay = QVBoxLayout(self)
                t = QLabel("Metrologija Dashboard (nije učitan)")
                t.setStyleSheet("font-size: 18px; font-weight: 700;")
                info = QLabel("Dashboard modul nije mogao da se učita.\n\n" f"Detalj: {_metro_err}")
                info.setWordWrap(True)
                info.setStyleSheet("color: #a00;")
                lay.addWidget(t)
                lay.addWidget(info, 1)

            def refresh(self) -> None:
                return

    class RoleSwitchDialog(QDialog):
        def __init__(self, roles: List[str], current: str, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Promena uloge")
            self.resize(380, 160)

            self._roles = [str(r or "").strip().upper() for r in (roles or []) if str(r or "").strip()]
            if not self._roles:
                self._roles = [str(current or "READONLY").strip().upper()]

            self.cb = QComboBox()
            for r in self._roles:
                self.cb.addItem(r, r)

            cur = str(current or "").strip().upper()
            if cur:
                idx = self.cb.findText(cur, Qt.MatchFixedString)
                if idx >= 0:
                    self.cb.setCurrentIndex(idx)

            self.btn_ok = QPushButton("Primeni")
            self.btn_cancel = QPushButton("Otkaži")
            self.btn_ok.clicked.connect(self.accept)
            self.btn_cancel.clicked.connect(self.reject)

            lay = QVBoxLayout(self)
            lay.addWidget(QLabel("Izaberi aktivnu ulogu za ovu sesiju:"))
            lay.addWidget(self.cb)

            row = QHBoxLayout()
            row.addStretch(1)
            row.addWidget(self.btn_ok)
            row.addWidget(self.btn_cancel)
            lay.addLayout(row)

        def selected_role(self) -> str:
            return str(self.cb.currentData() or self.cb.currentText() or "").strip().upper()

    class MainWindow(QMainWindow):
        def __init__(self, logger: logging.Logger):
            super().__init__()
            self.logger = logger
            self.setWindowTitle(f"{APP_NAME} — {APP_VERSION}")
            self.resize(1200, 720)

            self._settings = None
            try:
                self._settings = QSettings("BazaS2", APP_NAME)
            except Exception:
                self._settings = None

            central = QWidget()
            root = QHBoxLayout(central)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(0)

            self.nav = QListWidget()
            self.pages = QStackedWidget()

            self.splitter = QSplitter(Qt.Horizontal)
            self.splitter.setChildrenCollapsible(True)

            self.nav.setMinimumWidth(160)
            self.nav.setMaximumWidth(360)

            self.splitter.addWidget(self.nav)
            self.splitter.addWidget(self.pages)
            self.splitter.setStretchFactor(0, 0)
            self.splitter.setStretchFactor(1, 1)

            root.addWidget(self.splitter, 1)
            self.setCentralWidget(central)

            self.statusBar().showMessage(f"DB: {DB_FILE} | Offline: ON | User: {_actor_name()}")

            self.lb_role = QLabel("")
            self.lb_role.setToolTip("Aktivna uloga (multi-role)")
            self.statusBar().addPermanentWidget(self.lb_role)

            self.btn_switch_role = QPushButton("Promeni ulogu")
            self.btn_switch_role.setToolTip("Promeni aktivnu ulogu za ovu sesiju (audit log)")
            self.statusBar().addPermanentWidget(self.btn_switch_role)
            self.btn_switch_role.clicked.connect(self._on_switch_role_clicked)

            self.btn_logout = QPushButton("Odjava")
            self.btn_logout.setToolTip("Odjavi se i prijavi drugog korisnika")
            self.statusBar().addPermanentWidget(self.btn_logout)
            self.btn_logout.clicked.connect(self._logout)

            self.nav.currentRowChanged.connect(self._on_nav_row_changed)

            self._rebuild_ui_by_profile()
            self._refresh_role_widgets()
            self._restore_geometry_and_splitter()

        def _restore_geometry_and_splitter(self) -> None:
            try:
                if not self._settings:
                    return
                ba = self._settings.value("ui/mainwindow/geometry", None)
                if isinstance(ba, (QByteArray, bytes)):
                    b2 = ba if isinstance(ba, QByteArray) else QByteArray(ba)
                    if b2 and len(b2) > 12:
                        self.restoreGeometry(b2)
            except Exception:
                pass

            try:
                if not self._settings:
                    return
                st = self._settings.value("ui/mainwindow/splitter", None)
                if isinstance(st, (QByteArray, bytes)):
                    s2 = st if isinstance(st, QByteArray) else QByteArray(st)
                    if s2 and len(s2) > 6:
                        self.splitter.restoreState(s2)
            except Exception:
                pass

        def _save_geometry_and_splitter(self) -> None:
            try:
                if not self._settings:
                    return
                self._settings.setValue("ui/mainwindow/geometry", self.saveGeometry())
                self._settings.setValue("ui/mainwindow/splitter", self.splitter.saveState())
                try:
                    self._settings.sync()
                except Exception:
                    pass
            except Exception:
                pass

        def closeEvent(self, e) -> None:  # type: ignore[override]
            try:
                self._save_geometry_and_splitter()
            except Exception:
                pass
            try:
                super().closeEvent(e)
            except Exception:
                pass

        def _safe_can(self, perm: str) -> bool:
            try:
                return bool(can(perm))
            except Exception:
                return False

        def _ui_mode_reason(self) -> str:
            u = _LAST_LOGIN_USER
            role = (_extract_role_from_user(u) or "").strip().upper()
            uname = (_extract_username_like(u) or "").strip()
            return (
                f"role={role or '—'}; user={uname or '—'}; "
                f"users_view={int(self._safe_can(PERM_USERS_VIEW))}; "
                f"settings_view={int(self._safe_can(PERM_SETTINGS_VIEW))}; "
                f"assets_create={int(self._safe_can(PERM_ASSETS_CREATE))}; "
                f"assign_create={int(self._safe_can(PERM_ASSIGN_CREATE))}; "
                f"metrology_view={int(self._safe_can(PERM_METRO_VIEW))}"
            )

        def _refresh_role_widgets(self) -> None:
            roles = _list_roles_safe()
            cur = _current_role_safe().strip().upper() or (_extract_role_from_user(_LAST_LOGIN_USER) or "").strip().upper()
            if not cur:
                cur = "READONLY"
            try:
                self.lb_role.setText(f"Uloga: {cur}")
            except Exception:
                pass
            try:
                self.btn_switch_role.setVisible(bool(len(roles) >= 2))
                self.btn_switch_role.setEnabled(bool(len(roles) >= 2))
            except Exception:
                pass

        def _on_switch_role_clicked(self) -> None:
            roles = _list_roles_safe()
            if len(roles) < 2:
                QMessageBox.information(self, "Info", "Ovaj korisnik nema više rola.")
                return
            cur = _current_role_safe().strip().upper()
            dlg = RoleSwitchDialog(roles=roles, current=cur, parent=self)
            if dlg.exec() != QDialog.Accepted:
                return
            new_role = dlg.selected_role()
            if not new_role or new_role == cur:
                return
            if new_role not in roles:
                QMessageBox.warning(self, "Greška", "Izabrana uloga nije dodeljena ovom korisniku.")
                return
            if not _set_active_role_safe(new_role, source="ui_mainwindow_role_switch"):
                QMessageBox.warning(self, "Greška", "Ne mogu da promenim ulogu (role switch failed).")
                return
            _sync_last_login_user_from_session()
            self._on_user_changed()
            self._refresh_role_widgets()

        def _nav_go_by_text(self, label: str) -> None:
            try:
                target = (label or "").strip()
                if not target:
                    return
                for i in range(self.nav.count()):
                    it = self.nav.item(i)
                    if it is None:
                        continue
                    if (it.text() or "").strip() == target:
                        if not (it.flags() & Qt.ItemIsEnabled):
                            return
                        self.nav.setCurrentRow(i)
                        return
            except Exception:
                pass

        def _is_metro_referent(self) -> bool:
            cur = (_current_role_safe() or "").strip().upper()
            if not cur:
                cur = (_extract_role_from_user(_LAST_LOGIN_USER) or "").strip().upper()
            return cur in {"REFERENT_METRO", "REFERENT_METROLOGIJE", "METRO_REFERENT"}

        def _is_basic_user(self) -> bool:
            cur = (_current_role_safe() or "").strip().upper()
            if not cur:
                cur = (_extract_role_from_user(_LAST_LOGIN_USER) or "").strip().upper()

            BASIC_NAMES = {
                "BASIC", "BASIC_USER", "USER", "EMPLOYEE", "KORISNIK", "OBICAN", "OBICAN_KORISNIK",
                "READONLY", "READ_ONLY", "VIEWONLY", "VIEW_ONLY",
            }
            FULL_NAMES = {"ADMIN", "SUPERUSER", "SECTOR_ADMIN", "REFERENT_IT", "NACELNIK", "NAČELNIK", "MANAGER", "FULL"}
            if cur:
                if cur in BASIC_NAMES:
                    return True
                if cur in FULL_NAMES:
                    return False

            if any([self._safe_can(PERM_USERS_VIEW), self._safe_can(PERM_ASSETS_CREATE), self._safe_can(PERM_ASSIGN_CREATE), self._safe_can(PERM_AUDIT_VIEW)]):
                return False
            return True

        def _clear_pages(self) -> None:
            try:
                while self.pages.count() > 0:
                    w = self.pages.widget(0)
                    self.pages.removeWidget(w)
                    try:
                        w.setParent(None)
                    except Exception:
                        pass
            except Exception:
                pass

        def _rebuild_ui_by_profile(self) -> None:
            _sync_last_login_user_from_session()
            reason = self._ui_mode_reason()

            # ✅ Jedino pravilo za prikaz dashboard-a u meniju:
            #   ako korisnik ima metrology.view -> vidi "Metrologija Dashboard"
            show_metro_dash = bool(self._safe_can(PERM_METRO_VIEW))

            self.nav.blockSignals(True)
            try:
                self.nav.clear()
                self._clear_pages()

                if self._is_metro_referent():
                    labels: List[str] = []
                    widgets: List[QWidget] = []

                    if show_metro_dash:
                        labels.append("Metrologija Dashboard")
                        widgets.append(MetrologyDashboardPage(self.logger))

                    labels += ["Metrologija", "Moj Dashboard", "Moja oprema", "Podešavanja"]
                    widgets += [
                        MetrologyPage(self.logger),
                        DashboardPage(self.logger, scope_mode="my", on_go_assets=lambda: self._nav_go_by_text("Moja oprema")),
                        MyAssetsPage(self.logger),
                        SettingsPage(self.logger),
                    ]

                    self.nav.addItems(labels)
                    for w in widgets:
                        self.pages.addWidget(w)

                    self.nav.setCurrentRow(0)
                    self.pages.setCurrentIndex(0)
                    self.statusBar().showMessage(f"DB: {DB_FILE} | Offline: ON | User: {_actor_name()} | Mode: METRO | {reason}")
                    return

                if self._is_basic_user():
                    labels2: List[str] = ["Moj Dashboard"]
                    widgets2: List[QWidget] = [
                        DashboardPage(self.logger, scope_mode="my", on_go_assets=lambda: self._nav_go_by_text("Moja oprema")),
                    ]

                    # ✅ BASIC vidi metrology dashboard samo ako ima metrology.view
                    if show_metro_dash:
                        labels2.append("Metrologija Dashboard")
                        widgets2.append(MetrologyDashboardPage(self.logger))

                    labels2 += ["Moja oprema", "Podešavanja"]
                    widgets2 += [MyAssetsPage(self.logger), SettingsPage(self.logger)]

                    self.nav.addItems(labels2)
                    for w in widgets2:
                        self.pages.addWidget(w)

                    self.nav.setCurrentRow(0)
                    self.pages.setCurrentIndex(0)
                    self.statusBar().showMessage(f"DB: {DB_FILE} | Offline: ON | User: {_actor_name()} | Mode: BASIC | {reason}")
                    return

                # FULL UI
                labels3: List[str] = ["Dashboard", "Sredstva", "Zaduženja", "Audit"]
                page_dashboard = DashboardPage(self.logger, on_go_assets=lambda: self._nav_go_by_text("Sredstva"), on_go_assign=lambda: self._nav_go_by_text("Zaduženja"), scope_mode="global")
                page_assets = AssetsPage(self.logger)
                page_assignments = AssignmentsPage(self.logger, page_assets)
                page_audit = AuditPage(self.logger)

                widgets3: List[QWidget] = [page_dashboard, page_assets, page_assignments, page_audit]

                if show_metro_dash:
                    labels3.append("Metrologija Dashboard")
                    widgets3.append(MetrologyDashboardPage(self.logger))

                labels3 += ["Metrologija", "Korisnici", "Podešavanja", "Moj Dashboard", "Moja oprema"]
                widgets3 += [
                    MetrologyPage(self.logger),
                    UsersPage(self.logger),
                    SettingsPage(self.logger),
                    DashboardPage(self.logger, scope_mode="my", on_go_assets=lambda: self._nav_go_by_text("Moja oprema")),
                    MyAssetsPage(self.logger),
                ]

                self.nav.addItems(labels3)
                for w in widgets3:
                    self.pages.addWidget(w)

                self.nav.setCurrentRow(0)
                self.pages.setCurrentIndex(0)
                self.statusBar().showMessage(f"DB: {DB_FILE} | Offline: ON | User: {_actor_name()} | Mode: FULL | {reason}")
            finally:
                self.nav.blockSignals(False)

        def _on_user_changed(self) -> None:
            try:
                self._rebuild_ui_by_profile()
            except Exception:
                pass
            self._refresh_role_widgets()

        def _logout(self) -> None:
            """
            KRITIČNO (fail-closed):
            - Ako korisnik otkaže login posle odjave, app ne sme ostati bez validnog user-a.
            """
            if QMessageBox.question(self, "Odjava", "Odjavi se i vrati na prijavu?", QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                return

            # očisti session (best-effort)
            try:
                set_current_user(None)  # type: ignore[arg-type]
            except Exception:
                try:
                    set_current_user({})  # type: ignore[arg-type]
                except Exception:
                    pass
            _remember_login_user(None)

            dlg = LoginDialog(self, logger=self.logger)
            if dlg.exec() != QDialog.Accepted:
                try:
                    self.close()
                except Exception:
                    pass
                try:
                    QApplication.quit()
                except Exception:
                    pass
                return

            u = dlg.selected_user()
            if not u:
                try:
                    self.close()
                except Exception:
                    pass
                try:
                    QApplication.quit()
                except Exception:
                    pass
                return

            if not isinstance(u, dict):
                try:
                    u = dict(u)  # type: ignore[arg-type]
                except Exception:
                    QMessageBox.critical(self, "Greška", "Login user payload nije validan (nije dict).")
                    try:
                        self.close()
                    except Exception:
                        pass
                    try:
                        QApplication.quit()
                    except Exception:
                        pass
                    return

            _remember_login_user(u)
            try:
                set_current_user(u)
            except Exception:
                QMessageBox.critical(self, "Greška", "Ne mogu da setujem current user u session.")
                try:
                    self.close()
                except Exception:
                    pass
                try:
                    QApplication.quit()
                except Exception:
                    pass
                return

            _sync_last_login_user_from_session()
            self._on_user_changed()

        def _on_nav_row_changed(self, row: int) -> None:
            if row < 0 or row >= self.pages.count():
                return
            it = self.nav.item(row)
            if it is not None and not (it.flags() & Qt.ItemIsEnabled):
                return

            self.pages.setCurrentIndex(row)

            # ✅ AUTO-REFRESH samo za Metrologija Dashboard (dugme "Osveži" ostaje u UI)
            try:
                label = (it.text() if it is not None else "") or ""
                if label.strip() == "Metrologija Dashboard":
                    w = self.pages.widget(row)
                    rf = getattr(w, "refresh", None)
                    if callable(rf):
                        QTimer.singleShot(0, rf)  # non-blocking, UI-friendly
            except Exception:
                pass

    app = QApplication(sys.argv)

    try:
        QApplication.setApplicationName(APP_NAME)
        QApplication.setApplicationDisplayName(APP_NAME)
        QApplication.setOrganizationName("BazaS2")
    except Exception:
        pass

    _install_qt_message_handler(logger)
    _apply_global_theme(app, logger)

    _install_dialog_responsiveness_policy(app, logger)

    # schema ensure (best-effort, ali ako padne ovde, bolje fail-closed sa porukom)
    try:
        ensure_users_schema()
    except Exception as e:
        tb = traceback.format_exc()
        _write_crash_report(logger, "ensure_users_schema failed", exc_info=sys.exc_info())
        show_fatal_message("BazaS2 — Schema error", f"Ne mogu da pripremim users schema.\n\n{e}\n\n{tb}")
        raise

    dlg = LoginDialog(None, logger=logger)
    if dlg.exec() != QDialog.Accepted:
        sys.exit(0)
    u = dlg.selected_user()
    if not u:
        sys.exit(0)

    # enforce dict payload (session očekuje dict)
    if not isinstance(u, dict):
        try:
            u = dict(u)  # type: ignore[arg-type]
        except Exception:
            show_fatal_message("BazaS2 — Login error", "Login user payload nije validan (nije dict).")
            sys.exit(1)

    _remember_login_user(u)
    try:
        set_current_user(u)
    except Exception:
        show_fatal_message("BazaS2 — Session error", "Ne mogu da setujem current user u session.")
        sys.exit(1)

    _sync_last_login_user_from_session()

    win = MainWindow(logger)
    win.show()
    sys.exit(app.exec())


def main() -> int:
    logger = setup_logging()
    logger.info("Napomena: sistem je projektovan za 100% OFFLINE okruženje (bez interneta).")
    _install_exception_hooks(logger)

    try:
        ensure_folders()

        did_apply, ok_restore, msg_restore = apply_pending_full_restore()
        if did_apply:
            if ok_restore:
                logger.info(msg_restore)
            else:
                logger.error(msg_restore)
                show_fatal_message("BazaS2 — FULL Restore failed", msg_restore)
                return 4

        args = sys.argv[1:]
        selfcheck_only = ("--self-check-only" in args)
        no_autofix = ("--no-autofix" in args)

        if not _preflight_dependencies(logger):
            show_fatal_message(
                "BazaS2 — Missing dependencies",
                "Nedostaju biblioteke (npr. PySide6).\n"
                "Pogledaj konzolu i/ili data/logs/pip_install_last.txt.\n"
                f"WHEELS_DIR: {WHEELS_DIR}",
            )
            return 2

        ok = _run_selfcheck(logger, auto_fix=False)
        if not ok:
            missing_from_report = _extract_missing_from_selfcheck_report(logger)
            if missing_from_report:
                try:
                    logger.error("Self-check missing (iz reporta): %s", ", ".join(missing_from_report))
                except Exception:
                    pass

                if _prompt_yes_no("Self-check nije prošao. Da li da pokušam OFFLINE instalaciju missing paketa iz selfcheck reporta?", default_no=True):
                    ok_i, msg_i = _pip_install_offline_from_wheels(logger, missing_from_report, Path(WHEELS_DIR))
                    if not ok_i:
                        show_fatal_message("BazaS2 — Offline install failed", msg_i)
                        if no_autofix:
                            return 2
                    ok = _run_selfcheck(logger, auto_fix=False)

            if not ok:
                if no_autofix:
                    msg = "Self-check nije prošao, a --no-autofix je uključen."
                    if missing_from_report:
                        msg += "\n\nMissing (report): " + ", ".join(missing_from_report)
                    logger.error(msg)
                    show_fatal_message("BazaS2 — Missing dependencies", msg)
                    return 2

                if _prompt_yes_no("Self-check i dalje nije prošao. Da li da pokušam OFFLINE auto-fix (self_check_and_fix auto_fix=True)?", default_no=True):
                    ok2 = _run_selfcheck(logger, auto_fix=True)
                    if not ok2:
                        msg = (
                            "Self-check i auto-fix nisu prošli.\n\n"
                            f"Rešenje (offline): ubaci odgovarajuće .whl pakete u: {WHEELS_DIR}\n"
                            "Detalji: data/logs/selfcheck_report.json i data/logs/pip_install_last.txt"
                        )
                        if missing_from_report:
                            msg += "\n\nMissing (report): " + ", ".join(missing_from_report)
                        logger.error(msg)
                        show_fatal_message("BazaS2 — Missing dependencies", msg)
                        return 2
                else:
                    msg = "Self-check nije prošao i instalacija nije potvrđena."
                    if missing_from_report:
                        msg += "\n\nMissing (report): " + ", ".join(missing_from_report)
                    logger.error(msg)
                    show_fatal_message("BazaS2 — Missing dependencies", msg)
                    return 2

        if selfcheck_only:
            logger.info("Self-check-only mode: završavam bez pokretanja UI.")
            return 0

        old_v, latest_v = init_db()
        logger.info(f"DB init OK. schema_version: {old_v} -> {latest_v}")

        start_ui(logger)
        return 0

    except Exception as e:
        tb = traceback.format_exc()
        try:
            logger.error(f"FATAL ERROR: {e}")
            logger.error(tb)
        except Exception:
            pass
        _write_crash_report(logger, "FATAL ERROR (main)", exc_info=sys.exc_info())
        show_fatal_message("BazaS2 — Fatal error", f"{e}\n\n{tb}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

# (FILENAME: app.py - REGEN - END)  [PART 2/2]
# FILENAME: app.py