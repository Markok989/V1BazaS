# FILENAME: ui/settings_page.py
# (FILENAME: ui/settings_page.py - START)  # Part 1/2
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/settings_page.py

Podešavanja (TAB UI):
- Moj nalog (self-service): promena PIN/lozinke + status must_change_creds
- Izgled i rad: Theme picker (token-based)
- Backup & Restore
- O aplikaciji
- Napredno (samo settings.manage) — PRO toolbox
"""

from __future__ import annotations

import os
import sys
import json
import shutil
import sqlite3
import zipfile
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from PySide6.QtWidgets import (  # type: ignore
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QMessageBox, QFileDialog, QDialog, QDialogButtonBox,
    QCheckBox, QPlainTextEdit, QApplication, QGroupBox,
    QFormLayout, QLineEdit, QTabWidget, QComboBox
)
from PySide6.QtCore import Qt, QUrl  # type: ignore
from PySide6.QtGui import QDesktopServices  # type: ignore

from core.backup import (
    create_backup_zip,
    hot_restore_db_from_zip,
    stage_full_restore,
)

# internal helper ok for V1 (fail-safe wrapper is below)
from core.backup import _app_root as _root_helper  # type: ignore

from core.config import APP_NAME, APP_VERSION, DB_FILE
from core.session import can
from core.rbac import PERM_SETTINGS_MANAGE

# ✅ Self-service kredencijali (fail-safe)
try:
    from services.users_service import (
        change_my_password,
        change_my_pin,
        get_user_credential_flags,
    )
except Exception:
    change_my_password = None  # type: ignore
    change_my_pin = None  # type: ignore
    get_user_credential_flags = None  # type: ignore

# ✅ Theme manager (token-based) — bez oslanjanja na posebne widgete
try:
    from ui.theme.theme_manager import (  # type: ignore
        list_themes as _list_themes,
        get_current_theme_id as _get_current_theme_id,
        get_theme_id_default as _get_theme_default,
        apply_theme as _apply_theme,
    )
except Exception:
    _list_themes = None  # type: ignore
    _get_current_theme_id = None  # type: ignore
    _get_theme_default = None  # type: ignore
    _apply_theme = None  # type: ignore


def _app_root() -> Path:
    """Fail-safe root resolver."""
    try:
        return Path(_root_helper()).resolve()
    except Exception:
        # fallback: root = 2 nivoa iznad ui/
        try:
            return Path(__file__).resolve().parents[2]
        except Exception:
            return Path(".").resolve()


def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


class FullRestoreConfirmDialog(QDialog):
    def __init__(self, zip_path: Path, safety_zip_path: Path, parent=None):
        super().__init__(parent)
        self.setWindowTitle("FULL Restore — biće urađen kontrolisani restart")
        self.resize(720, 360)

        title = QLabel("FULL Restore (baza + slike + šabloni + podešavanja)")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")

        info = QPlainTextEdit()
        info.setReadOnly(True)
        info.setPlainText(
            "FULL Restore vraća SVE iz izabranog backup-a (bazu + data folder: šabloni, slike, logove...).\n\n"
            "Da bi restore bio pouzdan, aplikacija mora da oslobodi sve otvorene fajlove (SQLite baza i prateći fajlovi).\n"
            "Zato će aplikacija uraditi kontrolisani restart.\n\n"
            "Pre nastavka proveri:\n"
            "- Ako trenutno unosiš/menjaš podatke u nekoj formi, završi i zatvori taj dijalog.\n"
            "- Ako radi import/export (u budućim modulima), sačekaj da se završi.\n\n"
            f"Backup fajl:\n  {zip_path}\n\n"
            f"Safety backup (pre restore-a) biće sačuvan kao:\n  {safety_zip_path}\n"
        )

        self.chk = QCheckBox("Razumem i želim da nastavim sa FULL Restore (restart + restore).")
        self.chk.setChecked(False)

        btns = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        ok_btn = btns.button(QDialogButtonBox.Ok)
        cancel_btn = btns.button(QDialogButtonBox.Cancel)
        if ok_btn:
            ok_btn.setText("Nastavi")
        if cancel_btn:
            cancel_btn.setText("Odustani")

        btns.accepted.connect(self._on_ok)
        btns.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addWidget(title)
        lay.addWidget(info, 1)
        lay.addWidget(self.chk)
        lay.addWidget(btns)

    def _on_ok(self):
        if not self.chk.isChecked():
            QMessageBox.warning(self, "Potvrda je obavezna", "Moraš čekirati potvrdu da razumeš da sledi restart.")
            return
        self.accept()


class SettingsPage(QWidget):
    def __init__(self, logger, parent=None):
        super().__init__(parent)
        self.logger = logger

        root = _app_root()
        self.data_dir = root / "data"
        self.logs_dir = root / "data" / "logs"
        self.backups_dir = root / "data" / "backups"

        # busy snapshot (da ne “zaglavi” dugmad posle akcija)
        self._busy_snapshot: Dict[int, bool] = {}

        try:
            self.logs_dir.mkdir(parents=True, exist_ok=True)
            self.backups_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        title = QLabel("Podešavanja")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")

        subtitle = QLabel(
            "Sve je lokalno (offline).\n"
            "Podešavanja su podeljena po tabovima — lakše za korišćenje i lakše za rast aplikacije."
        )
        subtitle.setWordWrap(True)
        subtitle.setProperty("muted", True)

        self.tabs = QTabWidget()

        # --- Tab: Moj nalog ---
        self.tab_account = self._build_tab_account()
        self.tabs.addTab(self.tab_account, "Moj nalog")

        # --- Tab: Izgled ---
        self.tab_appearance = self._build_tab_appearance()
        self.tabs.addTab(self.tab_appearance, "Izgled")

        # --- Tab: Backup & Restore ---
        self.tab_backup = self._build_tab_backup_restore()
        self.tabs.addTab(self.tab_backup, "Backup & Restore")

        # --- Tab: O aplikaciji ---
        self.tab_about = self._build_tab_about()
        self.tabs.addTab(self.tab_about, "O aplikaciji")

        # --- Tab: Napredno (samo manage) ---
        self.tab_advanced = None
        if self._can_manage_settings():
            self.tab_advanced = self._build_tab_advanced()
            self.tabs.addTab(self.tab_advanced, "Napredno")

        lay = QVBoxLayout(self)
        lay.addWidget(title)
        lay.addWidget(subtitle)
        lay.addSpacing(10)
        lay.addWidget(self.tabs, 1)

        self.refresh()

    # -------------------- RBAC helpers --------------------
    def _can_manage_settings(self) -> bool:
        try:
            return bool(can(PERM_SETTINGS_MANAGE))
        except Exception:
            return False

    # -------------------- refresh --------------------
    def refresh(self) -> None:
        """Best-effort refresh: status kredencijala + RBAC enable/disable + theme state."""
        try:
            self.refresh_cred_status()
        except Exception:
            pass

        can_manage = self._can_manage_settings()

        # Backup/Restore dugmad su RBAC-gated
        try:
            for b in [self.btn_backup, self.btn_restore_hot, self.btn_restore_full]:
                b.setEnabled(bool(can_manage))
        except Exception:
            pass

        try:
            self.lbl_backup_hint.setProperty("muted", True)
            if not can_manage:
                self.lbl_backup_hint.setText("⚠️ Backup/Restore akcije su dostupne samo admin/supervizor korisnicima.")
            else:
                self.lbl_backup_hint.setText("Backup/Restore akcije su dostupne (imaš settings.manage).")
        except Exception:
            pass

        try:
            self._refresh_theme_ui_state()
        except Exception:
            pass

    # -------------------- helpers --------------------
    def _set_busy(self, busy: bool) -> None:
        """
        Zaključaj kritična dugmad da se ne pokrene 2x akcija.
        Važno: vraća prethodno stanje (snapshot), da ništa ne ostane trajno disabled.
        """
        widgets = [
            getattr(self, "btn_backup", None),
            getattr(self, "btn_restore_hot", None),
            getattr(self, "btn_restore_full", None),
            getattr(self, "btn_change_pin", None),
            getattr(self, "btn_change_pw", None),
            getattr(self, "btn_theme_apply", None),
            getattr(self, "btn_theme_default", None),
        ]

        if busy:
            snap: Dict[int, bool] = {}
            for w in widgets:
                if w is None:
                    continue
                try:
                    snap[id(w)] = bool(w.isEnabled())
                    w.setEnabled(False)
                except Exception:
                    continue
            self._busy_snapshot = snap
            return

        # restore snapshot
        snap = getattr(self, "_busy_snapshot", {}) or {}
        for w in widgets:
            if w is None:
                continue
            try:
                w.setEnabled(bool(snap.get(id(w), True)))
            except Exception:
                continue
        self._busy_snapshot = {}

        # posle akcije najbolje je vratiti RBAC stanje (refresh)
        try:
            self.refresh()
        except Exception:
            pass

    def _open_folder(self, folder: Path):
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            QMessageBox.critical(self, "Folder", f"Ne mogu da napravim folder:\n{folder}\n\n{e}")
            return

        try:
            if os.name == "nt":
                os.startfile(str(folder))  # type: ignore[attr-defined]
            else:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))
        except Exception as e:
            QMessageBox.information(self, "Folder", f"{folder}\n\nNe mogu automatski da otvorim: {e}")

    def _restart_process(self):
        """Managed restart: podigne novu instancu i ugasi trenutnu."""
        try:
            exe = sys.executable

            # PyInstaller/frozen: sys.argv[0] je već .exe → ne dupliramo
            if getattr(sys, "frozen", False):
                args = [exe] + sys.argv[1:]
            else:
                args = [exe] + sys.argv

            popen_kwargs = {"cwd": str(_app_root())}

            if os.name == "nt":
                creationflags = 0
                try:
                    creationflags |= subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
                    creationflags |= subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
                except Exception:
                    creationflags = 0
                if creationflags:
                    popen_kwargs["creationflags"] = creationflags

            subprocess.Popen(args, **popen_kwargs)
        except Exception as e:
            QMessageBox.critical(self, "Restart nije uspeo", f"Ne mogu da restartujem aplikaciju automatski.\n\n{e}")
            return

        try:
            app = QApplication.instance()
            if app:
                app.quit()
        except Exception:
            pass

    # -------------------- Theme (Izgled) --------------------
    def _theme_api_ok(self) -> bool:
        return callable(_list_themes) and callable(_get_current_theme_id) and callable(_apply_theme)

    def _themes_dict(self) -> Dict[str, str]:
        if not callable(_list_themes):
            return {}
        try:
            d = _list_themes()
            return d if isinstance(d, dict) else {}
        except Exception:
            return {}

    def _get_saved_theme_id(self) -> str:
        try:
            tid = _get_current_theme_id() if callable(_get_current_theme_id) else ""
            tid = str(tid or "").strip().lower()
        except Exception:
            tid = ""
        if not tid:
            try:
                tid = str(_get_theme_default() if callable(_get_theme_default) else "dark_blue").strip().lower()
            except Exception:
                tid = "dark_blue"
        return tid

    def _refresh_theme_ui_state(self) -> None:
        """Sync UI sa sačuvanim theme_id (bez iznenadnog apply)."""
        if not hasattr(self, "cb_theme") or self.cb_theme is None:
            return

        if not self._theme_api_ok():
            try:
                self.lbl_theme_state.setText("Tema: modul nije dostupan.")
            except Exception:
                pass
            return

        saved = self._get_saved_theme_id()
        try:
            self.cb_theme.blockSignals(True)
            idx = self.cb_theme.findData(saved)
            if idx >= 0:
                self.cb_theme.setCurrentIndex(idx)
            self.cb_theme.blockSignals(False)
        except Exception:
            try:
                self.cb_theme.blockSignals(False)
            except Exception:
                pass

        # status label
        try:
            self.lbl_theme_state.setProperty("muted", True)
            label = self.cb_theme.currentText() or saved
            self.lbl_theme_state.setText(f"Aktivna tema: {label} ({saved})")
        except Exception:
            pass

    def _apply_selected_theme(self) -> None:
        if not self._theme_api_ok():
            QMessageBox.warning(self, "Tema", "Theme modul nije dostupan (ui/theme/theme_manager.py).")
            return

        try:
            tid = str(self.cb_theme.currentData() or "").strip().lower()
        except Exception:
            tid = ""

        if not tid:
            QMessageBox.warning(self, "Tema", "Nije izabrana validna tema.")
            return

        app = QApplication.instance()
        if app is None:
            QMessageBox.warning(self, "Tema", "QApplication nije inicijalizovan.")
            return

        self._set_busy(True)
        try:
            ok = bool(_apply_theme(app, tid))  # type: ignore[misc]
            if ok:
                self._refresh_theme_ui_state()
                try:
                    self.logger.info(f"Theme applied: {tid}")
                except Exception:
                    pass
            else:
                QMessageBox.warning(self, "Tema", "Primena teme nije uspela (fallback nije uspeo).")
        except Exception as e:
            QMessageBox.warning(self, "Tema", f"Ne mogu da primenim temu.\n\n{e}")
        finally:
            self._set_busy(False)

    def _set_default_theme(self) -> None:
        if not self._theme_api_ok():
            QMessageBox.warning(self, "Tema", "Theme modul nije dostupan.")
            return

        try:
            default_id = str(_get_theme_default() if callable(_get_theme_default) else "dark_blue").strip().lower()
        except Exception:
            default_id = "dark_blue"

        # set combobox to default, then apply
        try:
            idx = self.cb_theme.findData(default_id)
            if idx >= 0:
                self.cb_theme.setCurrentIndex(idx)
        except Exception:
            pass

        self._apply_selected_theme()

    # -------------------- PRO helpers (Napredno) --------------------
    def _adv_out_set(self, text: str) -> None:
        try:
            if hasattr(self, "adv_out") and self.adv_out is not None:
                self.adv_out.setPlainText(text or "")
                self.adv_out.verticalScrollBar().setValue(self.adv_out.verticalScrollBar().maximum())
        except Exception:
            pass

    def _tail_text(self, fp: Path, max_lines: int = 200, max_bytes: int = 1024 * 1024) -> str:
        """Brz tail (best-effort): čita do poslednjih max_bytes pa uzme poslednjih max_lines."""
        try:
            if not fp.exists():
                return f"Fajl ne postoji:\n{fp}"
            with fp.open("rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - max_bytes))
                data = f.read()
            txt = data.decode("utf-8", errors="ignore")
            lines = txt.splitlines()
            if len(lines) > max_lines:
                lines = lines[-max_lines:]
            return "\n".join(lines)
        except Exception as e:
            return f"Ne mogu da pročitam:\n{fp}\n\n{e}"

    def _pretty_json_text(self, fp: Path, max_chars: int = 200_000) -> str:
        """Učitaj JSON i pretty-print (fail-safe)."""
        try:
            if not fp.exists():
                return f"Fajl ne postoji:\n{fp}"
            raw = fp.read_text(encoding="utf-8", errors="ignore")
            if not raw.strip():
                return f"Prazan fajl:\n{fp}"
            try:
                obj = json.loads(raw)
                txt = json.dumps(obj, ensure_ascii=False, indent=2)
            except Exception:
                txt = raw
            if len(txt) > max_chars:
                txt = txt[:max_chars] + "\n\n... (skraćeno) ..."
            return txt
        except Exception as e:
            return f"Ne mogu da učitam JSON:\n{fp}\n\n{e}"

    def _build_diagnostics_text(self) -> str:
        dbp = Path(DB_FILE)
        try:
            db_exists = dbp.exists()
            db_size = dbp.stat().st_size if db_exists else 0
            db_mtime = datetime.fromtimestamp(dbp.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S") if db_exists else "-"
        except Exception:
            db_exists, db_size, db_mtime = False, 0, "-"

        try:
            du = shutil.disk_usage(str(dbp.parent if dbp else _app_root()))
            disk_line = f"disk_free={du.free} disk_total={du.total}"
        except Exception:
            disk_line = "disk_free=? disk_total=?"

        lines = [
            f"{APP_NAME} {APP_VERSION}",
            f"timestamp={datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"os={platform.platform()}",
            f"python={sys.version.replace(os.linesep, ' ')}",
            f"root={_app_root()}",
            f"data_dir={self.data_dir}",
            f"logs_dir={self.logs_dir}",
            f"backups_dir={self.backups_dir}",
            f"db_file={DB_FILE}",
            f"db_exists={int(bool(db_exists))}",
            f"db_size_bytes={db_size}",
            f"db_mtime={db_mtime}",
            disk_line,
        ]

        try:
            from core.session import actor_name, current_role  # type: ignore
            lines.append(f"actor={actor_name()}")
            lines.append(f"role={current_role()}")
        except Exception:
            pass

        # theme info (best-effort)
        try:
            if callable(_get_current_theme_id):
                lines.append(f"theme_id={self._get_saved_theme_id()}")
        except Exception:
            pass

        return "\n".join(lines) + "\n"

    def _db_try_scalar(self, con: sqlite3.Connection, sql: str):
        try:
            cur = con.cursor()
            cur.execute(sql)
            row = cur.fetchone()
            if not row:
                return None
            return row[0]
        except Exception:
            return None

    def do_adv_show_system_info(self):
        try:
            self._adv_out_set(self._build_diagnostics_text())
            QMessageBox.information(self, "Sistem info", "Prikazano u output-u.")
        except Exception as e:
            self._adv_out_set(f"Ne mogu da napravim sistem info.\n\n{e}")

    def do_adv_view_selfcheck_report(self):
        try:
            fp = self.logs_dir / "selfcheck_report.json"
            self._adv_out_set(self._pretty_json_text(fp))
        except Exception as e:
            self._adv_out_set(f"Greška pri čitanju selfcheck_report.json:\n{e}")

    def do_adv_view_pip_last(self):
        try:
            fp = self.logs_dir / "pip_install_last.txt"
            self._adv_out_set(self._tail_text(fp, max_lines=300, max_bytes=2 * 1024 * 1024))
        except Exception as e:
            self._adv_out_set(f"Greška pri čitanju pip_install_last.txt:\n{e}")

    def do_adv_view_errors_log(self):
        try:
            fp = self.logs_dir / "errors.log"
            self._adv_out_set(self._tail_text(fp, max_lines=200))
        except Exception as e:
            self._adv_out_set(f"Greška pri čitanju errors.log:\n{e}")

    def do_adv_view_app_log(self):
        try:
            fp = self.logs_dir / "app.log"
            self._adv_out_set(self._tail_text(fp, max_lines=200))
        except Exception as e:
            self._adv_out_set(f"Greška pri čitanju app.log:\n{e}")

    def do_adv_db_integrity_check(self):
        """PRAGMA integrity_check; (read-only, best-effort)."""
        dbp = Path(DB_FILE)
        if not dbp.exists():
            self._adv_out_set(f"DB fajl ne postoji:\n{dbp}")
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            con = sqlite3.connect(str(dbp))
            try:
                cur = con.cursor()
                cur.execute("PRAGMA integrity_check;")
                rows = cur.fetchall() or []
            finally:
                try:
                    con.close()
                except Exception:
                    pass

            out_lines = ["DB integrity_check:", f"DB: {dbp}", ""]
            if not rows:
                out_lines.append("(nema rezultata)")
            else:
                for r in rows:
                    out_lines.append(str(r[0]))
            self._adv_out_set("\n".join(out_lines))

            ok = any(str(r[0]).strip().lower() == "ok" for r in rows) if rows else False
            if ok and len(rows) == 1:
                QMessageBox.information(self, "DB integrity_check", "OK")
            else:
                QMessageBox.warning(self, "DB integrity_check", "Nije čisto 'OK' — vidi detalje u output-u.")

            try:
                self.logger.info("DB integrity_check executed (Napredno).")
            except Exception:
                pass
        except Exception as e:
            self._adv_out_set(f"Ne mogu da uradim integrity_check.\n\nDB: {dbp}\n\n{e}")
        finally:
            try:
                QApplication.restoreOverrideCursor()
            except Exception:
                pass

    def do_adv_db_version_info(self):
        """Pokušaj da prikaže schema_version (koliko god da je tvoja šema)."""
        dbp = Path(DB_FILE)
        if not dbp.exists():
            self._adv_out_set(f"DB fajl ne postoji:\n{dbp}")
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            con = sqlite3.connect(str(dbp))
            try:
                user_version = self._db_try_scalar(con, "PRAGMA user_version;")
                probes = [
                    ("schema_version(version)", "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1;"),
                    ("schema_migrations(MAX(version))", "SELECT MAX(version) FROM schema_migrations;"),
                    ("migrations(MAX(version))", "SELECT MAX(version) FROM migrations;"),
                    ("meta(schema_version)", "SELECT value FROM meta WHERE key='schema_version' LIMIT 1;"),
                    ("app_meta(schema_version)", "SELECT value FROM app_meta WHERE key='schema_version' LIMIT 1;"),
                    ("settings(schema_version)", "SELECT value FROM settings WHERE key='schema_version' LIMIT 1;"),
                ]
                found: List[Tuple[str, Any]] = []
                for label, sql in probes:
                    v = self._db_try_scalar(con, sql)
                    if v is not None and str(v).strip() != "":
                        found.append((label, v))
            finally:
                try:
                    con.close()
                except Exception:
                    pass

            lines = ["DB version info:", f"DB: {dbp}", ""]
            lines.append(f"PRAGMA user_version = {user_version}")
            lines.append("")
            if found:
                lines.append("Schema version candidates:")
                for label, v in found:
                    lines.append(f"- {label}: {v}")
            else:
                lines.append("Schema version nije nađen kroz tipične tabele/ključeve.")
                lines.append("Napomena: ovo je fail-safe probe (ne zna tvoju internu šemu unapred).")

            self._adv_out_set("\n".join(lines))
            QMessageBox.information(self, "DB info", "Prikazano u output-u.")

            try:
                self.logger.info("DB version info executed (Napredno).")
            except Exception:
                pass
        except Exception as e:
            self._adv_out_set(f"Ne mogu da očitam DB version info.\n\n{e}")
        finally:
            try:
                QApplication.restoreOverrideCursor()
            except Exception:
                pass

    def do_adv_create_log_bundle(self):
        """ZIP: logovi + selfcheck fajlovi + ui_settings + diagnostics.txt"""
        try:
            self.logs_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        suggested = str(self.logs_dir / f"bazas2_log_bundle_{_now_stamp()}.zip")
        path, _ = QFileDialog.getSaveFileName(self, "Sačuvaj Log Bundle ZIP", suggested, "ZIP Files (*.zip)")
        if not path:
            return

        zip_path = Path(path)

        candidates = [
            self.logs_dir / "app.log",
            self.logs_dir / "errors.log",
            self.logs_dir / "selfcheck_report.json",
            self.logs_dir / "pip_install_last.txt",
            self.data_dir / "settings" / "ui_settings.json",
            self.data_dir / "db_path.txt",
        ]

        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            added = 0
            root = _app_root()

            with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
                for fp in candidates:
                    try:
                        if fp.exists() and fp.is_file():
                            try:
                                arc = fp.relative_to(root)
                                arcname = str(arc)
                            except Exception:
                                arcname = fp.name
                            z.write(fp, arcname=arcname)
                            added += 1
                    except Exception:
                        continue

                try:
                    z.writestr("diagnostics.txt", self._build_diagnostics_text())
                    added += 1
                except Exception:
                    pass

            self._adv_out_set(f"Log Bundle kreiran:\n{zip_path}\n\nUbačeno stavki: {added}")
            QMessageBox.information(self, "Log Bundle", f"Kreiran ZIP:\n{zip_path}\n\nUbačeno stavki: {added}")

            try:
                self.logger.info(f"Log Bundle created: {zip_path} (items={added})")
            except Exception:
                pass

        except Exception as e:
            self._adv_out_set(f"Ne mogu da napravim Log Bundle.\n\n{e}")
            QMessageBox.critical(self, "Log Bundle", f"Ne mogu da napravim Log Bundle.\n\n{e}")
        finally:
            try:
                QApplication.restoreOverrideCursor()
            except Exception:
                pass

    # -------------------- TAB builders --------------------
    def _build_tab_account(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        self.grp_account = QGroupBox("Moj nalog (kredencijali)")
        self.grp_account.setCheckable(False)

        self.lbl_cred_state = QLabel("")
        self.lbl_cred_state.setWordWrap(True)
        self.lbl_cred_state.setProperty("muted", True)

        self.in_old_pin = QLineEdit()
        self.in_old_pin.setEchoMode(QLineEdit.Password)
        self.in_old_pin.setPlaceholderText("trenutni PIN")

        self.in_new_pin = QLineEdit()
        self.in_new_pin.setEchoMode(QLineEdit.Password)
        self.in_new_pin.setPlaceholderText("novi PIN (4-8 cifara)")

        self.btn_change_pin = QPushButton("Promeni PIN")

        self.in_old_pw = QLineEdit()
        self.in_old_pw.setEchoMode(QLineEdit.Password)
        self.in_old_pw.setPlaceholderText("trenutna lozinka")

        self.in_new_pw = QLineEdit()
        self.in_new_pw.setEchoMode(QLineEdit.Password)
        self.in_new_pw.setPlaceholderText("nova lozinka (min 6 karaktera)")

        self.btn_change_pw = QPushButton("Promeni lozinku")

        form = QFormLayout()
        form.addRow(QLabel("Status:"), self.lbl_cred_state)
        form.addRow(QLabel("Trenutni PIN:"), self.in_old_pin)
        form.addRow(QLabel("Novi PIN:"), self.in_new_pin)
        form.addRow(QLabel(""), self.btn_change_pin)
        form.addRow(QLabel("Trenutna lozinka:"), self.in_old_pw)
        form.addRow(QLabel("Nova lozinka:"), self.in_new_pw)
        form.addRow(QLabel(""), self.btn_change_pw)

        self.grp_account.setLayout(form)

        self.btn_change_pin.clicked.connect(self.do_change_pin)
        self.btn_change_pw.clicked.connect(self.do_change_password)

        lay.addWidget(self.grp_account)
        lay.addStretch(1)
        return w

    def _build_tab_appearance(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        title = QLabel("Izgled i rad")
        title.setStyleSheet("font-size: 14px; font-weight: 700;")

        info = QLabel(
            "Tema se primenjuje globalno (QSS tokeni) i važi za sve strane.\n"
            "Primena je offline i pamti se lokalno u data/settings/ui_settings.json."
        )
        info.setWordWrap(True)
        info.setProperty("muted", True)

        lay.addWidget(title)
        lay.addWidget(info)
        lay.addSpacing(10)

        # --- Theme picker (ugrađen, bez zavisnosti od posebnog widgeta) ---
        grp = QGroupBox("Tema")
        gl = QVBoxLayout(grp)

        self.lbl_theme_state = QLabel("")
        self.lbl_theme_state.setWordWrap(True)
        self.lbl_theme_state.setProperty("muted", True)

        row = QHBoxLayout()
        self.cb_theme = QComboBox()
        self.cb_theme.setMinimumWidth(280)

        self.btn_theme_apply = QPushButton("Primeni temu")
        self.btn_theme_default = QPushButton("Reset na podrazumevanu")

        row.addWidget(QLabel("Izaberi temu:"))
        row.addWidget(self.cb_theme, 1)
        row.addWidget(self.btn_theme_apply)
        row.addWidget(self.btn_theme_default)
        row.addStretch(1)

        gl.addLayout(row)
        gl.addWidget(self.lbl_theme_state)

        if self._theme_api_ok():
            themes = self._themes_dict()
            # punimo combobox: label + theme_id u data()
            for tid, label in themes.items():
                self.cb_theme.addItem(str(label), str(tid).strip().lower())
            if self.cb_theme.count() == 0:
                self.cb_theme.addItem("Dark (Plava)", "dark_blue")
        else:
            self.cb_theme.addItem("Tema modul nije dostupan", "")
            self.cb_theme.setEnabled(False)
            self.btn_theme_apply.setEnabled(False)
            self.btn_theme_default.setEnabled(False)
            self.lbl_theme_state.setText("Tema: modul nije dostupan. Proveri ui/theme/theme_manager.py")

        self.btn_theme_apply.clicked.connect(self._apply_selected_theme)
        self.btn_theme_default.clicked.connect(self._set_default_theme)

        lay.addWidget(grp)
        lay.addStretch(1)
        return w

    def _build_tab_backup_restore(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        self.lbl_backup_hint = QLabel("")
        self.lbl_backup_hint.setWordWrap(True)
        self.lbl_backup_hint.setProperty("muted", True)

        self.btn_backup = QPushButton("Napravi Backup (ZIP)")
        self.btn_restore_hot = QPushButton("Restore baze (bez restart-a)")
        self.btn_restore_full = QPushButton("FULL Restore (restart + sve)")
        self.btn_open_backups = QPushButton("Otvori folder: backups")
        self.btn_open_logs = QPushButton("Otvori folder: logs")

        self.btn_backup.clicked.connect(self.do_backup)
        self.btn_restore_hot.clicked.connect(self.do_restore_hot)
        self.btn_restore_full.clicked.connect(self.do_restore_full)
        self.btn_open_backups.clicked.connect(lambda: self._open_folder(self.backups_dir))
        self.btn_open_logs.clicked.connect(lambda: self._open_folder(self.logs_dir))

        row1 = QHBoxLayout()
        row1.addWidget(self.btn_backup)
        row1.addWidget(self.btn_restore_hot)
        row1.addWidget(self.btn_restore_full)
        row1.addStretch(1)

        row2 = QHBoxLayout()
        row2.addWidget(self.btn_open_backups)
        row2.addWidget(self.btn_open_logs)
        row2.addStretch(1)

        info = QLabel(
            f"Root:     {_app_root()}\n"
            f"DB:       {DB_FILE}\n"
            f"Data:     {self.data_dir}\n"
            f"Backups:  {self.backups_dir}\n"
            f"Logs:     {self.logs_dir}"
        )
        info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        info.setStyleSheet("font-family: Consolas, monospace;")

        lay.addWidget(self.lbl_backup_hint)
        lay.addSpacing(6)
        lay.addLayout(row1)
        lay.addLayout(row2)
        lay.addSpacing(10)
        lay.addWidget(QLabel("Putanje:"))
        lay.addWidget(info)
        lay.addStretch(1)
        return w

    def _build_tab_about(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        title = QLabel("O aplikaciji")
        title.setStyleSheet("font-size: 14px; font-weight: 700;")

        theme_line = ""
        try:
            if callable(_get_current_theme_id):
                theme_line = f"Tema: {self._get_saved_theme_id()}\n"
        except Exception:
            theme_line = ""

        info = QLabel(
            f"{APP_NAME} — {APP_VERSION}\n"
            "Režim: OFFLINE (bez interneta)\n\n"
            f"{theme_line}"
            f"DB: {DB_FILE}\n"
            f"Root: {_app_root()}\n"
            f"Data: {self.data_dir}\n"
            f"Backups: {self.backups_dir}\n"
            f"Logs: {self.logs_dir}\n"
        )
        info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        info.setStyleSheet("font-family: Consolas, monospace;")

        lay.addWidget(title)
        lay.addWidget(info)
        lay.addStretch(1)
        return w

    def _build_tab_advanced(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        title = QLabel("Napredno (admin/supervizor)")
        title.setStyleSheet("font-size: 14px; font-weight: 700;")

        info = QLabel(
            "PRO alati (offline) za brzo rešavanje problema:\n"
            "- pregled logova (tail)\n"
            "- self-check report viewer\n"
            "- DB integrity_check + DB version info\n"
            "- Log Bundle (ZIP) za slanje/čuvanje dijagnostike\n"
        )
        info.setWordWrap(True)
        info.setProperty("muted", True)

        grp = QGroupBox("Dijagnostika")
        gl = QVBoxLayout(grp)

        row1 = QHBoxLayout()
        self.btn_adv_errors = QPushButton("Prikaži errors.log (poslednjih 200)")
        self.btn_adv_app = QPushButton("Prikaži app.log (poslednjih 200)")
        self.btn_adv_selfcheck = QPushButton("Prikaži self-check report (JSON)")
        self.btn_adv_pip = QPushButton("Prikaži pip_install_last.txt")
        row1.addWidget(self.btn_adv_errors)
        row1.addWidget(self.btn_adv_app)
        row1.addWidget(self.btn_adv_selfcheck)
        row1.addWidget(self.btn_adv_pip)
        gl.addLayout(row1)

        row2 = QHBoxLayout()
        self.btn_adv_db_check = QPushButton("DB integrity_check")
        self.btn_adv_db_info = QPushButton("DB info (schema_version)")
        self.btn_adv_sysinfo = QPushButton("Sistem info")
        self.btn_adv_bundle = QPushButton("Kreiraj Log Bundle (ZIP)")
        row2.addWidget(self.btn_adv_db_check)
        row2.addWidget(self.btn_adv_db_info)
        row2.addWidget(self.btn_adv_sysinfo)
        row2.addWidget(self.btn_adv_bundle)
        gl.addLayout(row2)

        row3 = QHBoxLayout()
        self.btn_adv_open_logs = QPushButton("Otvori folder: logs")
        self.btn_adv_open_data = QPushButton("Otvori folder: data")
        row3.addWidget(self.btn_adv_open_logs)
        row3.addWidget(self.btn_adv_open_data)
        row3.addStretch(1)
        gl.addLayout(row3)

        self.btn_adv_errors.clicked.connect(self.do_adv_view_errors_log)
        self.btn_adv_app.clicked.connect(self.do_adv_view_app_log)
        self.btn_adv_selfcheck.clicked.connect(self.do_adv_view_selfcheck_report)
        self.btn_adv_pip.clicked.connect(self.do_adv_view_pip_last)
        self.btn_adv_db_check.clicked.connect(self.do_adv_db_integrity_check)
        self.btn_adv_db_info.clicked.connect(self.do_adv_db_version_info)
        self.btn_adv_sysinfo.clicked.connect(self.do_adv_show_system_info)
        self.btn_adv_bundle.clicked.connect(self.do_adv_create_log_bundle)
        self.btn_adv_open_logs.clicked.connect(lambda: self._open_folder(self.logs_dir))
        self.btn_adv_open_data.clicked.connect(lambda: self._open_folder(self.data_dir))

        self.adv_out = QPlainTextEdit()
        self.adv_out.setReadOnly(True)
        self.adv_out.setPlaceholderText("Output (logovi, self-check, DB info, dijagnostika) će se prikazati ovde...")
        self.adv_out.setStyleSheet("font-family: Consolas, monospace;")
        gl.addWidget(self.adv_out, 1)

        paths = QLabel(
            f"DB: {DB_FILE}\n"
            f"Logs: {self.logs_dir}\n"
            f"Data: {self.data_dir}\n"
        )
        paths.setTextInteractionFlags(Qt.TextSelectableByMouse)
        paths.setStyleSheet("font-family: Consolas, monospace;")

        lay.addWidget(title)
        lay.addWidget(info)
        lay.addWidget(grp, 1)
        lay.addWidget(QLabel("Putanje (read-only):"))
        lay.addWidget(paths)
        lay.addStretch(1)

        return w

# (FILENAME: ui/settings_page.py - END)  # Part 1/2

# FILENAME: ui/settings_page.py
# (FILENAME: ui/settings_page.py - START)  # Part 2/2

    # -------------------- kredencijali --------------------
    def refresh_cred_status(self):
        try:
            if callable(get_user_credential_flags):
                # actor se uzima iz session-a u servisu (ne verujemo parametru) – ovde prosleđujemo None kao i do sad
                flags = get_user_credential_flags(None) or {}
                has_pin = bool(flags.get("has_pin"))
                has_pw = bool(flags.get("has_password"))
                must_change = int(flags.get("must_change_creds") or 0)

                txt = f"PIN: {'DA' if has_pin else 'NE'} | Lozinka: {'DA' if has_pw else 'NE'}"
                if must_change:
                    txt += "  ⚠️ Moraš promeniti kredencijale (admin reset)."

                self.lbl_cred_state.setText(txt)
                self.lbl_cred_state.setProperty("muted", True)
            else:
                self.lbl_cred_state.setText("Kredencijali: servis nije dostupan.")
                self.lbl_cred_state.setProperty("muted", True)
        except Exception:
            self.lbl_cred_state.setText("Kredencijali: ne mogu da očitam stanje.")
            self.lbl_cred_state.setProperty("muted", True)

    def do_change_pin(self):
        if not callable(change_my_pin):
            QMessageBox.warning(self, "Nije dostupno", "Self-service promena PIN-a nije dostupna.")
            return

        old_pin = (self.in_old_pin.text() or "").strip()
        new_pin = (self.in_new_pin.text() or "").strip()

        if not old_pin or not new_pin:
            QMessageBox.warning(self, "PIN", "Popuni trenutni i novi PIN.")
            return

        # minimalna lokalna validacija (servis je autoritativan)
        if not new_pin.isdigit() or not (4 <= len(new_pin) <= 8):
            QMessageBox.warning(self, "PIN", "Novi PIN mora imati 4–8 cifara.")
            return

        self._set_busy(True)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            ok, msg = change_my_pin(old_pin=old_pin, new_pin=new_pin)
            if ok:
                try:
                    self.logger.info(f"Self PIN change OK: {msg}")
                except Exception:
                    pass
                self.in_old_pin.clear()
                self.in_new_pin.clear()
                self.refresh_cred_status()
                QMessageBox.information(self, "PIN", msg)
            else:
                QMessageBox.warning(self, "PIN", msg)
        except Exception as e:
            QMessageBox.critical(self, "PIN", f"Ne mogu da promenim PIN.\n\n{e}")
        finally:
            try:
                QApplication.restoreOverrideCursor()
            except Exception:
                pass
            self._set_busy(False)

    def do_change_password(self):
        if not callable(change_my_password):
            QMessageBox.warning(self, "Nije dostupno", "Self-service promena lozinke nije dostupna.")
            return

        old_pw = (self.in_old_pw.text() or "")
        new_pw = (self.in_new_pw.text() or "")

        if not old_pw.strip() or not new_pw.strip():
            QMessageBox.warning(self, "Lozinka", "Popuni trenutnu i novu lozinku.")
            return

        # minimalna lokalna validacija (servis je autoritativan)
        if len(new_pw.strip()) < 6:
            QMessageBox.warning(self, "Lozinka", "Nova lozinka mora imati minimum 6 karaktera.")
            return

        self._set_busy(True)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            ok, msg = change_my_password(old_password=old_pw, new_password=new_pw)
            if ok:
                try:
                    self.logger.info(f"Self password change OK: {msg}")
                except Exception:
                    pass
                self.in_old_pw.clear()
                self.in_new_pw.clear()
                self.refresh_cred_status()
                QMessageBox.information(self, "Lozinka", msg)
            else:
                QMessageBox.warning(self, "Lozinka", msg)
        except Exception as e:
            QMessageBox.critical(self, "Lozinka", f"Ne mogu da promenim lozinku.\n\n{e}")
        finally:
            try:
                QApplication.restoreOverrideCursor()
            except Exception:
                pass
            self._set_busy(False)

    # -------------------- Backup/Restore actions --------------------
    def do_backup(self):
        if not self._can_manage_settings():
            QMessageBox.warning(self, "Nema prava", "Nemaš pravo za Backup/Restore (settings.manage).")
            return

        self._set_busy(True)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.backups_dir.mkdir(parents=True, exist_ok=True)
            suggested = str(self.backups_dir / f"bazas2_backup_{_now_stamp()}.zip")
            path, _ = QFileDialog.getSaveFileName(self, "Sačuvaj Backup ZIP", suggested, "ZIP Files (*.zip)")
            if not path:
                return

            zip_path = Path(path)

            # UX: ako korisnik izabere existing zip, pitaj pre overwrite
            if zip_path.exists():
                if QMessageBox.question(
                    self,
                    "Prepisivanje fajla",
                    f"Fajl već postoji:\n{zip_path}\n\nDa li želiš da ga prepišeš?",
                    QMessageBox.Yes | QMessageBox.No
                ) != QMessageBox.Yes:
                    return

            count, _ = create_backup_zip(zip_path)
            try:
                self.logger.info(f"Backup kreiran: {zip_path} (files={count})")
            except Exception:
                pass
            QMessageBox.information(self, "Backup OK", f"Kreiran backup:\n{zip_path}\n\nBroj fajlova: {count}")
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da napravim backup.\n\n{e}")
        finally:
            try:
                QApplication.restoreOverrideCursor()
            except Exception:
                pass
            self._set_busy(False)

    def do_restore_hot(self):
        if not self._can_manage_settings():
            QMessageBox.warning(self, "Nema prava", "Nemaš pravo za Backup/Restore (settings.manage).")
            return

        self._set_busy(True)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.backups_dir.mkdir(parents=True, exist_ok=True)
            path, _ = QFileDialog.getOpenFileName(
                self, "Izaberi Backup ZIP", str(self.backups_dir), "ZIP Files (*.zip)"
            )
            if not path:
                return

            zip_path = Path(path)
            if not zip_path.exists():
                QMessageBox.warning(self, "Restore", "Izabrani fajl ne postoji.")
                return

            ok, msg = hot_restore_db_from_zip(zip_path)
            if ok:
                try:
                    self.logger.info(msg)
                except Exception:
                    pass
                QMessageBox.information(
                    self,
                    "Restore baze OK",
                    f"{msg}\n\nTip: pređi na 'Sredstva' i klikni Osveži (ili promeni tab pa se vrati)."
                )
            else:
                try:
                    self.logger.error(msg)
                except Exception:
                    pass
                QMessageBox.critical(self, "Restore baze nije uspeo", msg)
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Restore baze nije uspeo.\n\n{e}")
        finally:
            try:
                QApplication.restoreOverrideCursor()
            except Exception:
                pass
            self._set_busy(False)

    def do_restore_full(self):
        if not self._can_manage_settings():
            QMessageBox.warning(self, "Nema prava", "Nemaš pravo za Backup/Restore (settings.manage).")
            return

        self._set_busy(True)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.backups_dir.mkdir(parents=True, exist_ok=True)
            path, _ = QFileDialog.getOpenFileName(
                self, "Izaberi Backup ZIP", str(self.backups_dir), "ZIP Files (*.zip)"
            )
            if not path:
                return

            zip_path = Path(path)
            if not zip_path.exists():
                QMessageBox.warning(self, "FULL Restore", "Izabrani fajl ne postoji.")
                return

            safety_zip = self.backups_dir / f"auto_pre_restore_{_now_stamp()}.zip"
            try:
                create_backup_zip(safety_zip)
            except Exception as e:
                QMessageBox.critical(self, "Ne mogu safety backup", f"Ne mogu da napravim safety backup.\n\n{e}")
                return

            dlg = FullRestoreConfirmDialog(zip_path, safety_zip, self)
            if dlg.exec() != QDialog.Accepted:
                return

            ok, msg, pending = stage_full_restore(zip_path)
            if not ok:
                try:
                    self.logger.error(msg)
                except Exception:
                    pass
                QMessageBox.critical(self, "FULL Restore nije zakazan", msg)
                return

            try:
                self.logger.info(f"{msg} pending={pending}")
            except Exception:
                pass

            QMessageBox.information(
                self,
                "FULL Restore zakazan",
                "FULL Restore je zakazan. Aplikacija će sada uraditi kontrolisani restart.\n\n"
                "Posle restarta restore će se automatski primeniti pre otvaranja baze."
            )
            self._restart_process()
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da uradim FULL Restore.\n\n{e}")
        finally:
            try:
                QApplication.restoreOverrideCursor()
            except Exception:
                pass
            self._set_busy(False)

# (FILENAME: ui/settings_page.py - END)  # Part 2/2