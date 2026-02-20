# FILENAME: ui/utils/dialog_responsive.py
# (FILENAME: ui/utils/dialog_responsive.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/utils/dialog_responsive.py

Global "enterprise" dijalog politika:
- Svi naši QDialog prozori postaju resizable (uključuju maximize gde je moguće)
- Pametan minimum (baziran na sizeHint + hard floor)
- Persist geometry (veličina/pozicija + maximized) u QSettings
- Key je stabilan: objectName() ako postoji, inače className()
- Per-user/per-role prefix (ako session API postoji)

Napomena:
- Scrollbar fallback "uvek" se radi kroz ResponsiveDialog (QScrollArea).
  To nije 100% bezbedno automatski nametati postojećim dijalozima bez refaktora.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from PySide6.QtCore import QObject, QEvent, Qt, QRect, QSettings, QByteArray  # type: ignore
from PySide6.QtGui import QGuiApplication  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QApplication,
    QDialog,
    QMessageBox,
    QFileDialog,
    QColorDialog,
    QFontDialog,
    QInputDialog,
    QSizePolicy,
    QWidget,
    QVBoxLayout,
    QScrollArea,
)


def _settings() -> QSettings:
    return QSettings("BazaS2", "BazaS2")


def _session_prefix() -> str:
    """
    Per-user / per-role prefix (best effort).
    Ako ne postoji session modul, vraća prazan prefix.
    """
    actor = ""
    role = ""
    try:
        from core.session import actor_key  # type: ignore
        actor = (actor_key() or "").strip()
    except Exception:
        actor = ""

    # multi-role (best effort)
    for fn_name in ("active_role_key", "active_profile_key", "active_role", "active_profile"):
        try:
            from core import session  # type: ignore
            fn = getattr(session, fn_name, None)
            if callable(fn):
                role = str(fn() or "").strip()
                break
        except Exception:
            continue

    parts = [p for p in (actor, role) if p]
    return "|".join(parts)


def _dialog_key(dlg: QDialog) -> str:
    name = (dlg.objectName() or "").strip()
    if name:
        return name
    try:
        return str(dlg.metaObject().className() or "QDialog")
    except Exception:
        return "QDialog"


def _is_builtin_dialog(dlg: QDialog) -> bool:
    # Ne diramo Qt built-in dijaloge i message box-eve
    return isinstance(dlg, (QMessageBox, QFileDialog, QColorDialog, QFontDialog, QInputDialog))


def _screen_available_rect_for(dlg: QWidget) -> QRect:
    try:
        win = dlg.windowHandle()
        if win and win.screen():
            return win.screen().availableGeometry()
    except Exception:
        pass
    try:
        sc = QGuiApplication.primaryScreen()
        return sc.availableGeometry() if sc else QRect(0, 0, 1920, 1080)
    except Exception:
        return QRect(0, 0, 1920, 1080)


def _clamp_rect(rect: QRect, bounds: QRect) -> QRect:
    w = min(rect.width(), bounds.width())
    h = min(rect.height(), bounds.height())
    x = max(bounds.x(), min(rect.x(), bounds.x() + bounds.width() - w))
    y = max(bounds.y(), min(rect.y(), bounds.y() + bounds.height() - h))
    return QRect(x, y, w, h)


@dataclass(frozen=True)
class DialogPolicy:
    min_size: Tuple[int, int] = (720, 480)
    default_size: Tuple[int, int] = (980, 680)
    enable_maximize: bool = True
    enable_size_grip: bool = True
    persist_geometry: bool = True


def apply_dialog_policy(dlg: QDialog, policy: DialogPolicy) -> None:
    """
    Safe "unlock + resize" pass:
    - skida fixed size (setFixedSize) tako što resetuje min/max
    - uključuje maximize dugme (ako ima smisla)
    - osigurava Expanding sizePolicy
    """
    if dlg is None or not isinstance(dlg, QDialog):
        return
    if _is_builtin_dialog(dlg):
        return

    # opt-out
    try:
        if bool(dlg.property("bazas2_no_autoresize")):
            return
    except Exception:
        pass

    # prevent double-apply
    try:
        if bool(dlg.property("_bazas2_autoresize_applied")):
            return
        dlg.setProperty("_bazas2_autoresize_applied", True)
    except Exception:
        pass

    # Window buttons
    try:
        if policy.enable_maximize:
            dlg.setWindowFlag(Qt.WindowMaximizeButtonHint, True)
            dlg.setWindowFlag(Qt.WindowMinimizeButtonHint, True)
    except Exception:
        pass

    # Size grip
    try:
        if policy.enable_size_grip:
            dlg.setSizeGripEnabled(True)
    except Exception:
        pass

    # Unlock fixed size (override any earlier setFixedSize)
    try:
        dlg.setMaximumSize(16777215, 16777215)
    except Exception:
        pass

    # Smart min based on sizeHint
    try:
        hint = dlg.sizeHint()
        base_w = max(int(hint.width()), int(policy.min_size[0]))
        base_h = max(int(hint.height()), int(policy.min_size[1]))
        dlg.setMinimumSize(base_w, base_h)
    except Exception:
        try:
            dlg.setMinimumSize(int(policy.min_size[0]), int(policy.min_size[1]))
        except Exception:
            pass

    # Ensure layouts can expand
    try:
        dlg.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    except Exception:
        pass


def _geom_group(key: str) -> str:
    return f"ui/dialog_geometry/{key}"


def restore_dialog_geometry(dlg: QDialog, key: str, policy: DialogPolicy) -> None:
    if not policy.persist_geometry:
        # fallback default size
        try:
            dlg.resize(int(policy.default_size[0]), int(policy.default_size[1]))
        except Exception:
            pass
        return

    pref = _session_prefix()
    full_key = f"{pref}::{key}" if pref else key

    s = _settings()
    s.beginGroup(_geom_group(full_key))
    try:
        g = s.value("geometry", None)
        was_max = bool(s.value("maximized", False))
    finally:
        s.endGroup()

    # If no saved geometry -> default size + center
    if not isinstance(g, (QByteArray, bytes)):
        try:
            dlg.resize(int(policy.default_size[0]), int(policy.default_size[1]))
        except Exception:
            pass
        _center_dialog(dlg)
        return

    try:
        ba = g if isinstance(g, QByteArray) else QByteArray(g)
        ok = dlg.restoreGeometry(ba)
        if not ok:
            raise RuntimeError("restoreGeometry returned False")
    except Exception:
        try:
            dlg.resize(int(policy.default_size[0]), int(policy.default_size[1]))
        except Exception:
            pass
        _center_dialog(dlg)
        return

    # Clamp to visible screen
    try:
        bounds = _screen_available_rect_for(dlg)
        r = dlg.frameGeometry()
        r2 = _clamp_rect(r, bounds)
        if r2.topLeft() != r.topLeft() or r2.size() != r.size():
            dlg.setGeometry(r2)
    except Exception:
        pass

    # Restore maximized state (if allowed)
    if policy.enable_maximize and was_max:
        try:
            dlg.setWindowState(dlg.windowState() | Qt.WindowMaximized)
        except Exception:
            pass


def save_dialog_geometry(dlg: QDialog, key: str, policy: DialogPolicy) -> None:
    if not policy.persist_geometry:
        return
    if dlg is None or not isinstance(dlg, QDialog):
        return
    if _is_builtin_dialog(dlg):
        return

    pref = _session_prefix()
    full_key = f"{pref}::{key}" if pref else key

    try:
        geom = dlg.saveGeometry()
    except Exception:
        return

    try:
        is_max = bool(dlg.windowState() & Qt.WindowMaximized)
    except Exception:
        is_max = False

    s = _settings()
    s.beginGroup(_geom_group(full_key))
    try:
        s.setValue("geometry", geom)
        s.setValue("maximized", bool(is_max))
    finally:
        s.endGroup()


def _center_dialog(dlg: QDialog) -> None:
    try:
        parent = dlg.parentWidget()
        if parent:
            pr = parent.frameGeometry()
            r = dlg.frameGeometry()
            r.moveCenter(pr.center())
            dlg.move(r.topLeft())
            return
    except Exception:
        pass
    try:
        bounds = _screen_available_rect_for(dlg)
        r = dlg.frameGeometry()
        r.moveCenter(bounds.center())
        dlg.move(r.topLeft())
    except Exception:
        pass


class DialogAutoResizer(QObject):
    """
    Global event filter:
    - On Show: apply policy + restore geometry
    - On Close/Hide: save geometry
    """
    def __init__(self, policy: Optional[DialogPolicy] = None, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._policy = policy or DialogPolicy()

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        try:
            if not isinstance(obj, QDialog):
                return False
            dlg: QDialog = obj
            if _is_builtin_dialog(dlg):
                return False

            et = event.type()
            if et == QEvent.Show:
                apply_dialog_policy(dlg, self._policy)
                restore_dialog_geometry(dlg, _dialog_key(dlg), self._policy)

            elif et in (QEvent.Close, QEvent.Hide):
                save_dialog_geometry(dlg, _dialog_key(dlg), self._policy)

        except Exception:
            # fail-safe: nikad ne ruši UI
            return False

        return False


def install_dialog_autoresize(app: Optional[QApplication] = None, policy: Optional[DialogPolicy] = None) -> None:
    """
    Pozovi jednom (idealno u app.py posle kreiranja QApplication).
    """
    app = app or QApplication.instance()
    if app is None:
        return

    # prevent duplicate install
    try:
        if bool(app.property("_bazas2_dialog_autoresizer_installed")):
            return
        app.setProperty("_bazas2_dialog_autoresizer_installed", True)
    except Exception:
        pass

    filt = DialogAutoResizer(policy=policy, parent=app)
    app.installEventFilter(filt)

    # keep strong ref (extra safety)
    try:
        app.setProperty("_bazas2_dialog_autoresizer_ref", filt)
    except Exception:
        pass


# ---------- Optional: base class for "always scrollbars" dialogs ----------
class ResponsiveDialog(QDialog):
    """
    Base za dijaloge gde želiš garantovane scrollbars:
    - Body je u QScrollArea (kad prozor postane manji, automatski se pojave scrollbars)
    - Sam dijalog i dalje prati global policy (resizable + persist)
    """
    def __init__(self, title: str, object_name: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setObjectName(object_name)

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)

        self._scroll = QScrollArea(self)
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QScrollArea.NoFrame)

        self._body_host = QWidget(self)
        self._body_layout = QVBoxLayout(self._body_host)
        self._body_layout.setContentsMargins(0, 0, 0, 0)
        self._body_layout.setSpacing(10)

        self._scroll.setWidget(self._body_host)
        root.addWidget(self._scroll, 1)

    def body_layout(self) -> QVBoxLayout:
        return self._body_layout

# (FILENAME: ui/utils/dialog_responsive.py - END)