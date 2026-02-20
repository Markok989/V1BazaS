# FILENAME: ui/dashboard_page.py
# (FILENAME: ui/dashboard_page.py - START)
# -*- coding: utf-8 -*-
"""
BazaS2 (offline) — ui/dashboard_page.py

Dashboard režimi:
- scope_mode="global" -> RBAC + global metrike
    - metrologija GLOBAL: samo za PERM_METRO_MANAGE (admin / referenti)
- scope_mode="my"     -> self-scope metrike (svaki user za opremu koju duži)
- scope_mode="metro"  -> METRO dashboard (sektor): samo metrologija KPI + alarmi
    (bez zaduženja / bez global aktivnosti)

Napomena:
- Fail-closed RBAC: ako can() pukne, tretiramo kao da permisija NE postoji.
- Auto-override: ako je user REFERENT_METRO i scope_mode je "global", prebacujemo na "metro".
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from PySide6.QtCore import QSignalBlocker, Qt  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QApplication,
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QComboBox, QPushButton,
    QTableWidget, QTableWidgetItem, QMessageBox, QGridLayout, QGroupBox,
    QAbstractItemView,
)

from core.session import actor_name, can
from core.rbac import (
    PERM_ASSETS_CREATE,
    PERM_ASSIGN_VIEW, PERM_ASSIGN_CREATE,
    PERM_METRO_VIEW,
    PERM_METRO_EDIT,
    PERM_METRO_MANAGE,
)

from services.dashboard_service import (
    # GLOBAL (scope-aware u servisu)
    get_kpi_counts,
    list_overdue_assignments,
    list_recent_assignments,
    get_metrology_alarm_counts,
    list_metrology_alarms,
    # MY (compat)
    get_my_kpi_counts,
    list_my_overdue_assets,
    list_my_recent_assignments,
    get_my_metrology_alarm_counts,
    list_my_metrology_alarms,
)

from ui.asset_detail_dialog import AssetDetailDialog
from ui.utils.datetime_fmt import fmt_dt_sr, fmt_date_sr
from ui.columns_dialog import ColSpec
from ui.utils.table_columns import wire_columns
from ui.utils.table_copy import (
    wire_table_selection_plus_copy as _wire_copy_sel,
    wire_table_header_plus_copy as _wire_copy_hdr,
)

# -------------------- small helpers --------------------

def _actor_name() -> str:
    return actor_name()


def _safe_int_from_combo(cb: QComboBox, default: int) -> int:
    try:
        return int((cb.currentText() or "").strip())
    except Exception:
        return default


def _wire_table_selection_plus_copy(table: QTableWidget) -> None:
    # FULL CONTROL selekcija + Ctrl+C (TSV)
    try:
        table.setSelectionBehavior(QAbstractItemView.SelectItems)
        table.setSelectionMode(QAbstractItemView.ExtendedSelection)
    except Exception:
        pass

    try:
        _wire_copy_sel(table)
        return
    except Exception:
        pass
    try:
        _wire_copy_hdr(table)
    except Exception:
        pass


def _current_role() -> str:
    """Robusno: aktivna rola iz session-a (multi-role) uz fallback na user dict."""
    try:
        from core.session import active_role  # type: ignore
        r = (active_role() or "").strip().upper()
        if r:
            return r
    except Exception:
        pass

    try:
        from core.session import get_current_user  # type: ignore
        u = get_current_user() or {}
        if isinstance(u, dict):
            return (u.get("role") or u.get("user_role") or "").strip().upper()
        return ""
    except Exception:
        return ""


# -------------------- UI class --------------------

class DashboardPage(QWidget):
    """
    Dashboard može da radi u 3 režima:
    - scope_mode="global" -> koristi RBAC + global metrike
    - scope_mode="my"     -> koristi MY metrike (samo za korisnika), bez "Novo" akcija
    - scope_mode="metro"  -> samo metrologija KPI + alarmi (sektor), bez zaduženja/aktivnosti
    """

    def __init__(
        self,
        logger: logging.Logger,
        on_go_assets: Optional[Callable[[], None]] = None,
        on_go_assign: Optional[Callable[[], None]] = None,
        scope_mode: str = "global",
        parent=None
    ):
        super().__init__(parent)
        self.logger = logger
        self.on_go_assets = on_go_assets
        self.on_go_assign = on_go_assign

        self._refreshing = False  # re-entrancy guard
        self._busy_depth = 0      # robust busy cursor nesting

        sm = (scope_mode or "global").strip().lower()

        # ✅ Auto-override: REFERENT_METRO ne sme da vidi "global" dashboard sadržaj
        if sm == "global" and _current_role() == "REFERENT_METRO":
            sm = "metro"

        self.scope_mode = sm

        self.btn_refresh = QPushButton("Osveži")
        self.btn_new_asset = QPushButton("Novo sredstvo")
        self.btn_new_assign = QPushButton("Novo zaduženje")

        # UX: mali “quality of life”
        try:
            self.btn_refresh.setCursor(Qt.PointingHandCursor)
            self.btn_new_asset.setCursor(Qt.PointingHandCursor)
            self.btn_new_assign.setCursor(Qt.PointingHandCursor)
            self.btn_refresh.setToolTip("Osveži prikaz")
        except Exception:
            pass

        top = QHBoxLayout()
        self.lbl_title = QLabel("Dashboard (V1)")
        self.lbl_title.setStyleSheet("font-size: 18px; font-weight: 600;")
        top.addWidget(self.lbl_title)
        top.addStretch(1)
        top.addWidget(self.btn_refresh)
        top.addWidget(self.btn_new_asset)
        top.addWidget(self.btn_new_assign)

        # KPI (assets)
        self.kpi_total = QLabel("0")
        self.kpi_active = QLabel("0")
        self.kpi_on_loan = QLabel("0")
        self.kpi_service = QLabel("0")
        self.kpi_scrapped = QLabel("0")

        # KPI (metrology)
        self.kpi_met_expiring = QLabel("0")
        self.kpi_met_expired = QLabel("0")

        for w in [
            self.kpi_total, self.kpi_active, self.kpi_on_loan, self.kpi_service, self.kpi_scrapped,
            self.kpi_met_expiring, self.kpi_met_expired
        ]:
            w.setStyleSheet("font-size: 22px; font-weight: 700;")

        kpi_box = QGroupBox("Statistika")
        self.box_kpi = kpi_box
        kpi_grid = QGridLayout(kpi_box)

        self.lbl_kpi_total = QLabel("Ukupno:")
        self.lbl_kpi_active = QLabel("Aktivna:")
        self.lbl_kpi_on_loan = QLabel("Na zaduženju:")
        self.lbl_kpi_service = QLabel("Servis:")
        self.lbl_kpi_scrapped = QLabel("Rashod:")

        kpi_grid.addWidget(self.lbl_kpi_total, 0, 0)
        kpi_grid.addWidget(self.kpi_total, 0, 1)
        kpi_grid.addWidget(self.lbl_kpi_active, 0, 2)
        kpi_grid.addWidget(self.kpi_active, 0, 3)

        kpi_grid.addWidget(self.lbl_kpi_on_loan, 1, 0)
        kpi_grid.addWidget(self.kpi_on_loan, 1, 1)
        kpi_grid.addWidget(self.lbl_kpi_service, 1, 2)
        kpi_grid.addWidget(self.kpi_service, 1, 3)

        kpi_grid.addWidget(self.lbl_kpi_scrapped, 2, 0)
        kpi_grid.addWidget(self.kpi_scrapped, 2, 1)

        # --- MET WARN DAYS (kritičan fix) ---
        # Originalni bug: isti QComboBox je bio ubačen u 2 layout-a -> Qt ga “premesti”.
        # Rešenje: dva combo-a, sinhronizovana.
        self.cb_met_warn_days_kpi = QComboBox()
        self.cb_met_warn_days = QComboBox()

        for cb in (self.cb_met_warn_days_kpi, self.cb_met_warn_days):
            cb.addItems(["7", "14", "30", "60", "90"])
            cb.setCurrentText("30")

        self.lbl_met_expiring = QLabel("Metrologija ističe (≤N dana):")
        self.lbl_met_expired = QLabel("Metrologija isteklo:")
        self.lbl_met_n = QLabel("N (dana):")

        kpi_grid.addWidget(self.lbl_met_expiring, 3, 0)
        kpi_grid.addWidget(self.kpi_met_expiring, 3, 1)
        kpi_grid.addWidget(self.lbl_met_expired, 3, 2)
        kpi_grid.addWidget(self.kpi_met_expired, 3, 3)

        kpi_grid.addWidget(self.lbl_met_n, 4, 0)
        kpi_grid.addWidget(self.cb_met_warn_days_kpi, 4, 1)

        # Overdue (zaduženja)
        self.cb_overdue_days = QComboBox()
        self.cb_overdue_days.addItems(["7", "14", "30", "60", "90"])
        self.cb_overdue_days.setCurrentText("30")

        overdue_box = QGroupBox("Alarmi — zaduženja starija od N dana (bez razduženja)")
        self.box_overdue = overdue_box
        overdue_top = QHBoxLayout()
        overdue_top.addWidget(QLabel("Prag (dana):"))
        overdue_top.addWidget(self.cb_overdue_days)

        self.btn_cols_overdue = QPushButton("Kolone")
        overdue_top.addStretch(1)
        overdue_top.addWidget(self.btn_cols_overdue)

        self.tbl_overdue = QTableWidget(0, 5)
        self.tbl_overdue.setHorizontalHeaderLabels(["Asset UID", "Naziv", "Kod koga", "Datum", "Lokacija"])
        self.tbl_overdue.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_overdue.setAlternatingRowColors(True)
        self.tbl_overdue.horizontalHeader().setStretchLastSection(True)
        try:
            self.tbl_overdue.verticalHeader().setVisible(False)
        except Exception:
            pass
        _wire_table_selection_plus_copy(self.tbl_overdue)

        overdue_lay = QVBoxLayout(overdue_box)
        overdue_lay.addLayout(overdue_top)
        overdue_lay.addWidget(self.tbl_overdue, 1)

        # Recent (zaduženja)
        recent_box = QGroupBox("Poslednje aktivnosti (zaduženja)")
        self.box_recent = recent_box
        recent_top = QHBoxLayout()
        self.btn_cols_recent = QPushButton("Kolone")
        recent_top.addStretch(1)
        recent_top.addWidget(self.btn_cols_recent)

        self.tbl_recent = QTableWidget(0, 6)
        self.tbl_recent.setHorizontalHeaderLabels(["Vreme", "UID", "Naziv", "Akcija", "Od", "Ka"])
        self.tbl_recent.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_recent.setAlternatingRowColors(True)
        self.tbl_recent.horizontalHeader().setStretchLastSection(True)
        try:
            self.tbl_recent.verticalHeader().setVisible(False)
        except Exception:
            pass
        _wire_table_selection_plus_copy(self.tbl_recent)

        recent_lay = QVBoxLayout(recent_box)
        recent_lay.addLayout(recent_top)
        recent_lay.addWidget(self.tbl_recent, 1)

        # Metrologija alarmi
        met_box = QGroupBox("Alarmi — metrologija (isteklo / ističe) — dvoklik otvara sredstvo")
        self.box_met = met_box
        met_top = QHBoxLayout()
        met_top.addWidget(QLabel("Prag (dana):"))
        met_top.addWidget(self.cb_met_warn_days)

        self.btn_cols_met = QPushButton("Kolone")
        met_top.addStretch(1)
        met_top.addWidget(self.btn_cols_met)

        self.tbl_met = QTableWidget(0, 6)
        self.tbl_met.setHorizontalHeaderLabels(["Status", "Met UID", "Asset UID", "Važi do", "Tip", "Izvršilac/Lab"])
        self.tbl_met.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_met.setAlternatingRowColors(True)
        self.tbl_met.horizontalHeader().setStretchLastSection(True)
        try:
            self.tbl_met.verticalHeader().setVisible(False)
        except Exception:
            pass
        _wire_table_selection_plus_copy(self.tbl_met)

        met_lay = QVBoxLayout(met_box)
        met_lay.addLayout(met_top)
        met_lay.addWidget(self.tbl_met, 1)

        main = QVBoxLayout(self)
        main.addLayout(top)
        main.addWidget(kpi_box)

        two = QHBoxLayout()
        two.addWidget(overdue_box, 1)
        two.addWidget(recent_box, 1)
        main.addLayout(two, 1)

        main.addWidget(met_box, 1)

        # signals
        self.btn_refresh.clicked.connect(self.refresh)

        # kontrolisani handleri (da ne pravi duple refresh-e kod combo sync-a)
        self.cb_overdue_days.currentIndexChanged.connect(self._on_overdue_days_changed)
        self.cb_met_warn_days.currentIndexChanged.connect(self._on_met_warn_days_changed)
        self.cb_met_warn_days_kpi.currentIndexChanged.connect(self._on_met_warn_days_changed)

        self.btn_new_asset.clicked.connect(self._go_assets)
        self.btn_new_assign.clicked.connect(self._go_assign)

        self.tbl_met.cellDoubleClicked.connect(self._open_asset_from_met_alarm)

        overdue_specs = [
            ColSpec("asset_uid", "Asset UID", True, 160),
            ColSpec("asset_name", "Naziv", True, 240),
            ColSpec("holder", "Kod koga", True, 160),
            ColSpec("date", "Datum", True, 150),
            ColSpec("location", "Lokacija", True, 160),
        ]
        recent_specs = [
            ColSpec("time", "Vreme", True, 160),
            ColSpec("uid", "UID", True, 160),
            ColSpec("name", "Naziv", True, 220),
            ColSpec("action", "Akcija", True, 120),
            ColSpec("from", "Od", True, 160),
            ColSpec("to", "Ka", True, 160),
        ]
        met_specs = [
            ColSpec("status", "Status", True, 120),
            ColSpec("met_uid", "Met UID", True, 140),
            ColSpec("asset_uid", "Asset UID", True, 160),
            ColSpec("valid_until", "Važi do", True, 140),
            ColSpec("calib_type", "Tip", True, 140),
            ColSpec("provider", "Izvršilac/Lab", True, 200),
        ]

        self._apply_cols_overdue = wire_columns(self, self.tbl_overdue, self.btn_cols_overdue, "dash_overdue_v1", overdue_specs)
        self._apply_cols_recent = wire_columns(self, self.tbl_recent, self.btn_cols_recent, "dash_recent_v1", recent_specs)
        self._apply_cols_met = wire_columns(self, self.tbl_met, self.btn_cols_met, "dash_met_v1", met_specs)

        if self.scope_mode == "my":
            self.lbl_title.setText("Moj Dashboard")
        elif self.scope_mode == "metro":
            self.lbl_title.setText("Dashboard metrologije (sektor)")
        else:
            self.lbl_title.setText("Dashboard (V1)")

        self._apply_rbac()
        self.refresh()

    # -------------------- UX helpers --------------------

    def _set_busy(self, busy: bool) -> None:
        """
        UX: pokaži “busy” kursor i spreči spam klikova dok traje refresh.
        Robustno: podržava ugnježdene pozive.
        """
        try:
            if busy:
                self._busy_depth += 1
                if self._busy_depth == 1:
                    try:
                        QApplication.setOverrideCursor(Qt.WaitCursor)
                    except Exception:
                        pass
                    try:
                        self.btn_refresh.setEnabled(False)
                    except Exception:
                        pass
            else:
                self._busy_depth = max(0, self._busy_depth - 1)
                if self._busy_depth == 0:
                    try:
                        QApplication.restoreOverrideCursor()
                    except Exception:
                        pass
                    try:
                        self.btn_refresh.setEnabled(True)
                    except Exception:
                        pass
        except Exception:
            pass

    # -------------------- RBAC / UI helpers --------------------

    def _can_perm(self, perm: str) -> bool:
        """Fail-closed: ako RBAC pukne -> False."""
        try:
            return bool(can(perm))
        except Exception:
            return False

    def _can_metro_alarm_access(self) -> bool:
        """
        Usklađeno sa servisom:
        - servisi traže metrology.view + (metrology.manage ili metrology.edit)
        """
        return self._can_perm(PERM_METRO_VIEW) and (self._can_perm(PERM_METRO_MANAGE) or self._can_perm(PERM_METRO_EDIT))

    def _set_assets_kpi_na(self) -> None:
        for lab in [self.kpi_total, self.kpi_active, self.kpi_on_loan, self.kpi_service, self.kpi_scrapped]:
            lab.setText("—")

    def _set_met_kpi_na(self) -> None:
        self.kpi_met_expiring.setText("—")
        self.kpi_met_expired.setText("—")

    def _clear_table(self, tbl: QTableWidget) -> None:
        try:
            tbl.setUpdatesEnabled(False)
            tbl.setRowCount(0)
        finally:
            try:
                tbl.setUpdatesEnabled(True)
            except Exception:
                pass

    def _hide_assignments_blocks(self) -> None:
        try:
            self.box_overdue.setVisible(False)
            self.box_recent.setVisible(False)
            self.box_overdue.setEnabled(False)
            self.box_recent.setEnabled(False)
        except Exception:
            pass

    def _show_assignments_blocks(self) -> None:
        try:
            self.box_overdue.setVisible(True)
            self.box_recent.setVisible(True)
        except Exception:
            pass

    def _sync_combo_text(self, src: QComboBox, dst: QComboBox) -> None:
        try:
            t = (src.currentText() or "").strip()
            if not t:
                return
            if (dst.currentText() or "").strip() == t:
                return
            with QSignalBlocker(dst):
                dst.setCurrentText(t)
        except Exception:
            pass

    def _get_met_warn_days(self) -> int:
        # Jedini izvor istine: cb_met_warn_days (met box)
        return _safe_int_from_combo(self.cb_met_warn_days, 30)

    def _on_met_warn_days_changed(self) -> None:
        if self.sender() is self.cb_met_warn_days:
            self._sync_combo_text(self.cb_met_warn_days, self.cb_met_warn_days_kpi)
        elif self.sender() is self.cb_met_warn_days_kpi:
            self._sync_combo_text(self.cb_met_warn_days_kpi, self.cb_met_warn_days)
        self.refresh()

    def _on_overdue_days_changed(self) -> None:
        self.refresh()

    def _apply_rbac(self) -> None:
        # U MY režimu: nema quick akcija uopšte
        if self.scope_mode == "my":
            self.btn_new_asset.setVisible(False)
            self.btn_new_assign.setVisible(False)
            self.btn_new_asset.setEnabled(False)
            self.btn_new_assign.setEnabled(False)
            try:
                self._show_assignments_blocks()
                self.box_overdue.setEnabled(True)
                self.box_recent.setEnabled(True)
                self.box_met.setEnabled(True)
            except Exception:
                pass
            return

        # METRO režim: samo metrologija
        if self.scope_mode == "metro":
            self.btn_new_asset.setVisible(False)
            self.btn_new_assign.setVisible(False)
            self.btn_new_asset.setEnabled(False)
            self.btn_new_assign.setEnabled(False)

            self._hide_assignments_blocks()
            self._set_assets_kpi_na()

            try:
                self.box_met.setEnabled(self._can_metro_alarm_access())
            except Exception:
                pass
            return

        # GLOBAL režim
        try:
            can_assets_create = self._can_perm(PERM_ASSETS_CREATE)
            self.btn_new_asset.setVisible(can_assets_create)
            self.btn_new_asset.setEnabled(can_assets_create)
        except Exception:
            pass

        try:
            can_assign_create = self._can_perm(PERM_ASSIGN_CREATE)
            self.btn_new_assign.setVisible(can_assign_create)
            self.btn_new_assign.setEnabled(can_assign_create)
        except Exception:
            pass

        try:
            can_assign_view = self._can_perm(PERM_ASSIGN_VIEW)
            self._show_assignments_blocks()
            self.box_overdue.setEnabled(can_assign_view)
            self.box_recent.setEnabled(can_assign_view)
        except Exception:
            pass

        # GLOBAL metrologija: VIEW + MANAGE
        try:
            can_metro_global = self._can_perm(PERM_METRO_VIEW) and self._can_perm(PERM_METRO_MANAGE)
            self.box_met.setEnabled(can_metro_global)
        except Exception:
            pass

    def _go_assets(self) -> None:
        if callable(self.on_go_assets):
            self.on_go_assets()

    def _go_assign(self) -> None:
        if callable(self.on_go_assign):
            self.on_go_assign()

    def _open_asset_from_met_alarm(self, r: int, c: int) -> None:
        try:
            if r < 0:
                return
            item = self.tbl_met.item(r, 2)  # Asset UID (logički index)
            asset_uid = item.text().strip() if item else ""
            if not asset_uid:
                return
            dlg = AssetDetailDialog(asset_uid, self)
            dlg.exec()
        except PermissionError as e:
            QMessageBox.information(self, "RBAC", f"Nemaš pravo da otvoriš sredstvo.\n\n{e}")
        except Exception as e:
            QMessageBox.critical(self, "Greška", f"Ne mogu da otvorim detalje sredstva.\n\n{e}")

    # -------------------- Table population helpers --------------------

    def _fill_table(
        self,
        tbl: QTableWidget,
        rows: List[Dict[str, Any]],
        value_builder: Callable[[Dict[str, Any]], List[Any]],
        apply_cols: Optional[Callable[[], None]] = None,
    ) -> None:
        """
        Stabilno i brže punjenje QTableWidget:
        - setRowCount(len)
        - bez insertRow u petlji
        - updates + sorting off tokom fill
        """
        try:
            tbl.setUpdatesEnabled(False)
            try:
                tbl.setSortingEnabled(False)
            except Exception:
                pass

            tbl.setRowCount(len(rows))
            for i, rr in enumerate(rows):
                vals = value_builder(rr)
                max_cols = min(len(vals), tbl.columnCount())
                for cc in range(max_cols):
                    tbl.setItem(i, cc, QTableWidgetItem(str(vals[cc])))

        finally:
            try:
                tbl.setUpdatesEnabled(True)
            except Exception:
                pass
            try:
                tbl.setSortingEnabled(True)
            except Exception:
                pass

        if apply_cols:
            try:
                apply_cols()
            except Exception:
                pass

    # -------------------- Refresh --------------------

    def refresh(self) -> None:
        if self._refreshing:
            return
        self._refreshing = True
        self._set_busy(True)

        errors: List[str] = []
        try:
            # ===== MY SCOPE =====
            if self.scope_mode == "my":
                actor = _actor_name()
                met_warn = self._get_met_warn_days()
                overdue_days = _safe_int_from_combo(self.cb_overdue_days, 30)

                try:
                    kpi = get_my_kpi_counts(actor)
                    self.kpi_total.setText(str(kpi.get("total", 0)))
                    self.kpi_active.setText(str(kpi.get("active", 0)))
                    self.kpi_on_loan.setText(str(kpi.get("on_loan", 0)))
                    self.kpi_service.setText(str(kpi.get("service", 0)))
                    self.kpi_scrapped.setText(str(kpi.get("scrapped", 0)))
                except Exception as e:
                    self._set_assets_kpi_na()
                    errors.append(f"My KPI: {e}")

                try:
                    met_counts = get_my_metrology_alarm_counts(actor, warn_days=met_warn)
                    self.kpi_met_expiring.setText(str(met_counts.get("expiring", 0)))
                    self.kpi_met_expired.setText(str(met_counts.get("expired", 0)))
                except Exception as e:
                    self._set_met_kpi_na()
                    errors.append(f"My Met KPI: {e}")

                try:
                    overdue = list_my_overdue_assets(actor, days=overdue_days, limit=50) or []
                except Exception as e:
                    overdue = []
                    errors.append(f"My Overdue: {e}")

                try:
                    self._fill_table(
                        self.tbl_overdue,
                        overdue,
                        lambda rr: [
                            rr.get("asset_uid", ""),
                            rr.get("asset_name", ""),
                            rr.get("last_to_holder", "") or "",
                            fmt_dt_sr(rr.get("last_created_at", "") or ""),
                            rr.get("location", "") or "",
                        ],
                        apply_cols=self._apply_cols_overdue,
                    )
                except Exception as e:
                    errors.append(f"My Overdue UI: {e}")
                    self._clear_table(self.tbl_overdue)

                try:
                    recent = list_my_recent_assignments(actor, limit=20) or []
                except Exception as e:
                    recent = []
                    errors.append(f"My Recent: {e}")

                try:
                    self._fill_table(
                        self.tbl_recent,
                        recent,
                        lambda rr: [
                            fmt_dt_sr(rr.get("created_at", "")),
                            rr.get("asset_uid", ""),
                            rr.get("asset_name", ""),
                            rr.get("action", ""),
                            rr.get("from_holder", ""),
                            rr.get("to_holder", ""),
                        ],
                        apply_cols=self._apply_cols_recent,
                    )
                except Exception as e:
                    errors.append(f"My Recent UI: {e}")
                    self._clear_table(self.tbl_recent)

                try:
                    met_rows = list_my_metrology_alarms(actor, warn_days=met_warn, limit=50) or []
                except Exception as e:
                    met_rows = []
                    errors.append(f"My Met alarms: {e}")

                try:
                    self._fill_table(
                        self.tbl_met,
                        met_rows,
                        lambda rr: [
                            rr.get("status", ""),
                            rr.get("met_uid", ""),
                            rr.get("asset_uid", ""),
                            fmt_date_sr(rr.get("valid_until", "") or ""),
                            rr.get("calib_type", "") or "",
                            rr.get("provider_name", "") or "",
                        ],
                        apply_cols=self._apply_cols_met,
                    )
                except Exception as e:
                    errors.append(f"My Met table UI: {e}")
                    self._clear_table(self.tbl_met)

                if errors:
                    try:
                        self.logger.error("MyDashboard refresh partial issues: " + " | ".join(errors))
                    except Exception:
                        pass
                return

            # ===== METRO SCOPE =====
            if self.scope_mode == "metro":
                if not self._can_metro_alarm_access():
                    self._set_met_kpi_na()
                    self._clear_table(self.tbl_met)
                    return

                met_warn = self._get_met_warn_days()

                try:
                    met_counts = get_metrology_alarm_counts(warn_days=met_warn)
                    self.kpi_met_expiring.setText(str(met_counts.get("expiring", 0)))
                    self.kpi_met_expired.setText(str(met_counts.get("expired", 0)))
                except PermissionError:
                    self._set_met_kpi_na()
                except Exception as e:
                    self._set_met_kpi_na()
                    errors.append(f"Metro Met KPI: {e}")

                try:
                    met_rows = list_metrology_alarms(warn_days=met_warn, limit=50) or []
                except PermissionError:
                    met_rows = []
                except Exception as e:
                    met_rows = []
                    errors.append(f"Metro Met alarms: {e}")

                try:
                    self._fill_table(
                        self.tbl_met,
                        met_rows,
                        lambda rr: [
                            rr.get("status", ""),
                            rr.get("met_uid", ""),
                            rr.get("asset_uid", ""),
                            fmt_date_sr(rr.get("valid_until", "") or ""),
                            rr.get("calib_type", "") or "",
                            rr.get("provider_name", "") or "",
                        ],
                        apply_cols=self._apply_cols_met,
                    )
                except Exception as e:
                    errors.append(f"Metro Met table UI: {e}")
                    self._clear_table(self.tbl_met)

                if errors:
                    try:
                        self.logger.error("MetroDashboard refresh partial issues: " + " | ".join(errors))
                    except Exception:
                        pass
                return

            # ===== GLOBAL SCOPE =====

            try:
                kpi = get_kpi_counts()
                self.kpi_total.setText(str(kpi.get("total", 0)))
                self.kpi_active.setText(str(kpi.get("active", 0)))
                self.kpi_on_loan.setText(str(kpi.get("on_loan", 0)))
                self.kpi_service.setText(str(kpi.get("service", 0)))
                self.kpi_scrapped.setText(str(kpi.get("scrapped", 0)))
            except PermissionError:
                self._set_assets_kpi_na()
            except Exception as e:
                self._set_assets_kpi_na()
                errors.append(f"KPI: {e}")

            can_assign_view = self._can_perm(PERM_ASSIGN_VIEW)
            overdue_days = _safe_int_from_combo(self.cb_overdue_days, 30)

            if can_assign_view:
                try:
                    overdue = list_overdue_assignments(days=overdue_days, limit=50) or []
                except PermissionError:
                    overdue = []
                except Exception as e:
                    overdue = []
                    errors.append(f"Overdue: {e}")
            else:
                overdue = []

            try:
                self._fill_table(
                    self.tbl_overdue,
                    overdue,
                    lambda rr: [
                        rr.get("asset_uid", ""),
                        rr.get("asset_name", ""),
                        rr.get("last_to_holder", "") or "",
                        fmt_dt_sr(rr.get("last_created_at", "") or ""),
                        rr.get("location", "") or "",
                    ],
                    apply_cols=self._apply_cols_overdue,
                )
            except Exception as e:
                errors.append(f"Overdue UI: {e}")
                self._clear_table(self.tbl_overdue)

            if can_assign_view:
                try:
                    recent = list_recent_assignments(limit=20) or []
                except PermissionError:
                    recent = []
                except Exception as e:
                    recent = []
                    errors.append(f"Recent: {e}")
            else:
                recent = []

            try:
                self._fill_table(
                    self.tbl_recent,
                    recent,
                    lambda rr: [
                        fmt_dt_sr(rr.get("created_at", "")),
                        rr.get("asset_uid", ""),
                        rr.get("asset_name", ""),
                        rr.get("action", ""),
                        rr.get("from_holder", ""),
                        rr.get("to_holder", ""),
                    ],
                    apply_cols=self._apply_cols_recent,
                )
            except Exception as e:
                errors.append(f"Recent UI: {e}")
                self._clear_table(self.tbl_recent)

            met_warn = self._get_met_warn_days()
            can_metro_global = self._can_perm(PERM_METRO_VIEW) and self._can_perm(PERM_METRO_MANAGE)

            if not can_metro_global:
                self._set_met_kpi_na()
                self._clear_table(self.tbl_met)
            else:
                try:
                    met_counts = get_metrology_alarm_counts(warn_days=met_warn)
                    self.kpi_met_expiring.setText(str(met_counts.get("expiring", 0)))
                    self.kpi_met_expired.setText(str(met_counts.get("expired", 0)))
                except PermissionError:
                    self._set_met_kpi_na()
                except Exception as e:
                    self._set_met_kpi_na()
                    errors.append(f"Met KPI: {e}")

                try:
                    met_rows = list_metrology_alarms(warn_days=met_warn, limit=50) or []
                except PermissionError:
                    met_rows = []
                except Exception as e:
                    met_rows = []
                    errors.append(f"Met alarms: {e}")

                try:
                    self._fill_table(
                        self.tbl_met,
                        met_rows,
                        lambda rr: [
                            rr.get("status", ""),
                            rr.get("met_uid", ""),
                            rr.get("asset_uid", ""),
                            fmt_date_sr(rr.get("valid_until", "") or ""),
                            rr.get("calib_type", "") or "",
                            rr.get("provider_name", "") or "",
                        ],
                        apply_cols=self._apply_cols_met,
                    )
                except Exception as e:
                    errors.append(f"Met table UI: {e}")
                    self._clear_table(self.tbl_met)

            if errors:
                try:
                    self.logger.error("Dashboard refresh partial issues: " + " | ".join(errors))
                except Exception:
                    pass

        finally:
            self._set_busy(False)
            self._refreshing = False


# (FILENAME: ui/dashboard_page.py - END)