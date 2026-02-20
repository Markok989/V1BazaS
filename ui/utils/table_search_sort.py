# FILENAME: ui/utils/table_search_sort.py
# (FILENAME: ui/utils/table_search_sort.py - START)
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtWidgets import (  # type: ignore
    QWidget, QHBoxLayout, QLineEdit, QPushButton, QCheckBox, QLabel, QTableWidget, QTableWidgetItem
)

# ------------------------------------------------------------
# SMART SORTING (datum / broj / tekst)
# ------------------------------------------------------------

_RE_ISO_DT = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})(?:\s+(\d{2}):(\d{2})(?::(\d{2}))?)?\s*$")
_RE_DOT_DT = re.compile(r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?\s*$")
_RE_SLASH_DT = re.compile(r"^\s*(\d{1,2})/(\d{1,2})/(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?\s*$")

_RE_NUM_EU = re.compile(r"^\s*[+-]?\d{1,3}(\.\d{3})*(,\d+)?\s*$")  # 1.234,56
_RE_NUM_US = re.compile(r"^\s*[+-]?\d{1,3}(,\d{3})*(\.\d+)?\s*$")  # 1,234.56
_RE_NUM_DOT = re.compile(r"^\s*[+-]?\d+(\.\d+)?\s*$")              # 1234.56
_RE_NUM_COM = re.compile(r"^\s*[+-]?\d+(,\d+)?\s*$")              # 1234,56

# Sort key se čuva u UserRole+1 da ne sudara sa tvojim drugim rolama.
_SORT_ROLE = int(Qt.UserRole) + 1


def _try_parse_datetime(s: str) -> Optional[float]:
    """
    Vraća timestamp (float) ako prepozna datum.
    Podržava:
      - YYYY-MM-DD [HH:MM[:SS]]
      - DD.MM.YYYY [HH:MM[:SS]]
      - DD/MM/YYYY [HH:MM[:SS]]
    """
    if not s:
        return None

    m = _RE_ISO_DT.match(s)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hh = int(m.group(4) or 0)
        mm = int(m.group(5) or 0)
        ss = int(m.group(6) or 0)
        try:
            return datetime(y, mo, d, hh, mm, ss).timestamp()
        except Exception:
            return None

    m = _RE_DOT_DT.match(s)
    if m:
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hh = int(m.group(4) or 0)
        mm = int(m.group(5) or 0)
        ss = int(m.group(6) or 0)
        try:
            return datetime(y, mo, d, hh, mm, ss).timestamp()
        except Exception:
            return None

    m = _RE_SLASH_DT.match(s)
    if m:
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hh = int(m.group(4) or 0)
        mm = int(m.group(5) or 0)
        ss = int(m.group(6) or 0)
        try:
            return datetime(y, mo, d, hh, mm, ss).timestamp()
        except Exception:
            return None

    return None


def _try_parse_number(s: str) -> Optional[float]:
    """
    Vraća float ako prepozna broj u EU/US/neutral formatu.
    """
    if not s:
        return None

    t = s.strip().replace(" ", "")
    try:
        if _RE_NUM_EU.match(t):
            # 1.234,56 -> 1234.56
            t2 = t.replace(".", "").replace(",", ".")
            return float(t2)
        if _RE_NUM_US.match(t):
            # 1,234.56 -> 1234.56
            t2 = t.replace(",", "")
            return float(t2)
        if _RE_NUM_DOT.match(t):
            return float(t)
        if _RE_NUM_COM.match(t):
            return float(t.replace(",", "."))
    except Exception:
        return None
    return None


def smart_sort_key(text: str) -> Tuple[int, object]:
    """
    Tip-rang:
      0 = datum/vreme (timestamp)
      1 = broj (float)
      2 = tekst (casefold)
    """
    s = (text or "").strip()
    if not s:
        return (2, "")  # prazno ide “na vrh” među tekstovima, ali stabilno

    dt = _try_parse_datetime(s)
    if dt is not None:
        return (0, dt)

    num = _try_parse_number(s)
    if num is not None:
        return (1, num)

    return (2, s.casefold())


class SmartTableWidgetItem(QTableWidgetItem):
    """
    QTableWidgetItem koji sortira po upisanom sort-key (UserRole+1),
    a fallback je tekst.
    """
    def __lt__(self, other: "QTableWidgetItem") -> bool:  # type: ignore[override]
        try:
            a = self.data(_SORT_ROLE)
            b = other.data(_SORT_ROLE)
            if a is None:
                a = smart_sort_key(self.text())
            if b is None:
                b = smart_sort_key(other.text())

            # a i b su tuple(int, val)
            if isinstance(a, tuple) and isinstance(b, tuple) and len(a) == 2 and len(b) == 2:
                if a[0] != b[0]:
                    return a[0] < b[0]
                return a[1] < b[1]
        except Exception:
            pass
        return super().__lt__(other)


def make_item(text: str, *, sort_key: Optional[Tuple[int, object]] = None) -> SmartTableWidgetItem:
    it = SmartTableWidgetItem(text or "")
    it.setData(_SORT_ROLE, sort_key if sort_key is not None else smart_sort_key(text or ""))
    return it


# ------------------------------------------------------------
# SEARCH / FILTER (radi nad QTableWidget: hideRow)
# ------------------------------------------------------------

def _tokenize(q: str) -> List[str]:
    t = (q or "").strip().casefold()
    if not t:
        return []
    # razdvoj po whitespace, ali ignoriši prazno
    return [x for x in re.split(r"\s+", t) if x]


def table_row_texts(tbl: QTableWidget, row: int, cols: Optional[Sequence[int]] = None) -> List[str]:
    out: List[str] = []
    use_cols = list(cols) if cols is not None else list(range(tbl.columnCount()))
    for c in use_cols:
        it = tbl.item(row, c)
        if it is None:
            continue
        out.append((it.text() or "").casefold())
    return out


def apply_table_filter(tbl: QTableWidget, query: str, cols: Optional[Sequence[int]] = None) -> None:
    tokens = _tokenize(query)
    rc = tbl.rowCount()

    if not tokens:
        for r in range(rc):
            tbl.setRowHidden(r, False)
        return

    for r in range(rc):
        texts = table_row_texts(tbl, r, cols=cols)
        hay = " | ".join(texts)
        ok = True
        for tok in tokens:
            if tok not in hay:
                ok = False
                break
        tbl.setRowHidden(r, not ok)


# ------------------------------------------------------------
# TOOLBAR WIDGET (Search + Clear + Sort toggle)
# ------------------------------------------------------------

@dataclass
class TableToolsConfig:
    placeholder: str = "Pretraga… (npr: pera 1234567890123 sektor)"
    show_sort_toggle: bool = True
    default_sort_enabled: bool = True
    filter_columns: Optional[Sequence[int]] = None  # None = sve kolone
    on_sort_toggled: Optional[Callable[[bool], None]] = None


class TableToolsBar(QWidget):
    """
    Univerzalna traka iznad tabele:
    - Search + Clear
    - Sort toggle (uključi/isključi)
    """
    def __init__(self, tbl: QTableWidget, config: Optional[TableToolsConfig] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.tbl = tbl
        self.cfg = config or TableToolsConfig()

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)

        self.lb = QLabel("Filter:")
        lay.addWidget(self.lb)

        self.ed = QLineEdit()
        self.ed.setPlaceholderText(self.cfg.placeholder)
        lay.addWidget(self.ed, 1)

        self.btn_clear = QPushButton("X")
        self.btn_clear.setToolTip("Očisti pretragu")
        self.btn_clear.setFixedWidth(32)
        lay.addWidget(self.btn_clear)

        self.chk_sort = QCheckBox("Sort")
        self.chk_sort.setToolTip("Uključi sortiranje kolona (pametno: datum/broj/tekst)")
        self.chk_sort.setVisible(bool(self.cfg.show_sort_toggle))
        lay.addWidget(self.chk_sort)

        lay.addStretch(0)

        # wiring
        self.ed.textChanged.connect(self._on_text_changed)
        self.btn_clear.clicked.connect(self._clear)
        self.chk_sort.toggled.connect(self._on_sort_toggled)

        # init
        self.chk_sort.setChecked(bool(self.cfg.default_sort_enabled))
        self.tbl.setSortingEnabled(bool(self.cfg.default_sort_enabled))

    def _on_text_changed(self, text: str) -> None:
        apply_table_filter(self.tbl, text, cols=self.cfg.filter_columns)

    def _clear(self) -> None:
        self.ed.setText("")

    def _on_sort_toggled(self, on: bool) -> None:
        try:
            self.tbl.setSortingEnabled(bool(on))
        except Exception:
            pass
        if self.cfg.on_sort_toggled:
            try:
                self.cfg.on_sort_toggled(bool(on))
            except Exception:
                pass


# (FILENAME: ui/utils/table_search_sort.py - END)