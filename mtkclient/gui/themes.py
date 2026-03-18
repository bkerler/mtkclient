# MTKClient GUI theme stylesheets
# LIGHT_THEME is an empty string — Qt's native style is used.
# DARK_THEME is a full QSS override targeting every widget class used in the GUI.

LIGHT_THEME = """
/* ── Buttons (light mode) ─────────────────────────────────── */
QPushButton {
    background-color: #4a86c8;
    color: #ffffff;
    border: 1px solid #3a76b8;
    border-radius: 3px;
    padding: 4px 10px;
}
QPushButton:hover {
    background-color: #5a96d8;
}
QPushButton:pressed {
    background-color: #3a76b8;
}
QPushButton:disabled {
    background-color: #b0c4de;
    color: #ffffff;
    border: 1px solid #9ab4ce;
}
"""

DARK_THEME = """
/* ── Base windows ─────────────────────────────────────────── */
QMainWindow, QDialog, QWidget {
    background-color: #2b2b2b;
    color: #ffffff;
}

/* ── Menu bar ─────────────────────────────────────────────── */
QMenuBar {
    background-color: #3c3f41;
    color: #bbbbbb;
}
QMenuBar::item:selected {
    background-color: #4c5052;
}
QMenu {
    background-color: #3c3f41;
    color: #bbbbbb;
    border: 1px solid #555555;
}
QMenu::item:selected {
    background-color: #4c5052;
}

/* ── Tabs ─────────────────────────────────────────────────── */
QTabWidget::pane {
    background-color: #2b2b2b;
    border: 1px solid #555555;
}
QTabBar::tab {
    background-color: #3c3f41;
    color: #bbbbbb;
    padding: 4px 12px;
    border: 1px solid #555555;
    border-bottom: none;
}
QTabBar::tab:selected {
    background-color: #2b2b2b;
    color: #ffffff;
}
QTabBar::tab:hover {
    background-color: #4c5052;
}

/* ── Buttons ──────────────────────────────────────────────── */
QPushButton {
    background-color: #4a86c8;
    color: #ffffff;
    border: 1px solid #3a76b8;
    border-radius: 3px;
    padding: 4px 10px;
}
QPushButton:hover {
    background-color: #5a96d8;
}
QPushButton:pressed {
    background-color: #3a76b8;
}
QPushButton:disabled {
    background-color: #4a4a4a;
    color: #888888;
    border: 1px solid #3a3a3a;
}

/* ── Text areas ───────────────────────────────────────────── */
QPlainTextEdit, QLineEdit {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: 1px solid #555555;
    selection-background-color: #4a86c8;
}

/* ── Labels ───────────────────────────────────────────────── */
QLabel {
    color: #dddddd;
    background-color: transparent;
}

/* ── Checkboxes ───────────────────────────────────────────── */
QCheckBox {
    color: #dddddd;
    background-color: transparent;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    background-color: #5a5a5a;
    border: 1px solid #909090;
    border-radius: 2px;
}
QCheckBox::indicator:checked {
    background-color: #4a86c8;
    border: 1px solid #3a76b8;
}
QCheckBox::indicator:disabled {
    background-color: #3a3a3a;
    border: 1px solid #555555;
}

/* ── Progress bars ────────────────────────────────────────── */
QProgressBar {
    background-color: #3c3f41;
    color: #ffffff;
    border: 1px solid #555555;
    border-radius: 3px;
    text-align: center;
}
QProgressBar::chunk {
    background-color: #4a86c8;
    border-radius: 2px;
}

/* ── Scroll bars ──────────────────────────────────────────── */
QScrollBar:vertical {
    background-color: #3c3f41;
    width: 12px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background-color: #606060;
    min-height: 20px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background-color: #808080;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background-color: #3c3f41;
    height: 12px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background-color: #606060;
    min-width: 20px;
    border-radius: 4px;
}
QScrollBar::handle:horizontal:hover {
    background-color: #808080;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* ── Scroll areas ─────────────────────────────────────────── */
QScrollArea {
    background-color: #2b2b2b;
    border: 1px solid #555555;
}
QScrollArea QWidget {
    background-color: #2b2b2b;
}

/* ── Tables ───────────────────────────────────────────────── */
QTableWidget {
    background-color: #1e1e1e;
    color: #dddddd;
    gridline-color: #555555;
    border: 1px solid #555555;
    selection-background-color: #4a86c8;
}
QHeaderView::section {
    background-color: #3c3f41;
    color: #bbbbbb;
    border: 1px solid #555555;
    padding: 4px;
}

/* ── List widgets ─────────────────────────────────────────── */
QListWidget {
    background-color: #1e1e1e;
    color: #dddddd;
    border: 1px solid #555555;
    selection-background-color: #4a86c8;
}
QListWidget::item:hover {
    background-color: #3c3f41;
}

/* ── Separator frames ─────────────────────────────────────── */
QFrame[frameShape="4"],
QFrame[frameShape="5"] {
    color: #555555;
}
"""
