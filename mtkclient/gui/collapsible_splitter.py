from PySide6.QtCore import Qt
from PySide6.QtWidgets import QSplitter, QSplitterHandle, QToolButton


class CollapsibleSplitterHandle(QSplitterHandle):
    """Splitter handle with a centered ▲/▼ toggle button."""

    def __init__(self, orientation, parent):
        super().__init__(orientation, parent)
        self._collapsed = False
        self._btn = QToolButton(self)
        self._btn.setFixedSize(24, 16)
        self._btn.setText("▲")
        self._btn.clicked.connect(self._toggle)
        self._btn.show()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        bw, bh = self._btn.width(), self._btn.height()
        self._btn.move((self.width() - bw) // 2, (self.height() - bh) // 2)

    def _toggle(self):
        sp = self.splitter()
        sizes = sp.sizes()
        if not sizes:
            return
        if self._collapsed:
            top = sp._stored_top or max(sp.height() // 3, 100)
            sp.setSizes([top, max(0, sizes[1] - top)])
        else:
            sp._stored_top = sizes[0]
            sp.setSizes([0, sizes[0] + sizes[1]])
        self._collapsed = not self._collapsed
        self._btn.setText("▼" if self._collapsed else "▲")

    def set_collapsed(self, collapsed: bool):
        """Sync icon to an externally triggered collapse/expand."""
        if collapsed != self._collapsed:
            self._collapsed = collapsed
            self._btn.setText("▼" if collapsed else "▲")


class CollapsibleSplitter(QSplitter):
    """Vertical QSplitter whose top child can be collapsed via a handle button."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._stored_top = 0
        self.setHandleWidth(20)

    def createHandle(self):
        return CollapsibleSplitterHandle(self.orientation(), self)

    def showEvent(self, event):
        super().showEvent(event)
        if self.count() > 0:
            self.setCollapsible(0, True)

    def collapse_top(self):
        sizes = self.sizes()
        if sizes and sizes[0] != 0:
            self._stored_top = sizes[0]
            self.setSizes([0, sum(sizes)])
        self._sync_handle(True)

    def expand_top(self):
        sizes = self.sizes()
        if sizes and sizes[0] == 0:
            top = self._stored_top or max(self.height() // 3, 100)
            self.setSizes([top, max(0, sum(sizes) - top)])
        self._sync_handle(False)

    def _sync_handle(self, collapsed: bool):
        if self.count() > 1:
            h = self.handle(1)
            if isinstance(h, CollapsibleSplitterHandle):
                h.set_collapsed(collapsed)
