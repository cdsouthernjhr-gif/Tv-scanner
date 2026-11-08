"""Run slow service calls (OCR, PDF text extraction, analysis) off the UI thread.

Only service code runs in the worker; all widget updates happen in the
``on_done`` / ``on_error`` callbacks, which Qt delivers on the UI thread.
SQLite access is serialised by the Database lock.
"""
from __future__ import annotations

import logging
import traceback
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

log = logging.getLogger(__name__)
_active: set["_Task"] = set()   # keep references until finished


class _Signals(QObject):
    done = Signal(object)
    failed = Signal(str)


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], Any]):
        super().__init__()
        self.fn = fn
        self.signals = _Signals()
        self.setAutoDelete(False)

    def run(self) -> None:  # worker thread
        try:
            result = self.fn()
        except Exception as exc:
            log.error("Background task failed:\n%s", traceback.format_exc())
            self.signals.failed.emit(str(exc))
        else:
            self.signals.done.emit(result)


def run_async(fn: Callable[[], Any], on_done: Callable[[Any], None],
              on_error: Callable[[str], None] | None = None, busy: list | None = None) -> _Task:
    """Run ``fn`` in the global thread pool. Widgets in ``busy`` are disabled meanwhile."""
    busy = busy or []
    for w in busy:
        w.setEnabled(False)
    task = _Task(fn)

    def finish():
        for w in busy:
            w.setEnabled(True)
        _active.discard(task)

    def ok(result):
        finish()
        on_done(result)

    def bad(msg):
        finish()
        if on_error:
            on_error(msg)

    task.signals.done.connect(ok)
    task.signals.failed.connect(bad)
    _active.add(task)
    QThreadPool.globalInstance().start(task)
    return task


def busy_count() -> int:
    return len(_active)
