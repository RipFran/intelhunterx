from __future__ import annotations

import threading
from typing import Optional

from rich.console import Console
from rich.text import Text


class RichLogger:
    def __init__(self, console: Optional[Console] = None, verbose: bool = False):
        self.console = console or Console()
        self.verbose = verbose
        self._lock = threading.Lock()

    def _emit(self, level: str, msg: str, style: str) -> None:
        with self._lock:
            tag = Text(level.ljust(5), style=style)
            self.console.log(tag, msg)

    def info(self, msg: str) -> None:
        self._emit("INFO", msg, "bold green")

    def warn(self, msg: str) -> None:
        self._emit("WARN", msg, "bold yellow")

    def error(self, msg: str) -> None:
        self._emit("ERROR", msg, "bold red")

    def debug(self, msg: str) -> None:
        if not self.verbose:
            return
        self._emit("DEBUG", msg, "bold blue")

    def done(self, msg: str) -> None:
        self._emit("DONE", msg, "bold cyan")
