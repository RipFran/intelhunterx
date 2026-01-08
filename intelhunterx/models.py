from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Occurrence:
    source: str
    line_no: int
    snippet: str


@dataclass(frozen=True)
class Finding:
    category: str
    value: str
    occurrence: Occurrence
    context: dict[str, object] | None = None
