from __future__ import annotations

import re
from typing import Iterator

TRAILING_PUNCT = ".,;:!?)]}>'\""


def trim_snippet(text: str, max_len: int = 240) -> str:
    value = text.strip()
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def strip_html_tags(text: str) -> str:
    if "<" not in text or ">" not in text:
        return text
    return re.sub(r"<[^>]{1,500}>", " ", text)


def iter_printable_strings(data: bytes, min_len: int = 6) -> Iterator[str]:
    buf = []
    for b in data:
        if 32 <= b <= 126 or b in (9,):
            buf.append(chr(b))
            continue
        if len(buf) >= min_len:
            yield "".join(buf)
        buf.clear()
    if len(buf) >= min_len:
        yield "".join(buf)


def refang_text(text: str) -> str:
    refanged = text
    refanged = re.sub(r"(?i)\bhxxps\b", "https", refanged)
    refanged = re.sub(r"(?i)\bhxxp\b", "http", refanged)
    refanged = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", refanged)
    refanged = re.sub(r"\[\:\]|\(\:\)", ":", refanged)
    refanged = re.sub(r"(?i)\s+dot\s+", ".", refanged)
    refanged = re.sub(r"(?i)\[(?:at)\]|\((?:at)\)", "@", refanged)
    refanged = re.sub(
        r"(?i)\b([A-Z0-9._%+\-]{1,64})\s+at\s+([A-Z0-9.\-]{1,255}\.[A-Z]{2,63})\b",
        r"\1@\2",
        refanged,
    )
    return refanged
