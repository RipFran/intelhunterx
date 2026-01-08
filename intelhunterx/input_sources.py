from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, Optional

from .console import RichLogger
from .intelx_exports import IntelXFileMeta

DATA_FILE_EXTENSIONS = {
    ".txt",
    ".csv",
    ".tsv",
    ".psv",
    ".log",
    ".json",
    ".jsonl",
    ".ndjson",
    ".xml",
    ".yaml",
    ".yml",
    ".cfg",
    ".conf",
    ".ini",
    ".dat",
    ".dump",
    ".sql",
    ".lst",
    ".list",
    ".out",
}

HTML_FILE_EXTENSIONS = {".html", ".htm", ".xhtml"}


def detect_text_encoding(sample: bytes) -> str:
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff"):
        return "utf-16"
    return "utf-8"


def is_likely_binary(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    non_printable = 0
    for b in sample[:2048]:
        if b in (9, 10, 13):
            continue
        if 32 <= b <= 126:
            continue
        non_printable += 1
    return (non_printable / max(1, min(len(sample), 2048))) > 0.25


@dataclass(frozen=True)
class InputItem:
    display_name: str
    size_bytes: int
    is_zip_member: bool
    file_path: Optional[Path] = None
    zip_path: Optional[Path] = None
    zip_member: Optional[str] = None
    relative_path: Optional[str] = None
    meta: Optional[IntelXFileMeta] = None

    def open_binary(self) -> io.BufferedReader | io.BytesIO:
        if self.is_zip_member:
            assert self.zip_path is not None and self.zip_member is not None
            zf = zipfile.ZipFile(self.zip_path, "r")
            with zf.open(self.zip_member, "r") as f:
                data = f.read()
            return io.BytesIO(data)
        assert self.file_path is not None
        return open(self.file_path, "rb")


def _item_suffix(item: InputItem) -> str:
    name = ""
    if item.is_zip_member and item.zip_member:
        name = item.zip_member
    elif item.file_path is not None:
        name = item.file_path.name
    else:
        name = item.display_name
    return Path(name).suffix.lower()


def is_data_item(item: InputItem) -> bool:
    suffix = _item_suffix(item)
    if not suffix:
        return False
    if suffix in HTML_FILE_EXTENSIONS:
        return True
    return suffix in DATA_FILE_EXTENSIONS


def _lookup_meta(rel_path: str, metadata: Optional[Dict[str, IntelXFileMeta]]) -> Optional[IntelXFileMeta]:
    if not metadata:
        return None
    normalized = rel_path.replace("\\", "/")
    if normalized in metadata:
        return metadata[normalized]
    if rel_path in metadata:
        return metadata[rel_path]
    name = Path(rel_path).name
    return metadata.get(name)


def iter_input_items(
    input_path: Path,
    follow_symlinks: bool,
    logger: RichLogger,
    metadata: Optional[Dict[str, IntelXFileMeta]] = None,
) -> Iterator[InputItem]:
    if not input_path.exists():
        raise FileNotFoundError(str(input_path))

    if input_path.is_file() and input_path.suffix.lower() == ".zip":
        logger.info(f"Input is a ZIP archive: {input_path}")
        with zipfile.ZipFile(input_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                rel_path = info.filename
                if Path(rel_path).name.lower() == "info.csv":
                    continue
                yield InputItem(
                    display_name=f"{input_path.name}:{info.filename}",
                    size_bytes=info.file_size,
                    is_zip_member=True,
                    zip_path=input_path,
                    zip_member=info.filename,
                    relative_path=rel_path,
                    meta=_lookup_meta(rel_path, metadata),
                )
        return

    if input_path.is_file():
        st = input_path.stat()
        rel_path = input_path.name
        yield InputItem(
            display_name=str(input_path),
            size_bytes=st.st_size,
            is_zip_member=False,
            file_path=input_path,
            relative_path=rel_path,
            meta=_lookup_meta(rel_path, metadata),
        )
        return

    for p in input_path.rglob("*"):
        try:
            if p.is_dir():
                continue
            if (not follow_symlinks) and p.is_symlink():
                continue
            st = p.stat()
            try:
                rel_path = str(p.relative_to(input_path))
            except Exception:
                rel_path = p.name
            if Path(rel_path).name.lower() == "info.csv":
                continue
            yield InputItem(
                display_name=str(p),
                size_bytes=st.st_size,
                is_zip_member=False,
                file_path=p,
                relative_path=rel_path,
                meta=_lookup_meta(rel_path, metadata),
            )
        except Exception as e:
            logger.warn(f"Skipping unreadable path: {p} ({e})")
