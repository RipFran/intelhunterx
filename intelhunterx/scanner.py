from __future__ import annotations

import csv
import io
from typing import Dict, List

from .console import RichLogger
from .extractors import extract_from_text
from .input_sources import InputItem, detect_text_encoding, is_data_item, is_likely_binary
from .results import CategorySink, ResultStore
from .selector import SelectorContext
from .text_utils import iter_printable_strings


class Scanner:
    def __init__(
        self,
        selector_ctx: SelectorContext,
        store: ResultStore,
        sink: CategorySink,
        logger: RichLogger,
        selector_filter: bool = False,
        include_emails: bool = True,
        include_surface: bool = True,
        include_credentials: bool = True,
        extra_stores: List[ResultStore] | None = None,
        relevance_window: int = 0,
        max_line_len: int = 200000,
        max_file_mb: int = 25,
    ):
        self.selector_ctx = selector_ctx
        self.matcher = selector_ctx.matcher
        self.store = store
        self.sink = sink
        self.logger = logger
        self.selector_filter = selector_filter
        self.include_emails = include_emails
        self.include_surface = include_surface
        self.include_credentials = include_credentials
        self.extra_stores = extra_stores or []
        self.relevance_window = max(0, relevance_window)
        self.max_line_len = max(1024, max_line_len)
        self.max_file_bytes = max(1, max_file_mb) * 1024 * 1024

    def _process_relevant_line(self, line: str, source: str, line_no: int, meta) -> int:
        new_count = 0
        for f in extract_from_text(
            line,
            source,
            line_no,
            self.selector_ctx,
            include_emails=self.include_emails,
            include_surface=self.include_surface,
            include_credentials=self.include_credentials,
        ):
            if f.category == "credentials":
                for extra_store in self.extra_stores:
                    extra_store.add_credential(f, meta=meta)
                if self.store.add_credential(f, meta=meta):
                    self.sink.write_unique(f, meta=meta)
                    new_count += 1
                continue
            for extra_store in self.extra_stores:
                extra_store.add(f, meta=meta)
            if self.store.add(f, meta=meta):
                self.sink.write_unique(f, meta=meta)
                new_count += 1
        return new_count

    def scan_item(self, item: InputItem) -> Dict[str, int]:
        stats = {
            "lines": 0,
            "relevant_lines": 0,
            "new_findings": 0,
            "skipped": 0,
        }

        meta = getattr(item, "meta", None)
        if not is_data_item(item) and meta is None:
            self.logger.debug(f"Skipping non-data file: {item.display_name}")
            stats["skipped"] += 1
            return stats

        if item.size_bytes == 0:
            self.logger.debug(f"Empty file: {item.display_name}")
            stats["skipped"] += 1
            return stats

        if item.size_bytes > self.max_file_bytes:
            self.logger.warn(f"Skipping too-large file ({item.size_bytes} bytes): {item.display_name}")
            stats["skipped"] += 1
            return stats

        try:
            with item.open_binary() as bf:
                sample = bf.read(4096)
                bf.seek(0)
                sample_is_binary = is_likely_binary(sample) and not self._meta_says_text(meta)

                if sample_is_binary:
                    stats["lines"] = 0
                    relevance_budget = 0
                    buf = sample + bf.read(self.max_file_bytes - len(sample))
                    for idx, text in enumerate(iter_printable_strings(buf), start=1):
                        stats["lines"] += 1
                        if not text:
                            continue
                        chunk = text[: self.max_line_len]
                        is_relevant, relevance_budget = self._should_process(chunk, relevance_budget)
                        if not is_relevant:
                            continue
                        stats["relevant_lines"] += 1
                        stats["new_findings"] += self._process_relevant_line(
                            chunk, item.display_name, idx, meta
                        )
                    return stats

                enc = detect_text_encoding(sample)
                tf = io.TextIOWrapper(bf, encoding=enc, errors="replace", newline="")
                relevance_budget = 0

                is_csv = item.display_name.lower().endswith(".csv")

                if is_csv:
                    try:
                        bf.seek(0)
                        tf2 = io.TextIOWrapper(bf, encoding=enc, errors="replace", newline="")
                        reader = csv.reader(tf2)
                        for row_no, row in enumerate(reader, start=1):
                            stats["lines"] += 1
                            line = " , ".join(cell.strip() for cell in row if cell is not None)
                            if not line:
                                continue
                            if len(line) > self.max_line_len:
                                line = line[: self.max_line_len]
                            is_relevant, relevance_budget = self._should_process(line, relevance_budget)
                            if not is_relevant:
                                continue

                            stats["relevant_lines"] += 1
                            stats["new_findings"] += self._process_relevant_line(
                                line, item.display_name, row_no, meta
                            )
                        return stats
                    except Exception:
                        bf.seek(0)
                        tf = io.TextIOWrapper(bf, encoding=enc, errors="replace", newline="")

                for line_no, line in enumerate(tf, start=1):
                    stats["lines"] += 1
                    raw = line.rstrip("\n\r")

                    if len(raw) > self.max_line_len:
                        chunk_size = self.max_line_len
                        overlap = 256
                        chunks = []
                        start = 0
                        while start < len(raw):
                            end = min(len(raw), start + chunk_size)
                            chunks.append(raw[start:end])
                            if end == len(raw):
                                break
                            start = max(0, end - overlap)
                    else:
                        chunks = [raw]

                    for chunk in chunks:
                        is_relevant, relevance_budget = self._should_process(chunk, relevance_budget)
                        if not is_relevant:
                            continue

                        stats["relevant_lines"] += 1
                        stats["new_findings"] += self._process_relevant_line(chunk, item.display_name, line_no, meta)

                return stats

        except Exception as e:
            self.logger.warn(f"Failed to scan {item.display_name}: {e}")
            stats["skipped"] += 1
            return stats

    def _should_process(self, text: str, relevance_budget: int) -> tuple[bool, int]:
        if not self.selector_filter:
            return True, relevance_budget
        matched = self.matcher.matches(text)
        if matched:
            relevance_budget = self.relevance_window
        elif relevance_budget > 0:
            relevance_budget -= 1
        return matched or relevance_budget > 0, relevance_budget

    def _meta_says_text(self, meta) -> bool:
        if meta is None:
            return False
        try:
            content_type = (meta.content_type or "").lower()
        except AttributeError:
            content_type = ""
        try:
            media = (meta.media or "").lower()
        except AttributeError:
            media = ""
        if any(keyword in content_type for keyword in ("text", "csv", "json", "xml", "sql", "config", "log")):
            return True
        if any(keyword in media for keyword in ("text", "paste", "url", "forum", "pdf", "excel", "word", "database")):
            return True
        return False
