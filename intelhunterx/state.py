from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable


SEARCH_META_NAME = "search.json"
SCAN_LOG_NAME = "scanned.jsonl"


@dataclass(frozen=True)
class SearchSpec:
    key: str
    selectors: list[str]
    extract: str


def normalize_selectors(selectors: Iterable[str]) -> list[str]:
    normalized = []
    seen = set()
    for raw in selectors:
        value = raw.strip().lower()
        if not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return sorted(normalized)


def build_search_spec(selectors: Iterable[str], extract: str | None) -> SearchSpec:
    normalized = normalize_selectors(selectors)
    extract_mode = extract or "all"
    payload = {"selectors": normalized, "extract": extract_mode}
    digest = hashlib.blake2b(digest_size=16)
    digest.update(json.dumps(payload, sort_keys=True).encode("utf-8"))
    key = digest.hexdigest()
    return SearchSpec(key=key, selectors=normalized, extract=extract_mode)


def ensure_search_dir(state_root: Path, spec: SearchSpec) -> Path:
    search_dir = state_root / "searches" / spec.key
    search_dir.mkdir(parents=True, exist_ok=True)
    meta_path = search_dir / SEARCH_META_NAME
    now = dt.datetime.now().isoformat(timespec="seconds")
    if meta_path.exists():
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        data["updated_at"] = now
        _atomic_json_write(meta_path, data)
        return search_dir
    payload = {
        "version": 1,
        "selectors": spec.selectors,
        "extract": spec.extract,
        "created_at": now,
        "updated_at": now,
    }
    _atomic_json_write(meta_path, payload)
    return search_dir


def load_scan_log(log_path: Path, query_content_ids: Dict[str, str]) -> Dict[str, set[str]]:
    scanned: Dict[str, set[str]] = {qid: set() for qid in query_content_ids}
    if not log_path.exists():
        return scanned
    with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            query_id = str(data.get("query_id") or "")
            content_id = str(data.get("content_id") or "")
            file_id = str(data.get("file") or "")
            if not query_id or not content_id or not file_id:
                continue
            if query_id not in query_content_ids:
                continue
            if query_content_ids[query_id] != content_id:
                continue
            scanned.setdefault(query_id, set()).add(file_id)
    return scanned


class ScanLog:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, query_id: str, content_id: str, file_id: str) -> None:
        payload = {
            "query_id": query_id,
            "content_id": content_id,
            "file": file_id,
            "ts": dt.datetime.now().isoformat(timespec="seconds"),
        }
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
            handle.flush()


def _atomic_json_write(path: Path, payload: Dict[str, object]) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    tmp_path.replace(path)
