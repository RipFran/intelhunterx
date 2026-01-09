from __future__ import annotations

import datetime as dt
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional

from .normalize import build_query_dir_name

DB_META_NAME = "db.json"
QUERY_META_NAME = "query.json"


@dataclass(frozen=True)
class DbLayout:
    root: Path
    queries_dir: Path
    findings_dir: Path
    state_dir: Path


@dataclass(frozen=True)
class QueryInfo:
    query_id: str
    query: str
    normalized_query: str
    content_id: str
    created_at: str
    updated_at: str
    path: Path


def ensure_db_layout(root: Path) -> DbLayout:
    root = root.expanduser().resolve()
    queries_dir = root / "queries"
    findings_dir = root / "findings"
    state_dir = root / "state"
    queries_dir.mkdir(parents=True, exist_ok=True)
    findings_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    _ensure_db_meta(root)
    return DbLayout(root=root, queries_dir=queries_dir, findings_dir=findings_dir, state_dir=state_dir)


def _ensure_db_meta(root: Path) -> None:
    meta_path = root / DB_META_NAME
    if meta_path.exists():
        return
    payload = {
        "version": 1,
        "created_at": dt.datetime.now().isoformat(timespec="seconds"),
    }
    _atomic_json_write(meta_path, payload)


def list_query_dirs(layout: DbLayout) -> Iterable[Path]:
    if not layout.queries_dir.exists():
        return []
    return sorted([p for p in layout.queries_dir.iterdir() if p.is_dir()])


def query_id_from_value(raw: str) -> tuple[str, str]:
    query = raw.strip()
    if not query:
        raise ValueError("empty query")
    return build_query_dir_name(query), query


def load_query_info(query_dir: Path) -> Optional[QueryInfo]:
    meta_path = query_dir / QUERY_META_NAME
    if not meta_path.exists():
        return None
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    query_id = str(data.get("query_id") or query_dir.name)
    query = str(data.get("query") or query_id)
    normalized_query = str(data.get("normalized_query") or query)
    content_id = str(data.get("content_id") or _new_content_id())
    created_at = str(data.get("created_at") or dt.datetime.now().isoformat(timespec="seconds"))
    updated_at = str(data.get("updated_at") or created_at)
    return QueryInfo(
        query_id=query_id,
        query=query,
        normalized_query=normalized_query,
        content_id=content_id,
        created_at=created_at,
        updated_at=updated_at,
        path=query_dir,
    )


def ensure_query_info(
    query_dir: Path,
    query_id: str,
    query: str,
    normalized_query: str,
    content_id: Optional[str] = None,
) -> QueryInfo:
    existing = load_query_info(query_dir)
    if existing:
        return existing
    now = dt.datetime.now().isoformat(timespec="seconds")
    info = QueryInfo(
        query_id=query_id,
        query=query,
        normalized_query=normalized_query,
        content_id=content_id or _new_content_id(),
        created_at=now,
        updated_at=now,
        path=query_dir,
    )
    write_query_info(info)
    return info


def write_query_info(info: QueryInfo, extra: Optional[Dict[str, object]] = None) -> None:
    payload: Dict[str, object] = {
        "query_id": info.query_id,
        "query": info.query,
        "normalized_query": info.normalized_query,
        "content_id": info.content_id,
        "created_at": info.created_at,
        "updated_at": info.updated_at,
    }
    if extra:
        payload.update(extra)
    _atomic_json_write(info.path / QUERY_META_NAME, payload)


def update_query_content_id(info: QueryInfo) -> QueryInfo:
    now = dt.datetime.now().isoformat(timespec="seconds")
    return QueryInfo(
        query_id=info.query_id,
        query=info.query,
        normalized_query=info.normalized_query,
        content_id=_new_content_id(),
        created_at=info.created_at,
        updated_at=now,
        path=info.path,
    )


def _new_content_id() -> str:
    return uuid.uuid4().hex


def _atomic_json_write(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    tmp_path.replace(path)
