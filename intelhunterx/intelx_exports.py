from __future__ import annotations

import datetime as dt
import csv
import os
import shutil
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import requests

from .console import RichLogger
from .normalize import normalize_host, sanitize_for_fs

DEFAULT_BASE_URL = "https://2.intelx.io"
DEFAULT_USER_AGENT = "intelhunterx/1.0"
DEFAULT_RATE_LIMIT_SECONDS = 1.0
DEFAULT_RESULT_PAGE_SIZE = 200
DEFAULT_MAX_SEGMENTS = 0
DEFAULT_MIN_DATE = "1970-01-01 00:00:00"


class IntelXExportError(RuntimeError):
    pass


class IntelXAuthorizationError(IntelXExportError):
    pass


class IntelXCreditsError(IntelXExportError):
    pass


@dataclass(frozen=True)
class IntelXFileMeta:
    name: str
    date: str
    bucket: str
    media: str
    content_type: str
    size: Optional[int]
    system_id: Optional[str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "date": self.date,
            "bucket": self.bucket,
            "media": self.media,
            "content_type": self.content_type,
            "size": self.size,
            "system_id": self.system_id,
        }


@dataclass(frozen=True)
class ExportBatch:
    search_id: Optional[str]
    zip_path: Path
    extract_dir: Path
    date_from: Optional[str]
    date_to: Optional[str]
    result_count: int
    reused: bool


def read_domains_file(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(str(path))
    domains: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            raw = line.strip()
            if not raw or raw.startswith("#") or raw.startswith("//"):
                continue
            domains.append(raw)
    return domains


def normalize_domain(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("empty domain")
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"invalid domain: {value}")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return normalize_host(host)


def extract_zip(zip_path: Path, extract_dir: Path, logger: RichLogger) -> int:
    extract_dir.mkdir(parents=True, exist_ok=True)
    extracted = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = (extract_dir / info.filename).resolve()
            if not _is_within_directory(extract_dir, target):
                logger.warn(f"Skipping unsafe zip member: {info.filename}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as source, open(target, "wb") as dest:
                shutil.copyfileobj(source, dest)
            extracted += 1
    return extracted


def _is_within_directory(base_dir: Path, target: Path) -> bool:
    try:
        base = base_dir.resolve()
    except FileNotFoundError:
        base = base_dir
    try:
        return os.path.commonpath([str(base), str(target)]) == str(base)
    except ValueError:
        return False


def load_info_metadata(info_path: Path, logger: RichLogger) -> Dict[str, IntelXFileMeta]:
    metadata: Dict[str, IntelXFileMeta] = {}
    if not info_path.exists():
        return metadata

    try:
        with open(info_path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not row:
                    continue
                name = (row.get("Name") or "").strip()
                if not name:
                    continue
                date = (row.get("Date") or "").strip()
                bucket = (row.get("Bucket") or "").strip()
                media = (row.get("Media") or "").strip()
                content_type = (row.get("Content Type") or "").strip()
                size_raw = (row.get("Size") or "").strip()
                system_id = (row.get("System ID") or "").strip()
                try:
                    size_val: Optional[int] = int(size_raw)
                except ValueError:
                    size_val = None
                meta = IntelXFileMeta(
                    name=name,
                    date=date,
                    bucket=bucket,
                    media=media,
                    content_type=content_type,
                    size=size_val,
                    system_id=system_id or None,
                )
                metadata[name] = meta
    except Exception as exc:
        logger.warn(f"Failed to parse Info.csv: {exc}")
    return metadata


def find_info_csv(extract_dir: Path) -> Optional[Path]:
    info_path = extract_dir / "Info.csv"
    if info_path.exists():
        return info_path
    for candidate in extract_dir.rglob("*"):
        try:
            if candidate.is_file() and candidate.name.lower() == "info.csv":
                return candidate
        except Exception:
            continue
    return None


class IntelXClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        user_agent: str = DEFAULT_USER_AGENT,
        rate_limit_seconds: float = DEFAULT_RATE_LIMIT_SECONDS,
    ):
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.user_agent = user_agent.strip() or DEFAULT_USER_AGENT
        self.rate_limit_seconds = max(0.0, rate_limit_seconds)
        self.session = requests.Session()
        self._last_request = 0.0

    def _wait_rate_limit(self) -> None:
        if self.rate_limit_seconds <= 0:
            return
        now = time.time()
        delta = now - self._last_request
        if delta < self.rate_limit_seconds:
            time.sleep(self.rate_limit_seconds - delta)
        self._last_request = time.time()

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        self._wait_rate_limit()
        headers = kwargs.pop("headers", {})
        headers.setdefault("x-key", self.api_key)
        headers.setdefault("User-Agent", self.user_agent)
        try:
            resp = self.session.request(method, f"{self.base_url}{path}", headers=headers, timeout=30, **kwargs)
        except requests.RequestException as exc:
            raise IntelXExportError(f"Network error contacting IntelX: {exc}") from exc

        if resp.status_code == 401:
            raise IntelXAuthorizationError("IntelX API key unauthorized for this operation (401).")
        if resp.status_code == 402:
            raise IntelXCreditsError("IntelX credits exhausted for this function (402).")
        if resp.status_code >= 400:
            raise IntelXExportError(f"IntelX API error {resp.status_code}: {resp.text[:200]}")
        return resp

    def search(
        self,
        term: str,
        maxresults: int,
        buckets: Optional[List[str]] = None,
        timeout: int = 0,
        datefrom: Optional[str] = None,
        dateto: Optional[str] = None,
        sort: int = 4,
        media: int = 0,
        terminate: Optional[List[str]] = None,
    ) -> str:
        payload = {
            "term": term,
            "buckets": buckets or [],
            "lookuplevel": 0,
            "maxresults": maxresults,
            "timeout": timeout,
            "datefrom": datefrom or "",
            "dateto": dateto or "",
            "sort": sort,
            "media": media,
            "terminate": terminate or [],
        }
        resp = self._request("post", "/intelligent/search", json=payload)
        data = resp.json()
        status = data.get("status")
        if status != 0:
            raise IntelXExportError(f"Search failed for {term}: status={status}")
        search_id = data.get("id")
        if not search_id:
            raise IntelXExportError("Search did not return an id.")
        return str(search_id)

    def search_results(self, search_id: str, limit: int = DEFAULT_RESULT_PAGE_SIZE) -> Tuple[int, List[dict]]:
        params = {"id": search_id, "limit": max(1, limit)}
        resp = self._request("get", "/intelligent/search/result", params=params)
        data = resp.json()
        return int(data.get("status", -1)), data.get("records", []) or []

    def terminate(self, search_id: str) -> None:
        self._request("get", "/intelligent/search/terminate", params={"id": search_id})

    def collect_search_results(
        self,
        search_id: str,
        per_page: int = DEFAULT_RESULT_PAGE_SIZE,
        logger: Optional[RichLogger] = None,
        max_polls: int = 240,
        terminate_after: bool = True,
        max_records: Optional[int] = None,
    ) -> tuple[List[dict], int]:
        records: List[dict] = []
        polls = 0
        last_status = -1
        while polls < max_polls:
            status, chunk = self.search_results(search_id, per_page)
            last_status = status
            if chunk:
                records.extend(chunk)
                if max_records is not None and len(records) >= max_records:
                    records = records[:max_records]
                    break
            if status == 1:
                break
            if status not in (0, 3):
                break
            polls += 1
            time.sleep(self.rate_limit_seconds if self.rate_limit_seconds > 0 else 0.5)
        if polls >= max_polls and logger:
            logger.warn(f"Stopping polling for search {search_id}: max polls reached.")
        if terminate_after:
            try:
                self.terminate(search_id)
            except Exception:
                pass
        return records, last_status

    def export_search(self, search_id: str, limit: int, zip_path: Path) -> None:
        params = {"id": search_id, "f": 1, "l": limit, "k": self.api_key}
        resp = self._request("get", "/intelligent/search/export", params=params, stream=True)
        if resp.status_code == 204:
            raise IntelXExportError("Export returned 204 No Content.")
        content_type = resp.headers.get("Content-Type", "").lower()
        if "application/json" in content_type or content_type.startswith("text/"):
            body = resp.text[:500]
            raise IntelXExportError(f"Export returned {content_type}: {body}")

        zip_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = zip_path.with_suffix(zip_path.suffix + ".part")
        with open(tmp_path, "wb") as handle:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    handle.write(chunk)

        if not _looks_like_zip(tmp_path):
            try:
                snippet = tmp_path.read_bytes()[:200].decode("utf-8", errors="replace")
            except Exception:
                snippet = "<unreadable>"
            try:
                tmp_path.unlink()
            except Exception:
                pass
            raise IntelXExportError(f"Export did not return a ZIP archive. Payload starts with: {snippet}")

        tmp_path.replace(zip_path)


def _parse_record_date(record: dict) -> Optional[dt.datetime]:
    raw = record.get("date") or record.get("added")
    if not raw or not isinstance(raw, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _window_label(date_to: Optional[dt.datetime], idx: int) -> str:
    if not date_to:
        return f"seg{idx:02d}"
    return date_to.strftime("%Y%m%d_%H%M%S")


def _looks_like_zip(path: Path) -> bool:
    try:
        if not path.exists() or path.stat().st_size < 4:
            return False
        with open(path, "rb") as handle:
            sig = handle.read(4)
        return sig in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    except Exception:
        return False


def plan_export_batches(
    client: IntelXClient,
    domain: str,
    download_dir: Path,
    logger: RichLogger,
    max_results: int,
    export_limit: Optional[int],
    segment_days: int,
    max_segments: int = DEFAULT_MAX_SEGMENTS,
    reuse_existing: bool = False,
) -> List[ExportBatch]:
    if client is None:
        raise IntelXExportError("IntelX client is not initialized.")
    batches: List[ExportBatch] = []
    date_to: Optional[dt.datetime] = dt.datetime.now(dt.timezone.utc) if segment_days > 0 else None
    segments_run = 0

    while max_segments <= 0 or segments_run < max_segments:
        date_to_str = date_to.strftime("%Y-%m-%d %H:%M:%S") if date_to else ""
        date_from_val: Optional[str] = None
        if segment_days > 0 and date_to:
            start_dt = date_to - dt.timedelta(days=segment_days)
            date_from_val = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        elif segment_days == 0 and date_to is not None:
            # IntelX requires both datefrom and dateto if using date filters.
            date_from_val = DEFAULT_MIN_DATE
        logger.info(f"IntelX search window: datefrom='{date_from_val or ''}' dateto='{date_to_str}'")
        search_id = client.search(
            domain,
            maxresults=max_results,
            datefrom=date_from_val,
            dateto=date_to_str,
            sort=4,
        )
        records = client.collect_search_results(
            search_id,
            per_page=min(DEFAULT_RESULT_PAGE_SIZE, max_results),
            logger=logger,
            terminate_after=False,
            max_records=((export_limit or max_results) + 1) if segment_days == 0 else None,
        )
        sampled_records, last_status = records
        record_count = len(sampled_records)
        logger.info(f"Search {search_id}: collected {record_count} records")

        if record_count == 0:
            logger.warn(f"No results for search window (datefrom='{date_from_val or ''}', dateto='{date_to_str}')")
            client.terminate(search_id)
            break

        label_base = _window_label(date_to, segments_run + 1)
        window_label = label_base if date_to is None else f"{label_base}_seg{segments_run + 1:02d}"
        zip_path = download_dir / f"{sanitize_for_fs(domain)}_{window_label}.zip"
        extract_dir = download_dir / f"{sanitize_for_fs(domain)}_{window_label}_extracted"

        try:
            if zip_path.exists() and reuse_existing:
                reused = True
                logger.info(f"Reusing existing export: {zip_path}")
            else:
                client.export_search(search_id, export_limit or max_results, zip_path)
                reused = False
                logger.info(f"Downloaded export to {zip_path}")
        finally:
            try:
                client.terminate(search_id)
            except Exception:
                pass

        batches.append(
            ExportBatch(
                search_id=search_id,
                zip_path=zip_path,
                extract_dir=extract_dir,
                date_from=date_from_val,
                date_to=date_to_str or None,
                result_count=record_count,
                reused=reused,
            )
        )

        segments_run += 1

        if segment_days > 0:
            if not date_from_val:
                break
            start_dt = _parse_record_date({"date": date_from_val})
            if start_dt is None:
                break
            next_date_to = start_dt - dt.timedelta(seconds=1)
        else:
            export_cap = export_limit or max_results
            has_more = last_status != 1 or record_count > export_cap
            if not has_more:
                break
            boundary_idx = min(export_cap - 1, record_count - 1)
            boundary_dt = _parse_record_date(sampled_records[boundary_idx]) if boundary_idx >= 0 else None
            if boundary_dt is None:
                logger.warn("Could not infer a boundary date from results; stopping segmentation.")
                break
            next_date_to = boundary_dt - dt.timedelta(seconds=1)

        if date_to is not None and next_date_to >= date_to:
            logger.warn(
                f"No further date progress after {date_to_str}; stopping segmentation to avoid repeated windows."
            )
            break
        date_to = next_date_to

    return batches
