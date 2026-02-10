from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table

from .console import RichLogger
from .database import QueryInfo, ensure_db_layout, list_query_dirs, query_id_from_value, update_query_content_id, write_query_info
from .input_sources import InputItem, iter_input_items
from .results import CategorySink, ResultStore, ResultWriter, load_findings
from .scanner import Scanner
from .selector import build_selector_contexts
from .state import ScanLog, build_search_spec, ensure_search_dir, load_scan_log

DEFAULT_MAX_LINE_LEN = 200000
DEFAULT_MAX_FILE_MB = 25
DEFAULT_RELEVANCE_WINDOW = 0
DEFAULT_MAX_RESULTS = 1000
DEFAULT_MAX_SEGMENTS = 0
DEFAULT_SEGMENT_TMP_SUFFIX = ".__extracting__"
DEFAULT_DOWNLOAD_META_VERSION = 1


def default_thread_count() -> int:
    return min(32, (os.cpu_count() or 4) + 4)


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="intelhunterx",
        description="Download IntelX exports into a local database and search them in separate runs.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    dl = sub.add_parser(
        "download",
        help="Download IntelX exports into a database folder.",
    )
    dl.add_argument("--db", required=True, help="Database root folder.")
    dl.add_argument(
        "--query",
        required=True,
        help="IntelX search query or a file containing one query per line.",
    )
    dl.add_argument(
        "--update",
        action="store_true",
        help="Replace existing query data in the database.",
    )
    dl.add_argument(
        "--segment-days",
        type=int,
        default=0,
        help="Only download documents from the last N days (0 = unlimited history).",
    )
    dl.add_argument(
        "--max-segments",
        type=int,
        default=DEFAULT_MAX_SEGMENTS,
        help="Safety cap on segmented searches per query (0 = unlimited, default: 0).",
    )
    dl.add_argument(
        "--max-results",
        type=int,
        default=DEFAULT_MAX_RESULTS,
        help="Max IntelX results per search (default: 1000).",
    )
    dl.add_argument(
        "--export-limit",
        type=int,
        default=None,
        help="Max results per export ZIP (default: --max-results).",
    )
    dl.add_argument(
        "--api-key",
        help="IntelX API key (UUID). You can also set INTELX_API_KEY env var.",
    )
    dl.add_argument(
        "--base-url",
        default="https://2.intelx.io",
        help="IntelX API base URL (paid commonly uses 2.intelx.io).",
    )
    dl.add_argument(
        "--user-agent",
        default="intelhunterx/1.0",
        help="User-Agent header (required by IntelX).",
    )
    dl.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logs")

    search = sub.add_parser(
        "search",
        help="Search existing database documents for selectors.",
    )
    search.add_argument("--db", required=True, help="Database root folder.")
    search.add_argument(
        "--selector",
        action="append",
        required=True,
        help="Selector(s) to search for (repeat or provide a file with one selector per line).",
    )
    search.add_argument(
        "--query",
        help="Limit search to a query or a file containing one query per line.",
    )
    search.add_argument(
        "--threads",
        type=int,
        default=default_thread_count(),
        help="Worker threads for scanning (default: auto).",
    )
    search.add_argument(
        "--extract",
        choices=("credentials", "emails", "surface"),
        help="Limit extraction to: credentials, emails, or surface (endpoints/hostnames/assets).",
    )
    search.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logs")

    return ap


def _resolve_api_key(explicit: str | None) -> str | None:
    if explicit and explicit.strip():
        return explicit.strip()
    for key in ("INTELX_API_KEY", "INTELX_APIKEY", "INTELX_KEY"):
        value = os.environ.get(key, "")
        if value.strip():
            return value.strip()
    return None


def _collect_queries(raw_queries: Iterable[str], logger: RichLogger) -> List[str]:
    queries: List[str] = []
    seen: set[str] = set()
    for raw in raw_queries:
        value = raw.strip()
        if not value:
            continue
        try:
            query_id, _ = query_id_from_value(value)
        except ValueError:
            logger.warn(f"Skipping invalid query entry: {raw}")
            continue
        if query_id in seen:
            continue
        seen.add(query_id)
        queries.append(value)
    return queries


def _collect_selectors(raw_selectors: Iterable[str]) -> List[str]:
    selectors: List[str] = []
    seen: set[str] = set()
    for raw in raw_selectors:
        value = raw.strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        selectors.append(value)
    return selectors


def _read_selector_inputs(
    values: Iterable[str],
    read_list_file,
) -> tuple[List[str], List[Path]]:
    raw_selectors: List[str] = []
    selector_files: List[Path] = []
    for raw in values:
        if not raw:
            continue
        value = raw.strip()
        if not value:
            continue
        path = Path(value).expanduser()
        if path.exists():
            if path.is_dir():
                raise ValueError(f"--selector path is a directory, expected file or selector: {path}")
            try:
                raw_selectors.extend(read_list_file(path))
            except Exception as exc:
                raise ValueError(f"Failed to read selector file {path}: {exc}") from exc
            selector_files.append(path.resolve())
        else:
            raw_selectors.append(value)
    return raw_selectors, selector_files


def _read_query_inputs(value: str, read_list_file) -> tuple[List[str], Optional[Path]]:
    raw_queries: List[str] = []
    query_file: Optional[Path] = None
    query_value = value.strip()
    if not query_value:
        return raw_queries, query_file
    query_path = Path(query_value).expanduser()
    if query_path.exists():
        if query_path.is_dir():
            raise ValueError(f"--query path is a directory, expected file or query: {query_path}")
        query_file = query_path.resolve()
        raw_queries.extend(read_list_file(query_file))
    else:
        raw_queries.append(query_value)
    return raw_queries, query_file


@dataclass(frozen=True)
class ScanTask:
    item: InputItem
    query_id: str
    content_id: str
    file_id: str


def _clone_item(item: InputItem, display_name: str) -> InputItem:
    return InputItem(
        display_name=display_name,
        size_bytes=item.size_bytes,
        is_zip_member=item.is_zip_member,
        file_path=item.file_path,
        zip_path=item.zip_path,
        zip_member=item.zip_member,
        relative_path=item.relative_path,
        meta=item.meta,
    )


def _build_file_id(query_dir: Path, segment_dir: Path, item: InputItem) -> str:
    rel_segment = segment_dir.relative_to(query_dir).as_posix()
    rel_path = item.relative_path or Path(item.display_name).name
    rel_path = rel_path.replace("\\", "/")
    return f"{rel_segment}/{rel_path}"


def _build_source_label(query_id: str, file_id: str) -> str:
    return (Path("queries") / query_id / Path(file_id)).as_posix()


def _scan_tasks(
    tasks: List[ScanTask],
    scanner: Scanner,
    threads: int,
    console: Console,
    logger: RichLogger,
    verbose: bool,
    scan_log: ScanLog,
) -> Dict[str, int]:
    stats = {
        "files_total": len(tasks),
        "files_skipped_scan": 0,
        "new_findings_unique_written": 0,
    }
    if not tasks:
        return stats

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold]Scanning files"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    )

    with progress:
        task_id = progress.add_task("scan", total=len(tasks))
        with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
            future_map = {executor.submit(scanner.scan_item, task.item): task for task in tasks}
            for future in as_completed(future_map):
                task = future_map[future]
                try:
                    file_stats = future.result()
                except Exception as exc:
                    logger.warn(f"Failed to scan {task.item.display_name}: {exc}")
                    stats["files_skipped_scan"] += 1
                    progress.advance(task_id)
                    continue

                skipped = file_stats.get("skipped", 0)
                stats["files_skipped_scan"] += skipped
                stats["new_findings_unique_written"] += file_stats.get("new_findings", 0)
                if skipped == 0:
                    scan_log.record(task.query_id, task.content_id, task.file_id)
                if verbose and file_stats.get("new_findings", 0) > 0:
                    logger.debug(
                        f"Hit {task.item.display_name}: new={file_stats.get('new_findings', 0)}, "
                        f"relevant_lines={file_stats.get('relevant_lines', 0)}"
                    )
                progress.advance(task_id)

    return stats


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _fmt_intelx_dt(value: dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_intelx_dt(value: str) -> Optional[dt.datetime]:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        parsed = dt.datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return parsed.replace(tzinfo=dt.timezone.utc)


def _load_json_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _looks_like_zip(path: Path) -> bool:
    try:
        if not path.exists() or path.stat().st_size < 4:
            return False
        with open(path, "rb") as handle:
            sig = handle.read(4)
        return sig in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    except Exception:
        return False


def _cleanup_segment_artifacts(segments_dir: Path, segment_name: Optional[str], logger: RichLogger) -> None:
    if not segments_dir.exists():
        return

    # Best-effort cleanup for interruptions (Ctrl+C) leaving partial ZIPs or temp extraction folders behind.
    patterns = ["*.zip.part"]
    if segment_name:
        patterns.extend([f"{segment_name}.zip.part", f"{segment_name}{DEFAULT_SEGMENT_TMP_SUFFIX}"])

    # Remove `.zip.part` files.
    for glob_pat in patterns:
        try:
            for candidate in segments_dir.glob(glob_pat):
                if candidate.is_file():
                    candidate.unlink(missing_ok=True)
                elif candidate.is_dir() and candidate.name.endswith(DEFAULT_SEGMENT_TMP_SUFFIX):
                    shutil.rmtree(candidate, ignore_errors=True)
        except Exception:
            continue


def _segment_dir_is_complete(segment_dir: Path) -> bool:
    if not segment_dir.exists() or not segment_dir.is_dir():
        return False
    marker = segment_dir / ".ihx_complete"
    if marker.exists():
        return True
    # Backwards-compat: older versions do not write markers; treat non-empty dirs as complete.
    try:
        for candidate in segment_dir.rglob("*"):
            if candidate.is_file():
                return True
            # If it's a directory, keep going.
        return False
    except Exception:
        # If we cannot reliably inspect it, err on the side of "complete" to avoid deleting data.
        return True


def _extract_zip_atomic(zip_path: Path, final_dir: Path, logger: RichLogger, extract_zip) -> int:
    tmp_dir = final_dir.with_name(final_dir.name + DEFAULT_SEGMENT_TMP_SUFFIX)

    # If an earlier run was interrupted mid-extraction, remove the temp folder.
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # If the final dir exists but doesn't look complete, remove it so we can replace it atomically.
    if final_dir.exists() and not _segment_dir_is_complete(final_dir):
        shutil.rmtree(final_dir, ignore_errors=True)

    extracted = 0
    try:
        extracted = extract_zip(zip_path, tmp_dir, logger)
        if final_dir.exists():
            # Someone/something created it while we were extracting; keep existing and clean tmp.
            shutil.rmtree(tmp_dir, ignore_errors=True)
        else:
            tmp_dir.replace(final_dir)
            try:
                (final_dir / ".ihx_complete").write_text(
                    dt.datetime.now().isoformat(timespec="seconds"),
                    encoding="utf-8",
                )
            except Exception:
                pass
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    return extracted


def run_download(args) -> int:
    console = Console()
    logger = RichLogger(console=console, verbose=args.verbose)

    try:
        from .intelx_exports import (
            IntelXClient,
            IntelXExportError,
            DEFAULT_MIN_DATE,
            DEFAULT_RESULT_PAGE_SIZE,
            extract_zip,
            read_domains_file,
        )
    except ImportError as exc:
        logger.error(str(exc))
        return 2

    api_key = _resolve_api_key(args.api_key)
    if not api_key:
        logger.error("Missing IntelX API key. Use --api-key or set INTELX_API_KEY.")
        return 2

    try:
        raw_queries, queries_file = _read_query_inputs(args.query, read_domains_file)
    except ValueError as exc:
        logger.error(str(exc))
        return 2

    queries = _collect_queries(raw_queries, logger)
    if not queries:
        logger.error("No valid queries to process.")
        return 2

    layout = ensure_db_layout(Path(args.db))
    client = IntelXClient(api_key, base_url=args.base_url, user_agent=args.user_agent)

    failures = 0
    try:
        from .database import load_query_info
    except Exception:
        load_query_info = None  # type: ignore[assignment]

    def _existing_segment_indices(segments_dir: Path) -> List[int]:
        indices: List[int] = []
        if not segments_dir.exists():
            return indices
        for candidate in segments_dir.iterdir():
            if not candidate.is_dir():
                continue
            match = re.fullmatch(r"seg(\d+)", candidate.name)
            if not match:
                continue
            try:
                indices.append(int(match.group(1)))
            except ValueError:
                continue
        return sorted(set(indices))

    def _next_missing_index(indices: List[int]) -> int:
        expected = 1
        for idx in indices:
            if idx == expected:
                expected += 1
                continue
            if idx > expected:
                break
        return expected

    def _write_download_meta(info: QueryInfo, download_meta: Dict[str, Any]) -> QueryInfo:
        now_ts = dt.datetime.now().isoformat(timespec="seconds")
        updated = QueryInfo(
            query_id=info.query_id,
            query=info.query,
            normalized_query=info.normalized_query,
            content_id=info.content_id,
            created_at=info.created_at,
            updated_at=now_ts,
            path=info.path,
        )
        write_query_info(
            updated,
            extra={
                "download": download_meta,
                "segments": download_meta.get("segments"),
                "extracted_files": download_meta.get("extracted_files", 0),
                "queries_file": str(queries_file) if queries_file else None,
            },
        )
        return updated

    for query in queries:
        query_id, normalized = query_id_from_value(query)
        query_dir = layout.queries_dir / query_id
        segments_dir = query_dir / "segments"
        meta_path = query_dir / "query.json"

        lookback_days = max(0, int(getattr(args, "segment_days", 0) or 0))
        desired_export_limit = args.export_limit
        desired_max_results = max(1, int(args.max_results))
        desired_export_cap = max(1, int(desired_export_limit or desired_max_results))
        if desired_export_cap > desired_max_results:
            logger.warn(
                f"--export-limit ({desired_export_cap}) is higher than --max-results ({desired_max_results}); "
                f"raising --max-results to {desired_export_cap}."
            )
            desired_max_results = desired_export_cap

        existing_payload = _load_json_file(meta_path) if query_dir.exists() else None
        existing_download = (
            existing_payload.get("download") if isinstance(existing_payload, dict) else None  # type: ignore[union-attr]
        )
        legacy_complete = False
        if isinstance(existing_payload, dict) and "download" not in existing_payload:
            legacy_segments = existing_payload.get("segments")
            if isinstance(legacy_segments, list) and legacy_segments:
                legacy_complete = True

        existing_info = None
        if load_query_info and query_dir.exists():
            try:
                existing_info = load_query_info(query_dir)
            except Exception:
                existing_info = None

        # Decide whether we should skip, resume, or start over.
        if query_dir.exists() and not args.update:
            status = str(existing_download.get("status") or "").lower() if isinstance(existing_download, dict) else ""
            if status == "complete":
                if segments_dir.exists() and any(_segment_dir_is_complete(p) for p in segments_dir.iterdir() if p.is_dir()):
                    logger.info(f"Query exists, skipping download: {query}")
                    continue
                logger.warn(f"Query marked complete but no segments found; continuing: {query}")
            elif legacy_complete:
                logger.info(f"Query exists, skipping download: {query}")
                continue

        if query_dir.exists() and args.update:
            try:
                shutil.rmtree(query_dir)
            except Exception as exc:
                logger.error(f"Failed to reset query folder {query_dir}: {exc}")
                failures += 1
                continue

        query_dir.mkdir(parents=True, exist_ok=True)
        segments_dir.mkdir(parents=True, exist_ok=True)

        # Build / load QueryInfo and select download settings.
        now_ts = dt.datetime.now().isoformat(timespec="seconds")
        if existing_info:
            info = QueryInfo(
                query_id=query_id,
                query=query,
                normalized_query=normalized,
                content_id=existing_info.content_id,
                created_at=existing_info.created_at,
                updated_at=existing_info.updated_at,
                path=query_dir,
            )
        else:
            info = QueryInfo(
                query_id=query_id,
                query=query,
                normalized_query=normalized,
                content_id="new",
                created_at=now_ts,
                updated_at=now_ts,
                path=query_dir,
            )

        if args.update or not existing_info:
            info = update_query_content_id(info)

        # Load or initialize the download state.
        download_meta: Dict[str, Any] = {}
        if isinstance(existing_download, dict) and not args.update:
            download_meta = dict(existing_download)

        # If resuming, keep the original range/settings unless the user used --update.
        if download_meta and not args.update:
            saved_settings = download_meta.get("settings") if isinstance(download_meta.get("settings"), dict) else {}
            saved_range = download_meta.get("range") if isinstance(download_meta.get("range"), dict) else {}

            saved_max_results = int(saved_settings.get("max_results") or desired_max_results)
            saved_export_limit = saved_settings.get("export_limit")
            saved_export_cap = int(saved_settings.get("export_cap") or (saved_export_limit or saved_max_results))
            saved_lookback_days = int(saved_range.get("lookback_days") or 0)

            if saved_max_results != desired_max_results or saved_export_limit != desired_export_limit or saved_lookback_days != lookback_days:
                logger.warn(
                    "Resuming with previous download settings for consistency. "
                    "Use --update to restart with new --max-results/--export-limit/--segment-days."
                )

            effective_max_results = saved_max_results
            effective_export_limit = saved_export_limit
            effective_export_cap = saved_export_cap
            range_from = str(saved_range.get("from") or DEFAULT_MIN_DATE)
            range_to = str(saved_range.get("to") or _fmt_intelx_dt(_utc_now()))

            if effective_export_cap > effective_max_results:
                # Keep the original intent (export_cap) but ensure searches can sample enough records to segment safely.
                logger.warn(
                    f"Saved export cap ({effective_export_cap}) is higher than saved max results ({effective_max_results}); "
                    f"raising max results to {effective_export_cap}."
                )
                effective_max_results = effective_export_cap

            # Normalize missing keys from older download states.
            download_meta.setdefault("version", DEFAULT_DOWNLOAD_META_VERSION)
            download_meta.setdefault("started_at", download_meta.get("started_at") or now_ts)
            download_meta.setdefault("finished_at", None)
            download_meta.setdefault("canceled_at", None)
            download_meta.setdefault("failed_at", None)
            download_meta["range"] = {"from": range_from, "to": range_to, "lookback_days": saved_lookback_days}
            merged_settings: Dict[str, Any] = dict(saved_settings)
            merged_settings.setdefault("max_results", effective_max_results)
            merged_settings.setdefault("export_limit", effective_export_limit)
            merged_settings.setdefault("export_cap", effective_export_cap)
            merged_settings.setdefault("base_url", args.base_url)
            merged_settings.setdefault("user_agent", args.user_agent)
            download_meta["settings"] = merged_settings
            download_meta.setdefault("segments", [])
            download_meta.setdefault("extracted_files", 0)
            download_meta.setdefault("segment_index_next", 1)
            download_meta.setdefault("cursor", download_meta.get("cursor") or range_to)
            if queries_file:
                download_meta["queries_file"] = str(queries_file)
        else:
            effective_max_results = desired_max_results
            effective_export_limit = desired_export_limit
            effective_export_cap = desired_export_cap
            range_to_dt = _utc_now()
            range_to = _fmt_intelx_dt(range_to_dt)
            if lookback_days > 0:
                range_from = _fmt_intelx_dt(range_to_dt - dt.timedelta(days=lookback_days))
            else:
                range_from = DEFAULT_MIN_DATE

            download_meta = {
                "version": DEFAULT_DOWNLOAD_META_VERSION,
                "status": "in_progress",
                "started_at": now_ts,
                "finished_at": None,
                "canceled_at": None,
                "failed_at": None,
                "range": {"from": range_from, "to": range_to, "lookback_days": lookback_days},
                "cursor": range_to,
                "segment_index_next": 1,
                "segments": [],
                "extracted_files": 0,
                "settings": {
                    "max_results": effective_max_results,
                    "export_limit": effective_export_limit,
                    "export_cap": effective_export_cap,
                    "base_url": args.base_url,
                    "user_agent": args.user_agent,
                },
                "queries_file": str(queries_file) if queries_file else None,
            }

        range_from_dt = _parse_intelx_dt(str(range_from)) if range_from else None
        cursor_dt = _parse_intelx_dt(str(download_meta.get("cursor") or range_to)) or _parse_intelx_dt(str(range_to))
        segment_index = int(download_meta.get("segment_index_next") or 1)
        extracted_total = int(download_meta.get("extracted_files") or 0)
        segment_entries: List[Dict[str, Any]] = list(download_meta.get("segments") or [])

        # If we have existing segments but no usable cursor/index (legacy interrupted runs),
        # fast-forward the cursor by re-running only the search boundary logic (no export).
        if (cursor_dt is None or segment_index <= 1) and segments_dir.exists():
            indices = _existing_segment_indices(segments_dir)
            if indices:
                segment_index = _next_missing_index(indices)
                cursor_dt = _parse_intelx_dt(str(range_to)) or _utc_now()
                logger.warn(
                    f"Recovered legacy partial state for {query}: found {len(indices)} existing segment(s); "
                    f"resuming from seg{segment_index:02d}."
                )

                for idx in range(1, segment_index):
                    if cursor_dt is None:
                        break
                    if range_from_dt and cursor_dt < range_from_dt:
                        cursor_dt = None
                        break
                    date_to_str = _fmt_intelx_dt(cursor_dt)
                    search_id = ""
                    sampled_records = []
                    last_status = -1
                    try:
                        search_id = client.search(
                            query,
                            maxresults=effective_max_results,
                            datefrom=range_from,
                            dateto=date_to_str,
                            sort=4,
                        )
                        sampled_records, last_status = client.collect_search_results(
                            search_id,
                            per_page=min(DEFAULT_RESULT_PAGE_SIZE, effective_max_results),
                            logger=logger,
                            terminate_after=False,
                            max_records=effective_export_cap + 1,
                        )
                    except IntelXExportError:
                        cursor_dt = None
                        break
                    finally:
                        try:
                            if search_id:
                                client.terminate(search_id)
                        except Exception:
                            pass

                    record_count = len(sampled_records)
                    if record_count == 0:
                        cursor_dt = None
                        break
                    has_more = last_status != 1 or record_count > effective_export_cap
                    if not has_more:
                        cursor_dt = None
                        break
                    boundary_idx = min(effective_export_cap - 1, record_count - 1)
                    boundary_raw = sampled_records[boundary_idx]
                    boundary_dt = None
                    try:
                        raw_date = boundary_raw.get("date") or boundary_raw.get("added")
                        if isinstance(raw_date, str) and raw_date:
                            boundary_dt = dt.datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
                            if boundary_dt.tzinfo is None:
                                boundary_dt = boundary_dt.replace(tzinfo=dt.timezone.utc)
                            boundary_dt = boundary_dt.astimezone(dt.timezone.utc)
                    except Exception:
                        boundary_dt = None
                    if boundary_dt is None:
                        cursor_dt = None
                        break
                    next_cursor = boundary_dt - dt.timedelta(seconds=1)
                    if next_cursor >= cursor_dt:
                        cursor_dt = None
                        break
                    cursor_dt = next_cursor

        # Ensure we persist "in progress" state before doing any network or filesystem-heavy work.
        download_meta["status"] = "in_progress"
        download_meta["canceled_at"] = None
        download_meta["failed_at"] = None
        download_meta["finished_at"] = None
        download_meta["cursor"] = _fmt_intelx_dt(cursor_dt) if cursor_dt else None
        download_meta["segment_index_next"] = max(1, int(segment_index))
        download_meta["segments"] = segment_entries
        download_meta["extracted_files"] = extracted_total
        info = _write_download_meta(info, download_meta)

        logger.info(f"Downloading exports for {query}")

        downloaded_segments_this_run = 0
        stop_due_to_cap = False
        try:
            while cursor_dt is not None:
                if range_from_dt and cursor_dt < range_from_dt:
                    cursor_dt = None
                    break

                if args.max_segments and args.max_segments > 0 and downloaded_segments_this_run >= args.max_segments:
                    stop_due_to_cap = True
                    break

                segment_name = f"seg{segment_index:02d}"
                zip_path = segments_dir / f"{segment_name}.zip"
                extract_dir = segments_dir / segment_name
                part_path = zip_path.with_suffix(zip_path.suffix + ".part")

                _cleanup_segment_artifacts(segments_dir, segment_name, logger)

                date_to_str = _fmt_intelx_dt(cursor_dt)
                logger.info(f"IntelX search window: datefrom='{range_from}' dateto='{date_to_str}'")

                search_id = ""
                sampled_records: List[Dict[str, Any]] = []
                last_status = -1
                try:
                    search_id = client.search(
                        query,
                        maxresults=effective_max_results,
                        datefrom=range_from,
                        dateto=date_to_str,
                        sort=4,
                    )
                    sampled_records, last_status = client.collect_search_results(
                        search_id,
                        per_page=min(DEFAULT_RESULT_PAGE_SIZE, effective_max_results),
                        logger=logger,
                        terminate_after=False,
                        max_records=effective_export_cap + 1,
                    )
                    record_count = len(sampled_records)
                    logger.info(f"Search {search_id}: collected {record_count} records")
                    if record_count == 0:
                        break

                    has_more = last_status != 1 or record_count > effective_export_cap
                    boundary_dt = None
                    if has_more:
                        boundary_idx = min(effective_export_cap - 1, record_count - 1)
                        boundary_raw = sampled_records[boundary_idx]
                        try:
                            raw_date = boundary_raw.get("date") or boundary_raw.get("added")
                            if isinstance(raw_date, str) and raw_date:
                                boundary_dt = dt.datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
                                if boundary_dt.tzinfo is None:
                                    boundary_dt = boundary_dt.replace(tzinfo=dt.timezone.utc)
                                boundary_dt = boundary_dt.astimezone(dt.timezone.utc)
                        except Exception:
                            boundary_dt = None
                        if boundary_dt is None:
                            logger.warn("Could not infer a boundary date from results; stopping segmentation.")
                            has_more = False

                    next_cursor_dt = None
                    if has_more and boundary_dt is not None:
                        next_cursor_dt = boundary_dt - dt.timedelta(seconds=1)
                        if next_cursor_dt >= cursor_dt:
                            logger.warn(
                                f"No further date progress after {date_to_str}; stopping segmentation to avoid repeated windows."
                            )
                            next_cursor_dt = None
                        if range_from_dt and next_cursor_dt is not None and next_cursor_dt < range_from_dt:
                            next_cursor_dt = None

                    need_export = not _segment_dir_is_complete(extract_dir)
                    reused_zip = False
                    extracted_count = 0

                    if need_export:
                        if zip_path.exists() and not _looks_like_zip(zip_path):
                            try:
                                zip_path.unlink(missing_ok=True)
                            except Exception:
                                pass
                        if zip_path.exists() and _looks_like_zip(zip_path):
                            reused_zip = True
                            logger.info(f"Reusing existing export: {zip_path}")
                        else:
                            client.export_search(search_id, effective_export_cap, zip_path)
                            logger.info(f"Downloaded export to {zip_path}")

                        try:
                            extracted_count = _extract_zip_atomic(zip_path, extract_dir, logger, extract_zip)
                        except zipfile.BadZipFile as exc:
                            logger.error(f"Failed to extract {zip_path}: {exc}")
                            try:
                                zip_path.unlink(missing_ok=True)
                            except Exception:
                                pass
                            raise

                        extracted_total += extracted_count

                        try:
                            zip_path.unlink(missing_ok=True)
                        except Exception:
                            logger.warn(f"Unable to delete ZIP: {zip_path}")

                        segment_entry = {
                            "name": extract_dir.name,
                            "search_id": search_id,
                            "date_from": range_from,
                            "date_to": date_to_str,
                            "result_count": record_count,
                            "reused": reused_zip,
                            "extracted_files": extracted_count,
                            "completed_at": dt.datetime.now().isoformat(timespec="seconds"),
                        }
                        segment_entries.append(segment_entry)
                        downloaded_segments_this_run += 1
                    else:
                        logger.info(f"Segment exists, skipping export: {extract_dir.name}")

                    # Persist progress after each segment so Ctrl+C leaves a resumable state.
                    cursor_dt = next_cursor_dt
                    segment_index += 1
                    download_meta["cursor"] = _fmt_intelx_dt(cursor_dt) if cursor_dt else None
                    download_meta["segment_index_next"] = segment_index
                    download_meta["segments"] = segment_entries
                    download_meta["extracted_files"] = extracted_total
                    info = _write_download_meta(info, download_meta)
                finally:
                    try:
                        if search_id:
                            client.terminate(search_id)
                    except Exception:
                        pass

        except KeyboardInterrupt:
            logger.warn("Download canceled by user (Ctrl+C). Cleaning up partial artifacts...")
            _cleanup_segment_artifacts(segments_dir, segment_name if "segment_name" in locals() else None, logger)
            if "part_path" in locals() and isinstance(part_path, Path):
                try:
                    part_path.unlink(missing_ok=True)
                except Exception:
                    pass
            download_meta["status"] = "canceled"
            download_meta["canceled_at"] = dt.datetime.now().isoformat(timespec="seconds")
            download_meta["cursor"] = _fmt_intelx_dt(cursor_dt) if cursor_dt else download_meta.get("cursor")
            download_meta["segment_index_next"] = segment_index
            download_meta["segments"] = segment_entries
            download_meta["extracted_files"] = extracted_total
            _write_download_meta(info, download_meta)
            return 1
        except IntelXExportError as exc:
            logger.error(str(exc))
            _cleanup_segment_artifacts(segments_dir, segment_name if "segment_name" in locals() else None, logger)
            download_meta["status"] = "failed"
            download_meta["failed_at"] = dt.datetime.now().isoformat(timespec="seconds")
            download_meta["cursor"] = _fmt_intelx_dt(cursor_dt) if cursor_dt else download_meta.get("cursor")
            download_meta["segment_index_next"] = segment_index
            download_meta["segments"] = segment_entries
            download_meta["extracted_files"] = extracted_total
            _write_download_meta(info, download_meta)
            failures += 1
            continue
        except Exception as exc:
            logger.error(f"Unexpected error while downloading '{query}': {exc}")
            _cleanup_segment_artifacts(segments_dir, segment_name if "segment_name" in locals() else None, logger)
            download_meta["status"] = "failed"
            download_meta["failed_at"] = dt.datetime.now().isoformat(timespec="seconds")
            download_meta["cursor"] = _fmt_intelx_dt(cursor_dt) if cursor_dt else download_meta.get("cursor")
            download_meta["segment_index_next"] = segment_index
            download_meta["segments"] = segment_entries
            download_meta["extracted_files"] = extracted_total
            _write_download_meta(info, download_meta)
            failures += 1
            continue

        if stop_due_to_cap:
            download_meta["status"] = "partial"
            download_meta["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
            download_meta["stopped_reason"] = "max_segments"
        else:
            download_meta["status"] = "complete"
            download_meta["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
            download_meta["cursor"] = None
            download_meta.pop("stopped_reason", None)

        download_meta["segment_index_next"] = segment_index
        download_meta["segments"] = segment_entries
        download_meta["extracted_files"] = extracted_total
        _write_download_meta(info, download_meta)
        logger.done(f"Stored query '{query}' in {query_dir}")

    return 1 if failures else 0


def run_search(args) -> int:
    console = Console()
    logger = RichLogger(console=console, verbose=args.verbose)

    try:
        from .intelx_exports import find_info_csv, load_info_metadata, read_domains_file
    except ImportError as exc:
        logger.error(str(exc))
        return 2

    layout = ensure_db_layout(Path(args.db))

    try:
        raw_selectors, selector_files = _read_selector_inputs(args.selector, read_domains_file)
    except ValueError as exc:
        logger.error(str(exc))
        return 2
    selectors = _collect_selectors(raw_selectors)
    if not selectors:
        logger.error("No valid selectors to process.")
        return 2

    selector_ctx = build_selector_contexts(selectors, selector_only=True)
    extract_mode = args.extract
    include_emails = extract_mode in (None, "emails")
    include_credentials = extract_mode in (None, "credentials")
    include_surface = extract_mode in (None, "surface")

    query_infos: List[QueryInfo] = []
    failures = 0
    queries_file = None
    if args.query:
        try:
            raw_queries, queries_file = _read_query_inputs(args.query, read_domains_file)
        except ValueError as exc:
            logger.error(str(exc))
            return 2
        queries = _collect_queries(raw_queries, logger)
        if not queries:
            logger.error("No valid queries to process.")
            return 2
        for query in queries:
            query_id, normalized = query_id_from_value(query)
            query_dir = layout.queries_dir / query_id
            if not query_dir.exists():
                logger.warn(f"Query not found in database: {query}")
                failures += 1
                continue
            existing = None
            try:
                from .database import load_query_info, ensure_query_info

                existing = load_query_info(query_dir)
                if existing is None:
                    existing = ensure_query_info(query_dir, query_id, query, normalized)
            except Exception:
                existing = QueryInfo(
                    query_id=query_id,
                    query=query,
                    normalized_query=normalized,
                    content_id="manual",
                    created_at=dt.datetime.now().isoformat(timespec="seconds"),
                    updated_at=dt.datetime.now().isoformat(timespec="seconds"),
                    path=query_dir,
                )
            query_infos.append(existing)
    else:
        for query_dir in list_query_dirs(layout):
            try:
                from .database import load_query_info, ensure_query_info

                existing = load_query_info(query_dir)
                if existing is None:
                    existing = ensure_query_info(
                        query_dir,
                        query_dir.name,
                        query_dir.name,
                        query_dir.name,
                    )
            except Exception:
                existing = QueryInfo(
                    query_id=query_dir.name,
                    query=query_dir.name,
                    normalized_query=query_dir.name,
                    content_id="manual",
                    created_at=dt.datetime.now().isoformat(timespec="seconds"),
                    updated_at=dt.datetime.now().isoformat(timespec="seconds"),
                    path=query_dir,
                )
            query_infos.append(existing)

    if not query_infos:
        logger.error("No queries available to search.")
        return 2

    started_at = dt.datetime.now().isoformat(timespec="seconds")
    spec = build_search_spec(selectors, extract_mode)
    search_dir = ensure_search_dir(layout.state_dir, spec)
    scan_log_path = search_dir / "scanned.jsonl"
    query_content_ids = {info.query_id: info.content_id for info in query_infos}
    scanned_files = load_scan_log(scan_log_path, query_content_ids)
    scan_log = ScanLog(scan_log_path)

    logger.info(f"Selectors: {', '.join(selectors)}")
    if selector_files:
        logger.info("Selector files: " + ", ".join(str(p) for p in selector_files))
    if extract_mode:
        logger.info(f"Extraction focus: {extract_mode}")

    store = ResultStore()
    load_findings(layout.findings_dir, store, logger)
    sink = CategorySink(layout.findings_dir)
    scanner = Scanner(
        selector_ctx=selector_ctx,
        store=store,
        sink=sink,
        logger=logger,
        selector_filter=False,
        include_emails=include_emails,
        include_surface=include_surface,
        include_credentials=include_credentials,
        extra_stores=None,
        relevance_window=DEFAULT_RELEVANCE_WINDOW,
        max_line_len=DEFAULT_MAX_LINE_LEN,
        max_file_mb=DEFAULT_MAX_FILE_MB,
    )

    all_tasks: List[ScanTask] = []
    scan_inputs: List[str] = []
    skipped_by_memory = 0
    total_items = 0
    for info in query_infos:
        segments_dir = info.path / "segments"
        if not segments_dir.exists():
            logger.warn(f"No segments found for query: {info.query}")
            continue
        segment_dirs = sorted(
            [
                p
                for p in segments_dir.iterdir()
                if p.is_dir() and not p.name.endswith(DEFAULT_SEGMENT_TMP_SUFFIX)
            ]
        )
        if not segment_dirs:
            logger.warn(f"No segments found for query: {info.query}")
            continue
        scanned_for_query = scanned_files.get(info.query_id, set())
        for segment_dir in segment_dirs:
            info_path = find_info_csv(segment_dir)
            info_map = load_info_metadata(info_path, logger) if info_path else {}
            for item in iter_input_items(segment_dir, False, logger, metadata=info_map):
                total_items += 1
                file_id = _build_file_id(info.path, segment_dir, item)
                if file_id in scanned_for_query:
                    skipped_by_memory += 1
                    continue
                source_label = _build_source_label(info.query_id, file_id)
                all_tasks.append(
                    ScanTask(
                        item=_clone_item(item, source_label),
                        query_id=info.query_id,
                        content_id=info.content_id,
                        file_id=file_id,
                    )
                )
            scan_inputs.append(str(segment_dir))

    if not all_tasks:
        logger.warn("No new files to scan. Memory indicates all files are already processed.")

    scan_stats = _scan_tasks(
        all_tasks,
        scanner,
        args.threads,
        console,
        logger,
        args.verbose,
        scan_log,
    )
    scan_stats["files_skipped_memory"] = skipped_by_memory
    scan_stats["files_seen_total"] = total_items

    summary = store.summary()
    table = Table(title="Findings Summary", header_style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Unique", justify="right")
    table.add_column("Total", justify="right")
    for cat, cstats in sorted(summary.get("categories", {}).items()):
        table.add_row(cat, str(cstats.get("unique", 0)), str(cstats.get("total", 0)))
    console.print(table)

    run_metadata: Dict[str, object] = {
        "selectors": selectors,
        "selector_files": [str(p) for p in selector_files] if selector_files else None,
        "queries_file": str(queries_file) if queries_file else None,
        "extract": extract_mode or "all",
        "search_key": spec.key,
        "db_root": str(layout.root),
        "findings_dir": str(layout.findings_dir),
        "state_dir": str(layout.state_dir),
        "input": sorted(set(scan_inputs)),
        "queries": [
            {
                "query_id": info.query_id,
                "query": info.query,
                "content_id": info.content_id,
                "path": str(info.path),
            }
            for info in query_infos
        ],
        "settings": {
            "relevance_window": scanner.relevance_window,
            "max_line_len": scanner.max_line_len,
            "max_file_mb": round(scanner.max_file_bytes / (1024 * 1024), 2),
            "threads": args.threads,
            "extract": extract_mode or "all",
        },
        "scan_stats": scan_stats,
        "started_at": started_at,
    }
    run_metadata["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")

    writer = ResultWriter(
        out_dir=layout.root,
        logger=logger,
        findings_dir=layout.findings_dir,
        metadata_dir=layout.findings_dir,
    )
    writer.write_all(store, run_metadata)

    return 1 if failures else 0


def main() -> int:
    args = build_arg_parser().parse_args()
    if args.command == "download":
        return run_download(args)
    if args.command == "search":
        return run_search(args)
    return 2
