from __future__ import annotations

import argparse
import datetime as dt
import os
import shutil
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

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
        help="Segment searches by rolling window of N days (0 = adaptive segmentation).",
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


def run_download(args) -> int:
    console = Console()
    logger = RichLogger(console=console, verbose=args.verbose)

    try:
        from .intelx_exports import (
            IntelXClient,
            IntelXExportError,
            extract_zip,
            plan_export_batches,
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
    for query in queries:
        query_id, normalized = query_id_from_value(query)
        query_dir = layout.queries_dir / query_id
        existing_info = QueryInfo(
            query_id=query_id,
            query=query,
            normalized_query=normalized,
            content_id="",
            created_at=dt.datetime.now().isoformat(timespec="seconds"),
            updated_at=dt.datetime.now().isoformat(timespec="seconds"),
            path=query_dir,
        )
        if query_dir.exists() and not args.update:
            logger.info(f"Query exists, skipping download: {query}")
            continue
        if query_dir.exists() and args.update:
            try:
                existing_loaded = None
                try:
                    from .database import load_query_info

                    existing_loaded = load_query_info(query_dir)
                except Exception:
                    existing_loaded = None
                if existing_loaded:
                    existing_info = existing_loaded
                shutil.rmtree(query_dir)
            except Exception as exc:
                logger.error(f"Failed to reset query folder {query_dir}: {exc}")
                failures += 1
                continue

        query_dir.mkdir(parents=True, exist_ok=True)
        segments_dir = query_dir / "segments"
        segments_dir.mkdir(parents=True, exist_ok=True)

        base_info = QueryInfo(
            query_id=query_id,
            query=query,
            normalized_query=normalized,
            content_id=existing_info.content_id or "new",
            created_at=existing_info.created_at,
            updated_at=existing_info.updated_at,
            path=query_dir,
        )
        info = update_query_content_id(base_info)

        logger.info(f"Downloading exports for {query}")
        try:
            batches = plan_export_batches(
                client,
                query,
                segments_dir,
                logger,
                max_results=max(1, args.max_results),
                export_limit=args.export_limit,
                segment_days=max(0, args.segment_days),
                max_segments=args.max_segments,
                reuse_existing=False,
                name_pattern="seg{index:02d}",
                include_domain_in_name=False,
                extract_suffix="",
            )
        except IntelXExportError as exc:
            logger.error(str(exc))
            failures += 1
            continue

        if not batches:
            logger.error(f"No exports prepared for {query}")
            failures += 1
            continue

        segment_entries = []
        extracted_total = 0
        for batch in batches:
            try:
                extracted_count = extract_zip(batch.zip_path, batch.extract_dir, logger)
                extracted_total += extracted_count
            except zipfile.BadZipFile as exc:
                logger.error(f"Failed to extract {batch.zip_path}: {exc}")
                failures += 1
                continue
            except Exception as exc:
                logger.error(f"Failed to extract {batch.zip_path}: {exc}")
                failures += 1
                continue
            try:
                if batch.zip_path.exists():
                    batch.zip_path.unlink()
            except Exception:
                logger.warn(f"Unable to delete ZIP: {batch.zip_path}")
            segment_entries.append(
                {
                    "name": batch.extract_dir.name,
                    "search_id": batch.search_id,
                    "date_from": batch.date_from,
                    "date_to": batch.date_to,
                    "result_count": batch.result_count,
                    "reused": batch.reused,
                }
            )

        finished_at = dt.datetime.now().isoformat(timespec="seconds")
        info = QueryInfo(
            query_id=info.query_id,
            query=info.query,
            normalized_query=info.normalized_query,
            content_id=info.content_id,
            created_at=info.created_at,
            updated_at=finished_at,
            path=info.path,
        )
        write_query_info(
            info,
            extra={
                "segments": segment_entries,
                "extracted_files": extracted_total,
                "queries_file": str(queries_file) if queries_file else None,
            },
        )
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
        segment_dirs = sorted([p for p in segments_dir.iterdir() if p.is_dir()])
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
