from __future__ import annotations

import argparse
import datetime as dt
import os
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table

from .console import RichLogger
from .input_sources import iter_input_items
from .normalize import build_output_dir, sanitize_for_fs
from .results import CategorySink, ResultStore, ResultWriter
from .scanner import Scanner
from .selector import build_selector_contexts

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
        description="Download IntelX exports for domains, unzip them, and scan for secrets/artifacts.",
    )
    ap.add_argument(
        "--query",
        required=True,
        help="IntelX search domain (download scope) or a file containing one domain per line.",
    )
    ap.add_argument(
        "--output-dir",
        "-o",
        default="results",
        help="Root output directory (default: ./results)",
    )
    ap.add_argument(
        "--threads",
        type=int,
        default=default_thread_count(),
        help="Worker threads for scanning (default: auto)",
    )
    ap.add_argument(
        "--offline",
        action="store_true",
        help="Skip IntelX API calls and only scan existing ZIPs under --downloads-dir",
    )
    ap.add_argument(
        "--reuse-downloads",
        action="store_true",
        help="Reuse existing ZIP exports if they already exist (avoids extra API calls)",
    )
    ap.add_argument(
        "--selector",
        action="append",
        required=True,
        help="Selector(s) to search for (repeat or provide a file with one selector per line).",
    )
    ap.add_argument(
        "--extract",
        choices=("credentials", "emails", "surface"),
        help="Limit extraction to: credentials, emails, or surface (endpoints/hostnames/assets).",
    )
    ap.add_argument(
        "--downloads-dir",
        help="Where to store IntelX ZIPs and extracted data (default: <output-dir>/intelx_exports)",
    )
    ap.add_argument(
        "--segment-days",
        type=int,
        default=0,
        help="Segment searches by rolling window of N days (0 = adaptive segmentation).",
    )
    ap.add_argument(
        "--max-segments",
        type=int,
        default=DEFAULT_MAX_SEGMENTS,
        help="Safety cap on segmented searches per domain (0 = unlimited, default: 0).",
    )
    ap.add_argument(
        "--max-results",
        type=int,
        default=DEFAULT_MAX_RESULTS,
        help="Max IntelX results per search (default: 1000).",
    )
    ap.add_argument(
        "--export-limit",
        type=int,
        default=None,
        help="Max results per export ZIP (default: --max-results).",
    )
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logs")
    ap.add_argument(
        "--api-key",
        help="IntelX API key (UUID). You can also set INTELX_API_KEY env var.",
    )
    ap.add_argument(
        "--base-url",
        default="https://2.intelx.io",
        help="IntelX API base URL (paid commonly uses 2.intelx.io).",
    )
    ap.add_argument(
        "--user-agent",
        default="intelhunterx/1.0",
        help="User-Agent header (required by IntelX).",
    )
    return ap


def _resolve_api_key(explicit: str | None) -> str | None:
    if explicit and explicit.strip():
        return explicit.strip()
    for key in ("INTELX_API_KEY", "INTELX_APIKEY", "INTELX_KEY"):
        value = os.environ.get(key, "")
        if value.strip():
            return value.strip()
    return None


def _collect_domains(raw_domains: Iterable[str], logger: RichLogger, normalize_domain) -> List[str]:
    domains: List[str] = []
    seen: set[str] = set()
    for raw in raw_domains:
        try:
            dom = normalize_domain(raw)
        except ValueError:
            logger.warn(f"Skipping invalid domain entry: {raw}")
            continue
        if dom in seen:
            continue
        seen.add(dom)
        domains.append(dom)
    return domains


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


def _scan_items(
    items,
    scanner: Scanner,
    threads: int,
    console: Console,
    logger: RichLogger,
    verbose: bool,
) -> Dict[str, int]:
    total_files = 0
    skipped_files = 0
    total_new = 0

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
        task_id = progress.add_task("scan", total=len(items))
        with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
            future_map = {executor.submit(scanner.scan_item, item): item for item in items}
            for future in as_completed(future_map):
                total_files += 1
                try:
                    stats = future.result()
                except Exception as e:
                    logger.warn(f"Failed to scan {future_map[future].display_name}: {e}")
                    skipped_files += 1
                    progress.advance(task_id)
                    continue

                skipped_files += stats.get("skipped", 0)
                total_new += stats.get("new_findings", 0)
                if verbose and stats.get("new_findings", 0) > 0:
                    logger.debug(
                        f"Hit {future_map[future].display_name}: new={stats.get('new_findings', 0)}, "
                        f"relevant_lines={stats.get('relevant_lines', 0)}"
                    )

                progress.advance(task_id)

    return {
        "files_total": total_files,
        "files_skipped": skipped_files,
        "new_findings_unique_written": total_new,
    }


def main() -> int:
    args = build_arg_parser().parse_args()

    console = Console()
    logger = RichLogger(console=console, verbose=args.verbose)

    try:
        from .intelx_exports import (
            IntelXClient,
            IntelXExportError,
            ExportBatch,
            find_info_csv,
            extract_zip,
            normalize_domain,
            plan_export_batches,
            read_domains_file,
            load_info_metadata,
        )
    except ImportError as exc:
        logger.error(str(exc))
        return 2

    api_key = _resolve_api_key(args.api_key) if not args.offline else None

    raw_domains: List[str] = []
    domains_file_path = None
    query_value = args.query.strip()
    if not query_value:
        logger.error("Missing --query value.")
        return 2
    query_path = Path(query_value).expanduser()
    if query_path.exists():
        if query_path.is_dir():
            logger.error(f"--query path is a directory, expected file or domain: {query_path}")
            return 2
        domains_file_path = query_path.resolve()
        try:
            raw_domains.extend(read_domains_file(domains_file_path))
        except Exception as exc:
            logger.error(f"Failed to read domains file {domains_file_path}: {exc}")
            return 2
    else:
        raw_domains.append(query_value)

    domains = _collect_domains(raw_domains, logger, normalize_domain)
    if not domains:
        logger.error("No valid domains to process.")
        return 2

    selector_files: List[Path] = []
    selector_source = "explicit"
    try:
        raw_selectors, selector_files = _read_selector_inputs(args.selector, read_domains_file)
    except ValueError as exc:
        logger.error(str(exc))
        return 2
    selectors = _collect_selectors(raw_selectors)
    if not selectors:
        logger.error("No valid selectors to process.")
        return 2

    base_out = Path(args.output_dir).expanduser().resolve()
    downloads_root = (
        Path(args.downloads_dir).expanduser().resolve()
        if args.downloads_dir
        else base_out / "intelx_exports"
    )

    batch_stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_url = args.base_url

    client = None
    if not args.offline and api_key:
        client = IntelXClient(api_key, base_url=base_url, user_agent=args.user_agent)

    failures = 0
    global_store = ResultStore()
    global_scan_stats = {"files_total": 0, "files_skipped": 0, "new_findings_unique_written": 0}
    global_export_summaries: List[dict] = []
    global_inputs: List[str] = []
    per_domain_outputs: List[str] = []
    global_started = dt.datetime.now().isoformat(timespec="seconds")
    selector_ctx = build_selector_contexts(selectors, selector_only=True)
    extract_mode = args.extract
    include_emails = extract_mode in (None, "emails")
    include_credentials = extract_mode in (None, "credentials")
    include_surface = extract_mode in (None, "surface")
    logger.info(f"Selectors ({selector_source}): {', '.join(selectors)}")
    if selector_files:
        logger.info("Selector files: " + ", ".join(str(p) for p in selector_files))
    if extract_mode:
        logger.info(f"Extraction focus: {extract_mode}")
    if args.offline:
        logger.info("Offline mode: only existing ZIPs will be processed.")
    elif args.reuse_downloads:
        logger.info("Reuse mode: existing ZIPs will be reused when available.")

    domain_batches: Dict[str, List[ExportBatch]] = {}

    for domain in domains:
        logger.info(f"Preparing exports for {domain}")
        safe_domain = sanitize_for_fs(domain)

        existing_zips: List[Path] = []
        if downloads_root.exists():
            existing_zips = list(downloads_root.rglob(f"{safe_domain}*.zip"))

        batches: List[ExportBatch] = []
        if args.offline or (args.reuse_downloads and existing_zips):
            if not existing_zips:
                logger.error(f"No ZIP exports found for {domain} under {downloads_root}")
                failures += 1
                continue
            batches = [
                ExportBatch(
                    search_id=None,
                    zip_path=zip_path,
                    extract_dir=zip_path.parent / f"{zip_path.stem}_extracted",
                    date_from=None,
                    date_to=None,
                    result_count=0,
                    reused=True,
                )
                for zip_path in sorted(existing_zips)
            ]
        else:
            if client is None:
                logger.error("Missing IntelX API key. Use --api-key or set INTELX_API_KEY.")
                failures += 1
                continue
            download_dir = downloads_root / f"{safe_domain}_{batch_stamp}"
            download_dir.mkdir(parents=True, exist_ok=True)
            try:
                batches = plan_export_batches(
                    client,
                    domain,
                    download_dir,
                    logger,
                    max_results=max(1, args.max_results),
                    export_limit=args.export_limit,
                    segment_days=max(0, args.segment_days),
                    max_segments=args.max_segments,
                    reuse_existing=args.reuse_downloads,
                )
            except IntelXExportError as exc:
                logger.error(str(exc))
                failures += 1
                continue

        if not batches:
            logger.error(f"No exports prepared for {domain}")
            failures += 1
            continue

        domain_batches[domain] = batches

    for domain in domains:
        batches = domain_batches.get(domain)
        if not batches:
            continue
        logger.info(f"Scanning exports for {domain}")
        run_started = dt.datetime.now().isoformat(timespec="seconds")

        out_dir = build_output_dir(base_out, domain, batch_stamp)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "findings").mkdir(parents=True, exist_ok=True)

        store = ResultStore()
        sink = CategorySink(out_dir / "findings")
        scanner = Scanner(
            selector_ctx=selector_ctx,
            store=store,
            sink=sink,
            logger=logger,
            selector_filter=False,
            include_emails=include_emails,
            include_surface=include_surface,
            include_credentials=include_credentials,
            extra_stores=[global_store],
            relevance_window=DEFAULT_RELEVANCE_WINDOW,
            max_line_len=DEFAULT_MAX_LINE_LEN,
            max_file_mb=DEFAULT_MAX_FILE_MB,
        )

        logger.info(f"Output : {out_dir}")
        logger.info(f"Threads: {args.threads}")

        all_items = []
        export_summaries = []

        for batch in batches:
            try:
                extracted_count = extract_zip(batch.zip_path, batch.extract_dir, logger)
            except zipfile.BadZipFile as exc:
                logger.error(f"Failed to extract {batch.zip_path}: {exc}")
                failures += 1
                continue
            except Exception as exc:
                logger.error(f"Failed to extract {batch.zip_path}: {exc}")
                failures += 1
                continue

            info_path = find_info_csv(batch.extract_dir)
            info_map = load_info_metadata(info_path, logger) if info_path else {}

            items = list(iter_input_items(batch.extract_dir, False, logger, metadata=info_map))
            logger.info(
                f"Export {batch.zip_path.name}: extracted {extracted_count} files, metadata entries={len(info_map)}, items_to_scan={len(items)}"
            )
            all_items.extend(items)
            export_summaries.append(
                {
                    "zip": str(batch.zip_path),
                    "extract_dir": str(batch.extract_dir),
                    "search_id": batch.search_id,
                    "date_from": batch.date_from,
                    "date_to": batch.date_to,
                    "result_count": batch.result_count,
                    "reused": batch.reused,
                    "info_csv": str(info_path) if info_path else None,
                    "info_entries": len(info_map),
                    "extracted_files": extracted_count,
                }
            )
            global_export_summaries.append(export_summaries[-1])
            global_inputs.append(str(batch.extract_dir))

        if not all_items:
            logger.warn(f"No files to scan for {domain}")
            continue

        run_metadata: Dict[str, object] = {
            "domain": domain,
            "selector": selectors[0] if selectors else None,
            "selectors": selectors,
            "selector_source": selector_source,
            "selector_mode": "literal",
            "input": [str(e["extract_dir"]) for e in export_summaries],
            "output": str(out_dir),
            "downloads_dir": str(downloads_root),
            "domains_file": str(domains_file_path) if domains_file_path else None,
            "selectors_file": [str(p) for p in selector_files] if selector_files else None,
            "batch": batch_stamp,
            "started_at": run_started,
            "settings": {
                "relevance_window": scanner.relevance_window,
                "max_line_len": scanner.max_line_len,
                "max_file_mb": round(scanner.max_file_bytes / (1024 * 1024), 2),
                "threads": args.threads,
                "extract": extract_mode or "all",
                "intelx_max_results": max(1, args.max_results),
                "intelx_export_limit": args.export_limit or args.max_results,
                "intelx_base_url": base_url,
                "intelx_user_agent": args.user_agent,
                "segment_days": max(0, args.segment_days),
                "max_segments": args.max_segments,
                "offline": args.offline,
                "reuse_downloads": args.reuse_downloads,
                "selector_filter": False,
            },
            "intelx": {
                "searches": export_summaries,
            },
        }

        run_metadata["scan_stats"] = _scan_items(all_items, scanner, args.threads, console, logger, args.verbose)
        run_metadata["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")

        writer = ResultWriter(out_dir, logger)
        writer.write_all(store, run_metadata)
        per_domain_outputs.append(str(out_dir))
        global_scan_stats["files_total"] += run_metadata["scan_stats"].get("files_total", 0)
        global_scan_stats["files_skipped"] += run_metadata["scan_stats"].get("files_skipped", 0)
        global_scan_stats["new_findings_unique_written"] += run_metadata["scan_stats"].get("new_findings_unique_written", 0)

        summary = store.summary()
        table = Table(title=f"Findings Summary ({domain})", header_style="bold")
        table.add_column("Category", style="cyan")
        table.add_column("Unique", justify="right")
        table.add_column("Total", justify="right")
        for cat, cstats in sorted(summary.get("categories", {}).items()):
            table.add_row(cat, str(cstats.get("unique", 0)), str(cstats.get("total", 0)))
        console.print(table)

    if failures:
        logger.warn(f"Completed with {failures} domain(s) failed.")
        if global_store.records or global_store.credentials:
            global_metadata: Dict[str, object] = {
                "domains": domains,
                "selector": selectors[0] if selectors else None,
                "selectors": selectors,
                "selector_source": selector_source,
                "selector_mode": "literal",
                "input": sorted(set(global_inputs)),
                "output": str(base_out),
                "downloads_dir": str(downloads_root),
                "domains_file": str(domains_file_path) if domains_file_path else None,
                "selectors_file": [str(p) for p in selector_files] if selector_files else None,
                "batch": batch_stamp,
                "started_at": global_started,
                "finished_at": dt.datetime.now().isoformat(timespec="seconds"),
                "settings": {
                    "relevance_window": DEFAULT_RELEVANCE_WINDOW,
                    "max_line_len": DEFAULT_MAX_LINE_LEN,
                    "max_file_mb": DEFAULT_MAX_FILE_MB,
                    "threads": args.threads,
                    "extract": extract_mode or "all",
                    "intelx_max_results": max(1, args.max_results),
                    "intelx_export_limit": args.export_limit or args.max_results,
                    "intelx_base_url": base_url,
                    "intelx_user_agent": args.user_agent,
                    "segment_days": max(0, args.segment_days),
                    "max_segments": args.max_segments,
                    "offline": args.offline,
                    "reuse_downloads": args.reuse_downloads,
                    "selector_filter": False,
                },
                "intelx": {
                    "searches": global_export_summaries,
                },
                "per_domain_outputs": per_domain_outputs,
                "scan_stats": global_scan_stats,
            }
            global_writer = ResultWriter(base_out, logger)
            global_writer.write_all(global_store, global_metadata)

    return 1 if failures else 0
