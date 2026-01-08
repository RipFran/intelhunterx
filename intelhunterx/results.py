from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set

from .console import RichLogger
from .models import Finding, Occurrence
from .normalize import stable_key


@dataclass
class CredentialRecord:
    value: str
    username: str
    password: str
    email_domain: str | None
    context_domains: Set[str]
    context_urls: Set[str]
    occurrence: Occurrence
    source_meta: dict | None


class ResultStore:
    def __init__(self):
        self._lock = threading.Lock()
        self.unique: Dict[str, Set[str]] = {}
        self.first_seen: Dict[str, Dict[str, Occurrence]] = {}
        self.count_total: Dict[str, int] = {}
        self.count_unique: Dict[str, int] = {}
        self.credentials: Dict[str, CredentialRecord] = {}
        self.records: Dict[str, Dict[str, Finding]] = {}

    def _with_meta(self, finding: Finding, meta) -> Finding:
        if meta is None:
            return finding
        meta_dict = {}
        if hasattr(meta, "to_dict"):
            try:
                meta_dict = meta.to_dict()
            except Exception:
                meta_dict = {}
        merged_ctx = dict(finding.context or {})
        if meta_dict and "source_meta" not in merged_ctx:
            merged_ctx["source_meta"] = meta_dict
        return Finding(finding.category, finding.value, finding.occurrence, merged_ctx)

    def add(self, finding: Finding, meta=None) -> bool:
        finding = self._with_meta(finding, meta)
        with self._lock:
            self.count_total[finding.category] = self.count_total.get(finding.category, 0) + 1
            catset = self.unique.setdefault(finding.category, set())
            key = stable_key(finding.category, finding.value)
            if key in catset:
                return False
            catset.add(key)
            self.count_unique[finding.category] = self.count_unique.get(finding.category, 0) + 1
            self.first_seen.setdefault(finding.category, {})[key] = finding.occurrence
            self.records.setdefault(finding.category, {})[key] = finding
            return True

    def add_credential(self, finding: Finding, meta=None) -> bool:
        if finding.category != "credentials":
            raise ValueError("add_credential called with non-credential finding")
        context = finding.context or {}
        username = str(context.get("username", "")).strip()
        password = str(context.get("password", "")).strip()
        if (not username or not password) and ":" in finding.value:
            user_part, pass_part = finding.value.split(":", 1)
            username = username or user_part
            password = password or pass_part
        email_domain = context.get("email_domain")
        context_domains = set(context.get("context_domains", []) or [])
        context_urls = set(context.get("context_urls", []) or [])

        meta_dict = None
        if meta is not None and hasattr(meta, "to_dict"):
            try:
                meta_dict = meta.to_dict()
            except Exception:
                meta_dict = None

        with self._lock:
            self.count_total["credentials"] = self.count_total.get("credentials", 0) + 1
            catset = self.unique.setdefault("credentials", set())
            key = stable_key("credentials", finding.value)

            record = self.credentials.get(key)
            if record is None:
                record = CredentialRecord(
                    value=finding.value,
                    username=username,
                    password=password,
                    email_domain=email_domain if isinstance(email_domain, str) else None,
                    context_domains=set(context_domains),
                    context_urls=set(context_urls),
                    occurrence=finding.occurrence,
                    source_meta=meta_dict,
                )
                self.credentials[key] = record
                catset.add(key)
                self.count_unique["credentials"] = self.count_unique.get("credentials", 0) + 1
                self.first_seen.setdefault("credentials", {})[key] = finding.occurrence
                return True

            had_context = bool(record.context_domains or record.context_urls)
            record.context_domains.update(context_domains)
            record.context_urls.update(context_urls)
            if not record.email_domain and isinstance(email_domain, str) and email_domain:
                record.email_domain = email_domain
            if (context_domains or context_urls) and not had_context:
                record.occurrence = finding.occurrence
            return False

    def summary(self) -> Dict[str, object]:
        with self._lock:
            cats = sorted(set(self.count_total.keys()) | set(self.count_unique.keys()))
            return {
                "categories": {
                    c: {"total": self.count_total.get(c, 0), "unique": self.count_unique.get(c, 0)}
                    for c in cats
                },
            }


class ResultWriter:
    def __init__(self, out_dir: Path, logger: RichLogger):
        self.out_dir = out_dir
        self.logger = logger
        self.findings_dir = out_dir / "findings"
        self.findings_dir.mkdir(parents=True, exist_ok=True)

    def write_all(self, store: ResultStore, run_metadata: Dict[str, object]) -> None:
        categories = sorted(store.records.keys())
        for cat in categories:
            if cat == "credentials":
                self._write_credentials(store)
                continue
            jsonl_path = self.findings_dir / f"{cat}.jsonl"
            findings = list(store.records.get(cat, {}).values())
            findings.sort(key=lambda f: (f.value, f.occurrence.source, f.occurrence.line_no))
            with open(jsonl_path, "w", encoding="utf-8") as f:
                for finding in findings:
                    payload = {
                        "category": finding.category,
                        "value": finding.value,
                        "source": finding.occurrence.source,
                        "line_no": finding.occurrence.line_no,
                        "snippet": finding.occurrence.snippet,
                    }
                    if finding.context:
                        payload["context"] = finding.context
                    f.write(json.dumps(payload, ensure_ascii=False) + "\n")

        # Always write credentials after other categories
        self._write_credentials(store)

        with open(self.out_dir / "summary.json", "w", encoding="utf-8") as f:
            json.dump(store.summary(), f, indent=2)

        with open(self.out_dir / "run_metadata.json", "w", encoding="utf-8") as f:
            json.dump(run_metadata, f, indent=2)

        self.logger.done(f"Results written to: {self.out_dir}")

    def _write_credentials(self, store: ResultStore) -> None:
        if not store.credentials:
            return
        jsonl_path = self.findings_dir / "credentials.jsonl"

        records = sorted(store.credentials.values(), key=lambda r: r.value)
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for record in records:
                payload = {
                    "category": "credentials",
                    "value": record.value,
                    "username": record.username,
                    "password": record.password,
                    "email_domain": record.email_domain,
                    "context_domains": sorted(record.context_domains),
                    "context_urls": sorted(record.context_urls),
                    "source": record.occurrence.source,
                    "line_no": record.occurrence.line_no,
                    "snippet": record.occurrence.snippet,
                    "source_meta": record.source_meta,
                }
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")


class CategorySink:
    def __init__(self, findings_dir: Path):
        self.findings_dir = findings_dir
        self._locks: Dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()

    def _lock_for(self, category: str) -> threading.Lock:
        with self._global_lock:
            if category not in self._locks:
                self._locks[category] = threading.Lock()
            return self._locks[category]

    def write_unique(self, finding: Finding) -> None:
        lock = self._lock_for(finding.category)
        path = self.findings_dir / f"{finding.category}.jsonl"
        rec = {
            "category": finding.category,
            "value": finding.value,
            "source": finding.occurrence.source,
            "line_no": finding.occurrence.line_no,
            "snippet": finding.occurrence.snippet,
        }
        if finding.context:
            rec["context"] = finding.context
        with lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
