from __future__ import annotations

import datetime as dt
import hashlib
import re
from pathlib import Path
from typing import Optional


DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ftps": 21,
    "sftp": 22,
    "ssh": 22,
    "smtp": 25,
    "smtps": 465,
    "imap": 143,
    "imaps": 993,
    "pop3": 110,
    "pop3s": 995,
    "ldap": 389,
    "ldaps": 636,
    "mysql": 3306,
    "postgres": 5432,
    "postgresql": 5432,
    "mssql": 1433,
    "sqlserver": 1433,
    "redis": 6379,
    "mongodb": 27017,
    "mongodb+srv": 27017,
    "amqp": 5672,
    "amqps": 5671,
    "mqtt": 1883,
    "mqtts": 8883,
    "rdp": 3389,
    "mariadb": 3306,
}


def normalize_email(email: str) -> str:
    return email.strip().lower()


def normalize_host(host: str) -> str:
    return host.strip().strip(".").lower()


def normalize_credential(user: str, pwd: str) -> str:
    u = user.strip()
    if "@" in u and "." in u.split("@")[-1]:
        u = normalize_email(u)
    return f"{u}:{pwd.strip()}"


def normalize_asset(scheme: str, host: str, port: int) -> str:
    host_value = normalize_host(host)
    if ":" in host_value and not host_value.startswith("["):
        host_value = f"[{host_value}]"
    return f"{scheme}://{host_value}:{port}"


def stable_key(category: str, value: str) -> str:
    h = hashlib.blake2b(digest_size=16)
    h.update(category.encode("utf-8", errors="ignore"))
    h.update(b"\x00")
    h.update(value.encode("utf-8", errors="ignore"))
    return h.hexdigest()


def sanitize_for_fs(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._\\-]+", "_", name.strip())
    safe = safe.strip("._-")
    return safe[:120] if safe else "selector"


def build_output_dir(base_out: Path, selector: str, stamp: Optional[str] = None) -> Path:
    ts = stamp or dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return base_out / f"{sanitize_for_fs(selector)}_{ts}"
