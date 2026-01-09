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


WINDOWS_FORBIDDEN_CHARS = set('<>:"/\\|?*')
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "CLOCK$",
}
SAFE_NAME_MAX_LEN = 120


def is_fs_safe_name(name: str) -> bool:
    if not name:
        return False
    if name != name.strip():
        return False
    if name.endswith((" ", ".")):
        return False
    for ch in name:
        if ch in WINDOWS_FORBIDDEN_CHARS:
            return False
        if ord(ch) < 32 or ord(ch) > 126:
            return False
    base = name.strip(" .").split(".", 1)[0]
    if base.upper() in WINDOWS_RESERVED_NAMES:
        return False
    if len(name) > SAFE_NAME_MAX_LEN:
        return False
    return True


def build_query_dir_name(query: str) -> str:
    raw = query.strip()
    if not raw:
        return "query"
    if is_fs_safe_name(raw):
        return raw
    slug = _slugify_query(raw)
    slug = slug.rstrip(" .")
    if not slug:
        slug = "query"
    digest = hashlib.blake2b(raw.encode("utf-8"), digest_size=5).hexdigest()
    suffix = f"__{digest}"
    max_len = SAFE_NAME_MAX_LEN
    if len(slug) + len(suffix) > max_len:
        slug = slug[: max(1, max_len - len(suffix))].rstrip(" .")
        if not slug:
            slug = "query"
    name = f"{slug}{suffix}"
    base = name.strip(" .").split(".", 1)[0]
    if base.upper() in WINDOWS_RESERVED_NAMES:
        name = f"q_{name}"
        if len(name) > max_len:
            name = name[:max_len].rstrip(" .")
    return name


def _slugify_query(raw: str) -> str:
    replacements = {
        "*": "_wildcard_",
        "?": "_single_",
        ":": "_colon_",
        "/": "_slash_",
        "\\": "_slash_",
        "|": "_pipe_",
        "<": "_lt_",
        ">": "_gt_",
        "\"": "_quote_",
    }
    safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@+=,()[]{}")
    out = []
    for ch in raw:
        if ch in replacements:
            out.append(replacements[ch])
            continue
        if ch in safe_chars:
            out.append(ch)
            continue
        if ch.isspace():
            out.append("_")
            continue
        if ord(ch) < 32 or ord(ch) > 126:
            out.append("_")
            continue
        out.append("_")
    return "".join(out)


def build_output_dir(base_out: Path, selector: str, stamp: Optional[str] = None) -> Path:
    ts = stamp or dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return base_out / f"{sanitize_for_fs(selector)}_{ts}"
