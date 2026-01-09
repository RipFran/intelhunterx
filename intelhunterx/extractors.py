from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional
from urllib.parse import urlsplit, urlunsplit

from .models import Finding, Occurrence
from .normalize import DEFAULT_PORTS, normalize_asset, normalize_credential, normalize_email, normalize_host
from .patterns import EMAIL_BODY_PATTERN, EMAIL_RX, HOSTNAME_FULL_RX, HOST_RX, URL_SCHEME_RX, URL_WWW_RX
from .selector import SelectorContext
from .text_utils import TRAILING_PUNCT, refang_text, strip_html_tags, trim_snippet

PROTOCOL_USER_BLACKLIST = {
    "http",
    "https",
    "ftp",
    "ftps",
    "sftp",
    "smtp",
    "imap",
    "pop3",
    "ssh",
    "telnet",
    "ldap",
    "ldaps",
    "rdp",
    "mysql",
    "postgres",
    "postgresql",
    "mongodb",
    "redis",
    "amqp",
    "mqtt",
    "mssql",
    "sqlserver",
    "snmp",
    "vnc",
}

CRED_KEYWORDS_RX = re.compile(r"(?i)\b(user(name)?|login|email|pass(word)?|pwd|passwd|credential|creds)\b")
COOKIE_HEADER_RX = re.compile(r"(?i)\bset-cookie\s*:")
COOKIE_INLINE_RX = re.compile(r"(?i)\bcookie\s*:")
PASSWORD_ALLOWED_RX = re.compile(r"^[\w!@#$%^&*+=._?\-]{4,128}$")
PASSWORD_HAS_DIGIT_RX = re.compile(r"\d")
PASSWORD_HAS_SYMBOL_RX = re.compile(r"[!@#$%^&*+=._,?\-]")
USER_FILE_EXT_RX = re.compile(r"(?i)\.(?:asp|aspx|php|jsp|js|css|html?)$")

CRED_USER_PATTERN = rf"(?:{EMAIL_BODY_PATTERN}|[A-Z0-9][A-Z0-9._\-]{{1,63}})"
CRED_PASS_PATTERN = r"[\w!@#$%^&*+=._?\-]{4,128}"
CRED_SEP_PATTERN = r"(?:[|,:;]|\t)+"
URL_CRED_TAIL_RX = re.compile(
    rf"^\s*{CRED_SEP_PATTERN}\s*(?P<user>{CRED_USER_PATTERN})\s*{CRED_SEP_PATTERN}\s*(?P<pwd>{CRED_PASS_PATTERN})(?:\s*{CRED_SEP_PATTERN}\s*.*)?$",
    re.IGNORECASE,
)
URL_CRED_TAIL_INLINE_RX = re.compile(
    rf"{CRED_SEP_PATTERN}\s*(?P<user>{CRED_USER_PATTERN})\s*{CRED_SEP_PATTERN}\s*(?P<pwd>{CRED_PASS_PATTERN})(?:\s*{CRED_SEP_PATTERN}\s*.*)?$",
    re.IGNORECASE,
)
URL_CRED_SPACE_TAIL_RX = re.compile(
    rf"^\s+(?P<user>{CRED_USER_PATTERN})\s*{CRED_SEP_PATTERN}\s*(?P<pwd>{CRED_PASS_PATTERN})(?:\s*{CRED_SEP_PATTERN}\s*.*)?$",
    re.IGNORECASE,
)

USER_BLACKLIST = {
    "user",
    "username",
    "login",
    "email",
    "userid",
    "uid",
    "account",
    "content-type",
    "content-length",
    "content-encoding",
    "content-security-policy",
    "content-disposition",
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "referer",
    "origin",
    "host",
    "connection",
    "cache-control",
    "pragma",
    "date",
    "server",
    "etag",
    "expires",
    "last-modified",
    "location",
    "upgrade",
    "upgrade-insecure-requests",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "path",
    "domain",
    "secure",
    "httponly",
    "samesite",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-real-ip",
    "x-requested-with",
    "title",
    "url",
    "value",
    "values",
    "from",
    "to",
    "subject",
    "password",
    "pass",
    "pwd",
    "secret",
    "amp",
    "nbsp",
    "true",
    "false",
    "email_domain",
    "email_status",
    "email_verification_status",
    "database_site_id",
    "database_individual_id",
    "predicted_email_server_type",
    "web_address",
    "city",
    "state",
    "city_state",
}

PASSWORD_PLACEHOLDERS = {
    "true",
    "false",
    "null",
    "none",
    "undefined",
    "yes",
    "no",
    "on",
    "off",
    "empty",
    "n/a",
    "na",
}


@dataclass(frozen=True)
class ParsedUrl:
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    username: Optional[str]
    password: Optional[str]


def is_valid_domain(host: str) -> bool:
    return HOSTNAME_FULL_RX.match(host) is not None


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_host(value: str) -> bool:
    if is_valid_ip(value):
        return True
    return is_valid_domain(value)


def is_valid_port(port: Optional[int]) -> bool:
    return port is not None and 1 <= port <= 65535


def parse_url_candidate(candidate: str) -> Optional[ParsedUrl]:
    cleaned = candidate.strip().strip(TRAILING_PUNCT)
    if not cleaned:
        return None
    cleaned = refang_text(cleaned)
    if cleaned.lower().startswith("www."):
        cleaned = "http://" + cleaned
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    host = parts.hostname or ""
    if not host:
        return None
    if not is_valid_host(host):
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    return ParsedUrl(
        scheme=parts.scheme.lower(),
        host=host,
        port=port,
        path=parts.path or "",
        query=parts.query or "",
        username=parts.username,
        password=parts.password,
    )


def trim_url_before_credential(candidate: str) -> str:
    raw = candidate.strip()
    if not raw:
        return raw
    lower = raw.lower()
    scheme_idx = lower.find("://")
    if scheme_idx >= 0:
        netloc_start = scheme_idx + 3
    else:
        netloc_start = 0

    netloc_end = len(raw)
    for i in range(netloc_start, len(raw)):
        ch = raw[i]
        if ch.isspace() or ch in "|,;":
            netloc_end = i
            break
        if ch in "/?#":
            netloc_end = i
            break

    netloc = raw[netloc_start:netloc_end]
    if not netloc:
        return raw

    if netloc.startswith("["):
        bracket_end = netloc.find("]")
        if bracket_end != -1:
            after = netloc[bracket_end + 1 :]
            if after.startswith(":") and after[1:] and not after[1:].isdigit():
                return raw[: netloc_start + bracket_end + 1]
        return raw

    at_idx = netloc.rfind("@")
    search_start = at_idx + 1 if at_idx != -1 else 0
    colon_idx = netloc.find(":", search_start)
    if colon_idx == -1:
        return raw

    j = colon_idx + 1
    while j < len(netloc) and netloc[j].isdigit():
        j += 1
    if j == colon_idx + 1:
        return raw[: netloc_start + colon_idx]
    if j < len(netloc):
        return raw[: netloc_start + j]
    return raw


def parse_url_candidate_loose(candidate: str) -> Optional[tuple[ParsedUrl, int]]:
    trimmed = candidate.strip()
    while trimmed and trimmed[-1] in TRAILING_PUNCT:
        trimmed = trimmed[:-1]

    parsed = parse_url_candidate(trimmed)
    if parsed:
        return parsed, len(trimmed)

    trimmed2 = trim_url_before_credential(trimmed)
    if trimmed2 and trimmed2 != trimmed:
        parsed2 = parse_url_candidate(trimmed2)
        if parsed2:
            return parsed2, len(trimmed2)

    return None


def build_url(parsed: ParsedUrl) -> str:
    host = normalize_host(parsed.host)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parsed.username:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo = f"{userinfo}:{parsed.password}"
        netloc = f"{userinfo}@{netloc}"
    if parsed.port:
        default_port = DEFAULT_PORTS.get(parsed.scheme)
        if not (default_port and parsed.port == default_port):
            netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, "")).strip(TRAILING_PUNCT)


def iter_url_candidates(text: str) -> Iterable[tuple[str, int, int]]:
    for m in URL_SCHEME_RX.finditer(text):
        yield (m.group(1), m.start(1), m.end(1))
    for m in URL_WWW_RX.finditer(text):
        yield (m.group(1), m.start(1), m.end(1))


def selector_allows_host(host: str, selector_ctx: SelectorContext) -> bool:
    host_norm = normalize_host(host)
    if selector_ctx.kind == "multi":
        if selector_ctx.domains:
            if is_valid_ip(host_norm):
                return False
            for dom in selector_ctx.domains:
                if host_norm == dom or host_norm.endswith(f".{dom}"):
                    return True
            return False
        if selector_ctx.keywords:
            if is_valid_ip(host_norm):
                return False
            return any(keyword in host_norm for keyword in selector_ctx.keywords)
        return True
    if selector_ctx.kind == "keyword":
        keyword = selector_ctx.raw.lower()
        if not keyword:
            return True
        if is_valid_ip(host_norm):
            return False
        return keyword in host_norm
    if selector_ctx.kind in ("domain", "email") and selector_ctx.domain:
        if is_valid_ip(host_norm):
            return False
        return host_norm == selector_ctx.domain or host_norm.endswith(f".{selector_ctx.domain}")
    return True


def selector_allows_email(email: str, selector_ctx: SelectorContext) -> bool:
    try:
        domain = email.split("@", 1)[1].lower()
    except IndexError:
        return False
    if selector_ctx.kind == "multi":
        email_norm = normalize_email(email)
        if selector_ctx.emails and email_norm in selector_ctx.emails:
            return True
        if selector_ctx.domains:
            return selector_allows_host(domain, selector_ctx)
        if selector_ctx.keywords:
            return any(keyword in email_norm for keyword in selector_ctx.keywords)
        return True
    return selector_allows_host(domain, selector_ctx)


def selector_allows_credential(user: str, selector_ctx: SelectorContext) -> bool:
    if "@" not in user:
        return True
    return selector_allows_email(user, selector_ctx)


def looks_like_url(value: str) -> bool:
    lowered = value.lower()
    return "://" in lowered or lowered.startswith("//") or lowered.startswith("www.")


def looks_masked(value: str) -> bool:
    if len(value) < 4:
        return False
    if len(set(value)) == 1 and value[0] in ("*", "x", "X", "#"):
        return True
    return False


def looks_like_email(value: str) -> bool:
    return "@" in value and "." in value.split("@")[-1]


def looks_like_domain(value: str) -> bool:
    if "@" in value:
        return False
    return is_valid_domain(value)


def is_user_blacklisted(user: str) -> bool:
    lowered = user.strip().lower()
    if lowered in USER_BLACKLIST:
        return True
    if lowered.startswith(("x-", "sec-", "cf-")):
        return True
    return False


def is_noise_password(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered in PASSWORD_PLACEHOLDERS


def is_password_candidate(password: str, user_is_email: bool, has_keywords: bool, has_context: bool) -> bool:
    if ":" in password or "/" in password or "\\" in password:
        return False
    if looks_like_url(password):
        return False
    if looks_like_email(password) or looks_like_domain(password):
        return False
    if "&" in password and "=" in password:
        return False
    if is_noise_password(password):
        return False
    if not PASSWORD_ALLOWED_RX.match(password):
        return False
    if user_is_email:
        return True
    if not (has_keywords or has_context):
        return False
    return bool(PASSWORD_HAS_DIGIT_RX.search(password) or PASSWORD_HAS_SYMBOL_RX.search(password))


def looks_like_netscape_cookie(line: str) -> bool:
    if "\t" not in line:
        return False
    if line.lstrip().startswith("#"):
        return True
    parts = line.split("\t")
    if len(parts) < 7:
        return False
    domain = parts[0].strip()
    flag = parts[1].strip().upper()
    path = parts[2].strip()
    secure = parts[3].strip().upper()
    expiry = parts[4].strip()
    if flag not in ("TRUE", "FALSE") or secure not in ("TRUE", "FALSE"):
        return False
    if not expiry.lstrip("-").isdigit():
        return False
    if not path.startswith("/"):
        return False
    dom = domain.lstrip(".")
    if not (is_valid_domain(dom) or is_valid_ip(dom)):
        return False
    return True


def looks_like_cookie_line(line: str) -> bool:
    if COOKIE_HEADER_RX.search(line) or COOKIE_INLINE_RX.search(line):
        return True
    return looks_like_netscape_cookie(line)


def build_context_url(parsed: ParsedUrl) -> str:
    host = normalize_host(parsed.host)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parsed.port:
        default_port = DEFAULT_PORTS.get(parsed.scheme)
        if not (default_port and parsed.port == default_port):
            netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, "")).strip(TRAILING_PUNCT)


def extract_credential_context(
    line: str,
    parsed_urls: List[ParsedUrl],
    selector_ctx: SelectorContext,
) -> tuple[set[str], set[str]]:
    domains: set[str] = set()
    urls: set[str] = set()

    for parsed in parsed_urls:
        if not selector_allows_host(parsed.host, selector_ctx):
            continue
        domains.add(normalize_host(parsed.host))
        urls.add(build_context_url(parsed))

    for m in HOST_RX.finditer(line):
        host = normalize_host(m.group(1))
        if not is_valid_domain(host):
            continue
        if m.start() > 0 and line[m.start() - 1] == "@":
            continue
        if not selector_allows_host(host, selector_ctx):
            continue
        domains.add(host)

    return domains, urls


def prune_self_domain(domains: set[str], user: str) -> set[str]:
    if not looks_like_domain(user):
        return domains
    user_host = normalize_host(user)
    if user_host not in domains:
        return domains
    pruned = set(domains)
    pruned.discard(user_host)
    return pruned


def should_accept_credential(
    user: str,
    password: str,
    is_simple_line: bool,
    has_keywords: bool,
    has_context: bool,
    selector_ctx: SelectorContext,
    context_allows: bool = False,
) -> bool:
    user = user.strip()
    password = password.strip()
    user_is_email = looks_like_email(user)

    if user.lower() in PROTOCOL_USER_BLACKLIST:
        return False
    if is_user_blacklisted(user):
        return False
    if USER_FILE_EXT_RX.search(user) and not has_keywords:
        return False
    if len(user) < 3 and not user_is_email:
        return False
    if looks_masked(password):
        return False
    if len(password) < 4 or len(password) > 128:
        return False
    if not selector_allows_credential(user, selector_ctx) and not context_allows:
        return False

    if not is_password_candidate(password, user_is_email, has_keywords, has_context):
        return False

    if user_is_email:
        return True

    if looks_like_domain(user) and not (has_keywords or has_context or is_simple_line):
        return False

    if user.isdigit():
        return has_keywords or has_context
    if not any(ch.isalpha() for ch in user):
        return has_keywords or has_context
    if user.isupper() and password.isupper() and not (has_keywords or has_context):
        return False

    if is_simple_line:
        return True

    return has_keywords or has_context


def extract_from_text(
    line: str,
    source: str,
    line_no: int,
    selector_ctx: SelectorContext,
    include_emails: bool = True,
    include_surface: bool = True,
    include_credentials: bool = True,
) -> List[Finding]:
    findings: List[Finding] = []
    raw = line.strip()
    if not raw:
        return findings
    if not (include_emails or include_surface or include_credentials):
        return findings

    cleaned = strip_html_tags(raw)
    refanged = refang_text(cleaned)
    occ = Occurrence(source=source, line_no=line_no, snippet=trim_snippet(cleaned))
    line_strip = refanged.strip()
    url_entries: List[tuple[str, ParsedUrl, int, int]] = []

    if include_emails:
        for m in EMAIL_RX.finditer(refanged):
            email = normalize_email(m.group(1))
            if selector_allows_email(email, selector_ctx):
                findings.append(Finding("emails", email, occ))

    if include_surface or include_credentials:
        for candidate, start, end in iter_url_candidates(refanged):
            parsed_info = parse_url_candidate_loose(candidate)
            if not parsed_info:
                continue
            parsed, trimmed_len = parsed_info
            adjusted_end = start + trimmed_len
            candidate_trimmed = candidate[:trimmed_len]
            inline_match = URL_CRED_TAIL_INLINE_RX.search(candidate_trimmed)
            if inline_match:
                base_candidate = candidate_trimmed[: inline_match.start()]
                parsed_base = parse_url_candidate(base_candidate)
                if parsed_base:
                    parsed = parsed_base
                adjusted_end = start + inline_match.start()
            url_entries.append((candidate_trimmed, parsed, start, adjusted_end))
            if include_surface and selector_allows_host(parsed.host, selector_ctx):
                url_value = build_context_url(parsed)
                findings.append(Finding("hostnames", normalize_host(parsed.host), occ))
                findings.append(Finding("endpoints", url_value, occ))
                asset_port = parsed.port if parsed.port is not None else DEFAULT_PORTS.get(parsed.scheme)
                if is_valid_port(asset_port):
                    asset_value = normalize_asset(parsed.scheme, parsed.host, asset_port)
                    findings.append(Finding("assets", asset_value, occ))

    if include_surface:
        for m in HOST_RX.finditer(refanged):
            host = normalize_host(m.group(1))
            if not is_valid_domain(host):
                continue
            if selector_allows_host(host, selector_ctx):
                findings.append(Finding("hostnames", host, occ))

    if include_credentials and not looks_like_cookie_line(line_strip):
        has_keywords = CRED_KEYWORDS_RX.search(line_strip) is not None

        for _, parsed, _, end in url_entries:
            if not selector_allows_host(parsed.host, selector_ctx):
                continue
            if parsed.username and parsed.password is not None:
                user = parsed.username
                pwd = parsed.password
                url_domains = {normalize_host(parsed.host)}
                url_contexts = {build_context_url(parsed)}
                candidate_domains = prune_self_domain(url_domains, user)
                candidate_has_context = True
                if should_accept_credential(
                    user,
                    pwd,
                    False,
                    has_keywords,
                    candidate_has_context,
                    selector_ctx,
                    context_allows=True,
                ):
                    normalized_value = normalize_credential(user, pwd)
                    normalized_user = normalize_email(user) if looks_like_email(user) else user.strip()
                    email_domain = normalize_host(user.split("@", 1)[1]) if looks_like_email(user) else None
                    findings.append(
                        Finding(
                            "credentials",
                            normalized_value,
                            occ,
                            context={
                                "username": normalized_user,
                                "password": pwd,
                                "email_domain": email_domain,
                                "context_domains": sorted(candidate_domains),
                                "context_urls": sorted(url_contexts),
                            },
                        )
            )
            tail = refanged[end:]
            m = URL_CRED_TAIL_RX.match(tail)
            if not m:
                m = URL_CRED_SPACE_TAIL_RX.match(tail)
            if not m:
                continue
            user = m.group("user").strip().strip("'\"")
            pwd = m.group("pwd").strip().strip("'\"")
            url_domains = {normalize_host(parsed.host)}
            url_contexts = {build_context_url(parsed)}
            candidate_domains = prune_self_domain(url_domains, user)
            candidate_has_context = True
            if not should_accept_credential(
                user,
                pwd,
                False,
                has_keywords,
                candidate_has_context,
                selector_ctx,
                context_allows=True,
            ):
                continue
            normalized_value = normalize_credential(user, pwd)
            normalized_user = normalize_email(user) if looks_like_email(user) else user.strip()
            email_domain = normalize_host(user.split("@", 1)[1]) if looks_like_email(user) else None
            findings.append(
                Finding(
                    "credentials",
                    normalized_value,
                    occ,
                    context={
                        "username": normalized_user,
                        "password": pwd,
                        "email_domain": email_domain,
                        "context_domains": sorted(candidate_domains),
                        "context_urls": sorted(url_contexts),
                    },
                )
            )

    return findings
