from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from .normalize import normalize_email, normalize_host


def _looks_like_email(value: str) -> bool:
    return "@" in value and "." in value.split("@")[-1]


def _looks_like_domain(value: str) -> bool:
    if " " in value or "/" in value:
        return False
    if "." not in value:
        return False
    if _looks_like_email(value):
        return False
    return True


def _build_defang_regex_for_domain(domain: str) -> str:
    parts = domain.strip().lower().split(".")
    if len(parts) < 2:
        return re.escape(domain)
    sep = r"(?:\.|\[\.\]|\(\.\)|\s+dot\s+)"
    return sep.join(re.escape(p) for p in parts)


def _build_defang_regex_for_email(email: str) -> str:
    if "@" not in email:
        return re.escape(email)
    user, dom = email.split("@", 1)
    at = r"(?:@|\s*\[at\]\s*|\s*\(at\)\s*)"
    dom_re = _build_defang_regex_for_domain(dom)
    return re.escape(user) + at + dom_re


def _strip_tld(domain: str) -> str:
    host = normalize_host(domain)
    parts = host.split(".")
    if len(parts) <= 1:
        return host
    return ".".join(parts[:-1])


class SelectorMatcher:
    def __init__(self, selector: str | Sequence[str]):
        if isinstance(selector, (list, tuple, set)):
            selectors = [s.strip() for s in selector if s and s.strip()]
            if not selectors:
                raise ValueError("Selectors cannot be empty")
            self.selector = ",".join(selectors)
            patterns = []
            for item in selectors:
                if _looks_like_email(item):
                    patterns.append(_build_defang_regex_for_email(item))
                elif _looks_like_domain(item):
                    dom_re = _build_defang_regex_for_domain(item.lower())
                    sub = r"(?:[a-z0-9-]{1,63}(?:\.|\[\.\]|\(\.\)|\s+dot\s+))*"
                    patterns.append(sub + dom_re)
                else:
                    patterns.append(re.escape(item))
            pattern = "(?:" + "|".join(patterns) + ")"
        else:
            self.selector = selector.strip()
            if not self.selector:
                raise ValueError("Selector cannot be empty")
            if _looks_like_email(self.selector):
                pattern = _build_defang_regex_for_email(self.selector)
            elif _looks_like_domain(self.selector):
                dom_re = _build_defang_regex_for_domain(self.selector.lower())
                sub = r"(?:[a-z0-9-]{1,63}(?:\.|\[\.\]|\(\.\)|\s+dot\s+))*"
                pattern = sub + dom_re
            else:
                pattern = re.escape(self.selector)

        self._rx = re.compile(pattern, re.IGNORECASE)

    def matches(self, text: str) -> bool:
        return self._rx.search(text) is not None


@dataclass(frozen=True)
class SelectorContext:
    raw: str
    kind: str
    domain: Optional[str]
    email: Optional[str]
    matcher: SelectorMatcher
    domains: tuple[str, ...] = ()
    emails: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()


def build_selector_context(selector: str, selector_only: bool = True) -> SelectorContext:
    raw = selector.strip()
    if _looks_like_email(raw):
        email = normalize_email(raw)
        domain = normalize_host(email.split("@", 1)[1])
        kind = "email"
    elif _looks_like_domain(raw):
        email = None
        domain = normalize_host(raw)
        kind = "domain"
    else:
        email = None
        domain = None
        kind = "keyword"
    if selector_only:
        domains = (domain,) if domain else ()
        emails = (email,) if email else ()
        keywords = (raw.lower(),) if kind == "keyword" else ()
    else:
        domains = ()
        emails = ()
        if kind == "domain" and domain:
            keywords = (_strip_tld(domain),)
        elif kind == "email" and email:
            keywords = (_strip_tld(email.split("@", 1)[1]),)
        else:
            keywords = (raw.lower(),) if raw else ()
    match_input = raw if selector_only else list(keywords)
    return SelectorContext(
        raw=raw,
        kind=kind,
        domain=domain,
        email=email,
        matcher=SelectorMatcher(match_input),
        domains=domains,
        emails=emails,
        keywords=keywords,
    )


def build_selector_contexts(selectors: Iterable[str], selector_only: bool = True) -> SelectorContext:
    items = [s.strip() for s in selectors if s and s.strip()]
    if not items:
        raise ValueError("Selectors cannot be empty")

    domains: list[str] = []
    emails: list[str] = []
    keywords: list[str] = []
    for raw in items:
        if _looks_like_email(raw):
            email = normalize_email(raw)
            emails.append(email)
            domains.append(normalize_host(email.split("@", 1)[1]))
        elif _looks_like_domain(raw):
            domains.append(normalize_host(raw))
        else:
            keywords.append(raw.lower())

    domain = domains[0] if domains else None
    email = emails[0] if emails else None

    if not selector_only:
        keywords.extend(_strip_tld(d) for d in domains)
        domains = []
        emails = []

    match_input = items if selector_only else list(set(keywords))
    return SelectorContext(
        raw=",".join(items),
        kind="multi",
        domain=domain,
        email=email,
        matcher=SelectorMatcher(match_input),
        domains=tuple(sorted(set(domains))),
        emails=tuple(sorted(set(emails))),
        keywords=tuple(sorted(set(keywords))),
    )
