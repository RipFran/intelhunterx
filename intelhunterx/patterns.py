from __future__ import annotations

import re

DOMAIN_LABEL = r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
TLD_LABEL = r"(?:[A-Z]{2,63}|XN--[A-Z0-9-]{2,59})"
DOMAIN_PATTERN = rf"(?:{DOMAIN_LABEL}\.)+{TLD_LABEL}"
EMAIL_BODY_PATTERN = rf"[A-Z0-9._%+\-]{{1,64}}@{DOMAIN_PATTERN}"

EMAIL_RX = re.compile(rf"(?i)(?<![A-Z0-9._%+\-])({EMAIL_BODY_PATTERN})")
HOST_RX = re.compile(rf"(?i)\b({DOMAIN_PATTERN})\b")
HOSTNAME_FULL_RX = re.compile(rf"(?i)^{DOMAIN_PATTERN}$")

URL_SCHEME_RX = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15}://[^\s\"'<>]{3,2048})")
URL_WWW_RX = re.compile(r"(?i)\b(www\.[^\s\"'<>]{3,2048})")
