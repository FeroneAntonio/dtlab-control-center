"""Central redaction and spreadsheet-safety helpers for DTLab exports."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from dtlab.contract import find_secret_leaks, validate_snapshot

_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_IPV4 = re.compile(
    r"(?<![0-9.])"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}"
    r"(?![0-9]|\.[0-9])"
)
_IP_TOKEN = re.compile(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f:.]{3,})(?![0-9A-Fa-f:.])")
_CSV_DANGEROUS = re.compile(r"^[\t\r\n ]*[=+\-@]")


class RedactionError(ValueError):
    """An export could expose secrets or was requested with unsafe settings."""


def _pseudonym(kind: str, value: str, salt: bytes) -> str:
    digest = hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:10]
    return f"{kind}-{digest}"


def _replace_addresses(value: str, salt: bytes) -> str:
    value = _MAC.sub(lambda match: _pseudonym("mac", match.group(0).lower(), salt), value)

    # IPv4 needs its own matcher: generic IP-like tokens can include a preceding
    # identifier colon (``record:172.16.10.10``) or trailing prose punctuation,
    # neither of which belongs to the address passed to ``ipaddress``.
    value = _IPV4.sub(
        lambda match: _pseudonym(
            "ip", str(ipaddress.ip_address(match.group(0))), salt
        ),
        value,
    )

    def replace_ip(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            normalized = str(ipaddress.ip_address(candidate))
        except ValueError:
            return candidate
        return _pseudonym("ip", normalized, salt)

    return _IP_TOKEN.sub(replace_ip, value)


def _redact_value(value: Any, salt: bytes) -> Any:
    if isinstance(value, Mapping):
        return {key: _redact_value(nested, salt) for key, nested in value.items()}
    if isinstance(value, list):
        return [_redact_value(nested, salt) for nested in value]
    if isinstance(value, str):
        return _replace_addresses(value, salt)
    return value


def redacted_snapshot(
    snapshot: Mapping[str, Any],
    *,
    mode: str,
    salt: bytes | None = None,
) -> dict[str, Any]:
    """Create an explicitly technical or public export copy.

    Technical exports preserve topology addresses but still reject credential-like material.
    Public exports pseudonymize IPv4, IPv6, and MAC values consistently within the bundle.
    """

    validate_snapshot(snapshot)
    leaks = find_secret_leaks(snapshot)
    if leaks:
        raise RedactionError("Lo snapshot contiene materiale sensibile")
    if mode == "technical":
        return deepcopy(snapshot)
    if mode != "public":
        raise RedactionError("mode deve essere 'technical' o 'public'")
    if not salt or len(salt) < 16:
        raise RedactionError("La redazione pubblica richiede un salt di almeno 16 byte")
    return _redact_value(snapshot, salt)


def safe_csv_cell(value: Any) -> Any:
    """Prevent spreadsheet formula execution while preserving non-string values."""

    if isinstance(value, str) and _CSV_DANGEROUS.match(value):
        return "'" + value
    return value
