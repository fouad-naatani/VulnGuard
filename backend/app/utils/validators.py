"""Reusable input validators shared by the schema layer."""
 
from __future__ import annotations
 
import ipaddress
import re
 
HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9-_.]{1,253}(?<!-)$")
 
 
def validate_ip_address(value: str) -> str:
    """Validate an IPv4/IPv6 address and return its normalised form."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:  # pragma: no cover - message is user facing
        raise ValueError("Invalid IP address") from exc
 
 
def validate_hostname(value: str) -> str:
    """Validate a DNS hostname (RFC 1123 subset)."""
    hostname = value.strip()
    if not HOSTNAME_RE.match(hostname):
        raise ValueError("Invalid hostname")
    return hostname
 
 
def validate_password_strength(value: str) -> str:
    """Enforce the platform password policy.
 
    A valid password is at least 10 characters long and mixes upper case,
    lower case, digits and symbols (at least three of the four classes).
    """
    if len(value) < 10:
        raise ValueError("Password must be at least 10 characters long")
    classes = [
        bool(re.search(r"[a-z]", value)),
        bool(re.search(r"[A-Z]", value)),
        bool(re.search(r"[0-9]", value)),
        bool(re.search(r"[^A-Za-z0-9]", value)),
    ]
    if sum(classes) < 3:
        raise ValueError(
            "Password must mix at least three of: lowercase, uppercase, digits, symbols"
        )
    return value