"""Client-side IPv4/IPv6, CIDR prefix, and API key validation utilities."""

from __future__ import annotations

import ipaddress
from typing import Sequence

from .errors import IpScopeValidationError
from .types import IpFamily


def validate_api_key(raw_api_key: object) -> str:
    """Validates and normalizes an IPScope API key, rejecting control characters."""
    if not isinstance(raw_api_key, str):
        raise IpScopeValidationError("API key must be a non-empty string", "api_key")
    trimmed = raw_api_key.strip()
    if not trimmed:
        raise IpScopeValidationError("API key cannot be empty", "api_key")
    if any(ch in trimmed for ch in ("\r", "\n", "\x00")):
        raise IpScopeValidationError(
            "API key contains invalid control characters", "api_key"
        )
    return trimmed


def validate_ip_address(raw_ip: object) -> tuple[str, IpFamily]:
    """Validates an IPv4 or IPv6 address string and returns `(canonical_ip, family)`."""
    if not isinstance(raw_ip, str):
        raise IpScopeValidationError("IP address must be a string", "ip")
    trimmed = raw_ip.strip()
    if not trimmed or "%" in trimmed:
        raise IpScopeValidationError(
            f'Invalid IPv4 or IPv6 address: "{trimmed}"', "ip"
        )
    try:
        addr = ipaddress.ip_address(trimmed)
    except ValueError as exc:
        raise IpScopeValidationError(
            f'Invalid IPv4 or IPv6 address: "{trimmed}"', "ip"
        ) from exc

    family: IpFamily = 6 if addr.version == 6 else 4
    return str(addr).lower(), family


def validate_cidr_prefix(raw_cidr: object) -> tuple[str, int, IpFamily, str]:
    """Validates a CIDR prefix (`<ip>/<prefix_length>`) and returns `(address, prefix_length, family, normalized_cidr)`."""
    if not isinstance(raw_cidr, str):
        raise IpScopeValidationError("CIDR prefix must be a string", "cidr")
    trimmed = raw_cidr.strip()
    if "/" not in trimmed or trimmed.count("/") != 1:
        raise IpScopeValidationError(
            f'Invalid CIDR notation "{trimmed}". Expected "<ip>/<prefixLength>" (e.g. "1.1.1.0/24")',
            "cidr",
        )

    raw_addr, raw_len = trimmed.split("/", 1)
    ip_str, family = validate_ip_address(raw_addr)
    raw_len_stripped = raw_len.strip()
    if not raw_len_stripped.isdigit():
        raise IpScopeValidationError(
            f'Invalid prefix length "{raw_len_stripped}" in CIDR "{trimmed}"', "cidr"
        )

    prefix_len = int(raw_len_stripped, 10)
    max_bits = 32 if family == 4 else 128
    if prefix_len < 0 or prefix_len > max_bits:
        raise IpScopeValidationError(
            f"Prefix length {prefix_len} out of range [0..{max_bits}] for IPv{family} CIDR \"{trimmed}\"",
            "cidr",
        )

    try:
        net = ipaddress.ip_network(f"{ip_str}/{prefix_len}", strict=False)
    except ValueError as exc:
        raise IpScopeValidationError(
            f'Invalid CIDR prefix: "{trimmed}"', "cidr"
        ) from exc

    net_addr = str(net.network_address).lower()
    return net_addr, net.prefixlen, family, f"{net_addr}/{net.prefixlen}"


def validate_and_deduplicate_batch_ips(
    raw_ips: object,
    max_batch_size: int = 100,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Validates a sequence of IPs (`1..max_batch_size`) and returns `(ordered_normalized_ips, unique_ips)`."""
    if isinstance(raw_ips, (str, bytes)) or not isinstance(raw_ips, Sequence):
        raise IpScopeValidationError(
            "Batch IPs must be a sequence of IPv4/IPv6 strings", "ips"
        )
    if len(raw_ips) == 0:
        raise IpScopeValidationError(
            "Batch IPs sequence must contain at least 1 IP address", "ips"
        )
    if len(raw_ips) > max_batch_size:
        raise IpScopeValidationError(
            f"Batch IPs length ({len(raw_ips)}) exceeds maximum single-request batch size ({max_batch_size}). Use lookup_batch_chunked() or lookup_batch_stream() for larger lists.",
            "ips",
        )

    ordered: list[str] = []
    unique_seen: dict[str, None] = {}
    for item in raw_ips:
        ip_str, _ = validate_ip_address(item)
        ordered.append(ip_str)
        unique_seen[ip_str] = None

    return tuple(ordered), tuple(unique_seen.keys())
