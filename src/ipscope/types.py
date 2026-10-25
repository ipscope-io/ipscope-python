"""Public, immutable, slotted dataclass types for the IPScope Python Server-Side SDK.

Covers strictly IP-intelligence operations (single IP lookup, visitor IP lookup,
batch & chunked/streamed batch IP lookup, network CIDR prefix lookup, dataset
metadata, feedback submission, and service status) with zero account or billing
surface area.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Generic, Literal, TypeVar

IpFamily = Literal[4, 6]

LocationType = Literal[
    "physical",
    "declared",
    "virtual",
    "anycast",
    "unknown",
]

AnonymizerType = Literal[
    "vpn",
    "proxy",
    "tor_exit",
    "tor_relay",
    "hosting_proxy",
    "apple_private_relay",
    "other_relay",
    "none",
    "unknown",
]

ConnectionType = Literal[
    "residential",
    "mobile",
    "business",
    "hosting",
    "education",
    "government",
    "unknown",
]

FeedbackRole = Literal["network_operator", "researcher", "end_user"]

FeedbackIssueType = Literal[
    "wrong_country",
    "wrong_city",
    "false_positive_vpn",
    "false_negative_vpn",
    "wrong_asn",
    "other",
]

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class GeoResponseBlock:
    """Geographic classification and confidence returned in `IpLookupResponse.geo`."""

    country_code: str | None
    city: str | None
    location_type: LocationType
    confidence: float
    subdivision: str | None = None
    timezone: str | None = None
    accuracy_radius_km: float | None = None
    declared_country_code: str | None = None
    physical_country_code: str | None = None
    is_virtual_location: bool | None = None


@dataclass(frozen=True, slots=True)
class NetworkResponseBlock:
    """Autonomous System and network operator details returned in `IpLookupResponse.network`."""

    asn: int | None
    organization: str | None


@dataclass(frozen=True, slots=True)
class SecurityResponseBlock:
    """Security, hosting, and anonymity classification returned in `IpLookupResponse.security`."""

    is_vpn: bool | None
    is_hosting: bool | None
    is_tor_exit: bool | None
    is_proxy: bool | None
    anonymizer_type: AnonymizerType
    confidence: float
    reason_codes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ConnectionResponseBlock:
    """Optional connection context block returned when licensed."""

    connection_type: ConnectionType
    is_residential: bool | None
    is_mobile: bool | None
    is_business: bool | None
    is_hosting: bool | None


@dataclass(frozen=True, slots=True)
class SecurityExtensionsResponseBlock:
    """Optional security extensions telemetry block returned when licensed."""

    abuse_velocity_score: float | None
    is_known_scanner: bool | None
    observation_recency_hours: float | None


@dataclass(frozen=True, slots=True)
class IpLookupResponse:
    """Canonical single IP lookup response (`GET /v1/ip/:ip` and `GET /v1/ip/me`)."""

    ip: str
    ip_version: IpFamily
    matched_network: str | None
    geo: GeoResponseBlock
    network: NetworkResponseBlock
    security: SecurityResponseBlock
    dataset_version: str
    updated_at: str | None
    connection: ConnectionResponseBlock | None = None
    security_extensions: SecurityExtensionsResponseBlock | None = None


@dataclass(frozen=True, slots=True)
class BatchLookupResponse:
    """Batch IP lookup response (`POST /v1/ip/batch`)."""

    dataset_version: str
    count: int
    results: tuple[IpLookupResponse, ...]


@dataclass(frozen=True, slots=True)
class CanonicalNetworkPrefixRecord:
    """Canonical network prefix record returned in `GET /v1/networks/:prefix/:length`."""

    prefix: str
    family: IpFamily
    asn: int | None
    organization: str | None
    country_code: str | None = None
    city: str | None = None
    location_type: LocationType | None = None
    is_vpn: bool | None = None
    is_hosting: bool | None = None
    is_tor_exit: bool | None = None
    is_proxy: bool | None = None
    anonymizer_type: AnonymizerType | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NetworkPrefixLookupResponse:
    """Network CIDR prefix lookup response (`GET /v1/networks/:prefix/:length`)."""

    queried_cidr: str
    family: IpFamily
    dataset_version: str
    record: CanonicalNetworkPrefixRecord | None


@dataclass(frozen=True, slots=True)
class DatasetSnapshotSummary:
    """Dataset snapshot summary entry returned in `GET /v1/metadata/datasets`."""

    snapshot_version: str
    digest: str
    ruleset_version: str
    published_at: str
    ipv4_prefix_count: int
    ipv6_prefix_count: int


@dataclass(frozen=True, slots=True)
class DatasetsMetadataResponse:
    """Datasets metadata response (`GET /v1/metadata/datasets`)."""

    active_version: str
    previous_version: str | None
    snapshots: tuple[DatasetSnapshotSummary, ...]


@dataclass(frozen=True, slots=True)
class FeedbackSubmissionInput:
    """Input payload for submitting IP/prefix correction feedback (`POST /v1/feedback`)."""

    prefix_or_ip: str
    role: FeedbackRole
    issue_type: FeedbackIssueType
    requested_correction: Mapping[str, Any]
    evidence_urls: Sequence[str] | None = None


@dataclass(frozen=True, slots=True)
class FeedbackSubmissionResponse:
    """Response returned when submitting IP/prefix correction feedback (`POST /v1/feedback`)."""

    id: str
    prefix_or_ip: str
    role: FeedbackRole
    issue_type: FeedbackIssueType
    requested_correction: Mapping[str, Any]
    created_at: str
    status: str
    evidence_urls: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class ServiceStatusResponse:
    """Public service health and active snapshot status (`GET /v1/status`)."""

    status: str
    current_version: str | None
    previous_version: str | None
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RateLimitMetadata:
    """Parsed user-scoped rate-limit headers returned by `@ipscope/api`."""

    limit_per_minute: int | None = None
    remaining: int | None = None
    reset_epoch_seconds: int | None = None
    scope: str | None = None
    burst_capacity: int | None = None
    rate_limit_rps: int | None = None


@dataclass(frozen=True, slots=True)
class IpScopeResultWithMeta(Generic[T]):
    """Envelope containing both the typed API response data and HTTP/rate-limit metadata."""

    data: T
    status: int
    rate_limit: RateLimitMetadata
    from_cache: bool


@dataclass(frozen=True, slots=True)
class CacheStats:
    """Telemetry for the in-memory O(1) LRU + TTL cache."""

    enabled: bool
    size: int
    max_entries: int
    ttl_seconds: float
    hits: int
    misses: int
    coalesced_in_flight_hits: int


@dataclass(frozen=True, slots=True)
class RetryOptions:
    """Retry policy configuration for transient network, 5xx, and 429 errors."""

    max_retries: int = 2
    base_delay_seconds: float = 0.15
    max_delay_seconds: float = 3.0
    retry_on_rate_limit: bool = True


@dataclass(frozen=True, slots=True)
class CacheOptions:
    """In-memory O(1) LRU + TTL cache configuration (`< 400 KB` default RAM ceiling)."""

    enabled: bool = True
    max_entries: int = 512
    ttl_seconds: float = 60.0


def parse_ip_lookup_response(raw: Mapping[str, Any]) -> IpLookupResponse:
    """Converts a raw JSON dictionary into an immutable `IpLookupResponse`."""
    geo_raw = raw.get("geo") or {}
    net_raw = raw.get("network") or {}
    sec_raw = raw.get("security") or {}
    conn_raw = raw.get("connection")
    ext_raw = raw.get("security_extensions")

    geo = GeoResponseBlock(
        country_code=geo_raw.get("country_code"),
        subdivision=geo_raw.get("subdivision"),
        city=geo_raw.get("city"),
        timezone=geo_raw.get("timezone"),
        location_type=geo_raw.get("location_type", "unknown"),
        confidence=float(geo_raw.get("confidence", 0.0)),
        accuracy_radius_km=(
            float(geo_raw["accuracy_radius_km"])
            if geo_raw.get("accuracy_radius_km") is not None
            else None
        ),
        declared_country_code=geo_raw.get("declared_country_code"),
        physical_country_code=geo_raw.get("physical_country_code"),
        is_virtual_location=geo_raw.get("is_virtual_location"),
    )

    network = NetworkResponseBlock(
        asn=int(net_raw["asn"]) if net_raw.get("asn") is not None else None,
        organization=net_raw.get("organization"),
    )

    security = SecurityResponseBlock(
        is_vpn=sec_raw.get("is_vpn"),
        is_hosting=sec_raw.get("is_hosting"),
        is_tor_exit=sec_raw.get("is_tor_exit"),
        is_proxy=sec_raw.get("is_proxy"),
        anonymizer_type=sec_raw.get("anonymizer_type", "unknown"),
        confidence=float(sec_raw.get("confidence", 0.0)),
        reason_codes=tuple(str(c) for c in (sec_raw.get("reason_codes") or ())),
    )

    connection = (
        ConnectionResponseBlock(
            connection_type=conn_raw.get("connection_type", "unknown"),
            is_residential=conn_raw.get("is_residential"),
            is_mobile=conn_raw.get("is_mobile"),
            is_business=conn_raw.get("is_business"),
            is_hosting=conn_raw.get("is_hosting"),
        )
        if isinstance(conn_raw, Mapping)
        else None
    )

    security_extensions = (
        SecurityExtensionsResponseBlock(
            abuse_velocity_score=(
                float(ext_raw["abuse_velocity_score"])
                if ext_raw.get("abuse_velocity_score") is not None
                else None
            ),
            is_known_scanner=ext_raw.get("is_known_scanner"),
            observation_recency_hours=(
                float(ext_raw["observation_recency_hours"])
                if ext_raw.get("observation_recency_hours") is not None
                else None
            ),
        )
        if isinstance(ext_raw, Mapping)
        else None
    )

    ip_ver = int(raw.get("ip_version", 4))
    return IpLookupResponse(
        ip=str(raw.get("ip", "")),
        ip_version=6 if ip_ver == 6 else 4,
        matched_network=raw.get("matched_network"),
        geo=geo,
        network=network,
        security=security,
        connection=connection,
        security_extensions=security_extensions,
        dataset_version=str(raw.get("dataset_version", "")),
        updated_at=raw.get("updated_at"),
    )


def parse_batch_lookup_response(raw: Mapping[str, Any]) -> BatchLookupResponse:
    """Converts a raw JSON dictionary into an immutable `BatchLookupResponse`."""
    results_raw = raw.get("results") or ()
    items = tuple(parse_ip_lookup_response(item) for item in results_raw)
    return BatchLookupResponse(
        dataset_version=str(raw.get("dataset_version", "")),
        count=int(raw.get("count", len(items))),
        results=items,
    )


def parse_network_lookup_response(raw: Mapping[str, Any]) -> NetworkPrefixLookupResponse:
    """Converts a raw JSON dictionary into an immutable `NetworkPrefixLookupResponse`."""
    rec_raw = raw.get("record")
    record: CanonicalNetworkPrefixRecord | None = None
    if isinstance(rec_raw, Mapping):
        rec_family = int(rec_raw.get("family", raw.get("family", 4)))
        record = CanonicalNetworkPrefixRecord(
            prefix=str(rec_raw.get("prefix", raw.get("queried_cidr", ""))),
            family=6 if rec_family == 6 else 4,
            asn=int(rec_raw["asn"]) if rec_raw.get("asn") is not None else None,
            organization=rec_raw.get("organization"),
            country_code=rec_raw.get("countryCode") or rec_raw.get("country_code"),
            city=rec_raw.get("city"),
            location_type=rec_raw.get("locationType") or rec_raw.get("location_type"),
            is_vpn=rec_raw.get("isVpn") if "isVpn" in rec_raw else rec_raw.get("is_vpn"),
            is_hosting=(
                rec_raw.get("isHosting") if "isHosting" in rec_raw else rec_raw.get("is_hosting")
            ),
            is_tor_exit=(
                rec_raw.get("isTorExit") if "isTorExit" in rec_raw else rec_raw.get("is_tor_exit")
            ),
            is_proxy=(rec_raw.get("isProxy") if "isProxy" in rec_raw else rec_raw.get("is_proxy")),
            anonymizer_type=(rec_raw.get("anonymizerType") or rec_raw.get("anonymizer_type")),
            raw=dict(rec_raw),
        )

    family_val = int(raw.get("family", 4))
    return NetworkPrefixLookupResponse(
        queried_cidr=str(raw.get("queried_cidr", "")),
        family=6 if family_val == 6 else 4,
        dataset_version=str(raw.get("dataset_version", "")),
        record=record,
    )


def parse_datasets_metadata_response(raw: Mapping[str, Any]) -> DatasetsMetadataResponse:
    """Converts a raw JSON dictionary into an immutable `DatasetsMetadataResponse`."""
    snaps_raw = raw.get("snapshots") or ()
    snapshots = tuple(
        DatasetSnapshotSummary(
            snapshot_version=str(s.get("snapshot_version", "")),
            digest=str(s.get("digest", "")),
            ruleset_version=str(s.get("ruleset_version", "")),
            published_at=str(s.get("published_at", "")),
            ipv4_prefix_count=int(s.get("ipv4_prefix_count", 0)),
            ipv6_prefix_count=int(s.get("ipv6_prefix_count", 0)),
        )
        for s in snaps_raw
    )
    return DatasetsMetadataResponse(
        active_version=str(raw.get("active_version", "")),
        previous_version=raw.get("previous_version"),
        snapshots=snapshots,
    )


def parse_feedback_response(raw: Mapping[str, Any]) -> FeedbackSubmissionResponse:
    """Converts a raw JSON dictionary into an immutable `FeedbackSubmissionResponse`."""
    ev_urls = raw.get("evidence_urls")
    return FeedbackSubmissionResponse(
        id=str(raw.get("id", "")),
        prefix_or_ip=str(raw.get("prefix_or_ip", "")),
        role=raw.get("role", "end_user"),
        issue_type=raw.get("issue_type", "other"),
        requested_correction=dict(raw.get("requested_correction") or {}),
        created_at=str(raw.get("createdAt") or raw.get("created_at") or ""),
        status=str(raw.get("status", "pending_review")),
        evidence_urls=tuple(str(u) for u in ev_urls) if ev_urls is not None else None,
    )


def parse_service_status_response(raw: Mapping[str, Any]) -> ServiceStatusResponse:
    """Converts a raw JSON dictionary into an immutable `ServiceStatusResponse`."""
    snap = raw.get("snapshot")
    current_ver = (
        str(snap.get("currentVersion"))
        if isinstance(snap, Mapping) and snap.get("currentVersion") is not None
        else None
    )
    prev_ver = (
        str(snap.get("previousVersion"))
        if isinstance(snap, Mapping) and snap.get("previousVersion") is not None
        else None
    )
    return ServiceStatusResponse(
        status=str(raw.get("status", "unknown")),
        current_version=current_ver,
        previous_version=prev_ver,
        raw=dict(raw),
    )
