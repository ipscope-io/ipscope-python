"""Official IPScope Server-Side Python SDK (Sync & Async IP Intelligence)."""

from __future__ import annotations

from .cache import AsyncLruTtlCache, SyncLruTtlCache
from .client import AsyncIpScopeClient, IpScopeClient, MAX_SINGLE_BATCH_SIZE
from .errors import (
    IpScopeApiError,
    IpScopeAuthenticationError,
    IpScopeError,
    IpScopeRateLimitError,
    IpScopeTimeoutError,
    IpScopeValidationError,
)
from .transport import (
    AsyncHttpTransport,
    AsyncTransportCallable,
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES,
    RawHttpResponse,
    SDK_USER_AGENT,
    SyncHttpTransport,
    SyncTransportCallable,
    parse_rate_limit_headers,
)
from .types import (
    AnonymizerType,
    BatchLookupResponse,
    CacheOptions,
    CacheStats,
    CanonicalNetworkPrefixRecord,
    ConnectionResponseBlock,
    ConnectionType,
    DatasetSnapshotSummary,
    DatasetsMetadataResponse,
    FeedbackIssueType,
    FeedbackRole,
    FeedbackSubmissionInput,
    FeedbackSubmissionResponse,
    GeoResponseBlock,
    IpFamily,
    IpLookupResponse,
    IpScopeResultWithMeta,
    LocationType,
    NetworkPrefixLookupResponse,
    NetworkResponseBlock,
    RateLimitMetadata,
    RetryOptions,
    SecurityExtensionsResponseBlock,
    SecurityResponseBlock,
    ServiceStatusResponse,
)
from .validation import (
    validate_and_deduplicate_batch_ips,
    validate_api_key,
    validate_cidr_prefix,
    validate_ip_address,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    # Clients
    "IpScopeClient",
    "AsyncIpScopeClient",
    "MAX_SINGLE_BATCH_SIZE",
    # Transports & Constants
    "SyncHttpTransport",
    "AsyncHttpTransport",
    "SyncTransportCallable",
    "AsyncTransportCallable",
    "RawHttpResponse",
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_RESPONSE_BYTES",
    "SDK_USER_AGENT",
    "parse_rate_limit_headers",
    # Cache
    "SyncLruTtlCache",
    "AsyncLruTtlCache",
    # Errors
    "IpScopeError",
    "IpScopeValidationError",
    "IpScopeTimeoutError",
    "IpScopeApiError",
    "IpScopeAuthenticationError",
    "IpScopeRateLimitError",
    # Types
    "IpFamily",
    "LocationType",
    "AnonymizerType",
    "ConnectionType",
    "FeedbackRole",
    "FeedbackIssueType",
    "GeoResponseBlock",
    "NetworkResponseBlock",
    "SecurityResponseBlock",
    "ConnectionResponseBlock",
    "SecurityExtensionsResponseBlock",
    "IpLookupResponse",
    "BatchLookupResponse",
    "CanonicalNetworkPrefixRecord",
    "NetworkPrefixLookupResponse",
    "DatasetSnapshotSummary",
    "DatasetsMetadataResponse",
    "FeedbackSubmissionInput",
    "FeedbackSubmissionResponse",
    "ServiceStatusResponse",
    "RateLimitMetadata",
    "IpScopeResultWithMeta",
    "CacheStats",
    "RetryOptions",
    "CacheOptions",
    # Validation
    "validate_api_key",
    "validate_ip_address",
    "validate_cidr_prefix",
    "validate_and_deduplicate_batch_ips",
]
