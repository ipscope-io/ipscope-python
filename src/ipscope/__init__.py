"""Official IPScope Server-Side Python SDK (Sync & Async IP Intelligence)."""

from __future__ import annotations

from .cache import AsyncLruTtlCache, SyncLruTtlCache
from .client import MAX_SINGLE_BATCH_SIZE, AsyncIpScopeClient, IpScopeClient
from .errors import (
    IpScopeApiError,
    IpScopeAuthenticationError,
    IpScopeError,
    IpScopeRateLimitError,
    IpScopeTimeoutError,
    IpScopeValidationError,
)
from .transport import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES,
    SDK_USER_AGENT,
    AsyncHttpTransport,
    AsyncTransportCallable,
    RawHttpResponse,
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
    DatasetsMetadataResponse,
    DatasetSnapshotSummary,
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
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_RESPONSE_BYTES",
    "MAX_SINGLE_BATCH_SIZE",
    "SDK_USER_AGENT",
    "AnonymizerType",
    "AsyncHttpTransport",
    "AsyncIpScopeClient",
    "AsyncLruTtlCache",
    "AsyncTransportCallable",
    "BatchLookupResponse",
    "CacheOptions",
    "CacheStats",
    "CanonicalNetworkPrefixRecord",
    "ConnectionResponseBlock",
    "ConnectionType",
    "DatasetSnapshotSummary",
    "DatasetsMetadataResponse",
    "FeedbackIssueType",
    "FeedbackRole",
    "FeedbackSubmissionInput",
    "FeedbackSubmissionResponse",
    "GeoResponseBlock",
    # Types
    "IpFamily",
    "IpLookupResponse",
    "IpScopeApiError",
    "IpScopeAuthenticationError",
    # Clients
    "IpScopeClient",
    # Errors
    "IpScopeError",
    "IpScopeRateLimitError",
    "IpScopeResultWithMeta",
    "IpScopeTimeoutError",
    "IpScopeValidationError",
    "LocationType",
    "NetworkPrefixLookupResponse",
    "NetworkResponseBlock",
    "RateLimitMetadata",
    "RawHttpResponse",
    "RetryOptions",
    "SecurityExtensionsResponseBlock",
    "SecurityResponseBlock",
    "ServiceStatusResponse",
    # Transports & Constants
    "SyncHttpTransport",
    # Cache
    "SyncLruTtlCache",
    "SyncTransportCallable",
    "__version__",
    "parse_rate_limit_headers",
    "validate_and_deduplicate_batch_ips",
    # Validation
    "validate_api_key",
    "validate_cidr_prefix",
    "validate_ip_address",
]
