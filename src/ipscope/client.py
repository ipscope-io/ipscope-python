"""Official Synchronous (`IpScopeClient`) and Asynchronous (`AsyncIpScopeClient`) Python SDK clients.

Provides strictly IP-related lookup operations (zero account, wallet, or billing
methods):
- Single IPv4 / IPv6 lookup (`lookup_ip`, `lookup_ip_with_meta`)
- Caller / visitor IP lookup (`lookup_caller_ip`)
- Batch IP lookup up to 100 IPs (`lookup_batch`) with cache hydration & deduplication
- Chunked batch IP lookup for >100 IPs (`lookup_batch_chunked`)
- Constant-RAM streaming batch generator (`lookup_batch_stream`)
- Canonical network CIDR prefix inspection (`lookup_network`)
- Dataset snapshot metadata (`get_datasets_metadata`)
- Geolocation / anonymity correction feedback (`submit_feedback`)
- Service health & active snapshot status (`get_status`)
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterable, AsyncIterator, Iterable, Iterator, Mapping, Sequence
import urllib.parse

import httpx

from .cache import AsyncLruTtlCache, SyncLruTtlCache
from .errors import IpScopeValidationError
from .transport import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT_SECONDS,
    AsyncHttpTransport,
    AsyncTransportCallable,
    SyncHttpTransport,
    SyncTransportCallable,
)
from .types import (
    BatchLookupResponse,
    CacheOptions,
    CacheStats,
    DatasetsMetadataResponse,
    FeedbackSubmissionInput,
    FeedbackSubmissionResponse,
    IpLookupResponse,
    IpScopeResultWithMeta,
    NetworkPrefixLookupResponse,
    RateLimitMetadata,
    RetryOptions,
    ServiceStatusResponse,
    parse_batch_lookup_response,
    parse_datasets_metadata_response,
    parse_feedback_response,
    parse_ip_lookup_response,
    parse_network_lookup_response,
    parse_service_status_response,
)
from .validation import (
    validate_and_deduplicate_batch_ips,
    validate_cidr_prefix,
    validate_ip_address,
)

MAX_SINGLE_BATCH_SIZE = 100


class IpScopeClient:
    """Official Synchronous IPScope Server-Side Python Client powered by `httpx.Client`."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        retry: RetryOptions | None = None,
        cache: CacheOptions | None = None,
        user_agent: str | None = None,
        http_client: httpx.Client | None = None,
        transport: httpx.BaseTransport | SyncTransportCallable | None = None,
    ) -> None:
        self._http = SyncHttpTransport(
            api_key=api_key,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            retry=retry,
            user_agent=user_agent,
            http_client=http_client,
            transport=transport,
        )
        cache_opts = cache or CacheOptions()
        self._ip_cache: SyncLruTtlCache[IpLookupResponse] = SyncLruTtlCache(cache_opts)
        self._network_cache: SyncLruTtlCache[NetworkPrefixLookupResponse] = (
            SyncLruTtlCache(
                CacheOptions(
                    enabled=cache_opts.enabled,
                    max_entries=min(128, cache_opts.max_entries),
                    ttl_seconds=cache_opts.ttl_seconds,
                )
            )
        )

    def close(self) -> None:
        """Closes the underlying `httpx.Client` connection pool and clears in-memory caches."""
        self.clear_cache()
        self._http.close()

    def lookup_ip(
        self,
        raw_ip: str,
        *,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> IpLookupResponse:
        """Looks up intelligence for a single IPv4 or IPv6 address (`GET /v1/ip/:ip`)."""
        return self.lookup_ip_with_meta(
            raw_ip,
            bypass_cache=bypass_cache,
            timeout_seconds=timeout_seconds,
            headers=headers,
        ).data

    def lookup_ip_with_meta(
        self,
        raw_ip: str,
        *,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> IpScopeResultWithMeta[IpLookupResponse]:
        """Looks up a single IPv4 or IPv6 address and returns both data and rate-limit metadata."""
        ip_str, _ = validate_ip_address(raw_ip)
        if not bypass_cache:
            cached = self._ip_cache.get(ip_str)
            if cached is not None:
                return IpScopeResultWithMeta(
                    data=cached,
                    status=200,
                    rate_limit=self._http.get_last_rate_limit() or RateLimitMetadata(),
                    from_cache=True,
                )

        encoded_ip = urllib.parse.quote(ip_str, safe="")
        raw_data, status, rate_limit = self._http.request(
            "GET",
            f"/v1/ip/{encoded_ip}",
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
        )
        parsed = parse_ip_lookup_response(raw_data)
        self._ip_cache.set(ip_str, parsed)
        canonical_lower = parsed.ip.lower()
        if canonical_lower != ip_str:
            self._ip_cache.set(canonical_lower, parsed)

        return IpScopeResultWithMeta(
            data=parsed,
            status=status,
            rate_limit=rate_limit,
            from_cache=False,
        )

    def lookup_caller_ip(
        self,
        *,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> IpLookupResponse:
        """Looks up intelligence for the caller's own server-observed IP (`GET /v1/ip/me`)."""
        raw_data, _, _ = self._http.request(
            "GET",
            "/v1/ip/me",
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
        )
        return parse_ip_lookup_response(raw_data)

    def lookup_batch(
        self,
        raw_ips: Sequence[str],
        *,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> BatchLookupResponse:
        """Performs a batch lookup for 1..100 IPs (`POST /v1/ip/batch`), deduplicating and reusing warm cache entries."""
        ordered_ips, unique_ips = validate_and_deduplicate_batch_ips(
            raw_ips, MAX_SINGLE_BATCH_SIZE
        )

        resolved_by_ip: dict[str, IpLookupResponse] = {}
        missing_ips: list[str] = []

        if not bypass_cache:
            for ip_str in unique_ips:
                cached = self._ip_cache.get(ip_str)
                if cached is not None:
                    resolved_by_ip[ip_str] = cached
                else:
                    missing_ips.append(ip_str)
        else:
            missing_ips.extend(unique_ips)

        dataset_version = ""

        if missing_ips:
            raw_data, _, _ = self._http.request(
                "POST",
                "/v1/ip/batch",
                body={"ips": missing_ips},
                timeout_seconds=timeout_seconds,
                extra_headers=headers,
            )
            batch_parsed = parse_batch_lookup_response(raw_data)
            dataset_version = batch_parsed.dataset_version
            for idx, req_ip in enumerate(missing_ips):
                if idx < len(batch_parsed.results):
                    item = batch_parsed.results[idx]
                    resolved_by_ip[req_ip] = item
                    self._ip_cache.set(req_ip, item)
                    canonical_lower = item.ip.lower()
                    if canonical_lower != req_ip:
                        self._ip_cache.set(canonical_lower, item)

        ordered_results = tuple(resolved_by_ip[ip_str] for ip_str in ordered_ips)
        if not dataset_version and ordered_results:
            dataset_version = ordered_results[0].dataset_version

        return BatchLookupResponse(
            dataset_version=dataset_version,
            count=len(ordered_results),
            results=ordered_results,
        )

    def lookup_batch_chunked(
        self,
        raw_ips: Sequence[str],
        *,
        chunk_size: int = MAX_SINGLE_BATCH_SIZE,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> BatchLookupResponse:
        """Performs a batch lookup for >100 IPs by deduplicating and splitting into chunks of up to 100 IPs."""
        if isinstance(raw_ips, (str, bytes)) or not isinstance(raw_ips, Sequence) or len(raw_ips) == 0:
            raise IpScopeValidationError(
                "Batch IPs sequence must contain at least 1 IP address", "ips"
            )

        effective_chunk = max(1, min(MAX_SINGLE_BATCH_SIZE, int(chunk_size)))
        ordered_ips: list[str] = []
        unique_seen: dict[str, None] = {}
        for item in raw_ips:
            ip_str, _ = validate_ip_address(item)
            ordered_ips.append(ip_str)
            unique_seen[ip_str] = None

        unique_list = list(unique_seen.keys())
        resolved_by_ip: dict[str, IpLookupResponse] = {}
        dataset_version = ""

        for i in range(0, len(unique_list), effective_chunk):
            chunk = unique_list[i : i + effective_chunk]
            batch_res = self.lookup_batch(
                chunk,
                bypass_cache=bypass_cache,
                timeout_seconds=timeout_seconds,
                headers=headers,
            )
            if not dataset_version and batch_res.dataset_version:
                dataset_version = batch_res.dataset_version
            for idx, req_ip in enumerate(chunk):
                if idx < len(batch_res.results):
                    resolved_by_ip[req_ip] = batch_res.results[idx]

        ordered_results = tuple(resolved_by_ip[ip_str] for ip_str in ordered_ips)
        return BatchLookupResponse(
            dataset_version=dataset_version,
            count=len(ordered_results),
            results=ordered_results,
        )

    def lookup_batch_stream(
        self,
        raw_ips: Iterable[str],
        *,
        chunk_size: int = MAX_SINGLE_BATCH_SIZE,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Iterator[BatchLookupResponse]:
        """Constant-RAM generator yielding `BatchLookupResponse` chunks for arbitrarily large IP iterables."""
        effective_chunk = max(1, min(MAX_SINGLE_BATCH_SIZE, int(chunk_size)))
        current_chunk: list[str] = []

        for raw_ip in raw_ips:
            ip_str, _ = validate_ip_address(raw_ip)
            current_chunk.append(ip_str)
            if len(current_chunk) >= effective_chunk:
                to_send = current_chunk
                current_chunk = []
                yield self.lookup_batch(
                    to_send,
                    bypass_cache=bypass_cache,
                    timeout_seconds=timeout_seconds,
                    headers=headers,
                )

        if current_chunk:
            yield self.lookup_batch(
                current_chunk,
                bypass_cache=bypass_cache,
                timeout_seconds=timeout_seconds,
                headers=headers,
            )

    def lookup_network(
        self,
        raw_cidr: str,
        *,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> NetworkPrefixLookupResponse:
        """Inspects canonical network prefix intelligence by CIDR notation (`GET /v1/networks/:prefix/:length`)."""
        address, prefix_len, _, normalized_cidr = validate_cidr_prefix(raw_cidr)
        if not bypass_cache:
            cached = self._network_cache.get(normalized_cidr)
            if cached is not None:
                return cached

        encoded_addr = urllib.parse.quote(address, safe="")
        raw_data, _, _ = self._http.request(
            "GET",
            f"/v1/networks/{encoded_addr}/{prefix_len}",
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
        )
        parsed = parse_network_lookup_response(raw_data)
        self._network_cache.set(normalized_cidr, parsed)
        return parsed

    def get_datasets_metadata(
        self,
        *,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> DatasetsMetadataResponse:
        """Lists active and historical dataset snapshot versions (`GET /v1/metadata/datasets`)."""
        raw_data, _, _ = self._http.request(
            "GET",
            "/v1/metadata/datasets",
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
        )
        return parse_datasets_metadata_response(raw_data)

    def submit_feedback(
        self,
        feedback: FeedbackSubmissionInput,
        *,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> FeedbackSubmissionResponse:
        """Submits geolocation, ASN, or anonymity correction feedback (`POST /v1/feedback`)."""
        if not isinstance(feedback, FeedbackSubmissionInput):
            raise IpScopeValidationError(
                "feedback must be a FeedbackSubmissionInput instance", "feedback"
            )
        target = feedback.prefix_or_ip.strip()
        if "/" in target:
            validate_cidr_prefix(target)
        else:
            validate_ip_address(target)

        payload: dict[str, object] = {
            "prefix_or_ip": target,
            "role": feedback.role,
            "issue_type": feedback.issue_type,
            "requested_correction": dict(feedback.requested_correction),
        }
        if feedback.evidence_urls is not None:
            payload["evidence_urls"] = list(feedback.evidence_urls)

        raw_data, _, _ = self._http.request(
            "POST",
            "/v1/feedback",
            body=payload,
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
        )
        return parse_feedback_response(raw_data)

    def get_status(
        self,
        *,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ServiceStatusResponse:
        """Fetches public service health and active snapshot status (`GET /v1/status`)."""
        raw_data, _, _ = self._http.request(
            "GET",
            "/v1/status",
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
            requires_auth=False,
        )
        return parse_service_status_response(raw_data)

    def get_last_rate_limit(self) -> RateLimitMetadata | None:
        """Returns the most recently observed user-scoped rate-limit headers."""
        return self._http.get_last_rate_limit()

    def get_cache_stats(self) -> CacheStats:
        """Returns current hit/miss statistics for the in-memory IP LRU cache."""
        return self._ip_cache.get_stats()

    def clear_cache(self) -> None:
        """Clears the in-memory IP and network prefix LRU caches."""
        self._ip_cache.clear()
        self._network_cache.clear()


class AsyncIpScopeClient:
    """Official Asynchronous IPScope Server-Side Python Client powered by `httpx.AsyncClient`."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        retry: RetryOptions | None = None,
        cache: CacheOptions | None = None,
        user_agent: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | AsyncTransportCallable | None = None,
    ) -> None:
        self._http = AsyncHttpTransport(
            api_key=api_key,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            retry=retry,
            user_agent=user_agent,
            http_client=http_client,
            transport=transport,
        )
        cache_opts = cache or CacheOptions()
        self._ip_cache: AsyncLruTtlCache[IpLookupResponse] = AsyncLruTtlCache(
            cache_opts
        )
        self._network_cache: AsyncLruTtlCache[NetworkPrefixLookupResponse] = (
            AsyncLruTtlCache(
                CacheOptions(
                    enabled=cache_opts.enabled,
                    max_entries=min(128, cache_opts.max_entries),
                    ttl_seconds=cache_opts.ttl_seconds,
                )
            )
        )

    async def close(self) -> None:
        """Closes the underlying `httpx.AsyncClient` connection pool and clears in-memory caches."""
        self.clear_cache()
        await self._http.close()

    async def lookup_ip(
        self,
        raw_ip: str,
        *,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> IpLookupResponse:
        """Looks up intelligence for a single IPv4 or IPv6 address (`GET /v1/ip/:ip`).

        Concurrent calls for the same IP are automatically coalesced into a single
        in-flight HTTP request.
        """
        res = await self.lookup_ip_with_meta(
            raw_ip,
            bypass_cache=bypass_cache,
            timeout_seconds=timeout_seconds,
            headers=headers,
        )
        return res.data

    async def lookup_ip_with_meta(
        self,
        raw_ip: str,
        *,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> IpScopeResultWithMeta[IpLookupResponse]:
        """Looks up a single IPv4 or IPv6 address and returns both data and rate-limit metadata."""
        ip_str, _ = validate_ip_address(raw_ip)
        last_status = 200
        last_rl = self._http.get_last_rate_limit() or RateLimitMetadata()

        async def _produce() -> IpLookupResponse:
            nonlocal last_status, last_rl
            encoded_ip = urllib.parse.quote(ip_str, safe="")
            raw_data, status, rl = await self._http.request(
                "GET",
                f"/v1/ip/{encoded_ip}",
                timeout_seconds=timeout_seconds,
                extra_headers=headers,
            )
            last_status = status
            last_rl = rl
            parsed = parse_ip_lookup_response(raw_data)
            canonical_lower = parsed.ip.lower()
            if canonical_lower != ip_str:
                self._ip_cache.set(canonical_lower, parsed)
            return parsed

        val, from_cache = await self._ip_cache.get_or_compute(
            ip_str, bypass_cache, _produce
        )
        return IpScopeResultWithMeta(
            data=val,
            status=last_status,
            rate_limit=self._http.get_last_rate_limit() or last_rl,
            from_cache=from_cache,
        )

    async def lookup_caller_ip(
        self,
        *,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> IpLookupResponse:
        """Looks up intelligence for the caller's own server-observed IP (`GET /v1/ip/me`)."""
        raw_data, _, _ = await self._http.request(
            "GET",
            "/v1/ip/me",
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
        )
        return parse_ip_lookup_response(raw_data)

    async def lookup_batch(
        self,
        raw_ips: Sequence[str],
        *,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> BatchLookupResponse:
        """Performs a batch lookup for 1..100 IPs (`POST /v1/ip/batch`), deduplicating and reusing warm cache entries."""
        ordered_ips, unique_ips = validate_and_deduplicate_batch_ips(
            raw_ips, MAX_SINGLE_BATCH_SIZE
        )

        resolved_by_ip: dict[str, IpLookupResponse] = {}
        missing_ips: list[str] = []

        if not bypass_cache:
            for ip_str in unique_ips:
                cached = self._ip_cache.get(ip_str)
                if cached is not None:
                    resolved_by_ip[ip_str] = cached
                else:
                    missing_ips.append(ip_str)
        else:
            missing_ips.extend(unique_ips)

        dataset_version = ""

        if missing_ips:
            raw_data, _, _ = await self._http.request(
                "POST",
                "/v1/ip/batch",
                body={"ips": missing_ips},
                timeout_seconds=timeout_seconds,
                extra_headers=headers,
            )
            batch_parsed = parse_batch_lookup_response(raw_data)
            dataset_version = batch_parsed.dataset_version
            for idx, req_ip in enumerate(missing_ips):
                if idx < len(batch_parsed.results):
                    item = batch_parsed.results[idx]
                    resolved_by_ip[req_ip] = item
                    self._ip_cache.set(req_ip, item)
                    canonical_lower = item.ip.lower()
                    if canonical_lower != req_ip:
                        self._ip_cache.set(canonical_lower, item)

        ordered_results = tuple(resolved_by_ip[ip_str] for ip_str in ordered_ips)
        if not dataset_version and ordered_results:
            dataset_version = ordered_results[0].dataset_version

        return BatchLookupResponse(
            dataset_version=dataset_version,
            count=len(ordered_results),
            results=ordered_results,
        )

    async def lookup_batch_chunked(
        self,
        raw_ips: Sequence[str],
        *,
        chunk_size: int = MAX_SINGLE_BATCH_SIZE,
        concurrency: int = 4,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> BatchLookupResponse:
        """Performs a batch lookup for >100 IPs with bounded async concurrency (`default: 4`)."""
        if isinstance(raw_ips, (str, bytes)) or not isinstance(raw_ips, Sequence) or len(raw_ips) == 0:
            raise IpScopeValidationError(
                "Batch IPs sequence must contain at least 1 IP address", "ips"
            )

        effective_chunk = max(1, min(MAX_SINGLE_BATCH_SIZE, int(chunk_size)))
        effective_concurrency = max(1, min(16, int(concurrency)))

        ordered_ips: list[str] = []
        unique_seen: dict[str, None] = {}
        for item in raw_ips:
            ip_str, _ = validate_ip_address(item)
            ordered_ips.append(ip_str)
            unique_seen[ip_str] = None

        unique_list = list(unique_seen.keys())
        chunks = [
            unique_list[i : i + effective_chunk]
            for i in range(0, len(unique_list), effective_chunk)
        ]

        resolved_by_ip: dict[str, IpLookupResponse] = {}
        dataset_version = ""
        sem = asyncio.Semaphore(effective_concurrency)

        async def _run_chunk(chunk: list[str]) -> None:
            nonlocal dataset_version
            async with sem:
                batch_res = await self.lookup_batch(
                    chunk,
                    bypass_cache=bypass_cache,
                    timeout_seconds=timeout_seconds,
                    headers=headers,
                )
                if not dataset_version and batch_res.dataset_version:
                    dataset_version = batch_res.dataset_version
                for idx, req_ip in enumerate(chunk):
                    if idx < len(batch_res.results):
                        resolved_by_ip[req_ip] = batch_res.results[idx]

        await asyncio.gather(*(_run_chunk(c) for c in chunks))

        ordered_results = tuple(resolved_by_ip[ip_str] for ip_str in ordered_ips)
        return BatchLookupResponse(
            dataset_version=dataset_version,
            count=len(ordered_results),
            results=ordered_results,
        )

    async def lookup_batch_stream(
        self,
        raw_ips: Iterable[str] | AsyncIterable[str],
        *,
        chunk_size: int = MAX_SINGLE_BATCH_SIZE,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> AsyncIterator[BatchLookupResponse]:
        """Constant-RAM async generator yielding `BatchLookupResponse` chunks for large IP streams."""
        effective_chunk = max(1, min(MAX_SINGLE_BATCH_SIZE, int(chunk_size)))
        current_chunk: list[str] = []

        if isinstance(raw_ips, AsyncIterable):
            async for raw_ip in raw_ips:
                ip_str, _ = validate_ip_address(raw_ip)
                current_chunk.append(ip_str)
                if len(current_chunk) >= effective_chunk:
                    to_send = current_chunk
                    current_chunk = []
                    yield await self.lookup_batch(
                        to_send,
                        bypass_cache=bypass_cache,
                        timeout_seconds=timeout_seconds,
                        headers=headers,
                    )
        else:
            for raw_ip in raw_ips:
                ip_str, _ = validate_ip_address(raw_ip)
                current_chunk.append(ip_str)
                if len(current_chunk) >= effective_chunk:
                    to_send = current_chunk
                    current_chunk = []
                    yield await self.lookup_batch(
                        to_send,
                        bypass_cache=bypass_cache,
                        timeout_seconds=timeout_seconds,
                        headers=headers,
                    )

        if current_chunk:
            yield await self.lookup_batch(
                current_chunk,
                bypass_cache=bypass_cache,
                timeout_seconds=timeout_seconds,
                headers=headers,
            )

    async def lookup_network(
        self,
        raw_cidr: str,
        *,
        bypass_cache: bool = False,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> NetworkPrefixLookupResponse:
        """Inspects canonical network prefix intelligence by CIDR notation (`GET /v1/networks/:prefix/:length`)."""
        address, prefix_len, _, normalized_cidr = validate_cidr_prefix(raw_cidr)

        async def _produce() -> NetworkPrefixLookupResponse:
            encoded_addr = urllib.parse.quote(address, safe="")
            raw_data, _, _ = await self._http.request(
                "GET",
                f"/v1/networks/{encoded_addr}/{prefix_len}",
                timeout_seconds=timeout_seconds,
                extra_headers=headers,
            )
            return parse_network_lookup_response(raw_data)

        val, _ = await self._network_cache.get_or_compute(
            normalized_cidr, bypass_cache, _produce
        )
        return val

    async def get_datasets_metadata(
        self,
        *,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> DatasetsMetadataResponse:
        """Lists active and historical dataset snapshot versions (`GET /v1/metadata/datasets`)."""
        raw_data, _, _ = await self._http.request(
            "GET",
            "/v1/metadata/datasets",
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
        )
        return parse_datasets_metadata_response(raw_data)

    async def submit_feedback(
        self,
        feedback: FeedbackSubmissionInput,
        *,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> FeedbackSubmissionResponse:
        """Submits geolocation, ASN, or anonymity correction feedback (`POST /v1/feedback`)."""
        if not isinstance(feedback, FeedbackSubmissionInput):
            raise IpScopeValidationError(
                "feedback must be a FeedbackSubmissionInput instance", "feedback"
            )
        target = feedback.prefix_or_ip.strip()
        if "/" in target:
            validate_cidr_prefix(target)
        else:
            validate_ip_address(target)

        payload: dict[str, object] = {
            "prefix_or_ip": target,
            "role": feedback.role,
            "issue_type": feedback.issue_type,
            "requested_correction": dict(feedback.requested_correction),
        }
        if feedback.evidence_urls is not None:
            payload["evidence_urls"] = list(feedback.evidence_urls)

        raw_data, _, _ = await self._http.request(
            "POST",
            "/v1/feedback",
            body=payload,
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
        )
        return parse_feedback_response(raw_data)

    async def get_status(
        self,
        *,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ServiceStatusResponse:
        """Fetches public service health and active snapshot status (`GET /v1/status`)."""
        raw_data, _, _ = await self._http.request(
            "GET",
            "/v1/status",
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
            requires_auth=False,
        )
        return parse_service_status_response(raw_data)

    def get_last_rate_limit(self) -> RateLimitMetadata | None:
        """Returns the most recently observed user-scoped rate-limit headers."""
        return self._http.get_last_rate_limit()

    def get_cache_stats(self) -> CacheStats:
        """Returns current hit/miss/coalescing statistics for the in-memory IP LRU cache."""
        return self._ip_cache.get_stats()

    def clear_cache(self) -> None:
        """Clears the in-memory IP and network prefix LRU caches."""
        self._ip_cache.clear()
        self._network_cache.clear()
