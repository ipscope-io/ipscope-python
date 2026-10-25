"""Resilient Sync (`SyncHttpTransport`) and Async (`AsyncHttpTransport`) HTTP transports powered by `httpx`.

Features:
- Powered by `httpx.Client` (Sync) and `httpx.AsyncClient` (Async) with persistent TCP/TLS connection pooling
- Bounded connection pool limits (`max_connections=20`, `max_keepalive_connections=10`, `keepalive_expiry=30.0`)
- Supports custom `httpx.Client` / `httpx.AsyncClient`, `httpx.BaseTransport` / `httpx.AsyncBaseTransport` (e.g. `httpx.MockTransport`), or custom transport callables
- Strict 2 MiB (`MAX_RESPONSE_BYTES`) streaming payload ceiling with guaranteed `finally` stream closure to protect Python heap memory
- Parses user-scoped rate-limit headers (`x-ratelimit-*`) on every response
- Exponential backoff with jitter on `429` and transient `502`/`503`/`504` errors
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from .errors import (
    IpScopeApiError,
    IpScopeAuthenticationError,
    IpScopeRateLimitError,
    IpScopeTimeoutError,
)
from .types import RateLimitMetadata, RetryOptions
from .validation import validate_api_key

DEFAULT_BASE_URL = "https://api.ipscope.io"
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB hard ceiling to protect heap RAM
SDK_USER_AGENT = "ipscope-python/1.0.0"

DEFAULT_POOL_LIMITS = httpx.Limits(
    max_connections=20,
    max_keepalive_connections=10,
    keepalive_expiry=30.0,
)


@dataclass(frozen=True, slots=True)
class RawHttpResponse:
    """Normalized low-level HTTP response returned by a transport execution."""

    status: int
    headers: Mapping[str, str]
    body_bytes: bytes


SyncTransportCallable = Callable[
    [str, str, Mapping[str, str], bytes | None, float], RawHttpResponse
]
AsyncTransportCallable = Callable[
    [str, str, Mapping[str, str], bytes | None, float], Awaitable[RawHttpResponse]
]


def parse_rate_limit_headers(headers: Mapping[str, str]) -> RateLimitMetadata:
    """Extracts user-scoped rate-limit metadata from case-insensitive HTTP headers."""
    lower = {k.lower(): v for k, v in headers.items()}

    def _parse_int(name: str) -> int | None:
        raw = lower.get(name)
        if not raw:
            return None
        try:
            return int(raw.strip(), 10)
        except ValueError:
            return None

    return RateLimitMetadata(
        limit_per_minute=_parse_int("x-ratelimit-limit"),
        remaining=_parse_int("x-ratelimit-remaining"),
        reset_epoch_seconds=_parse_int("x-ratelimit-reset"),
        scope=lower.get("x-ratelimit-scope"),
        burst_capacity=_parse_int("x-ratelimit-burst"),
        rate_limit_rps=_parse_int("x-ratelimit-rps"),
    )


def _extract_error_message(parsed_body: Any, status: int, path: str) -> str:
    if isinstance(parsed_body, Mapping):
        msg = parsed_body.get("message")
        if isinstance(msg, str) and msg.strip():
            return msg.strip()
        if isinstance(msg, list) and msg:
            return "; ".join(str(x) for x in msg)
    return f"IPScope API error ({status}) on {path}"


def _compute_retry_after_seconds(
    headers: Mapping[str, str], rate_limit: RateLimitMetadata
) -> float | None:
    lower = {k.lower(): v for k, v in headers.items()}
    retry_after = lower.get("retry-after")
    if retry_after:
        try:
            val = float(retry_after.strip())
            if val >= 0:
                return val
        except ValueError:
            pass
    if rate_limit.reset_epoch_seconds is not None:
        delta = float(rate_limit.reset_epoch_seconds) - time.time()
        if delta > 0:
            return delta
    return None


def _compute_backoff_seconds(attempt: int, retry: RetryOptions) -> float:
    exp = min(
        retry.max_delay_seconds,
        retry.base_delay_seconds * (2**attempt),
    )
    jitter = random.uniform(0.0, max(0.005, exp * 0.25))
    return min(retry.max_delay_seconds, exp + jitter)


class SyncHttpTransport:
    """Synchronous HTTP transport backed by `httpx.Client` with bounded streaming reads and automatic retries."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        retry: RetryOptions | None = None,
        user_agent: str | None = None,
        http_client: httpx.Client | None = None,
        transport: httpx.BaseTransport | SyncTransportCallable | None = None,
    ) -> None:
        self._api_key = validate_api_key(api_key)
        self._base_url = base_url.strip().rstrip("/") or DEFAULT_BASE_URL
        self._timeout_seconds = max(0.1, float(timeout_seconds))
        self._retry = retry or RetryOptions()
        self._user_agent = f"{user_agent} {SDK_USER_AGENT}" if user_agent else SDK_USER_AGENT
        self._last_rate_limit: RateLimitMetadata | None = None

        self._callable_transport: SyncTransportCallable | None = None
        if http_client is not None:
            self._client: httpx.Client | None = http_client
            self._owns_client = False
        elif isinstance(transport, httpx.BaseTransport) or transport is None:
            self._client = httpx.Client(
                base_url=self._base_url,
                timeout=httpx.Timeout(self._timeout_seconds),
                limits=DEFAULT_POOL_LIMITS,
                transport=transport,
                follow_redirects=False,
            )
            self._owns_client = True
        else:
            self._client = None
            self._owns_client = False
            self._callable_transport = transport

    def close(self) -> None:
        """Closes the underlying `httpx.Client` connection pool if owned by this SDK instance."""
        if self._owns_client and self._client is not None:
            self._client.close()

    def get_last_rate_limit(self) -> RateLimitMetadata | None:
        return self._last_rate_limit

    def _execute_httpx_sync(
        self,
        method: str,
        url: str,
        path: str,
        headers: Mapping[str, str],
        body_bytes: bytes | None,
        timeout_seconds: float,
    ) -> RawHttpResponse:
        if self._callable_transport is not None:
            return self._callable_transport(method, url, headers, body_bytes, timeout_seconds)

        assert self._client is not None
        with self._client.stream(
            method=method,
            url=url,
            headers=dict(headers),
            content=body_bytes,
            timeout=timeout_seconds,
        ) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            cl_raw = resp_headers.get("content-length")
            if cl_raw and cl_raw.isdigit() and int(cl_raw, 10) > MAX_RESPONSE_BYTES:
                raise IpScopeApiError(
                    f"IPScope response payload ({cl_raw} bytes) exceeds 2 MiB safety limit",
                    status=resp.status_code,
                    path=path,
                    code="IPSCOPE_RESPONSE_TOO_LARGE",
                )

            chunks: list[bytes] = []
            total = 0
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise IpScopeApiError(
                        "IPScope response payload exceeds 2 MiB safety limit",
                        status=resp.status_code,
                        path=path,
                        code="IPSCOPE_RESPONSE_TOO_LARGE",
                    )
                chunks.append(chunk)

            return RawHttpResponse(
                status=int(resp.status_code),
                headers=resp_headers,
                body_bytes=b"".join(chunks),
            )

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        timeout_seconds: float | None = None,
        extra_headers: Mapping[str, str] | None = None,
        requires_auth: bool = True,
    ) -> tuple[Any, int, RateLimitMetadata]:
        url = f"{self._base_url}{path}"
        effective_timeout = (
            max(0.1, float(timeout_seconds))
            if timeout_seconds is not None
            else self._timeout_seconds
        )

        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": self._user_agent,
        }
        if requires_auth:
            headers["x-api-key"] = self._api_key
            headers["Authorization"] = f"Bearer {self._api_key}"
        if body is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)

        body_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        max_retries = max(0, int(self._retry.max_retries))

        for attempt in range(max_retries + 1):
            try:
                raw_resp = self._execute_httpx_sync(
                    method, url, path, headers, body_bytes, effective_timeout
                )
            except (IpScopeApiError, IpScopeTimeoutError):
                raise
            except (httpx.TimeoutException, TimeoutError) as exc:
                raise IpScopeTimeoutError(path, effective_timeout) from exc
            except httpx.HTTPError as http_exc:
                if attempt < max_retries:
                    time.sleep(_compute_backoff_seconds(attempt, self._retry))
                    continue
                raise IpScopeApiError(
                    f'Network request to "{path}" failed: {http_exc}',
                    status=0,
                    path=path,
                    code="IPSCOPE_NETWORK_ERROR",
                ) from http_exc
            except Exception as exc:
                if attempt < max_retries:
                    time.sleep(_compute_backoff_seconds(attempt, self._retry))
                    continue
                raise IpScopeApiError(
                    f'Network request to "{path}" failed: {exc}',
                    status=0,
                    path=path,
                    code="IPSCOPE_NETWORK_ERROR",
                ) from exc

            if len(raw_resp.body_bytes) > MAX_RESPONSE_BYTES:
                raise IpScopeApiError(
                    "IPScope response payload exceeds 2 MiB safety limit",
                    status=raw_resp.status,
                    path=path,
                    code="IPSCOPE_RESPONSE_TOO_LARGE",
                )

            rate_limit = parse_rate_limit_headers(raw_resp.headers)
            self._last_rate_limit = rate_limit

            parsed_body: Any = None
            if raw_resp.body_bytes:
                text = raw_resp.body_bytes.decode("utf-8", errors="replace")
                try:
                    parsed_body = json.loads(text)
                except ValueError:
                    parsed_body = text

            if 200 <= raw_resp.status < 300:
                return parsed_body, raw_resp.status, rate_limit

            err_msg = _extract_error_message(parsed_body, raw_resp.status, path)

            if raw_resp.status in (401, 403):
                raise IpScopeAuthenticationError(
                    err_msg,
                    status=raw_resp.status,
                    path=path,
                    response_body=parsed_body,
                    rate_limit=rate_limit,
                )

            if raw_resp.status == 429:
                retry_after = _compute_retry_after_seconds(raw_resp.headers, rate_limit)
                if self._retry.retry_on_rate_limit and attempt < max_retries:
                    delay = min(
                        self._retry.max_delay_seconds,
                        retry_after
                        if retry_after is not None
                        else _compute_backoff_seconds(attempt, self._retry),
                    )
                    time.sleep(delay)
                    continue
                raise IpScopeRateLimitError(
                    err_msg,
                    path=path,
                    retry_after_seconds=retry_after,
                    response_body=parsed_body,
                    rate_limit=rate_limit,
                )

            if raw_resp.status in (502, 503, 504) and attempt < max_retries:
                time.sleep(_compute_backoff_seconds(attempt, self._retry))
                continue

            raise IpScopeApiError(
                err_msg,
                status=raw_resp.status,
                path=path,
                response_body=parsed_body,
                rate_limit=rate_limit,
            )

        raise IpScopeApiError(
            f'Exhausted {max_retries} retries for "{path}"',
            status=0,
            path=path,
            code="IPSCOPE_RETRY_EXHAUSTED",
        )


class AsyncHttpTransport:
    """Asynchronous HTTP transport backed by `httpx.AsyncClient` with bounded streaming reads and automatic retries."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        retry: RetryOptions | None = None,
        user_agent: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | AsyncTransportCallable | None = None,
    ) -> None:
        self._api_key = validate_api_key(api_key)
        self._base_url = base_url.strip().rstrip("/") or DEFAULT_BASE_URL
        self._timeout_seconds = max(0.1, float(timeout_seconds))
        self._retry = retry or RetryOptions()
        self._user_agent = f"{user_agent} {SDK_USER_AGENT}" if user_agent else SDK_USER_AGENT
        self._last_rate_limit: RateLimitMetadata | None = None

        self._callable_transport: AsyncTransportCallable | None = None
        if http_client is not None:
            self._client: httpx.AsyncClient | None = http_client
            self._owns_client = False
        elif isinstance(transport, httpx.AsyncBaseTransport) or transport is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(self._timeout_seconds),
                limits=DEFAULT_POOL_LIMITS,
                transport=transport,
                follow_redirects=False,
            )
            self._owns_client = True
        else:
            self._client = None
            self._owns_client = False
            self._callable_transport = transport

    async def close(self) -> None:
        """Closes the underlying `httpx.AsyncClient` connection pool if owned by this SDK instance."""
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    def get_last_rate_limit(self) -> RateLimitMetadata | None:
        return self._last_rate_limit

    async def _execute_httpx_async(
        self,
        method: str,
        url: str,
        path: str,
        headers: Mapping[str, str],
        body_bytes: bytes | None,
        timeout_seconds: float,
    ) -> RawHttpResponse:
        if self._callable_transport is not None:
            return await asyncio.wait_for(
                self._callable_transport(method, url, headers, body_bytes, timeout_seconds),
                timeout=timeout_seconds,
            )

        assert self._client is not None
        async with self._client.stream(
            method=method,
            url=url,
            headers=dict(headers),
            content=body_bytes,
            timeout=timeout_seconds,
        ) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            cl_raw = resp_headers.get("content-length")
            if cl_raw and cl_raw.isdigit() and int(cl_raw, 10) > MAX_RESPONSE_BYTES:
                raise IpScopeApiError(
                    f"IPScope response payload ({cl_raw} bytes) exceeds 2 MiB safety limit",
                    status=resp.status_code,
                    path=path,
                    code="IPSCOPE_RESPONSE_TOO_LARGE",
                )

            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise IpScopeApiError(
                        "IPScope response payload exceeds 2 MiB safety limit",
                        status=resp.status_code,
                        path=path,
                        code="IPSCOPE_RESPONSE_TOO_LARGE",
                    )
                chunks.append(chunk)

            return RawHttpResponse(
                status=int(resp.status_code),
                headers=resp_headers,
                body_bytes=b"".join(chunks),
            )

    async def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        timeout_seconds: float | None = None,
        extra_headers: Mapping[str, str] | None = None,
        requires_auth: bool = True,
    ) -> tuple[Any, int, RateLimitMetadata]:
        url = f"{self._base_url}{path}"
        effective_timeout = (
            max(0.1, float(timeout_seconds))
            if timeout_seconds is not None
            else self._timeout_seconds
        )

        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": self._user_agent,
        }
        if requires_auth:
            headers["x-api-key"] = self._api_key
            headers["Authorization"] = f"Bearer {self._api_key}"
        if body is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)

        body_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        max_retries = max(0, int(self._retry.max_retries))

        for attempt in range(max_retries + 1):
            try:
                raw_resp = await self._execute_httpx_async(
                    method, url, path, headers, body_bytes, effective_timeout
                )
            except (IpScopeApiError, IpScopeTimeoutError):
                raise
            except (httpx.TimeoutException, asyncio.TimeoutError, TimeoutError) as exc:
                raise IpScopeTimeoutError(path, effective_timeout) from exc
            except httpx.HTTPError as http_exc:
                if attempt < max_retries:
                    await asyncio.sleep(_compute_backoff_seconds(attempt, self._retry))
                    continue
                raise IpScopeApiError(
                    f'Network request to "{path}" failed: {http_exc}',
                    status=0,
                    path=path,
                    code="IPSCOPE_NETWORK_ERROR",
                ) from http_exc
            except Exception as exc:
                if attempt < max_retries:
                    await asyncio.sleep(_compute_backoff_seconds(attempt, self._retry))
                    continue
                raise IpScopeApiError(
                    f'Network request to "{path}" failed: {exc}',
                    status=0,
                    path=path,
                    code="IPSCOPE_NETWORK_ERROR",
                ) from exc

            if len(raw_resp.body_bytes) > MAX_RESPONSE_BYTES:
                raise IpScopeApiError(
                    "IPScope response payload exceeds 2 MiB safety limit",
                    status=raw_resp.status,
                    path=path,
                    code="IPSCOPE_RESPONSE_TOO_LARGE",
                )

            rate_limit = parse_rate_limit_headers(raw_resp.headers)
            self._last_rate_limit = rate_limit

            parsed_body: Any = None
            if raw_resp.body_bytes:
                text = raw_resp.body_bytes.decode("utf-8", errors="replace")
                try:
                    parsed_body = json.loads(text)
                except ValueError:
                    parsed_body = text

            if 200 <= raw_resp.status < 300:
                return parsed_body, raw_resp.status, rate_limit

            err_msg = _extract_error_message(parsed_body, raw_resp.status, path)

            if raw_resp.status in (401, 403):
                raise IpScopeAuthenticationError(
                    err_msg,
                    status=raw_resp.status,
                    path=path,
                    response_body=parsed_body,
                    rate_limit=rate_limit,
                )

            if raw_resp.status == 429:
                retry_after = _compute_retry_after_seconds(raw_resp.headers, rate_limit)
                if self._retry.retry_on_rate_limit and attempt < max_retries:
                    delay = min(
                        self._retry.max_delay_seconds,
                        retry_after
                        if retry_after is not None
                        else _compute_backoff_seconds(attempt, self._retry),
                    )
                    await asyncio.sleep(delay)
                    continue
                raise IpScopeRateLimitError(
                    err_msg,
                    path=path,
                    retry_after_seconds=retry_after,
                    response_body=parsed_body,
                    rate_limit=rate_limit,
                )

            if raw_resp.status in (502, 503, 504) and attempt < max_retries:
                await asyncio.sleep(_compute_backoff_seconds(attempt, self._retry))
                continue

            raise IpScopeApiError(
                err_msg,
                status=raw_resp.status,
                path=path,
                response_body=parsed_body,
                rate_limit=rate_limit,
            )

        raise IpScopeApiError(
            f'Exhausted {max_retries} retries for "{path}"',
            status=0,
            path=path,
            code="IPSCOPE_RETRY_EXHAUSTED",
        )
