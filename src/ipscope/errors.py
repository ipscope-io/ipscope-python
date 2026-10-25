"""Typed exception hierarchy for the IPScope Python Server-Side SDK."""

from __future__ import annotations

from typing import Any

from .types import RateLimitMetadata


class IpScopeError(Exception):
    """Base exception for all errors raised by `ipscope`."""

    code: str

    def __init__(self, message: str, code: str = "IPSCOPE_ERROR") -> None:
        super().__init__(message)
        self.code = code


class IpScopeValidationError(IpScopeError):
    """Raised when client-side validation fails before making an HTTP request."""

    field: str | None

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message, "IPSCOPE_VALIDATION_ERROR")
        self.field = field


class IpScopeTimeoutError(IpScopeError):
    """Raised when an HTTP request exceeds the configured timeout."""

    timeout_seconds: float
    path: str

    def __init__(self, path: str, timeout_seconds: float) -> None:
        super().__init__(
            f'IPScope request to "{path}" timed out after {timeout_seconds}s',
            "IPSCOPE_TIMEOUT_ERROR",
        )
        self.path = path
        self.timeout_seconds = timeout_seconds


class IpScopeApiError(IpScopeError):
    """Raised when the IPScope API returns a non-2xx HTTP status code."""

    status: int
    path: str
    response_body: Any
    rate_limit: RateLimitMetadata | None

    def __init__(
        self,
        message: str,
        *,
        status: int,
        path: str,
        code: str | None = None,
        response_body: Any = None,
        rate_limit: RateLimitMetadata | None = None,
    ) -> None:
        super().__init__(message, code or f"IPSCOPE_HTTP_{status}")
        self.status = status
        self.path = path
        self.response_body = response_body
        self.rate_limit = rate_limit


class IpScopeAuthenticationError(IpScopeApiError):
    """Raised on HTTP 401 Unauthorized or 403 Forbidden."""

    def __init__(
        self,
        message: str,
        *,
        status: int,
        path: str,
        response_body: Any = None,
        rate_limit: RateLimitMetadata | None = None,
    ) -> None:
        super().__init__(
            message,
            status=status,
            path=path,
            code="IPSCOPE_UNAUTHORIZED" if status == 401 else "IPSCOPE_FORBIDDEN_SCOPE",
            response_body=response_body,
            rate_limit=rate_limit,
        )


class IpScopeRateLimitError(IpScopeApiError):
    """Raised on HTTP 429 Too Many Requests when retries are exhausted or disabled."""

    retry_after_seconds: float | None

    def __init__(
        self,
        message: str,
        *,
        path: str,
        retry_after_seconds: float | None = None,
        response_body: Any = None,
        rate_limit: RateLimitMetadata | None = None,
    ) -> None:
        super().__init__(
            message,
            status=429,
            path=path,
            code="IPSCOPE_RATE_LIMITED",
            response_body=response_body,
            rate_limit=rate_limit,
        )
        self.retry_after_seconds = retry_after_seconds
