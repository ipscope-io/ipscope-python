"""Comprehensive unit tests for the IPScope Python SDK (Sync & Async clients)."""

from __future__ import annotations

import asyncio
import json
import unittest
from typing import Any, Mapping

from ipscope import (
    AsyncIpScopeClient,
    CacheOptions,
    FeedbackSubmissionInput,
    IpScopeApiError,
    IpScopeAuthenticationError,
    IpScopeClient,
    IpScopeRateLimitError,
    IpScopeTimeoutError,
    IpScopeValidationError,
    MAX_RESPONSE_BYTES,
    RawHttpResponse,
    RetryOptions,
    validate_and_deduplicate_batch_ips,
    validate_api_key,
    validate_cidr_prefix,
    validate_ip_address,
)


def make_mock_ip_record(ip: str) -> dict[str, Any]:
    return {
        "ip": ip,
        "ip_version": 6 if ":" in ip else 4,
        "matched_network": "2001:4860:4860::/48" if ":" in ip else "8.8.8.0/24",
        "geo": {
            "country_code": "US",
            "subdivision": "California",
            "city": "Mountain View",
            "timezone": "America/Los_Angeles",
            "location_type": "anycast",
            "confidence": 0.96,
            "accuracy_radius_km": 20.0,
            "declared_country_code": "US",
            "physical_country_code": "US",
            "is_virtual_location": False,
        },
        "network": {
            "asn": 15169,
            "organization": "Google LLC",
        },
        "security": {
            "is_vpn": False,
            "is_hosting": True,
            "is_tor_exit": False,
            "is_proxy": False,
            "anonymizer_type": "none",
            "confidence": 0.99,
            "reason_codes": ["ASN_HOSTING"],
        },
        "connection": {
            "connection_type": "hosting",
            "is_residential": False,
            "is_mobile": False,
            "is_business": False,
            "is_hosting": True,
        },
        "security_extensions": {
            "abuse_velocity_score": 0.02,
            "is_known_scanner": False,
            "observation_recency_hours": 1.5,
        },
        "dataset_version": "2026.10.25-001",
        "updated_at": "2026-10-25T00:00:00Z",
    }


DEFAULT_RATE_LIMIT_HEADERS: dict[str, str] = {
    "content-type": "application/json",
    "x-ratelimit-limit": "1000",
    "x-ratelimit-remaining": "998",
    "x-ratelimit-reset": "1761350400",
    "x-ratelimit-scope": "user",
    "x-ratelimit-burst": "100",
    "x-ratelimit-rps": "50",
}


class TestValidationAndScope(unittest.TestCase):
    def test_validate_api_key(self) -> None:
        self.assertEqual(
            validate_api_key("  ips_live_secret_123456  "),
            "ips_live_secret_123456",
        )
        with self.assertRaises(IpScopeValidationError):
            validate_api_key("")
        with self.assertRaises(IpScopeValidationError):
            validate_api_key("   ")
        with self.assertRaises(IpScopeValidationError):
            validate_api_key("ips_live_bad\nheader")

    def test_validate_ip_address(self) -> None:
        self.assertEqual(validate_ip_address(" 8.8.8.8 "), ("8.8.8.8", 4))
        self.assertEqual(
            validate_ip_address("2001:0db8:0000:0000:0000:0000:0000:0001"),
            ("2001:db8::1", 6),
        )
        with self.assertRaises(IpScopeValidationError):
            validate_ip_address("")
        with self.assertRaises(IpScopeValidationError):
            validate_ip_address("999.999.999.999")
        with self.assertRaises(IpScopeValidationError):
            validate_ip_address("8.8.8.0/24")

    def test_validate_cidr_prefix(self) -> None:
        self.assertEqual(
            validate_cidr_prefix("8.8.8.0/24"),
            ("8.8.8.0", 24, 4, "8.8.8.0/24"),
        )
        self.assertEqual(
            validate_cidr_prefix("2001:4860::/32"),
            ("2001:4860::", 32, 6, "2001:4860::/32"),
        )
        with self.assertRaises(IpScopeValidationError):
            validate_cidr_prefix("8.8.8.8")
        with self.assertRaises(IpScopeValidationError):
            validate_cidr_prefix("8.8.8.0/33")
        with self.assertRaises(IpScopeValidationError):
            validate_cidr_prefix("2001:db8::/129")

    def test_validate_and_deduplicate_batch_ips(self) -> None:
        ordered, unique = validate_and_deduplicate_batch_ips(
            ["8.8.8.8", "1.1.1.1", "8.8.8.8"]
        )
        self.assertEqual(ordered, ("8.8.8.8", "1.1.1.1", "8.8.8.8"))
        self.assertEqual(unique, ("8.8.8.8", "1.1.1.1"))

        with self.assertRaises(IpScopeValidationError):
            validate_and_deduplicate_batch_ips([])

    def test_no_account_or_billing_methods_exposed(self) -> None:
        forbidden = (
            "get_wallet",
            "top_up_wallet",
            "create_checkout",
            "list_api_keys",
            "create_api_key",
            "revoke_api_key",
            "login",
            "register",
            "get_billing",
            "update_subscription",
        )
        for attr in forbidden:
            self.assertFalse(
                hasattr(IpScopeClient, attr),
                f"IpScopeClient must not expose {attr}",
            )
            self.assertFalse(
                hasattr(AsyncIpScopeClient, attr),
                f"AsyncIpScopeClient must not expose {attr}",
            )


class TestSyncIpScopeClient(unittest.TestCase):
    def test_single_lookup_and_lru_cache_hit(self) -> None:
        calls: list[tuple[str, str, Mapping[str, str]]] = []

        def mock_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            calls.append((method, url, headers))
            payload = json.dumps(make_mock_ip_record("8.8.8.8")).encode("utf-8")
            return RawHttpResponse(
                status=200,
                headers=DEFAULT_RATE_LIMIT_HEADERS,
                body_bytes=payload,
            )

        with IpScopeClient(
            api_key="ips_live_valid_key_12345",
            transport=mock_transport,
        ) as client:
            first = client.lookup_ip("8.8.8.8")
            second = client.lookup_ip("8.8.8.8")

            self.assertEqual(first.ip, "8.8.8.8")
            self.assertEqual(first.geo.country_code, "US")
            self.assertEqual(first.network.asn, 15169)
            self.assertEqual(first.network.organization, "Google LLC")
            self.assertIs(first, second)
            self.assertEqual(len(calls), 1)
            self.assertEqual(
                calls[0][2].get("x-api-key"), "ips_live_valid_key_12345"
            )

            # Slotted frozen dataclass check (zero __dict__ overhead)
            self.assertFalse(hasattr(first, "__dict__"))
            self.assertEqual(client.get_cache_stats().size, 1)
            self.assertEqual(client.get_cache_stats().hits, 1)
            self.assertIsNotNone(client.get_last_rate_limit())
            self.assertEqual(client.get_last_rate_limit().remaining, 998)  # type: ignore[union-attr]

    def test_batch_lookup_deduplicates_and_reuses_cache(self) -> None:
        sent_bodies: list[dict[str, Any]] = []

        def mock_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            if url.endswith("/v1/ip/8.8.8.8"):
                return RawHttpResponse(
                    status=200,
                    headers=DEFAULT_RATE_LIMIT_HEADERS,
                    body_bytes=json.dumps(make_mock_ip_record("8.8.8.8")).encode("utf-8"),
                )
            assert body is not None
            parsed_body = json.loads(body.decode("utf-8"))
            sent_bodies.append(parsed_body)
            records = [make_mock_ip_record(ip) for ip in parsed_body["ips"]]
            return RawHttpResponse(
                status=200,
                headers=DEFAULT_RATE_LIMIT_HEADERS,
                body_bytes=json.dumps(
                    {
                        "dataset_version": "2026.10.25-001",
                        "count": len(records),
                        "results": records,
                    }
                ).encode("utf-8"),
            )

        with IpScopeClient(
            api_key="ips_live_valid_key_12345",
            transport=mock_transport,
        ) as client:
            # Prime cache with 8.8.8.8
            client.lookup_ip("8.8.8.8")

            # Batch lookup with cached 8.8.8.8 and duplicate 1.1.1.1
            batch = client.lookup_batch(
                ["8.8.8.8", "1.1.1.1", "8.8.8.8", "1.1.1.1", "9.9.9.9"]
            )
            self.assertEqual(len(sent_bodies), 1)
            # Only uncached unique IPs should be sent over the wire
            self.assertEqual(sent_bodies[0]["ips"], ["1.1.1.1", "9.9.9.9"])
            self.assertEqual(batch.count, 5)
            self.assertEqual(
                [r.ip for r in batch.results],
                ["8.8.8.8", "1.1.1.1", "8.8.8.8", "1.1.1.1", "9.9.9.9"],
            )

    def test_lookup_batch_chunked_and_stream(self) -> None:
        batch_calls = 0

        def mock_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            nonlocal batch_calls
            batch_calls += 1
            assert body is not None
            parsed = json.loads(body.decode("utf-8"))
            records = [make_mock_ip_record(ip) for ip in parsed["ips"]]
            return RawHttpResponse(
                status=200,
                headers=DEFAULT_RATE_LIMIT_HEADERS,
                body_bytes=json.dumps(
                    {
                        "dataset_version": "2026.10.25-001",
                        "count": len(records),
                        "results": records,
                    }
                ).encode("utf-8"),
            )

        with IpScopeClient(
            api_key="ips_live_valid_key_12345",
            cache=CacheOptions(enabled=False),
            transport=mock_transport,
        ) as client:
            ips = [f"10.0.0.{i}" for i in range(1, 251)]  # 250 IPs -> 3 chunks of 100, 100, 50
            chunks = list(client.lookup_batch_stream(ips))
            self.assertEqual(len(chunks), 3)
            self.assertEqual([c.count for c in chunks], [100, 100, 50])
            self.assertEqual(batch_calls, 3)

            combined = client.lookup_batch_chunked(ips)
            self.assertEqual(combined.count, 250)

    def test_network_caller_datasets_feedback_and_status(self) -> None:
        def mock_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            if "/v1/networks/" in url:
                return RawHttpResponse(
                    status=200,
                    headers=DEFAULT_RATE_LIMIT_HEADERS,
                    body_bytes=json.dumps(
                        {
                            "queried_cidr": "8.8.8.0/24",
                            "family": 4,
                            "dataset_version": "2026.10.25-001",
                            "record": {
                                "prefix": "8.8.8.0/24",
                                "family": 4,
                                "asn": 15169,
                                "organization": "Google LLC",
                                "country_code": "US",
                                "city": "Mountain View",
                                "location_type": "anycast",
                                "is_vpn": False,
                                "is_hosting": True,
                                "is_tor_exit": False,
                                "is_proxy": False,
                                "anonymizer_type": "none",
                            },
                        }
                    ).encode("utf-8"),
                )
            if url.endswith("/v1/ip/me"):
                return RawHttpResponse(
                    status=200,
                    headers=DEFAULT_RATE_LIMIT_HEADERS,
                    body_bytes=json.dumps(make_mock_ip_record("203.0.113.42")).encode("utf-8"),
                )
            if url.endswith("/v1/metadata/datasets"):
                return RawHttpResponse(
                    status=200,
                    headers=DEFAULT_RATE_LIMIT_HEADERS,
                    body_bytes=json.dumps(
                        {
                            "active_version": "2026.10.25-001",
                            "previous_version": "2026.10.24-001",
                            "snapshots": [
                                {
                                    "snapshot_version": "2026.10.25-001",
                                    "digest": "sha256:abc123",
                                    "ruleset_version": "v1",
                                    "published_at": "2026-10-25T00:00:00Z",
                                    "ipv4_prefix_count": 950000,
                                    "ipv6_prefix_count": 220000,
                                }
                            ],
                        }
                    ).encode("utf-8"),
                )
            if url.endswith("/v1/feedback"):
                return RawHttpResponse(
                    status=201,
                    headers=DEFAULT_RATE_LIMIT_HEADERS,
                    body_bytes=json.dumps(
                        {
                            "id": "fb_999",
                            "prefix_or_ip": "8.8.8.8",
                            "role": "network_operator",
                            "issue_type": "wrong_country",
                            "requested_correction": {"country_code": "US"},
                            "created_at": "2026-10-25T10:00:00Z",
                            "status": "pending_review",
                        }
                    ).encode("utf-8"),
                )
            if url.endswith("/v1/status"):
                return RawHttpResponse(
                    status=200,
                    headers=DEFAULT_RATE_LIMIT_HEADERS,
                    body_bytes=json.dumps(
                        {
                            "status": "ok",
                            "snapshot": {
                                "currentVersion": "2026.10.25-001",
                                "previousVersion": "2026.10.24-001",
                            },
                        }
                    ).encode("utf-8"),
                )
            raise AssertionError(f"Unexpected URL: {url}")

        with IpScopeClient(
            api_key="ips_live_valid_key_12345",
            transport=mock_transport,
        ) as client:
            net = client.lookup_network("8.8.8.0/24")
            self.assertEqual(net.queried_cidr, "8.8.8.0/24")
            self.assertIsNotNone(net.record)
            self.assertEqual(net.record.asn, 15169)  # type: ignore[union-attr]

            caller = client.lookup_caller_ip()
            self.assertEqual(caller.ip, "203.0.113.42")

            meta = client.get_datasets_metadata()
            self.assertEqual(meta.active_version, "2026.10.25-001")
            self.assertEqual(len(meta.snapshots), 1)

            fb = client.submit_feedback(
                FeedbackSubmissionInput(
                    prefix_or_ip="8.8.8.8",
                    role="network_operator",
                    issue_type="wrong_country",
                    requested_correction={"country_code": "US"},
                )
            )
            self.assertEqual(fb.id, "fb_999")

            status = client.get_status()
            self.assertEqual(status.status, "ok")
            self.assertEqual(status.current_version, "2026.10.25-001")

    def test_retries_on_429_and_503_and_error_mapping(self) -> None:
        attempts = 0

        def mock_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return RawHttpResponse(
                    status=429,
                    headers={**DEFAULT_RATE_LIMIT_HEADERS, "retry-after": "0.005"},
                    body_bytes=json.dumps({"message": "Too many requests"}).encode("utf-8"),
                )
            if attempts == 2:
                return RawHttpResponse(
                    status=503,
                    headers=DEFAULT_RATE_LIMIT_HEADERS,
                    body_bytes=json.dumps({"message": "Service unavailable"}).encode("utf-8"),
                )
            return RawHttpResponse(
                status=200,
                headers=DEFAULT_RATE_LIMIT_HEADERS,
                body_bytes=json.dumps(make_mock_ip_record("1.1.1.1")).encode("utf-8"),
            )

        with IpScopeClient(
            api_key="ips_live_valid_key_12345",
            retry=RetryOptions(
                max_retries=3, base_delay_seconds=0.005, max_delay_seconds=0.02
            ),
            transport=mock_transport,
        ) as client:
            record = client.lookup_ip("1.1.1.1")
            self.assertEqual(record.ip, "1.1.1.1")
            self.assertEqual(attempts, 3)

    def test_auth_error_and_oversized_response_guard(self) -> None:
        def mock_auth_fail(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            return RawHttpResponse(
                status=401,
                headers=DEFAULT_RATE_LIMIT_HEADERS,
                body_bytes=json.dumps({"message": "Invalid API Key"}).encode("utf-8"),
            )

        with IpScopeClient(
            api_key="ips_live_valid_key_12345",
            transport=mock_auth_fail,
        ) as client:
            with self.assertRaises(IpScopeAuthenticationError) as ctx:
                client.lookup_ip("8.8.8.8")
            self.assertEqual(ctx.exception.status, 401)
            self.assertEqual(ctx.exception.code, "IPSCOPE_UNAUTHORIZED")

        def mock_oversized(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            return RawHttpResponse(
                status=200,
                headers=DEFAULT_RATE_LIMIT_HEADERS,
                body_bytes=b"x" * (MAX_RESPONSE_BYTES + 10),
            )

        with IpScopeClient(
            api_key="ips_live_valid_key_12345",
            transport=mock_oversized,
        ) as client:
            with self.assertRaises(IpScopeApiError) as ctx2:
                client.lookup_ip("8.8.8.8")
            self.assertEqual(ctx2.exception.code, "IPSCOPE_RESPONSE_TOO_LARGE")

    def test_bounded_lru_cache_eviction(self) -> None:
        def mock_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            ip = url.rsplit("/", 1)[-1]
            return RawHttpResponse(
                status=200,
                headers=DEFAULT_RATE_LIMIT_HEADERS,
                body_bytes=json.dumps(make_mock_ip_record(ip)).encode("utf-8"),
            )

        with IpScopeClient(
            api_key="ips_live_valid_key_12345",
            cache=CacheOptions(enabled=True, max_entries=3, ttl_seconds=60.0),
            transport=mock_transport,
        ) as client:
            for i in range(1, 15):
                client.lookup_ip(f"10.0.0.{i}")
            self.assertLessEqual(client.get_cache_stats().size, 3)


class TestAsyncIpScopeClient(unittest.IsolatedAsyncioTestCase):
    async def test_async_singleflight_coalescing_and_cache(self) -> None:
        network_calls = 0

        async def mock_async_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            nonlocal network_calls
            network_calls += 1
            await asyncio.sleep(0.02)
            return RawHttpResponse(
                status=200,
                headers=DEFAULT_RATE_LIMIT_HEADERS,
                body_bytes=json.dumps(make_mock_ip_record("8.8.8.8")).encode("utf-8"),
            )

        async with AsyncIpScopeClient(
            api_key="ips_live_valid_key_12345",
            transport=mock_async_transport,
        ) as client:
            # Launch 25 concurrent lookups for the same IP; singleflight must coalesce into 1 HTTP call
            results = await asyncio.gather(
                *(client.lookup_ip("8.8.8.8") for _ in range(25))
            )
            self.assertEqual(network_calls, 1)
            self.assertEqual(len(results), 25)
            for item in results:
                self.assertIs(item, results[0])
            self.assertEqual(client.get_cache_stats().coalesced_in_flight_hits, 24)
            self.assertEqual(client.get_cache_stats().size, 1)

    async def test_async_batch_chunked_and_stream(self) -> None:
        in_flight = 0
        max_seen_in_flight = 0

        async def mock_async_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            nonlocal in_flight, max_seen_in_flight
            in_flight += 1
            max_seen_in_flight = max(max_seen_in_flight, in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1
            assert body is not None
            parsed = json.loads(body.decode("utf-8"))
            records = [make_mock_ip_record(ip) for ip in parsed["ips"]]
            return RawHttpResponse(
                status=200,
                headers=DEFAULT_RATE_LIMIT_HEADERS,
                body_bytes=json.dumps(
                    {
                        "dataset_version": "2026.10.25-001",
                        "count": len(records),
                        "results": records,
                    }
                ).encode("utf-8"),
            )

        async with AsyncIpScopeClient(
            api_key="ips_live_valid_key_12345",
            cache=CacheOptions(enabled=False),
            transport=mock_async_transport,
        ) as client:
            ips = [f"192.0.2.{i}" for i in range(1, 240)] + [
                f"198.51.100.{i}" for i in range(1, 240)
            ]
            batch = await client.lookup_batch_chunked(ips, concurrency=2)
            self.assertEqual(batch.count, len(ips))
            self.assertLessEqual(max_seen_in_flight, 2)

            streamed_count = 0
            async for chunk in client.lookup_batch_stream(ips[:150]):
                streamed_count += chunk.count
            self.assertEqual(streamed_count, 150)

    async def test_async_rate_limit_exhausted_and_timeout(self) -> None:
        async def mock_429(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            return RawHttpResponse(
                status=429,
                headers={**DEFAULT_RATE_LIMIT_HEADERS, "retry-after": "1"},
                body_bytes=json.dumps({"message": "Rate limit exceeded"}).encode("utf-8"),
            )

        async with AsyncIpScopeClient(
            api_key="ips_live_valid_key_12345",
            retry=RetryOptions(
                max_retries=1, base_delay_seconds=0.005, max_delay_seconds=0.01
            ),
            transport=mock_429,
        ) as client:
            with self.assertRaises(IpScopeRateLimitError) as ctx:
                await client.lookup_ip("1.1.1.1")
            self.assertEqual(ctx.exception.status, 429)
            self.assertEqual(ctx.exception.retry_after_seconds, 1.0)

        async def mock_timeout(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout_s: float,
        ) -> RawHttpResponse:
            raise TimeoutError("timed out")

        async with AsyncIpScopeClient(
            api_key="ips_live_valid_key_12345",
            retry=RetryOptions(max_retries=0),
            transport=mock_timeout,
        ) as client:
            with self.assertRaises(IpScopeTimeoutError):
                await client.lookup_ip("1.1.1.1")


if __name__ == "__main__":
    unittest.main()
