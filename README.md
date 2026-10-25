# `ipscope` — Official IPScope Server-Side Python SDK

Official, strictly typed server-side **Python SDK** for the **IPScope IP Intelligence Platform**, powered by **`httpx`** and supporting both **Synchronous (`IpScopeClient`)** and **Asynchronous (`AsyncIpScopeClient`)** execution.

> **Scope Notice:** This SDK is intentionally scoped strictly to **IP intelligence, network prefix, dataset metadata, feedback, and health operations**. It contains **zero account, billing, wallet, or key-management operations**, making it safe to deploy in production backend microservices, workers, and API gateways.

---

## Features

- **Both Sync & Async Clients Powered by `httpx`**:
  - `IpScopeClient`: Thread-safe synchronous client backed by persistent `httpx.Client` connection pooling (`client = IpScopeClient(api_key="...")`).
  - `AsyncIpScopeClient`: Coroutine-safe asynchronous client backed by `httpx.AsyncClient` (`client = AsyncIpScopeClient(api_key="...")`) with **singleflight request coalescing** (`asyncio.Task` deduplication) and bounded concurrency (`asyncio.Semaphore`).
- **100% Type-Safe (PEP 561 `py.typed`)**: Uses `@dataclass(frozen=True, slots=True)` models for all responses (`IpLookupResponse`, `GeoResponseBlock`, `NetworkResponseBlock`, `SecurityResponseBlock`, `ConnectionResponseBlock`, `SecurityExtensionsResponseBlock`, `BatchLookupResponse`, `NetworkPrefixLookupResponse`, `DatasetsMetadataResponse`, `FeedbackSubmissionResponse`, `ServiceStatusResponse`).
- **Low-RAM & Zero Memory Leaks**:
  - Slotted frozen dataclasses (`slots=True`) eliminate per-instance `__dict__` overhead (~55% lower RAM per record).
  - Bounded `OrderedDict` LRU + TTL cache (`max_entries=512` default, `< 400 KB` worst-case footprint).
  - Hard `2 MiB` streaming response ceiling (`MAX_RESPONSE_BYTES`) via `httpx` streaming prevents OOM on malformed upstream payloads.
  - Bounded `httpx.Limits(max_connections=20, max_keepalive_connections=10, keepalive_expiry=30.0)`.
  - `lookup_batch_stream(...)` generator / async generator yields batch chunks incrementally without holding large arrays in memory.

---

## Installation

```bash
pip install ipscope
```

---

## Quick Start (Synchronous Client)

```python
from ipscope import IpScopeClient

client = IpScopeClient(api_key="ips_live_your_api_key_here")

# 1. Single IPv4 or IPv6 lookup (cached automatically in LRU cache)
ip_info = client.lookup_ip("8.8.8.8")
print(ip_info.ip, ip_info.geo.country_code, ip_info.network.asn)
print("VPN:", ip_info.security.is_vpn, "Type:", ip_info.security.anonymizer_type)

# 2. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
batch = client.lookup_batch(["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
for record in batch.results:
    print(record.ip, record.network.organization)

# 3. Memory-bounded streaming batch lookup for 10,000+ IPs
for chunk in client.lookup_batch_stream(large_ip_list):
    for record in chunk.results:
        process_record(record)

# 4. Network CIDR prefix lookup
prefix = client.lookup_network("8.8.8.0/24")
print(prefix.queried_cidr, prefix.dataset_version, prefix.record)
```

---

## Quick Start (Asynchronous Client)

```python
import asyncio
from ipscope import AsyncIpScopeClient

client = AsyncIpScopeClient(api_key="ips_live_your_api_key_here")


async def main() -> None:
    # 1. Concurrent singleflight-coalesced lookups
    ip_info = await client.lookup_ip("1.1.1.1")
    print(ip_info.ip, ip_info.network.organization)

    # 2. Chunked async batch lookup with bounded concurrency (default max 4 in-flight)
    batch = await client.lookup_batch_chunked(
        ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
        concurrency=4,
    )
    print("Resolved:", batch.count)

    # 3. Async streaming generator for constant O(chunk) memory usage
    async for chunk in client.lookup_batch_stream(large_ip_list):
        for record in chunk.results:
            print(record.ip)


asyncio.run(main())
```

---

## Error Handling

```python
from ipscope import (
    IpScopeClient,
    IpScopeError,
    IpScopeValidationError,
    IpScopeAuthenticationError,
    IpScopeRateLimitError,
    IpScopeTimeoutError,
    IpScopeApiError,
)

client = IpScopeClient(api_key="ips_live_your_api_key_here")

try:
    res = client.lookup_ip("8.8.8.8")
except IpScopeValidationError as err:
    # Invalid IP / CIDR / batch size before any network request is made
    print("Validation failed:", err.field, err)
except IpScopeAuthenticationError as err:
    # 401 / 403 invalid or revoked API key
    print("Auth error:", err.status, err.code)
except IpScopeRateLimitError as err:
    # 429 after retries exhausted
    print("Rate limited, retry after s:", err.retry_after_seconds, err.rate_limit)
except IpScopeTimeoutError as err:
    print("Timed out after s:", err.timeout_seconds)
except IpScopeApiError as err:
    print("API error:", err.status, err.code)
except IpScopeError as err:
    print("SDK error:", err)
```
