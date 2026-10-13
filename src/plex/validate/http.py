"""Scoped HTTP client with runtime egress validation, rate limits, and evidence capture."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .scope import NetworkScope, ScopeViolationError, enforce_scope

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "api-key",
    "token",
    "secret",
}


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive authorization, cookies, and secret headers."""
    redacted: dict[str, str] = {}
    for k, v in headers.items():
        k_low = k.lower()
        if k_low == "set-cookie":
            parts = [p.strip() for p in v.split(";") if p.strip()]
            if parts and "=" in parts[0]:
                cookie_name = parts[0].split("=", 1)[0].strip()
                redacted[k] = "; ".join([f"{cookie_name}=[REDACTED]", *parts[1:]])
            else:
                redacted[k] = "[REDACTED]"
        elif k_low in SENSITIVE_HEADER_KEYS:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


@dataclass(frozen=True)
class HttpExchange:
    """Captured HTTP interaction used as verifiable proof evidence."""

    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str
    status_code: int
    response_headers: dict[str, str]
    response_body: str
    duration_ms: float
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status_code": self.status_code,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "duration_ms": round(self.duration_ms, 2),
            "digest": self.digest,
        }


def make_exchange(
    method: str,
    url: str,
    request_headers: dict[str, str],
    request_body: str,
    status_code: int,
    response_headers: dict[str, str],
    response_body: str,
    duration_ms: float,
) -> HttpExchange:
    """Create an HttpExchange with deterministic SHA-256 digest."""
    safe_req_headers = redact_headers(request_headers)
    safe_resp_headers = redact_headers(response_headers)
    body_snippet = response_body[:4096]

    canonical = json.dumps(
        {
            "method": method.upper(),
            "url": url,
            "status_code": status_code,
            "req_body": request_body,
            "resp_body": body_snippet,
        },
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return HttpExchange(
        method=method.upper(),
        url=url,
        request_headers=safe_req_headers,
        request_body=request_body,
        status_code=status_code,
        response_headers=safe_resp_headers,
        response_body=body_snippet,
        duration_ms=duration_ms,
        digest=digest,
    )


@dataclass
class ScopedHttpClient:
    """HTTP client technically enforcing destination allowlists, rate limits, and budgets."""

    scope: NetworkScope = field(default_factory=NetworkScope)
    requests_sent: int = 0
    _last_request_time: float = 0.0
    _start_time: float = field(default_factory=time.monotonic)

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        data: str | bytes | None = None,
        timeout: float = 10.0,
    ) -> HttpExchange:
        # 1. Enforce runtime technical network scope
        enforce_scope(url, self.scope)

        # 2. Enforce request budget
        if self.requests_sent >= self.scope.max_requests:
            raise ScopeViolationError(
                f"Request budget exhausted: {self.requests_sent} requests reached ceiling of {self.scope.max_requests}"
            )

        # 3. Enforce wall-clock watchdog limit
        elapsed = time.monotonic() - self._start_time
        if elapsed > self.scope.max_wall_time_seconds:
            raise ScopeViolationError(
                f"Wall-clock execution limit exceeded: {elapsed:.1f}s > {self.scope.max_wall_time_seconds}s"
            )

        # 4. Enforce rate limiting
        if self.scope.rate_limit_rps > 0:
            interval = 1.0 / self.scope.rate_limit_rps
            since_last = time.monotonic() - self._last_request_time
            if since_last < interval:
                time.sleep(interval - since_last)

        # 5. Execute HTTP request
        self.requests_sent += 1
        self._last_request_time = time.monotonic()

        req_headers = dict(headers or {})
        body_bytes = None
        req_body_str = ""
        if data is not None:
            if isinstance(data, str):
                body_bytes = data.encode("utf-8")
                req_body_str = data
            else:
                body_bytes = data
                req_body_str = data.decode("utf-8", errors="replace")

        req = Request(url, data=body_bytes, headers=req_headers, method=method.upper())

        start_clock = time.monotonic()
        try:
            with urlopen(req, timeout=timeout) as resp:
                resp_bytes = resp.read()
                resp_text = resp_bytes.decode("utf-8", errors="replace")
                resp_headers = dict(resp.headers.items())
                status = resp.status
        except HTTPError as exc:
            resp_bytes = exc.read()
            resp_text = resp_bytes.decode("utf-8", errors="replace")
            resp_headers = dict(exc.headers.items())
            status = exc.code
        except URLError as exc:
            duration_ms = (time.monotonic() - start_clock) * 1000.0
            return make_exchange(
                method=method,
                url=url,
                request_headers=req_headers,
                request_body=req_body_str,
                status_code=599,
                response_headers={},
                response_body=f"URLError: {exc.reason}",
                duration_ms=duration_ms,
            )

        duration_ms = (time.monotonic() - start_clock) * 1000.0
        return make_exchange(
            method=method,
            url=url,
            request_headers=req_headers,
            request_body=req_body_str,
            status_code=status,
            response_headers=resp_headers,
            response_body=resp_text,
            duration_ms=duration_ms,
        )
