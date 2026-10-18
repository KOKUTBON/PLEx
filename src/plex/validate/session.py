"""Stateful HTTP session management and HTML form/DOM extraction for PLEx Validate."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlencode, urljoin

from .http import HttpExchange, ScopedHttpClient
from .scope import NetworkScope

CSRF_FIELD_NAMES = {
    "csrf_token",
    "csrfmiddlewaretoken",
    "_csrf",
    "authenticity_token",
    "xsrf_token",
    "__requestverificationtoken",
}


@dataclass(frozen=True)
class ExtractedHtmlForm:
    """Structured representation of an HTML form extracted from DOM content."""

    action: str
    method: str = "GET"
    inputs: dict[str, str] = field(default_factory=dict)
    csrf_fields: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "inputs": dict(self.inputs),
            "csrf_fields": dict(self.csrf_fields),
        }


class _HtmlFormParser(HTMLParser):
    """Lightweight HTML parser extracting <form>, <input>, <textarea>, <select>, and <meta> tags."""

    def __init__(self, base_url: str = "") -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[ExtractedHtmlForm] = []
        self.meta_csrf: dict[str, str] = {}
        self._in_form: bool = False
        self._current_action: str = ""
        self._current_method: str = "GET"
        self._current_inputs: dict[str, str] = {}
        self._current_csrf: dict[str, str] = {}
        self._current_textarea_name: str | None = None
        self._current_textarea_chunks: list[str] = []
        self._current_select_name: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        tag_low = tag.lower()

        if tag_low == "meta":
            meta_name = attr_map.get("name", "").lower()
            meta_content = attr_map.get("content", "")
            if meta_name in {"csrf-token", "xsrf-token", "_csrf"} and meta_content:
                self.meta_csrf[meta_name] = meta_content
            return

        if tag_low == "form":
            self._in_form = True
            raw_action = attr_map.get("action", "")
            self._current_action = (
                urljoin(self.base_url, raw_action) if self.base_url else raw_action
            )
            self._current_method = attr_map.get("method", "GET").upper() or "GET"
            self._current_inputs = {}
            self._current_csrf = {}
            return

        if not self._in_form:
            return

        if tag_low == "input":
            name = attr_map.get("name", "")
            if not name:
                return
            val = attr_map.get("value", "")
            self._current_inputs[name] = val
            if name.lower() in CSRF_FIELD_NAMES:
                self._current_csrf[name] = val
        elif tag_low == "textarea":
            name = attr_map.get("name", "")
            if name:
                self._current_textarea_name = name
                self._current_textarea_chunks = []
        elif tag_low == "select":
            name = attr_map.get("name", "")
            if name:
                self._current_select_name = name
                self._current_inputs.setdefault(name, "")
        elif tag_low == "option" and self._current_select_name:
            val = attr_map.get("value", "")
            if "selected" in attr_map or not self._current_inputs.get(self._current_select_name):
                self._current_inputs[self._current_select_name] = val

    def handle_data(self, data: str) -> None:
        if self._in_form and self._current_textarea_name is not None:
            self._current_textarea_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag_low = tag.lower()
        if tag_low == "textarea" and self._current_textarea_name is not None:
            self._current_inputs[self._current_textarea_name] = "".join(
                self._current_textarea_chunks
            )
            self._current_textarea_name = None
            self._current_textarea_chunks = []
        elif tag_low == "select":
            self._current_select_name = None
        elif tag_low == "form" and self._in_form:
            self.forms.append(
                ExtractedHtmlForm(
                    action=self._current_action,
                    method=self._current_method,
                    inputs=dict(self._current_inputs),
                    csrf_fields=dict(self._current_csrf),
                )
            )
            self._in_form = False


def extract_html_forms(html_text: str, base_url: str = "") -> list[ExtractedHtmlForm]:
    """Extract all HTML forms, input defaults, and CSRF token fields from an HTML document."""
    parser = _HtmlFormParser(base_url=base_url)
    parser.feed(html_text)
    return parser.forms


def extract_meta_csrf_tokens(html_text: str) -> dict[str, str]:
    """Extract CSRF tokens embedded in <meta> tags."""
    parser = _HtmlFormParser()
    parser.feed(html_text)
    return parser.meta_csrf


@dataclass
class StatefulSessionClient:
    """Multi-step stateful HTTP session client preserving cookies and CSRF tokens within scope."""

    scope: NetworkScope = field(default_factory=NetworkScope)
    client: ScopedHttpClient | None = None
    csrf_tokens: dict[str, str] = field(default_factory=dict)
    history: list[HttpExchange] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.client is None:
            self.client = ScopedHttpClient(scope=self.scope, persist_cookies=True)
        else:
            self.client.persist_cookies = True

    @property
    def cookies(self) -> dict[str, str]:
        assert self.client is not None
        return self.client.cookie_jar

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        data: str | bytes | None = None,
        timeout: float = 10.0,
    ) -> HttpExchange:
        assert self.client is not None
        req_headers = dict(headers or {})
        # Automatically attach meta CSRF token on state-changing requests if present
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and self.csrf_tokens:
            if not any(k.lower() in {"x-csrf-token", "x-xsrf-token"} for k in req_headers):
                token_val = next(iter(self.csrf_tokens.values()))
                req_headers["X-CSRF-Token"] = token_val

        exchange = self.client.request(
            method=method,
            url=url,
            headers=req_headers,
            data=data,
            timeout=timeout,
        )
        self.history.append(exchange)
        meta_tokens = extract_meta_csrf_tokens(exchange.response_body)
        if meta_tokens:
            self.csrf_tokens.update(meta_tokens)
        for form in extract_html_forms(exchange.response_body, base_url=url):
            self.csrf_tokens.update(form.csrf_fields)
        return exchange

    def fetch_form(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[HttpExchange, list[ExtractedHtmlForm]]:
        """Fetch an HTML page and extract all forms while capturing session cookies and CSRF tokens."""
        exchange = self.request("GET", url, headers=headers)
        forms = extract_html_forms(exchange.response_body, base_url=url)
        return exchange, forms

    def submit_form(
        self,
        form: ExtractedHtmlForm,
        overrides: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpExchange:
        """Submit an extracted HTML form, merging default inputs, CSRF tokens, and overrides."""
        payload = dict(form.inputs)
        payload.update(form.csrf_fields)
        if overrides:
            payload.update(overrides)

        encoded = urlencode(payload)
        req_headers = dict(headers or {})
        method = form.method.upper()
        if method == "GET":
            sep = "&" if "?" in form.action else "?"
            target_url = f"{form.action}{sep}{encoded}" if encoded else form.action
            return self.request("GET", target_url, headers=req_headers)

        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return self.request(method, form.action, headers=req_headers, data=encoded)
