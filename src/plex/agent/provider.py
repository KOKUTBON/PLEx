"""Replaceable model provider interface supporting local and offline backends."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from .models import ToolCall

log = logging.getLogger(__name__)


@dataclass
class ModelMessage:
    """A standardized message passed to or from a model provider."""

    role: str
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None


@dataclass
class ModelResponse:
    """Standardized output returned from a model provider."""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = "stop"
    tokens_prompt: int = 0
    tokens_completion: int = 0
    model: str = ""


class ModelProvider(ABC):
    """Abstract interface for LLM backends."""

    name: str = "base"

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether the model backend is reachable and configured."""

    @abstractmethod
    def generate(
        self,
        messages: list[ModelMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> ModelResponse:
        """Generate a response given a conversation history and optional tool schemas."""


class LocalMockModelProvider(ModelProvider):
    """Deterministic, offline mock provider for hermetic testing and verification."""

    name = "mock"

    def __init__(
        self,
        scripted_responses: list[ModelResponse] | None = None,
        default_response: ModelResponse | None = None,
    ) -> None:
        self.scripted_responses: list[ModelResponse] = list(scripted_responses or [])
        self.default_response = default_response or ModelResponse(
            text="Completed analysis.",
            finish_reason="stop",
            tokens_prompt=10,
            tokens_completion=10,
            model="mock",
        )
        self.call_history: list[list[ModelMessage]] = []

    def is_available(self) -> bool:
        return True

    def queue_response(self, response: ModelResponse) -> None:
        """Enqueue a scripted response."""
        self.scripted_responses.append(response)

    def generate(
        self,
        messages: list[ModelMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> ModelResponse:
        self.call_history.append(list(messages))
        if self.scripted_responses:
            return self.scripted_responses.pop(0)
        return self.default_response


class OllamaModelProvider(ModelProvider):
    """Local model provider connecting to Ollama without external dependencies."""

    name = "ollama"

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "qwen2.5-coder:7b",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        """Check if local Ollama daemon is running."""
        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/tags",
                headers={"User-Agent": "PLEx-Agent/2.0"},
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return bool(resp.status == 200)
        except Exception:
            return False

    def generate(
        self,
        messages: list[ModelMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> ModelResponse:
        url = f"{self.base_url}/api/chat"
        formatted_messages: list[dict[str, Any]] = []
        for m in messages:
            msg_dict: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.tool_calls:
                msg_dict["tool_calls"] = [
                    {
                        "id": tc.call_id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in m.tool_calls
                ]
            formatted_messages.append(msg_dict)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": formatted_messages,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "PLEx-Agent/2.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Ollama connection error at {self.base_url}: {exc}") from exc

        msg = body.get("message", {})
        text = msg.get("content", "")
        raw_tools = msg.get("tool_calls", [])
        tool_calls: list[ToolCall] = []

        for rt in raw_tools:
            fn = rt.get("function", {})
            name = fn.get("name", "")
            args_raw = fn.get("arguments", {})
            if isinstance(args_raw, str):
                try:
                    args = json.loads(args_raw)
                except Exception:
                    args = {"raw": args_raw}
            elif isinstance(args_raw, dict):
                args = args_raw
            else:
                args = {}
            tool_calls.append(ToolCall(name=name, arguments=args, call_id=rt.get("id", "")))

        prompt_tokens = body.get("prompt_eval_count", 0)
        completion_tokens = body.get("eval_count", 0)

        return ModelResponse(
            text=text,
            tool_calls=tool_calls,
            finish_reason=body.get("done_reason", "stop"),
            tokens_prompt=prompt_tokens,
            tokens_completion=completion_tokens,
            model=self.model,
        )


class OpenAICompatibleProvider(ModelProvider):
    """Generic provider for OpenAI-compatible endpoints (e.g. vLLM, llama.cpp, LocalAI)."""

    name = "openai_compatible"

    def __init__(
        self,
        base_url: str = "http://localhost:8000/v1",
        api_key: str | None = None,
        model: str = "default",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(
                f"{self.base_url}/models",
                headers=self._headers(),
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return bool(resp.status == 200)
        except Exception:
            return False

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PLEx-Agent/2.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def generate(
        self,
        messages: list[ModelMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> ModelResponse:
        url = f"{self.base_url}/chat/completions"
        msgs: list[dict[str, Any]] = []
        for m in messages:
            d: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.tool_calls:
                d["tool_calls"] = [
                    {
                        "id": tc.call_id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in m.tool_calls
                ]
            msgs.append(d)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": msgs,
        }
        if tools:
            payload["tools"] = tools

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenAI compatible endpoint error: {exc}") from exc

        choices = body.get("choices", [])
        if not choices:
            return ModelResponse(text="", model=self.model)

        first = choices[0]
        msg = first.get("message", {})
        raw_tools = msg.get("tool_calls", [])
        tool_calls: list[ToolCall] = []

        for rt in raw_tools:
            fn = rt.get("function", {})
            name = fn.get("name", "")
            args_str = fn.get("arguments", "{}")
            try:
                args = json.loads(args_str) if isinstance(args_str, str) else args_str
            except Exception:
                args = {"raw": args_str}
            tool_calls.append(ToolCall(name=name, arguments=args, call_id=rt.get("id", "")))

        usage = body.get("usage", {})
        return ModelResponse(
            text=msg.get("content", "") or "",
            tool_calls=tool_calls,
            finish_reason=first.get("finish_reason", "stop"),
            tokens_prompt=usage.get("prompt_tokens", 0),
            tokens_completion=usage.get("completion_tokens", 0),
            model=body.get("model", self.model),
        )


def get_model_provider(
    provider_name: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
) -> ModelProvider:
    """Resolve and instantiate the requested model provider."""
    name = (provider_name or os.environ.get("PLEX_MODEL_PROVIDER") or "mock").lower()

    if name == "mock":
        return LocalMockModelProvider()
    elif name == "ollama":
        url = base_url or os.environ.get("OLLAMA_HOST") or "http://localhost:11434"
        m = model or "qwen2.5-coder:7b"
        return OllamaModelProvider(base_url=url, model=m)
    elif name in ("openai", "openai_compatible", "local"):
        url = base_url or os.environ.get("OPENAI_BASE_URL") or "http://localhost:8000/v1"
        m = model or "default"
        return OpenAICompatibleProvider(base_url=url, model=m)
    else:
        raise ValueError(
            f"Unknown model provider '{provider_name}'. Supported: mock, ollama, openai_compatible"
        )
