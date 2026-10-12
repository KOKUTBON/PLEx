"""Strict dataclass JSON decoding for report contracts, using only the stdlib."""

from __future__ import annotations

import math
import types
from dataclasses import MISSING, fields, is_dataclass
from typing import Any, Literal, TypeVar, Union, get_args, get_origin, get_type_hints

T = TypeVar("T")


def _decode(value: Any, expected: Any, path: str) -> Any:
    if expected is Any:
        # Even free-form metadata must be valid, finite JSON.
        if value is None or type(value) in (str, bool, int):
            return value
        if isinstance(value, float) and math.isfinite(value):
            return value
        if isinstance(value, list):
            return [_decode(item, Any, f"{path}[]") for item in value]
        if isinstance(value, dict) and all(isinstance(key, str) for key in value):
            return {key: _decode(item, Any, f"{path}.{key}") for key, item in value.items()}
        raise ValueError(f"{path}: expected finite JSON data")
    origin = get_origin(expected)
    args = get_args(expected)
    if origin in (Union, types.UnionType):
        for choice in args:
            try:
                return _decode(value, choice, path)
            except ValueError:
                pass
        raise ValueError(f"{path}: invalid value for {expected}")
    if origin is Literal:
        if any(type(value) is type(choice) and value == choice for choice in args):
            return value
        raise ValueError(f"{path}: expected one of {args}")
    if origin is list and isinstance(value, list):
        return [_decode(item, args[0], f"{path}[{i}]") for i, item in enumerate(value)]
    if origin is dict and isinstance(value, dict):
        return {
            _decode(key, args[0], path): _decode(item, args[1], f"{path}.{key}")
            for key, item in value.items()
        }
    if isinstance(expected, type) and is_dataclass(expected) and isinstance(value, dict):
        hints = get_type_hints(expected)
        declared = {item.name: item for item in fields(expected)}
        unknown = value.keys() - declared.keys()
        if unknown:
            raise ValueError(f"{path}: unknown fields {sorted(unknown)}")
        missing = [
            name
            for name, item in declared.items()
            if name not in value and item.default is MISSING and item.default_factory is MISSING
        ]
        if missing:
            raise ValueError(f"{path}: missing fields {missing}")
        return expected(
            **{name: _decode(item, hints[name], f"{path}.{name}") for name, item in value.items()}
        )
    if expected is float and type(value) in (int, float) and math.isfinite(value):
        return float(value)
    if expected in (str, int, bool, type(None)) and type(value) is expected:
        return value
    raise ValueError(f"{path}: expected {expected}")


def decode_record(record_type: type[T], raw: Any) -> T:
    return _decode(raw, record_type, record_type.__name__)  # type: ignore[no-any-return]
