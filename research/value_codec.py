"""
Type-Preserving Tagged Value Codec for PAI Verify Loop (H5)
Provides two-way, tamper-resistant serialization between Driver and Candidate Worker.

Supported Builtin Types:
- Primitives: int, float (including nan, inf, -inf), str, bool, NoneType
- Collections: list, tuple, set, frozenset, dict (with arbitrary hashable primitive keys)
- Binary: bytes

Security Guarantees:
1. Strict exact-type enforcement: type(x) is T (rejects subclasses like class S(tuple)).
2. Tag-forgery defense: every value is wrapped in a {"t": tag, "v": payload} envelope.
   A dict returned by a candidate is always encoded with t="dict" and pair list payload;
   candidate dictionaries containing keys "t" or "v" cannot forge tuple/set/other tags.
3. Denial-of-service defense: limits recursion depth (<= 32) and maximum item count (<= 50,000).
4. Circular reference detection: tracks object IDs to fail-closed on self-referential structures.
"""

from __future__ import annotations

import base64
import math
from typing import Any, Dict, List, Optional, Set, Tuple


class CodecError(Exception):
    """Raised when value serialization or deserialization fails codec constraints."""
    pass


class EqualityHijackError(CodecError):
    """Raised when candidate returns a non-builtin, subclassed, or equality-hijacked type."""
    pass


MAX_RECURSION_DEPTH = 32
MAX_ITEM_COUNT = 50_000


class _ItemCounter:
    __slots__ = ("count", "limit")

    def __init__(self, limit: int = MAX_ITEM_COUNT):
        self.count = 0
        self.limit = limit

    def increment(self) -> None:
        self.count += 1
        if self.count > self.limit:
            raise CodecError(f"Codec item limit exceeded: {self.limit} items")


def encode_value(
    val: Any,
    depth: int = 0,
    counter: Optional[_ItemCounter] = None,
    seen_ids: Optional[Set[int]] = None,
) -> Dict[str, Any]:
    """
    Encodes a Python value into a tagged envelope dict: {'t': tag, 'v': payload}.
    Enforces exact builtin types. Rejects subclasses, custom objects, and unhandled types
    with EqualityHijackError.
    """
    if counter is None:
        counter = _ItemCounter()
    counter.increment()

    if depth > MAX_RECURSION_DEPTH:
        raise CodecError(f"Codec recursion depth limit exceeded: {MAX_RECURSION_DEPTH}")

    t = type(val)

    # 1. Primitives (Check bool before int because bool subclasses int)
    if t is bool:
        return {"t": "bool", "v": val}

    if t is int:
        return {"t": "int", "v": val}

    if t is float:
        if math.isnan(val):
            return {"t": "float", "v": "nan"}
        if math.isinf(val):
            return {"t": "float", "v": "inf" if val > 0 else "-inf"}
        return {"t": "float", "v": val}

    if t is str:
        return {"t": "str", "v": val}

    if val is None and t is type(None):
        return {"t": "none", "v": None}

    if t is bytes:
        return {"t": "bytes", "v": base64.b64encode(val).decode("ascii")}

    # 2. Containers with cycle detection
    if seen_ids is None:
        seen_ids = set()

    val_id = id(val)
    if val_id in seen_ids:
        raise CodecError("Circular reference detected in structure")

    seen_ids.add(val_id)
    try:
        if t is list:
            return {
                "t": "list",
                "v": [encode_value(x, depth + 1, counter, seen_ids) for x in val],
            }

        if t is tuple:
            return {
                "t": "tuple",
                "v": [encode_value(x, depth + 1, counter, seen_ids) for x in val],
            }

        if t is set:
            return {
                "t": "set",
                "v": [encode_value(x, depth + 1, counter, seen_ids) for x in val],
            }

        if t is frozenset:
            return {
                "t": "frozenset",
                "v": [encode_value(x, depth + 1, counter, seen_ids) for x in val],
            }

        if t is dict:
            pairs = []
            for k, v in val.items():
                enc_k = encode_value(k, depth + 1, counter, seen_ids)
                enc_v = encode_value(v, depth + 1, counter, seen_ids)
                pairs.append([enc_k, enc_v])
            return {"t": "dict", "v": pairs}

    finally:
        seen_ids.remove(val_id)

    # 3. Any other type is an unapproved, subclassed, or custom object
    raise EqualityHijackError(
        f"Candidate returned non-builtin or subclassed object of type '{t.__name__}'"
    )


def decode_value(envelope: Any, depth: int = 0) -> Any:
    """
    Decodes a tagged envelope dict into the target Python builtin object.
    Raises CodecError on malformed envelopes or unknown tags.
    """
    if depth > MAX_RECURSION_DEPTH:
        raise CodecError(f"Codec recursion depth limit exceeded: {MAX_RECURSION_DEPTH}")

    if not isinstance(envelope, dict) or "t" not in envelope or "v" not in envelope:
        raise CodecError("Malformed envelope: must be a dict containing 't' and 'v' keys")

    tag = envelope["t"]
    val = envelope["v"]

    if tag == "int":
        if type(val) is not int or type(val) is bool:
            raise CodecError(f"Invalid payload for tag 'int': {val!r}")
        return val

    if tag == "bool":
        if type(val) is not bool:
            raise CodecError(f"Invalid payload for tag 'bool': {val!r}")
        return val

    if tag == "float":
        if isinstance(val, str):
            if val == "nan":
                return float("nan")
            if val == "inf":
                return float("inf")
            if val == "-inf":
                return float("-inf")
            raise CodecError(f"Invalid float special string: {val}")
        if type(val) in (int, float) and type(val) is not bool:
            return float(val)
        raise CodecError(f"Invalid payload for tag 'float': {val!r}")

    if tag == "str":
        if type(val) is not str:
            raise CodecError(f"Invalid payload for tag 'str': {val!r}")
        return val

    if tag == "none":
        if val is not None:
            raise CodecError(f"Invalid payload for tag 'none': {val!r}")
        return None

    if tag == "bytes":
        if type(val) is not str:
            raise CodecError(f"Invalid payload for tag 'bytes': {val!r}")
        try:
            return base64.b64decode(val.encode("ascii"))
        except Exception as e:
            raise CodecError(f"Failed to decode base64 bytes: {e}") from e

    if tag == "list":
        if type(val) is not list:
            raise CodecError(f"Invalid payload for tag 'list': {val!r}")
        return [decode_value(x, depth + 1) for x in val]

    if tag == "tuple":
        if type(val) is not list:
            raise CodecError(f"Invalid payload for tag 'tuple': {val!r}")
        return tuple(decode_value(x, depth + 1) for x in val)

    if tag == "set":
        if type(val) is not list:
            raise CodecError(f"Invalid payload for tag 'set': {val!r}")
        try:
            return {decode_value(x, depth + 1) for x in val}
        except TypeError as te:
            raise CodecError(f"Unhashable element in set: {te}") from te

    if tag == "frozenset":
        if type(val) is not list:
            raise CodecError(f"Invalid payload for tag 'frozenset': {val!r}")
        try:
            return frozenset(decode_value(x, depth + 1) for x in val)
        except TypeError as te:
            raise CodecError(f"Unhashable element in frozenset: {te}") from te

    if tag == "dict":
        if type(val) is not list:
            raise CodecError(f"Invalid payload for tag 'dict': {val!r}")
        res = {}
        for pair in val:
            if type(pair) is not list or len(pair) != 2:
                raise CodecError(f"Invalid dict entry pair: {pair!r}")
            k = decode_value(pair[0], depth + 1)
            v = decode_value(pair[1], depth + 1)
            try:
                res[k] = v
            except TypeError as te:
                raise CodecError(f"Unhashable key in dict: {te}") from te
        return res

    raise CodecError(f"Unknown codec tag: {tag!r}")
