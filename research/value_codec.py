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
MAX_COLLECTION_LENGTH = 1_000
MAX_ITEM_COUNT = 50_000
MIN_INT64 = -(1 << 63)       # -9223372036854775808
MAX_INT64 = (1 << 63) - 1    #  9223372036854775807


def get_codec_policy() -> Dict[str, Any]:
    """Returns the canonical codec policy limits and rules for conformance vectors."""
    return {
        "max_recursion_depth": MAX_RECURSION_DEPTH,
        "max_collection_length": MAX_COLLECTION_LENGTH,
        "max_item_count": MAX_ITEM_COUNT,
        "min_int64": MIN_INT64,
        "max_int64": MAX_INT64,
        "strict_envelope_keys": ["t", "v"],
        "reject_duplicate_dict_keys": True,
        "reject_duplicate_set_elements": True,
        "reject_bool_for_int_or_float": True,
    }


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
    Enforces exact builtin types, signed 64-bit integer bounds, recursion depth <= 32,
    and collection length <= MAX_COLLECTION_LENGTH. Rejects subclasses, custom objects,
    and unhandled types with EqualityHijackError.
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
        if val < MIN_INT64 or val > MAX_INT64:
            raise CodecError(
                f"Integer out of signed 64-bit range [{MIN_INT64}, {MAX_INT64}]: {val}"
            )
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

    # 2. Containers with cycle detection and collection length limits
    if seen_ids is None:
        seen_ids = set()

    val_id = id(val)
    if val_id in seen_ids:
        raise CodecError("Circular reference detected in structure")

    seen_ids.add(val_id)
    try:
        if t in (list, tuple, set, frozenset, dict):
            if len(val) > MAX_COLLECTION_LENGTH:
                raise CodecError(
                    f"Codec item limit exceeded: collection length {len(val)} > {MAX_COLLECTION_LENGTH}"
                )

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


def decode_value(
    envelope: Any,
    depth: int = 0,
    counter: Optional[_ItemCounter] = None,
) -> Any:
    """
    Decodes a tagged envelope dict into the target Python builtin object.
    Raises CodecError on malformed envelopes, extra keys, out-of-range i64 integers,
    recursion depth > 32, collection length > MAX_COLLECTION_LENGTH, duplicate dict/set keys,
    or unknown tags.
    """
    if counter is None:
        counter = _ItemCounter()
    counter.increment()

    if depth > MAX_RECURSION_DEPTH:
        raise CodecError(f"Codec recursion depth limit exceeded: {MAX_RECURSION_DEPTH}")

    if (
        type(envelope) is not dict
        or len(envelope) != 2
        or "t" not in envelope
        or "v" not in envelope
    ):
        raise CodecError("Malformed envelope: must be a dict containing strictly 't' and 'v' keys")

    tag = envelope["t"]
    val = envelope["v"]

    if tag == "int":
        if type(val) is not int or type(val) is bool:
            raise CodecError(f"Invalid payload for tag 'int': {val!r}")
        if val < MIN_INT64 or val > MAX_INT64:
            raise CodecError(
                f"Integer out of signed 64-bit range [{MIN_INT64}, {MAX_INT64}]: {val}"
            )
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
            return base64.b64decode(val.encode("ascii"), validate=True)
        except Exception as e:
            raise CodecError(f"Failed to decode base64 bytes: {e}") from e

    if tag == "list":
        if type(val) is not list:
            raise CodecError(f"Invalid payload for tag 'list': {val!r}")
        if len(val) > MAX_COLLECTION_LENGTH:
            raise CodecError(
                f"Codec item limit exceeded: list length {len(val)} > {MAX_COLLECTION_LENGTH}"
            )
        return [decode_value(x, depth + 1, counter) for x in val]

    if tag == "tuple":
        if type(val) is not list:
            raise CodecError(f"Invalid payload for tag 'tuple': {val!r}")
        if len(val) > MAX_COLLECTION_LENGTH:
            raise CodecError(
                f"Codec item limit exceeded: tuple length {len(val)} > {MAX_COLLECTION_LENGTH}"
            )
        return tuple(decode_value(x, depth + 1, counter) for x in val)

    if tag == "set":
        if type(val) is not list:
            raise CodecError(f"Invalid payload for tag 'set': {val!r}")
        if len(val) > MAX_COLLECTION_LENGTH:
            raise CodecError(
                f"Codec item limit exceeded: set length {len(val)} > {MAX_COLLECTION_LENGTH}"
            )
        try:
            res_set = set()
            for x in val:
                item = decode_value(x, depth + 1, counter)
                if item in res_set:
                    raise CodecError(f"Duplicate element in set envelope: {item!r}")
                res_set.add(item)
            return res_set
        except TypeError as te:
            raise CodecError(f"Unhashable element in set: {te}") from te

    if tag == "frozenset":
        if type(val) is not list:
            raise CodecError(f"Invalid payload for tag 'frozenset': {val!r}")
        if len(val) > MAX_COLLECTION_LENGTH:
            raise CodecError(
                f"Codec item limit exceeded: frozenset length {len(val)} > {MAX_COLLECTION_LENGTH}"
            )
        try:
            res_set = set()
            for x in val:
                item = decode_value(x, depth + 1, counter)
                if item in res_set:
                    raise CodecError(f"Duplicate element in frozenset envelope: {item!r}")
                res_set.add(item)
            return frozenset(res_set)
        except TypeError as te:
            raise CodecError(f"Unhashable element in frozenset: {te}") from te

    if tag == "dict":
        if type(val) is not list:
            raise CodecError(f"Invalid payload for tag 'dict': {val!r}")
        if len(val) > MAX_COLLECTION_LENGTH:
            raise CodecError(
                f"Codec item limit exceeded: dict length {len(val)} > {MAX_COLLECTION_LENGTH}"
            )
        res = {}
        for pair in val:
            if type(pair) is not list or len(pair) != 2:
                raise CodecError(f"Invalid dict entry pair: {pair!r}")
            k = decode_value(pair[0], depth + 1, counter)
            v = decode_value(pair[1], depth + 1, counter)
            try:
                if k in res:
                    raise CodecError(f"Duplicate key in dict envelope: {k!r}")
                res[k] = v
            except TypeError as te:
                raise CodecError(f"Unhashable key in dict: {te}") from te
        return res

    raise CodecError(f"Unknown codec tag: {tag!r}")

