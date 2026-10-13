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
import json
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
MAX_ENCODED_JSON_BYTES = 1_048_576
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
            encoded_items = [encode_value(x, depth + 1, counter, seen_ids) for x in val]
            encoded_items.sort(key=lambda item: json.dumps(item, sort_keys=True))
            return {
                "t": "set",
                "v": encoded_items,
            }

        if t is frozenset:
            encoded_items = [encode_value(x, depth + 1, counter, seen_ids) for x in val]
            encoded_items.sort(key=lambda item: json.dumps(item, sort_keys=True))
            return {
                "t": "frozenset",
                "v": encoded_items,
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
            if type(val) is int and (val < MIN_INT64 or val > MAX_INT64):
                raise CodecError(
                    f"Integer payload for tag 'float' out of signed 64-bit range [{MIN_INT64}, {MAX_INT64}]: {val}"
                )
            fval = float(val)
            if not math.isfinite(fval):
                raise CodecError(
                    f"Non-finite numeric float payload must use canonical string ('nan', 'inf', '-inf'): {val!r}"
                )
            return fval
        raise CodecError(f"Invalid payload for tag 'float': {val!r}")

    if tag == "str":
        if type(val) is not str:
            raise CodecError(f"Invalid payload for tag 'str': {val!r}")
        try:
            val.encode("utf-8")
        except UnicodeEncodeError as uee:
            raise CodecError(f"String payload contains invalid UTF-8 / lone surrogate: {uee}") from uee
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


def _reject_json_constant(const_str: str) -> Any:
    raise CodecError(f"Non-standard JSON constant rejected: {const_str!r}")


def _parse_bounded_json_int(int_str: str) -> int:
    if len(int_str) > 32:
        raise CodecError("JSON integer literal exceeds maximum digit length")
    val = int(int_str)
    if val < MIN_INT64 or val > MAX_INT64:
        raise CodecError(f"JSON integer out of signed 64-bit range [{MIN_INT64}, {MAX_INT64}]: {val}")
    return val


def _parse_bounded_json_float(float_str: str) -> float:
    fval = float(float_str)
    if not math.isfinite(fval):
        raise CodecError(f"JSON float literal overflowed to non-finite value: {float_str!r}")
    return fval


def _reject_duplicate_json_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    res: Dict[str, Any] = {}
    for k, v in pairs:
        try:
            k.encode("utf-8")
        except UnicodeEncodeError as uee:
            raise CodecError(f"JSON key contains lone surrogate: {uee}") from uee
        if k in res:
            raise CodecError(f"Duplicate key in JSON object: {k!r}")
        res[k] = v
    return res


def _validate_envelope_json_tree(root: Any, max_depth: int = 128, max_nodes: int = 200_000) -> None:
    stack: List[Tuple[Any, int]] = [(root, 0)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise CodecError(f"JSON node count limit exceeded: {max_nodes}")
        if depth > max_depth:
            raise CodecError(f"JSON nesting depth limit exceeded: {max_depth}")
        t = type(node)
        if t is dict:
            for k, v in node.items():
                nodes += 1
                if nodes > max_nodes:
                    raise CodecError(f"JSON node count limit exceeded: {max_nodes}")
                stack.append((v, depth + 1))
        elif t is list:
            for elt in node:
                stack.append((elt, depth + 1))
        elif t is str:
            try:
                node.encode("utf-8")
            except UnicodeEncodeError as uee:
                raise CodecError(f"JSON string contains lone surrogate: {uee}") from uee


def decode_envelope_json(raw_json: str) -> Any:
    """
    Parses a raw JSON string into a tagged envelope and decodes it via `decode_value`.
    Enforces:
    - Byte size <= MAX_ENCODED_JSON_BYTES (1 MiB)
    - Strict RFC 8259 JSON (no NaN/Infinity constants, no lone surrogates)
    - No duplicate keys in any JSON object
    - Signed 64-bit integer bounds and finite float literals
    - All `decode_value` policy rules (depth <= 32, collection length <= 1000, item count <= 50000)
    """
    if type(raw_json) is not str:
        raise CodecError("Envelope JSON input must be a string")
    try:
        raw_bytes = raw_json.encode("utf-8")
    except UnicodeEncodeError as uee:
        raise CodecError(f"Envelope JSON is not valid UTF-8: {uee}") from uee

    if len(raw_bytes) > MAX_ENCODED_JSON_BYTES:
        raise CodecError(
            f"Envelope JSON exceeds maximum byte size ({len(raw_bytes)} > {MAX_ENCODED_JSON_BYTES})"
        )

    try:
        envelope = json.loads(
            raw_json,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
            parse_int=_parse_bounded_json_int,
            parse_float=_parse_bounded_json_float,
        )
        _validate_envelope_json_tree(envelope)
    except CodecError:
        raise
    except (ValueError, RecursionError) as e:
        raise CodecError(f"Failed to parse envelope JSON: {e}") from e

    return decode_value(envelope)



