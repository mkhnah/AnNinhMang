"""
RFC 8785 JSON Canonicalization Scheme (JCS) Implementation for Backend.
Strictly conforms to RFC 8785:
- UTF-8 encoding
- Property ordering by UTF-16 code units (lexicographical)
- IEEE 754 number representation conforming to ECMAScript standard
- Rejection of duplicate keys, NaN, Infinity
"""
import hashlib
import json
import math
from typing import Any, Dict
import jcs


def _object_pairs_hook_reject_duplicates(pairs):
    res = {}
    for key, val in pairs:
        if key in res:
            raise ValueError(f"RFC 8785 rejection: Duplicate key detected in JSON object: '{key}'")
        res[key] = val
    return res


def _reject_illegal_constants(constant_name: str):
    raise ValueError(f"RFC 8785 rejection: Illegal constant in JSON: '{constant_name}' (NaN and Infinity are forbidden)")


def parse_strict_json(json_str: str) -> Any:
    """
    Parses a JSON string with strict RFC 8785 compliance:
    - Rejects duplicate keys
    - Rejects NaN, Infinity, -Infinity
    """
    if not isinstance(json_str, str):
        raise TypeError(f"Expected str, got {type(json_str).__name__}")
    
    result = json.loads(
        json_str,
        object_pairs_hook=_object_pairs_hook_reject_duplicates,
        parse_constant=_reject_illegal_constants
    )

    validate_json_types(result)
    return result


def validate_json_types(val: Any) -> None:
    """
    Recursively validates that the object structure does not contain NaN or Infinity.
    """
    if isinstance(val, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in val):
            raise ValueError("RFC 8785 forbids lone surrogates")
    elif isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            raise ValueError("RFC 8785 rejection: NaN or Infinity is not permitted in canonical JSON")
    elif isinstance(val, dict):
        for k, v in val.items():
            if not isinstance(k, str):
                raise TypeError(f"RFC 8785 rejection: Dictionary keys must be strings, got {type(k).__name__}")
            validate_json_types(k)
            validate_json_types(v)
    elif isinstance(val, (list, tuple)):
        for item in val:
            validate_json_types(item)

    elif val is not None and not isinstance(val, (bool, int)):
        raise TypeError("Unsupported JSON type")


def canonicalize(obj: Any) -> bytes:
    """
    Canonicalizes a Python dict/primitive into RFC 8785 canonical UTF-8 bytes.
    """
    validate_json_types(obj)
    return jcs.canonicalize(obj)


def canonicalize_jcs(obj: Any) -> bytes:
    """Alias for canonicalize."""
    return canonicalize(obj)


def compute_manifest_sha256(obj: Any) -> str:
    """
    Computes hex SHA-256 digest of RFC 8785 canonical bytes.
    """
    c_bytes = canonicalize(obj)
    return hashlib.sha256(c_bytes).hexdigest().lower()


def canonicalize_from_json(json_str: str) -> bytes:
    """
    Parses strict JSON and canonicalizes to RFC 8785 canonical UTF-8 bytes.
    """
    parsed = parse_strict_json(json_str)
    return canonicalize(parsed)
