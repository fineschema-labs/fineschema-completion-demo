"""Canonical serialization and content addressing.

Every hash in FineSchema is computed over *canonical JSON*: UTF-8, sorted keys,
no insignificant whitespace, no NaN/Infinity. This is the only hashing path in
the system — I-05 (Deterministic Replay) and I-08 (Immutable Provenance) both
depend on two different processes producing byte-identical input to sha256.

Do not add a second serializer.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .errors import CanonicalizationError


def canonical_json(value: Any) -> bytes:
    """Serialize to canonical JSON bytes.

    Rejects float NaN/Infinity outright: they are not representable in JSON and
    silently become `NaN` tokens that no other implementation can reproduce.
    """
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:  # non-serializable / NaN
        raise CanonicalizationError(str(exc)) from exc
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_id(value: Any) -> str:
    """Content address of a structured value: `sha256:<hex>`."""
    return "sha256:" + sha256_hex(canonical_json(value))


def blob_id(data: bytes) -> str:
    """Content address of raw bytes: `sha256:<hex>`."""
    return "sha256:" + sha256_hex(data)


def digest_of(values: Any) -> str:
    """Order-independent digest of a collection of content ids.

    Used where a set of evidence/results must contribute to a decision hash
    without the iteration order of a dict leaking into the hash.
    """
    ids = sorted(str(v) for v in values)
    return content_id(ids)
