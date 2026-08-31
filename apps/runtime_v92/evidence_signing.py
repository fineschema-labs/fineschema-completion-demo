"""HMAC-SHA256 integrity boundary for append-only v9.2 evidence events.

HMAC authenticates events to a configured deployment key; it is not a human
signature and does not create Completion Authority.  The key is accepted only
as bytes or through an environment reference and never appears in a receipt.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Mapping, Optional, Sequence, Tuple

from fineschema.canonical import canonical_json, content_id


EVIDENCE_HMAC_KEY_ENV = "EVIDENCE_HMAC_KEY"
EVIDENCE_SIGNING_REQUIRED = "EVIDENCE_SIGNING_REQUIRED"
SIGNED_EVENT_SCHEMA = "FineSchemaSignedEvidenceEvent/1.0"
SIGNED_EVENT_GENESIS = content_id(
    {"schema_version": SIGNED_EVENT_SCHEMA, "event": "GENESIS"}
)
_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


class EvidenceSigningError(RuntimeError):
    pass


class EvidenceSigningRequired(EvidenceSigningError):
    pass


class EvidenceSignatureInvalid(EvidenceSigningError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _decode_key(value: str) -> bytes:
    normalized = str(value or "").strip()
    if not normalized:
        raise EvidenceSigningRequired(EVIDENCE_SIGNING_REQUIRED)
    if len(normalized) > 512 or _KEY_PATTERN.fullmatch(normalized) is None:
        raise EvidenceSigningError("evidence signing key configuration is invalid")
    padding = "=" * ((4 - len(normalized) % 4) % 4)
    try:
        decoded = base64.b64decode(
            (normalized + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise EvidenceSigningError(
            "evidence signing key configuration is invalid"
        ) from exc
    if len(decoded) < 32 or len(set(decoded)) < 8:
        raise EvidenceSigningError("evidence signing key configuration is invalid")
    return decoded


def signing_key(environment: Mapping[str, str]) -> Optional[bytes]:
    raw = str(environment.get(EVIDENCE_HMAC_KEY_ENV, "") or "").strip()
    if not raw:
        return None
    return _decode_key(raw)


def _require_identifier(value: object, label: str) -> str:
    normalized = str(value or "").strip()
    if not normalized or len(normalized) > 512:
        raise ValueError("%s must be a non-empty bounded identifier" % label)
    return normalized


def _require_hash(value: object, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if (
        len(normalized) != 71
        or not normalized.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in normalized[7:])
    ):
        raise ValueError("%s must be a sha256 hash" % label)
    return normalized


@dataclass(frozen=True)
class SignedEvidenceEvent:
    event_id: str
    previous_event_hash: str
    payload_hash: str
    signed_at: str
    key_id: str
    signature: str
    event_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _require_identifier(self.event_id, "event_id"))
        object.__setattr__(
            self,
            "previous_event_hash",
            _require_hash(self.previous_event_hash, "previous_event_hash"),
        )
        object.__setattr__(self, "payload_hash", _require_hash(self.payload_hash, "payload_hash"))
        object.__setattr__(self, "signed_at", _require_identifier(self.signed_at, "signed_at"))
        object.__setattr__(self, "key_id", _require_identifier(self.key_id, "key_id"))
        signature = str(self.signature or "").strip()
        if len(signature) != 64 or any(c not in "0123456789abcdef" for c in signature):
            raise ValueError("signature must be a lowercase HMAC-SHA256 digest")
        object.__setattr__(self, "signature", signature)
        calculated = content_id(self.body())
        if self.event_hash and _require_hash(self.event_hash, "event_hash") != calculated:
            raise EvidenceSignatureInvalid("signed event hash mismatch")
        object.__setattr__(self, "event_hash", calculated)

    def signing_body(self) -> Dict[str, object]:
        return {
            "schema_version": SIGNED_EVENT_SCHEMA,
            "event_id": self.event_id,
            "previous_event_hash": self.previous_event_hash,
            "payload_hash": self.payload_hash,
            "signed_at": self.signed_at,
            "key_id": self.key_id,
        }

    def body(self) -> Dict[str, object]:
        value = self.signing_body()
        value["signature"] = self.signature
        return value

    def to_json(self) -> Dict[str, object]:
        value = self.body()
        value.update(
            {
                "event_hash": self.event_hash,
                "signature_algorithm": "HMAC-SHA256",
                "key_material_exposed": False,
                "completion_authority": False,
                "human_signature": False,
            }
        )
        return value


class EvidenceSigner:
    def __init__(self, key: bytes, *, key_id: str) -> None:
        if not isinstance(key, bytes) or len(key) < 32 or len(set(key)) < 8:
            raise EvidenceSigningError("evidence signing key configuration is invalid")
        self._key = key
        self.key_id = _require_identifier(key_id, "key_id")

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str],
        *,
        key_id: str,
    ) -> "EvidenceSigner":
        key = signing_key(environment)
        if key is None:
            raise EvidenceSigningRequired(EVIDENCE_SIGNING_REQUIRED)
        return cls(key, key_id=key_id)

    def _signature(self, signing_body: Mapping[str, object]) -> str:
        return hmac.new(
            self._key,
            canonical_json(dict(signing_body)),
            hashlib.sha256,
        ).hexdigest()

    def sign(
        self,
        payload: Mapping[str, object],
        *,
        event_id: str,
        previous_event_hash: str = SIGNED_EVENT_GENESIS,
        signed_at: str = "",
    ) -> SignedEvidenceEvent:
        payload_hash = content_id(dict(payload))
        unsigned = {
            "schema_version": SIGNED_EVENT_SCHEMA,
            "event_id": _require_identifier(event_id, "event_id"),
            "previous_event_hash": _require_hash(
                previous_event_hash, "previous_event_hash"
            ),
            "payload_hash": payload_hash,
            "signed_at": str(signed_at or _utc_now()),
            "key_id": self.key_id,
        }
        return SignedEvidenceEvent(signature=self._signature(unsigned), **{
            key: value for key, value in unsigned.items() if key != "schema_version"
        })

    def verify(
        self,
        event: SignedEvidenceEvent,
        payload: Mapping[str, object],
    ) -> None:
        if not isinstance(event, SignedEvidenceEvent):
            raise TypeError("event must be SignedEvidenceEvent")
        if event.key_id != self.key_id:
            raise EvidenceSignatureInvalid("evidence signing key id mismatch")
        if content_id(dict(payload)) != event.payload_hash:
            raise EvidenceSignatureInvalid("signed evidence payload hash mismatch")
        if not hmac.compare_digest(
            event.signature,
            self._signature(event.signing_body()),
        ):
            raise EvidenceSignatureInvalid("evidence HMAC signature mismatch")
        if content_id(event.body()) != event.event_hash:
            raise EvidenceSignatureInvalid("signed evidence event hash mismatch")

    def verify_chain(
        self,
        events_and_payloads: Sequence[Tuple[SignedEvidenceEvent, Mapping[str, object]]],
    ) -> str:
        previous = SIGNED_EVENT_GENESIS
        for event, payload in events_and_payloads:
            if event.previous_event_hash != previous:
                raise EvidenceSignatureInvalid("signed evidence chain mismatch")
            self.verify(event, payload)
            previous = event.event_hash
        return previous


__all__ = [
    "EVIDENCE_HMAC_KEY_ENV",
    "EVIDENCE_SIGNING_REQUIRED",
    "EvidenceSignatureInvalid",
    "EvidenceSigner",
    "EvidenceSigningError",
    "EvidenceSigningRequired",
    "SIGNED_EVENT_GENESIS",
    "SIGNED_EVENT_SCHEMA",
    "SignedEvidenceEvent",
    "signing_key",
]
