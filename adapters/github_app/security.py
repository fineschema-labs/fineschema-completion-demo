"""Bounded, constant-time GitHub webhook authentication."""
from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from collections.abc import Mapping as RuntimeMapping
from dataclasses import dataclass
from typing import Dict, Mapping


MAX_WEBHOOK_BODY_BYTES = 1024 * 1024
MAX_WEBHOOK_HEADERS = 64
MAX_HEADER_NAME_CHARS = 128
MAX_HEADER_VALUE_CHARS = 8192
_SIGNATURE_RE = re.compile(r"^sha256=([0-9a-fA-F]{64})$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")


class WebhookSecurityError(ValueError):
    """Webhook authentication, framing, or bound validation failed."""


def _normalized_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    if not isinstance(headers, RuntimeMapping):
        raise WebhookSecurityError("webhook headers must be a mapping")
    if len(headers) > MAX_WEBHOOK_HEADERS:
        raise WebhookSecurityError("webhook header count exceeds safe bound")
    normalized: Dict[str, str] = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise WebhookSecurityError("webhook header names and values must be text")
        if len(key) > MAX_HEADER_NAME_CHARS or not _HEADER_NAME_RE.fullmatch(key):
            raise WebhookSecurityError("webhook header name is invalid")
        if len(value) > MAX_HEADER_VALUE_CHARS:
            raise WebhookSecurityError("webhook header value exceeds safe bound")
        if any(
            (ord(character) < 0x20 and character != "\t")
            or 0x7F <= ord(character) <= 0x9F
            or ord(character) in (0x2028, 0x2029)
            for character in value
        ):
            raise WebhookSecurityError("webhook header value contains unsafe framing")
        lowered = key.lower()
        if lowered in normalized:
            raise WebhookSecurityError("duplicate webhook header")
        # HTTP optional whitespace is SP/HTAB. Python's general strip() also
        # removes CR/LF and Unicode separators, masking transport smuggling.
        normalized[lowered] = value.strip(" \t")
    return normalized


def _header(headers: Mapping[str, str], name: str, maximum: int) -> str:
    value = headers.get(name.lower())
    if not isinstance(value, str) or not value:
        raise WebhookSecurityError("missing %s header" % name)
    if len(value) > maximum:
        raise WebhookSecurityError("%s header exceeds safe bound" % name)
    return value


@dataclass(frozen=True)
class VerifiedWebhook:
    delivery_id: str
    event: str
    body_hash: str


class WebhookVerifier:
    """Verify one GitHub webhook without logging or retaining its secret/body.

    Replay safety is completed by passing the returned delivery id and body hash
    into ``DeliveryLedger.begin`` before any business operation.
    """

    def __init__(self, secret: bytes, max_body_bytes: int = MAX_WEBHOOK_BODY_BYTES):
        if not isinstance(secret, bytes) or not secret:
            raise WebhookSecurityError("webhook secret must be non-empty bytes")
        if not isinstance(max_body_bytes, int) or not 1 <= max_body_bytes <= 8 * 1024 * 1024:
            raise WebhookSecurityError("max_body_bytes is outside the safe bound")
        self._secret = secret
        self._max_body_bytes = max_body_bytes

    def verify(self, headers: Mapping[str, str], body: bytes) -> VerifiedWebhook:
        if not isinstance(body, bytes):
            raise WebhookSecurityError("webhook body must be bytes")
        if len(body) > self._max_body_bytes:
            raise WebhookSecurityError("webhook body exceeds configured bound")

        normalized_headers = _normalized_headers(headers)
        signature_header = _header(
            normalized_headers, "X-Hub-Signature-256", 71
        )
        match = _SIGNATURE_RE.fullmatch(signature_header)
        supplied = bytes.fromhex(match.group(1)) if match else bytes(32)
        expected = hmac.new(self._secret, body, hashlib.sha256).digest()
        signature_matches = hmac.compare_digest(expected, supplied)
        if match is None or not signature_matches:
            raise WebhookSecurityError("webhook signature is invalid")

        delivery_raw = _header(normalized_headers, "X-GitHub-Delivery", 64)
        try:
            delivery = str(uuid.UUID(delivery_raw))
        except (ValueError, AttributeError):
            raise WebhookSecurityError("delivery id must be a UUID")
        event = _header(normalized_headers, "X-GitHub-Event", 64)
        if not re.fullmatch(r"[a-z_]{1,64}", event):
            raise WebhookSecurityError("event name is invalid")
        return VerifiedWebhook(
            delivery_id=delivery,
            event=event,
            body_hash="sha256:" + hashlib.sha256(body).hexdigest(),
        )
