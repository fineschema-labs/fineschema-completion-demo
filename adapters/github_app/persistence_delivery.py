"""Shared append-only delivery ledger over FineSchema durable persistence.

This adapter reuses the v9.2 PostgreSQL compare-and-append primitive instead of
creating a second mutable database authority.  It stores hashes, UUIDs, bounded
event names, lease metadata, and publication receipts only; webhook bodies and
credentials are never persisted.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from apps.runtime_v91.persistence import (
    AppendRequest,
    PersistenceAdapter,
    PersistenceConflict,
    RecordType,
)

from .checks import canonical_hash
from .delivery import (
    DeliveryClaim,
    DeliveryInProgress,
    DeliveryLedgerError,
)


_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_RE = re.compile(r"^[a-z_]{1,64}$")
_TERMINAL_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,79}$")
_GLOBAL_OBJECT = "github-webhook-delivery-global-head-v1"
_POLICY_VERSION = "FineSchemaGitHubDurableDelivery/1.0"
_ACTOR = "FINESCHEMA_GITHUB_INGRESS"
_MAX_COMPARE_RETRIES = 8


class PersistenceDeliveryLedger:
    """Deduplicate signed webhooks on the shared append-only event chain.

    A single compare-and-append global head serializes the two identities that
    must be unique together: GitHub delivery UUID and ``event + body_hash``.
    The durable object for one canonical delivery then carries generation-bound
    state transitions without retaining its body.
    """

    def __init__(
        self,
        persistence: PersistenceAdapter,
        *,
        lease_seconds: int = 60,
        clock=time.time,
    ) -> None:
        if not isinstance(persistence, PersistenceAdapter):
            raise DeliveryLedgerError("persistence adapter is required")
        if not persistence.is_durable:
            raise DeliveryLedgerError("durable persistence is required")
        if not isinstance(lease_seconds, int) or not 5 <= lease_seconds <= 3600:
            raise DeliveryLedgerError("lease_seconds must be between 5 and 3600")
        self._persistence = persistence
        self._lease_seconds = lease_seconds
        self._clock = clock

    @staticmethod
    def _digest(value: str, field: str) -> str:
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise DeliveryLedgerError("%s must be canonical sha256" % field)
        return value

    @staticmethod
    def _event(value: str) -> str:
        if not isinstance(value, str) or not _EVENT_RE.fullmatch(value):
            raise DeliveryLedgerError("event_type is invalid")
        return value

    @staticmethod
    def _identity_hash(event_type: str, body_hash: str) -> str:
        return canonical_hash(
            {
                "schema_version": "FineSchemaGitHubDeliveryIdentity/1.0",
                "event_type": event_type,
                "body_hash": body_hash,
            }
        )

    @classmethod
    def _object_id(cls, event_type: str, body_hash: str) -> str:
        return "github-delivery-" + cls._identity_hash(
            event_type, body_hash
        ).split(":", 1)[1]

    def _request(self, object_id: str, event_type: str, document: dict) -> AppendRequest:
        return AppendRequest(
            record_type=RecordType.TRACE_INDEX,
            object_id=object_id,
            document=document,
            event_type=event_type,
            policy_version=_POLICY_VERSION,
            trace_id=object_id,
            actor=_ACTOR,
        )

    def _delivery_records(self):
        return tuple(
            record
            for record in self._persistence.events(record_type=RecordType.TRACE_INDEX)
            if record.policy_version == _POLICY_VERSION
            and record.event_type.startswith("GITHUB_DELIVERY_")
            and record.object_id != _GLOBAL_OBJECT
        )

    def _latest_by_object(self) -> dict:
        latest = {}
        for record in self._delivery_records():
            latest[record.object_id] = record
        return latest

    def begin(self, delivery_id: str, body_hash: str, event_type: str) -> DeliveryClaim:
        body_hash = self._digest(body_hash, "body_hash")
        event_type = self._event(event_type)
        if not isinstance(delivery_id, str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            delivery_id,
        ):
            raise DeliveryLedgerError("delivery_id is invalid")
        identity_hash = self._identity_hash(event_type, body_hash)
        object_id = self._object_id(event_type, body_hash)

        for _attempt in range(_MAX_COMPARE_RETRIES):
            global_head = self._persistence.latest(
                RecordType.TRACE_INDEX, _GLOBAL_OBJECT
            )
            latest = self._latest_by_object()
            same_body = latest.get(object_id)
            same_uuid = tuple(
                record
                for record in latest.values()
                if record.document.get("delivery_id") == delivery_id
            )
            if same_uuid and any(
                record.document.get("identity_hash") != identity_hash
                for record in same_uuid
            ):
                raise DeliveryLedgerError(
                    "delivery id was reused with a different event or body"
                )
            now = float(self._clock())
            if same_body is not None:
                document = dict(same_body.document)
                generation = int(document.get("generation", 0))
                state = document.get("state")
                if state == "COMPLETED":
                    result_hash = self._digest(
                        str(document.get("result_hash", "")), "result_hash"
                    )
                    return DeliveryClaim(
                        "REPLAY",
                        str(document["delivery_id"]),
                        body_hash,
                        event_type,
                        generation,
                        result_hash,
                        str(document.get("scope_hash", "")),
                    )
                if state == "IN_PROGRESS" and float(
                    document.get("lease_expires_at", 0.0)
                ) > now:
                    raise DeliveryInProgress("delivery is already in progress")
                if state not in ("IN_PROGRESS", "FAILED"):
                    raise DeliveryLedgerError("delivery has an invalid state")
                generation += 1
                canonical_id = str(document["delivery_id"])
                status = "RETRY"
                scope_hash = str(document.get("scope_hash", ""))
            else:
                generation = 1
                canonical_id = delivery_id
                status = "NEW"
                scope_hash = ""

            delivery_document = {
                "schema_version": _POLICY_VERSION,
                "delivery_id": canonical_id,
                "identity_hash": identity_hash,
                "event_type": event_type,
                "body_hash": body_hash,
                "scope_hash": scope_hash,
                "state": "IN_PROGRESS",
                "generation": generation,
                "lease_expires_at": now + self._lease_seconds,
                "result_hash": "",
                "terminal_code": "",
                "body_included": False,
                "secret_values_included": False,
            }
            global_document = {
                "schema_version": _POLICY_VERSION,
                "identity_hash": identity_hash,
                "delivery_object_id": object_id,
                "generation": generation,
                "body_included": False,
                "secret_values_included": False,
            }
            requests = (
                self._request(
                    _GLOBAL_OBJECT, "GITHUB_DELIVERY_GLOBAL_ADVANCED", global_document
                ),
                self._request(
                    object_id, "GITHUB_DELIVERY_CLAIMED", delivery_document
                ),
            )
            try:
                self._persistence.append_many_if_latest(
                    requests,
                    guard_record_type=RecordType.TRACE_INDEX,
                    guard_object_id=_GLOBAL_OBJECT,
                    expected_event_hash=(
                        global_head.event_hash if global_head is not None else None
                    ),
                )
                return DeliveryClaim(
                    status,
                    canonical_id,
                    body_hash,
                    event_type,
                    generation,
                    scope_hash=scope_hash,
                )
            except PersistenceConflict:
                continue
        raise DeliveryLedgerError("delivery claim compare-and-append did not converge")

    def _transition(
        self,
        claim: DeliveryClaim,
        *,
        event_type: str,
        state: str,
        scope_hash: Optional[str] = None,
        result_hash: str = "",
        terminal_code: str = "",
    ):
        object_id = self._object_id(claim.event_type, claim.body_hash)
        latest = self._persistence.latest(RecordType.TRACE_INDEX, object_id)
        if latest is None:
            raise DeliveryLedgerError("delivery state is missing")
        document = dict(latest.document)
        if (
            document.get("state") != "IN_PROGRESS"
            or int(document.get("generation", 0)) != claim.generation
            or document.get("delivery_id") != claim.delivery_id
        ):
            raise DeliveryLedgerError("delivery lost its active generation")
        if scope_hash is not None:
            scope_hash = self._digest(scope_hash, "scope_hash")
            previous_scope = str(document.get("scope_hash", ""))
            if previous_scope and previous_scope != scope_hash:
                raise DeliveryLedgerError("delivery scope binding changed")
            document["scope_hash"] = scope_hash
        if result_hash:
            document["result_hash"] = self._digest(result_hash, "result_hash")
        document["state"] = state
        document["terminal_code"] = terminal_code
        request = self._request(object_id, event_type, document)
        try:
            return self._persistence.append_many_if_latest(
                (request,),
                guard_record_type=RecordType.TRACE_INDEX,
                guard_object_id=object_id,
                expected_event_hash=latest.event_hash,
            )[0]
        except PersistenceConflict as exc:
            raise DeliveryLedgerError("delivery transition lost its generation") from exc

    def bind_scope(self, claim: DeliveryClaim, scope_hash: str) -> DeliveryClaim:
        self._transition(
            claim,
            event_type="GITHUB_DELIVERY_SCOPE_BOUND",
            state="IN_PROGRESS",
            scope_hash=scope_hash,
        )
        return DeliveryClaim(
            claim.status,
            claim.delivery_id,
            claim.body_hash,
            claim.event_type,
            claim.generation,
            claim.prior_result_hash,
            scope_hash,
        )

    def complete(self, claim: DeliveryClaim, result_hash: str) -> None:
        self._transition(
            claim,
            event_type="GITHUB_DELIVERY_COMPLETED",
            state="COMPLETED",
            result_hash=result_hash,
            terminal_code="COMPLETED",
        )

    def fail(self, claim: DeliveryClaim, terminal_code: str) -> None:
        code = (
            terminal_code
            if isinstance(terminal_code, str) and _TERMINAL_RE.fullmatch(terminal_code)
            else "SYSTEM_ERROR"
        )
        self._transition(
            claim,
            event_type="GITHUB_DELIVERY_FAILED",
            state="FAILED",
            terminal_code=code,
        )


__all__ = ["PersistenceDeliveryLedger"]
