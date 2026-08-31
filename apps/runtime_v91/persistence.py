"""Database-neutral durable persistence contract for runtime v9.1.

Only append operations are exposed.  A correction, invalidation, or new
version is another event; no interface method can update or delete history.
Concrete storage technology belongs outside FineSchema Core.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple

from fineschema.canonical import canonical_json, content_id


PERSISTENCE_REQUIRED = "PERSISTENCE_REQUIRED"
PERSISTENCE_BLOCKED_EXTERNAL_CREDENTIAL = (
    "PERSISTENCE_BLOCKED_EXTERNAL_CREDENTIAL"
)
PERSISTENCE_SCHEMA = "FineSchemaPersistenceEvent/1.0"
PERSISTENCE_GENESIS = content_id(
    {"schema_version": PERSISTENCE_SCHEMA, "event": "GENESIS"}
)


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class RecordType(_StringEnum):
    WORKSPACE = "WORKSPACE"
    PROJECT = "PROJECT"
    SESSION = "SESSION"
    MESSAGE = "MESSAGE"
    MODEL_ATTEMPT = "MODEL_ATTEMPT"
    PROJECTION_RECEIPT = "PROJECTION_RECEIPT"
    INTENT_IR = "INTENT_IR"
    SCOPE_CLOSURE = "SCOPE_CLOSURE"
    VERIFICATION_CONTRACT = "VERIFICATION_CONTRACT"
    RUN = "RUN"
    CHECK_RESULT = "CHECK_RESULT"
    EVIDENCE = "EVIDENCE"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    COMPLETION_DECISION = "COMPLETION_DECISION"
    TRACE_INDEX = "TRACE_INDEX"
    ACTION = "ACTION"
    PROVIDER_BUDGET = "PROVIDER_BUDGET"
    POLICY_VERSION = "POLICY_VERSION"
    INVALIDATION = "INVALIDATION"


class PersistenceError(RuntimeError):
    pass


class PersistenceRequired(PersistenceError):
    pass


class PersistenceBlockedExternalCredential(PersistenceRequired):
    pass


class PersistenceIntegrityError(PersistenceError):
    pass


class PersistenceConflict(PersistenceError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _required_identifier(value: object, label: str) -> str:
    normalized = str(value or "").strip()
    if not normalized or len(normalized) > 512:
        raise ValueError("%s must be a non-empty bounded identifier" % label)
    return normalized


def document_json(value: object, label: str = "document") -> Dict[str, object]:
    """Detach a mapping or ``to_json`` object using Core canonical JSON."""

    if isinstance(value, Mapping):
        raw = dict(value)
    else:
        serializer = getattr(value, "to_json", None)
        if not callable(serializer):
            raise TypeError("%s must be a mapping or a to_json object" % label)
        raw = serializer()
    import json

    detached = json.loads(canonical_json(raw).decode("utf-8"))
    if not isinstance(detached, dict):
        raise TypeError("%s must serialize to an object" % label)
    return detached


@dataclass(frozen=True)
class AppendRequest:
    record_type: RecordType
    object_id: str
    document: Mapping[str, object]
    event_type: str = "RECORDED"
    artifact_hash: str = ""
    provider_identity: Optional[Mapping[str, object]] = None
    policy_version: str = ""
    trace_id: str = ""
    actor: str = "FINESCHEMA_RUNTIME"
    occurred_at: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "record_type", RecordType(self.record_type))
        for name in ("object_id", "event_type", "actor"):
            object.__setattr__(
                self, name, _required_identifier(getattr(self, name), name)
            )
        object.__setattr__(self, "document", document_json(self.document))
        if self.provider_identity is not None:
            object.__setattr__(
                self,
                "provider_identity",
                document_json(self.provider_identity, "provider_identity"),
            )
        object.__setattr__(self, "occurred_at", str(self.occurred_at or _utc_now()))


@dataclass(frozen=True)
class PersistenceRecord:
    seq: int
    event_type: str
    record_type: RecordType
    object_id: str
    document: Mapping[str, object]
    document_hash: str
    artifact_hash: str
    provider_identity: Mapping[str, object]
    policy_version: str
    trace_id: str
    actor: str
    occurred_at: str
    prev_event_hash: str
    event_hash: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or self.seq < 0:
            raise ValueError("seq must be a non-negative integer")
        object.__setattr__(self, "record_type", RecordType(self.record_type))
        for name in ("event_type", "object_id", "actor", "prev_event_hash"):
            object.__setattr__(
                self, name, _required_identifier(getattr(self, name), name)
            )
        document = document_json(self.document)
        provider = document_json(self.provider_identity or {}, "provider_identity")
        object.__setattr__(self, "document", document)
        object.__setattr__(self, "provider_identity", provider)
        calculated_document_hash = content_id(document)
        if self.document_hash and self.document_hash != calculated_document_hash:
            raise PersistenceIntegrityError("document hash mismatch")
        object.__setattr__(self, "document_hash", calculated_document_hash)
        calculated_event_hash = content_id(self.body())
        if self.event_hash and self.event_hash != calculated_event_hash:
            raise PersistenceIntegrityError("event hash mismatch at seq %d" % self.seq)
        object.__setattr__(self, "event_hash", calculated_event_hash)

    def body(self) -> Dict[str, object]:
        return {
            "schema_version": PERSISTENCE_SCHEMA,
            "seq": self.seq,
            "event_type": self.event_type,
            "record_type": str(self.record_type),
            "object_id": self.object_id,
            "document": dict(self.document),
            "document_hash": self.document_hash,
            "artifact_hash": self.artifact_hash,
            "provider_identity": dict(self.provider_identity),
            "policy_version": self.policy_version,
            "trace_id": self.trace_id,
            "actor": self.actor,
            "occurred_at": self.occurred_at,
            "prev_event_hash": self.prev_event_hash,
        }

    def to_json(self) -> Dict[str, object]:
        value = self.body()
        value["event_hash"] = self.event_hash
        return value


class PersistenceAdapter(ABC):
    """Append-only persistence boundary; no concrete database dependency."""

    @property
    @abstractmethod
    def backend_id(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def is_durable(self) -> bool:
        raise NotImplementedError

    @property
    def status(self) -> str:
        return "DURABLE_CONFIGURED" if self.is_durable else PERSISTENCE_REQUIRED

    @abstractmethod
    def append(self, request: AppendRequest) -> PersistenceRecord:
        raise NotImplementedError

    def append_many(
        self, requests: Sequence[AppendRequest]
    ) -> Tuple[PersistenceRecord, ...]:
        return tuple(self.append(request) for request in requests)

    def append_many_if_latest(
        self,
        requests: Sequence[AppendRequest],
        *,
        guard_record_type: RecordType,
        guard_object_id: str,
        expected_event_hash: Optional[str],
    ) -> Tuple[PersistenceRecord, ...]:
        """Atomically compare one object head and append all requests.

        A durable backend that cannot provide this primitive must fail rather
        than emulate it with a racy read followed by append.
        """

        raise PersistenceError("backend lacks atomic compare-and-append")

    @abstractmethod
    def events(
        self,
        *,
        record_type: Optional[RecordType] = None,
        object_id: str = "",
        event_type: str = "",
    ) -> Tuple[PersistenceRecord, ...]:
        raise NotImplementedError

    @abstractmethod
    def verify_integrity(self) -> str:
        """Verify the complete chain and return its head hash."""

        raise NotImplementedError

    def latest(
        self, record_type: RecordType, object_id: str
    ) -> Optional[PersistenceRecord]:
        matches = self.events(record_type=record_type, object_id=object_id)
        return matches[-1] if matches else None

    def persist(
        self,
        record_type: RecordType,
        object_id: str,
        value: object,
        *,
        event_type: str = "RECORDED",
        artifact_hash: str = "",
        provider_identity: Optional[Mapping[str, object]] = None,
        policy_version: str = "",
        trace_id: str = "",
        actor: str = "FINESCHEMA_RUNTIME",
        occurred_at: str = "",
    ) -> PersistenceRecord:
        return self.append(
            AppendRequest(
                record_type=record_type,
                object_id=object_id,
                document=document_json(value),
                event_type=event_type,
                artifact_hash=str(artifact_hash or ""),
                provider_identity=provider_identity,
                policy_version=str(policy_version or ""),
                trace_id=str(trace_id or ""),
                actor=actor,
                occurred_at=str(occurred_at or ""),
            )
        )

    def persist_session(self, object_id: str, value: object, **kwargs) -> PersistenceRecord:
        return self.persist(RecordType.SESSION, object_id, value, **kwargs)

    def persist_message(self, object_id: str, value: object, **kwargs) -> PersistenceRecord:
        return self.persist(RecordType.MESSAGE, object_id, value, **kwargs)

    def persist_intent(self, object_id: str, value: object, **kwargs) -> PersistenceRecord:
        return self.persist(RecordType.INTENT_IR, object_id, value, **kwargs)

    def persist_scope(self, object_id: str, value: object, **kwargs) -> PersistenceRecord:
        return self.persist(RecordType.SCOPE_CLOSURE, object_id, value, **kwargs)

    def persist_contract(self, object_id: str, value: object, **kwargs) -> PersistenceRecord:
        return self.persist(RecordType.VERIFICATION_CONTRACT, object_id, value, **kwargs)

    def persist_run(self, object_id: str, value: object, **kwargs) -> PersistenceRecord:
        return self.persist(RecordType.RUN, object_id, value, **kwargs)

    def persist_check_result(self, object_id: str, value: object, **kwargs) -> PersistenceRecord:
        return self.persist(RecordType.CHECK_RESULT, object_id, value, **kwargs)

    def persist_evidence(self, object_id: str, value: object, **kwargs) -> PersistenceRecord:
        return self.persist(RecordType.EVIDENCE, object_id, value, **kwargs)

    def persist_completion_decision(
        self, object_id: str, value: object, **kwargs
    ) -> PersistenceRecord:
        return self.persist(RecordType.COMPLETION_DECISION, object_id, value, **kwargs)

    def persist_trace_index(self, object_id: str, value: object, **kwargs) -> PersistenceRecord:
        return self.persist(RecordType.TRACE_INDEX, object_id, value, **kwargs)

    @abstractmethod
    def invalidate_artifact(
        self,
        previous_artifact_hash: str,
        current_artifact_hash: str,
        *,
        actor: str = "FINESCHEMA_RUNTIME",
        occurred_at: str = "",
    ) -> Tuple[PersistenceRecord, ...]:
        raise NotImplementedError


def require_durable(adapter: Optional[PersistenceAdapter]) -> PersistenceAdapter:
    if adapter is None or not adapter.is_durable:
        status = adapter.status if adapter is not None else PERSISTENCE_REQUIRED
        if status == PERSISTENCE_BLOCKED_EXTERNAL_CREDENTIAL:
            raise PersistenceBlockedExternalCredential(status)
        raise PersistenceRequired(PERSISTENCE_REQUIRED)
    adapter.verify_integrity()
    return adapter


def record_types_present(records: Iterable[PersistenceRecord]) -> Tuple[str, ...]:
    return tuple(sorted(set(str(record.record_type) for record in records)))


__all__ = [
    "AppendRequest",
    "PERSISTENCE_BLOCKED_EXTERNAL_CREDENTIAL",
    "PERSISTENCE_GENESIS",
    "PERSISTENCE_REQUIRED",
    "PERSISTENCE_SCHEMA",
    "PersistenceAdapter",
    "PersistenceBlockedExternalCredential",
    "PersistenceConflict",
    "PersistenceError",
    "PersistenceIntegrityError",
    "PersistenceRecord",
    "PersistenceRequired",
    "RecordType",
    "document_json",
    "record_types_present",
    "require_durable",
]
