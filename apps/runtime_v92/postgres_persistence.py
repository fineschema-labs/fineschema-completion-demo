"""Driver-injected PostgreSQL-compatible append-only persistence for v9.2.

No PostgreSQL driver is bundled or imported.  Production composition supplies
a PEP-249 connection factory after the external database/driver is configured.
The SQLite dialect exists only for deterministic contract tests and identifies
itself as test-only; it must never be reported as Production durability.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from fineschema.canonical import canonical_json, content_id

from .evidence_signing import (
    SIGNED_EVENT_GENESIS,
    EvidenceSigner,
    EvidenceSigningRequired,
    SignedEvidenceEvent,
)

from apps.runtime_v91.persistence import (
    AppendRequest,
    PERSISTENCE_BLOCKED_EXTERNAL_CREDENTIAL,
    PERSISTENCE_GENESIS,
    PersistenceAdapter,
    PersistenceBlockedExternalCredential,
    PersistenceConflict,
    PersistenceIntegrityError,
    PersistenceRecord,
    RecordType,
)


POSTGRES_MIGRATION_PATH = Path(__file__).with_name("migrations") / "001_append_only_postgres.sql"
POSTGRES_BACKEND_ID = "POSTGRES_APPEND_ONLY_DRIVER_INJECTED_V92"
_COLUMNS = (
    "seq",
    "event_hash",
    "prev_event_hash",
    "event_type",
    "record_type",
    "object_id",
    "document_hash",
    "document_json",
    "artifact_hash",
    "provider_identity_json",
    "policy_version",
    "trace_id",
    "actor",
    "occurred_at",
)
_SELECT_COLUMNS = ", ".join(_COLUMNS)
_STALE_TYPES = {
    RecordType.CHECK_RESULT,
    RecordType.EVIDENCE,
    RecordType.HUMAN_REVIEW,
    RecordType.COMPLETION_DECISION,
}
_SIGNED_TYPES = {
    RecordType.MODEL_ATTEMPT,
    RecordType.PROJECTION_RECEIPT,
    RecordType.CHECK_RESULT,
    RecordType.EVIDENCE,
    RecordType.HUMAN_REVIEW,
    RecordType.COMPLETION_DECISION,
    RecordType.ACTION,
    RecordType.INVALIDATION,
}
_SIGNATURE_OBJECT_ID = "v92-evidence-signature-chain"
_SIGNATURE_EVENT_TYPE = "EVIDENCE_SIGNATURE_RECORDED"


def postgres_migration_sql() -> str:
    return POSTGRES_MIGRATION_PATH.read_text(encoding="utf-8")


class PostgresDurablePersistence(PersistenceAdapter):
    """Append-only persistence over an injected transaction-capable DB-API driver."""

    def __init__(
        self,
        connection_factory: Optional[Callable[[], object]] = None,
        *,
        dialect: str = "postgres",
        initialize: bool = False,
        evidence_signer: Optional[EvidenceSigner] = None,
    ) -> None:
        if dialect not in ("postgres", "sqlite-contract-test"):
            raise ValueError("unsupported persistence dialect")
        if dialect == "sqlite-contract-test" and connection_factory is None:
            raise ValueError("sqlite contract test requires a connection factory")
        self._connection_factory = connection_factory
        self._dialect = dialect
        if evidence_signer is not None and not isinstance(evidence_signer, EvidenceSigner):
            raise TypeError("evidence_signer must be EvidenceSigner or None")
        self._evidence_signer = evidence_signer
        if initialize and connection_factory is not None:
            self.apply_migrations()

    @property
    def backend_id(self) -> str:
        if self._dialect == "sqlite-contract-test":
            return "SQLITE_DBAPI_CONTRACT_TEST_ONLY_V92"
        return POSTGRES_BACKEND_ID

    @property
    def is_durable(self) -> bool:
        return self._connection_factory is not None

    @property
    def status(self) -> str:
        if self._connection_factory is None:
            return PERSISTENCE_BLOCKED_EXTERNAL_CREDENTIAL
        return (
            "CONTRACT_TEST_ONLY_NOT_PRODUCTION"
            if self._dialect == "sqlite-contract-test"
            else "DURABLE_CONFIGURED_NOT_LIVE_VERIFIED"
        )

    @property
    def placeholder(self) -> str:
        return "?" if self._dialect == "sqlite-contract-test" else "%s"

    def _connect(self):
        if self._connection_factory is None:
            raise PersistenceBlockedExternalCredential(
                PERSISTENCE_BLOCKED_EXTERNAL_CREDENTIAL
            )
        return self._connection_factory()

    def apply_migrations(self) -> None:
        connection = self._connect()
        try:
            if self._dialect == "sqlite-contract-test":
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS fineschema_chain_head_v92 (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        seq INTEGER NOT NULL,
                        event_hash TEXT NOT NULL
                    );
                    INSERT OR IGNORE INTO fineschema_chain_head_v92
                        (singleton, seq, event_hash)
                    VALUES (1, -1, 'sha256:cdcb43a005c535d75c73b33decbda5b0b197fed4c5b0fd45a2d69b659a117709');
                    CREATE TABLE IF NOT EXISTS fineschema_events_v92 (
                        seq INTEGER PRIMARY KEY,
                        event_hash TEXT NOT NULL UNIQUE,
                        prev_event_hash TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        record_type TEXT NOT NULL,
                        object_id TEXT NOT NULL,
                        document_hash TEXT NOT NULL,
                        document_json TEXT NOT NULL,
                        artifact_hash TEXT NOT NULL,
                        provider_identity_json TEXT NOT NULL,
                        policy_version TEXT NOT NULL,
                        trace_id TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        occurred_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS fineschema_events_v92_object
                        ON fineschema_events_v92(record_type, object_id, seq);
                    CREATE TRIGGER IF NOT EXISTS fineschema_events_v92_no_update
                    BEFORE UPDATE ON fineschema_events_v92
                    BEGIN SELECT RAISE(ABORT, 'FineSchema evidence is append-only'); END;
                    CREATE TRIGGER IF NOT EXISTS fineschema_events_v92_no_delete
                    BEFORE DELETE ON fineschema_events_v92
                    BEGIN SELECT RAISE(ABORT, 'FineSchema evidence is append-only'); END;
                    """
                )
                connection.commit()
            else:
                cursor = connection.cursor()
                try:
                    cursor.execute(postgres_migration_sql())
                    connection.commit()
                finally:
                    cursor.close()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _record_from_row(row: Sequence[object]) -> PersistenceRecord:
        values = dict(zip(_COLUMNS, row))
        try:
            document = json.loads(str(values["document_json"]))
            provider = json.loads(str(values["provider_identity_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PersistenceIntegrityError("stored persistence row is not valid JSON") from exc
        return PersistenceRecord(
            seq=int(values["seq"]),
            event_hash=str(values["event_hash"]),
            prev_event_hash=str(values["prev_event_hash"]),
            event_type=str(values["event_type"]),
            record_type=RecordType(str(values["record_type"])),
            object_id=str(values["object_id"]),
            document=document,
            document_hash=str(values["document_hash"]),
            artifact_hash=str(values["artifact_hash"]),
            provider_identity=provider,
            policy_version=str(values["policy_version"]),
            trace_id=str(values["trace_id"]),
            actor=str(values["actor"]),
            occurred_at=str(values["occurred_at"]),
        )

    @staticmethod
    def _make_record(request: AppendRequest, seq: int, previous: str) -> PersistenceRecord:
        return PersistenceRecord(
            seq=seq,
            event_type=request.event_type,
            record_type=request.record_type,
            object_id=request.object_id,
            document=request.document,
            document_hash=content_id(request.document),
            artifact_hash=request.artifact_hash,
            provider_identity=request.provider_identity or {},
            policy_version=request.policy_version,
            trace_id=request.trace_id,
            actor=request.actor,
            occurred_at=request.occurred_at,
            prev_event_hash=previous,
        )

    @staticmethod
    def _signature_payload(record: PersistenceRecord) -> Dict[str, object]:
        return {
            "schema_version": "FineSchemaPersistenceSignatureBinding/1.0",
            "target_seq": record.seq,
            "target_event_hash": record.event_hash,
            "target_record_type": str(record.record_type),
            "target_object_id": record.object_id,
            "target_document_hash": record.document_hash,
            "target_artifact_hash": record.artifact_hash,
            "target_provider_identity_hash": content_id(record.provider_identity),
            "target_policy_version": record.policy_version,
            "target_trace_id": record.trace_id,
            "target_actor": record.actor,
            "target_occurred_at": record.occurred_at,
        }

    def append(self, request: AppendRequest) -> PersistenceRecord:
        return self.append_many((request,))[0]

    def append_many(self, requests: Sequence[AppendRequest]) -> Tuple[PersistenceRecord, ...]:
        return self._append_many(tuple(requests))

    def append_many_if_latest(
        self,
        requests: Sequence[AppendRequest],
        *,
        guard_record_type: RecordType,
        guard_object_id: str,
        expected_event_hash: Optional[str],
    ) -> Tuple[PersistenceRecord, ...]:
        return self._append_many(
            tuple(requests),
            guard=(RecordType(guard_record_type), str(guard_object_id), expected_event_hash),
        )

    def _append_many(
        self,
        requests: Tuple[AppendRequest, ...],
        *,
        guard: Optional[Tuple[RecordType, str, Optional[str]]] = None,
    ) -> Tuple[PersistenceRecord, ...]:
        if not requests:
            return ()
        if any(not isinstance(request, AppendRequest) for request in requests):
            raise TypeError("append_many requires AppendRequest objects")
        connection = self._connect()
        cursor = connection.cursor()
        records: List[PersistenceRecord] = []
        p = self.placeholder
        try:
            cursor.execute(
                "BEGIN IMMEDIATE" if self._dialect == "sqlite-contract-test" else "BEGIN"
            )
            lock_suffix = "" if self._dialect == "sqlite-contract-test" else " FOR UPDATE"
            cursor.execute(
                "SELECT seq, event_hash FROM fineschema_chain_head_v92 "
                "WHERE singleton = %s%s" % (p, lock_suffix),
                (1 if self._dialect == "sqlite-contract-test" else True,),
            )
            head = cursor.fetchone()
            if head is None:
                raise PersistenceIntegrityError("persistence chain head is missing")
            if guard is not None:
                record_type, object_id, expected = guard
                cursor.execute(
                    "SELECT event_hash FROM fineschema_events_v92 "
                    "WHERE record_type = %s AND object_id = %s "
                    "ORDER BY seq DESC LIMIT 1" % (p, p),
                    (str(record_type), object_id),
                )
                row = cursor.fetchone()
                actual = str(row[0]) if row is not None else None
                if actual != expected:
                    raise PersistenceConflict(
                        "compare-and-append conflict for %s/%s" % (record_type, object_id)
                    )
            seq = int(head[0]) + 1
            previous = str(head[1])
            signed_head = SIGNED_EVENT_GENESIS
            if self._evidence_signer is not None:
                cursor.execute(
                    "SELECT document_json FROM fineschema_events_v92 "
                    "WHERE event_type = %s AND object_id = %s "
                    "ORDER BY seq DESC LIMIT 1" % (p, p),
                    (_SIGNATURE_EVENT_TYPE, _SIGNATURE_OBJECT_ID),
                )
                signed_row = cursor.fetchone()
                if signed_row is not None:
                    try:
                        signed_document = json.loads(str(signed_row[0]))
                        signed_head = str(
                            signed_document["signed_event"]["event_hash"]
                        )
                    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                        raise PersistenceIntegrityError(
                            "stored evidence signature head is invalid"
                        ) from exc
            placeholders = ", ".join([p] * len(_COLUMNS))
            for request in requests:
                record = self._make_record(request, seq, previous)
                cursor.execute(
                    "INSERT INTO fineschema_events_v92 (%s) VALUES (%s)"
                    % (_SELECT_COLUMNS, placeholders),
                    (
                        record.seq,
                        record.event_hash,
                        record.prev_event_hash,
                        record.event_type,
                        str(record.record_type),
                        record.object_id,
                        record.document_hash,
                        canonical_json(record.document).decode("utf-8"),
                        record.artifact_hash,
                        canonical_json(record.provider_identity).decode("utf-8"),
                        record.policy_version,
                        record.trace_id,
                        record.actor,
                        record.occurred_at,
                    ),
                )
                records.append(record)
                seq += 1
                previous = record.event_hash
                if (
                    self._evidence_signer is not None
                    and record.record_type in _SIGNED_TYPES
                ):
                    signature_payload = self._signature_payload(record)
                    signed_event = self._evidence_signer.sign(
                        signature_payload,
                        event_id=record.event_hash + ":signature",
                        previous_event_hash=signed_head,
                        signed_at=record.occurred_at,
                    )
                    signature_request = AppendRequest(
                        record_type=RecordType.POLICY_VERSION,
                        object_id=_SIGNATURE_OBJECT_ID,
                        document={
                            "signature_payload": signature_payload,
                            "signed_event": signed_event.to_json(),
                            "signature_algorithm": "HMAC-SHA256",
                            "key_material_exposed": False,
                            "human_signature": False,
                            "completion_authority": False,
                        },
                        event_type=_SIGNATURE_EVENT_TYPE,
                        artifact_hash=signed_event.payload_hash,
                        policy_version=request.policy_version,
                        trace_id=request.trace_id,
                        actor="FINESCHEMA_EVIDENCE_SIGNER",
                        occurred_at=request.occurred_at,
                    )
                    signature_record = self._make_record(
                        signature_request, seq, previous
                    )
                    cursor.execute(
                        "INSERT INTO fineschema_events_v92 (%s) VALUES (%s)"
                        % (_SELECT_COLUMNS, placeholders),
                        (
                            signature_record.seq,
                            signature_record.event_hash,
                            signature_record.prev_event_hash,
                            signature_record.event_type,
                            str(signature_record.record_type),
                            signature_record.object_id,
                            signature_record.document_hash,
                            canonical_json(signature_record.document).decode("utf-8"),
                            signature_record.artifact_hash,
                            canonical_json(signature_record.provider_identity).decode("utf-8"),
                            signature_record.policy_version,
                            signature_record.trace_id,
                            signature_record.actor,
                            signature_record.occurred_at,
                        ),
                    )
                    seq += 1
                    previous = signature_record.event_hash
                    signed_head = signed_event.event_hash
            cursor.execute(
                "UPDATE fineschema_chain_head_v92 SET seq = %s, event_hash = %s "
                "WHERE singleton = %s" % (p, p, p),
                (
                    seq - 1,
                    previous,
                    1 if self._dialect == "sqlite-contract-test" else True,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
            connection.close()
        self.verify_integrity()
        return tuple(records)

    def events(
        self,
        *,
        record_type: Optional[RecordType] = None,
        object_id: str = "",
        event_type: str = "",
    ) -> Tuple[PersistenceRecord, ...]:
        p = self.placeholder
        query = "SELECT %s FROM fineschema_events_v92" % _SELECT_COLUMNS
        clauses = []
        parameters: List[object] = []
        if record_type is not None:
            clauses.append("record_type = %s" % p)
            parameters.append(str(RecordType(record_type)))
        if object_id:
            clauses.append("object_id = %s" % p)
            parameters.append(str(object_id))
        if event_type:
            clauses.append("event_type = %s" % p)
            parameters.append(str(event_type))
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY seq ASC"
        connection = self._connect()
        cursor = connection.cursor()
        try:
            cursor.execute(query, tuple(parameters))
            rows = cursor.fetchall()
        finally:
            cursor.close()
            connection.close()
        return tuple(self._record_from_row(row) for row in rows)

    def verify_integrity(self) -> str:
        previous = PERSISTENCE_GENESIS
        for expected, record in enumerate(self.events()):
            if record.seq != expected:
                raise PersistenceIntegrityError("sequence break at %d" % expected)
            if record.prev_event_hash != previous:
                raise PersistenceIntegrityError("hash-chain break at seq %d" % record.seq)
            previous = record.event_hash
        return previous

    def verify_signed_evidence(self) -> str:
        if self._evidence_signer is None:
            raise EvidenceSigningRequired("EVIDENCE_SIGNING_REQUIRED")
        signed_pairs = []
        pending: Optional[PersistenceRecord] = None
        for record in self.events():
            if record.record_type in _SIGNED_TYPES:
                if pending is not None:
                    raise PersistenceIntegrityError(
                        "signed evidence record is missing its signature event"
                    )
                pending = record
                continue
            if record.event_type != _SIGNATURE_EVENT_TYPE:
                continue
            if pending is None or record.object_id != _SIGNATURE_OBJECT_ID:
                raise PersistenceIntegrityError("orphan evidence signature event")
            document = record.document
            payload = document.get("signature_payload")
            raw_signed = document.get("signed_event")
            if not isinstance(payload, Mapping) or not isinstance(raw_signed, Mapping):
                raise PersistenceIntegrityError("evidence signature document is invalid")
            expected = self._signature_payload(pending)
            if canonical_json(payload) != canonical_json(expected):
                raise PersistenceIntegrityError("evidence signature target mismatch")
            event = SignedEvidenceEvent(
                event_id=str(raw_signed.get("event_id", "")),
                previous_event_hash=str(raw_signed.get("previous_event_hash", "")),
                payload_hash=str(raw_signed.get("payload_hash", "")),
                signed_at=str(raw_signed.get("signed_at", "")),
                key_id=str(raw_signed.get("key_id", "")),
                signature=str(raw_signed.get("signature", "")),
                event_hash=str(raw_signed.get("event_hash", "")),
            )
            signed_pairs.append((event, payload))
            pending = None
        if pending is not None:
            raise PersistenceIntegrityError(
                "signed evidence record is missing its signature event"
            )
        return self._evidence_signer.verify_chain(tuple(signed_pairs))

    @staticmethod
    def _stale_candidate(record: PersistenceRecord) -> bool:
        if record.record_type == RecordType.CHECK_RESULT:
            return str(record.document.get("status") or "") == "PASS"
        if record.record_type == RecordType.HUMAN_REVIEW:
            return str(record.document.get("decision") or "").upper() in (
                "APPROVE", "APPROVED", "PASS"
            )
        return record.record_type in (RecordType.EVIDENCE, RecordType.COMPLETION_DECISION)

    def invalidate_artifact(
        self,
        previous_artifact_hash: str,
        current_artifact_hash: str,
        *,
        actor: str = "FINESCHEMA_RUNTIME",
        occurred_at: str = "",
    ) -> Tuple[PersistenceRecord, ...]:
        previous = str(previous_artifact_hash or "").strip()
        current = str(current_artifact_hash or "").strip()
        if not previous or not current or previous == current:
            raise ValueError("artifact invalidation requires two different hashes")
        invalidated = {
            str(record.document.get("invalidated_event_hash") or "")
            for record in self.events(
                record_type=RecordType.INVALIDATION,
                event_type="ARTIFACT_STALE",
            )
            if record.document.get("current_artifact_hash") == current
        }
        requests = []
        for record in self.events():
            if (
                record.record_type not in _STALE_TYPES
                or record.artifact_hash != previous
                or record.event_hash in invalidated
                or not self._stale_candidate(record)
            ):
                continue
            document = {
                "invalidated_event_hash": record.event_hash,
                "invalidated_object_type": str(record.record_type),
                "invalidated_object_id": record.object_id,
                "previous_artifact_hash": previous,
                "current_artifact_hash": current,
                "effective_status": (
                    "NOT_RUN" if record.record_type == RecordType.CHECK_RESULT else "STALE"
                ),
                "reason": "ARTIFACT_HASH_CHANGED",
            }
            requests.append(
                AppendRequest(
                    record_type=RecordType.INVALIDATION,
                    object_id=content_id(document),
                    document=document,
                    event_type="ARTIFACT_STALE",
                    artifact_hash=current,
                    actor=actor,
                    occurred_at=occurred_at,
                )
            )
        return self.append_many(tuple(requests))


__all__ = [
    "POSTGRES_BACKEND_ID",
    "POSTGRES_MIGRATION_PATH",
    "PostgresDurablePersistence",
    "postgres_migration_sql",
]
