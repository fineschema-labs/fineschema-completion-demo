"""Transactional webhook replay ledger and Check Run publication outbox."""
from __future__ import annotations

import re
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Optional

from .checks import canonical_hash


_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_RE = re.compile(r"^[a-z_]{1,64}$")
_EXTERNAL_ID_RE = re.compile(r"^fineschema:[0-9a-f]{64}$")


class DeliveryLedgerError(RuntimeError):
    """Delivery identity, lease, scope, or outbox state is inconsistent."""


class DeliveryInProgress(DeliveryLedgerError):
    """An authenticated copy of this event is covered by an active lease."""


class PublicationLockInProgress(DeliveryLedgerError):
    """Another delivery is evaluating the same head-scoped Check Run."""


@dataclass(frozen=True)
class DeliveryClaim:
    status: str
    delivery_id: str
    body_hash: str
    event_type: str
    generation: int
    prior_result_hash: Optional[str] = None
    scope_hash: str = ""


@dataclass(frozen=True)
class PublicationLock:
    external_id: str
    owner_token: str
    generation: int


class DeliveryLedger:
    """Deduplicate authenticated events and persist an idempotent outbox.

    The unique event/body key also suppresses an identical signed payload sent
    under a fresh GitHub delivery UUID.  Generation-bound leases prevent a
    stale worker from completing a recovered attempt.  Publication is prepared
    durably before the publisher's deterministic external-id upsert.
    """

    def __init__(
        self,
        connection_factory: Callable[[], sqlite3.Connection],
        initialize: bool = True,
        lease_seconds: int = 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(lease_seconds, int) or not 5 <= lease_seconds <= 3600:
            raise DeliveryLedgerError("lease_seconds must be between 5 and 3600")
        self._connection_factory = connection_factory
        self._lease_seconds = lease_seconds
        self._clock = clock
        if initialize:
            self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = self._connection_factory()
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS github_webhook_deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    body_hash TEXT NOT NULL,
                    scope_hash TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL CHECK(state IN ('IN_PROGRESS','COMPLETED','FAILED')),
                    generation INTEGER NOT NULL,
                    lease_expires_at REAL NOT NULL,
                    publication_state TEXT NOT NULL DEFAULT 'NONE'
                        CHECK(publication_state IN ('NONE','PENDING','PUBLISHED')),
                    external_id TEXT,
                    result_hash TEXT,
                    terminal_code TEXT NOT NULL DEFAULT '',
                    UNIQUE(event_type, body_hash)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS github_check_publications (
                    delivery_id TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    result_hash TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('PENDING','PUBLISHED')),
                    PRIMARY KEY(delivery_id, external_id),
                    FOREIGN KEY(delivery_id) REFERENCES github_webhook_deliveries(delivery_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS github_check_publication_locks (
                    external_id TEXT PRIMARY KEY,
                    owner_token TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    lease_expires_at REAL NOT NULL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

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

    def begin(
        self, delivery_id: str, body_hash: str, event_type: str
    ) -> DeliveryClaim:
        body_hash = self._digest(body_hash, "body_hash")
        event_type = self._event(event_type)
        now = float(self._clock())
        lease_expires = now + self._lease_seconds
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            identity = connection.execute(
                "SELECT * FROM github_webhook_deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
            if identity is not None and (
                identity["body_hash"] != body_hash
                or identity["event_type"] != event_type
            ):
                raise DeliveryLedgerError(
                    "delivery id was reused with a different event or body"
                )
            row = identity or connection.execute(
                "SELECT * FROM github_webhook_deliveries "
                "WHERE event_type = ? AND body_hash = ?",
                (event_type, body_hash),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO github_webhook_deliveries "
                    "(delivery_id, event_type, body_hash, state, generation, lease_expires_at) "
                    "VALUES (?, ?, ?, 'IN_PROGRESS', 1, ?)",
                    (delivery_id, event_type, body_hash, lease_expires),
                )
                connection.commit()
                return DeliveryClaim(
                    "NEW", delivery_id, body_hash, event_type, generation=1
                )
            canonical_id = row["delivery_id"]
            generation = int(row["generation"])
            if row["state"] == "COMPLETED":
                result_hash = self._digest(row["result_hash"], "result_hash")
                connection.commit()
                return DeliveryClaim(
                    "REPLAY",
                    canonical_id,
                    body_hash,
                    event_type,
                    generation,
                    result_hash,
                    row["scope_hash"],
                )
            if row["state"] == "IN_PROGRESS" and float(
                row["lease_expires_at"]
            ) > now:
                raise DeliveryInProgress("delivery is already in progress")
            if row["state"] not in ("IN_PROGRESS", "FAILED"):
                raise DeliveryLedgerError("delivery has an invalid state")
            generation += 1
            connection.execute(
                "UPDATE github_webhook_deliveries SET state = 'IN_PROGRESS', "
                "generation = ?, lease_expires_at = ?, terminal_code = '' "
                "WHERE delivery_id = ?",
                (generation, lease_expires, canonical_id),
            )
            connection.commit()
            return DeliveryClaim(
                "RETRY",
                canonical_id,
                body_hash,
                event_type,
                generation,
                scope_hash=row["scope_hash"],
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def bind_scope(self, claim: DeliveryClaim, scope_hash: str) -> DeliveryClaim:
        scope_hash = self._digest(scope_hash, "scope_hash")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT scope_hash FROM github_webhook_deliveries "
                "WHERE delivery_id = ? AND state = 'IN_PROGRESS' AND generation = ?",
                (claim.delivery_id, claim.generation),
            ).fetchone()
            if row is None:
                raise DeliveryLedgerError("delivery scope lost its active lease")
            if row["scope_hash"] and row["scope_hash"] != scope_hash:
                raise DeliveryLedgerError("delivery scope binding changed")
            connection.execute(
                "UPDATE github_webhook_deliveries SET scope_hash = ? "
                "WHERE delivery_id = ? AND generation = ?",
                (scope_hash, claim.delivery_id, claim.generation),
            )
            connection.commit()
            return DeliveryClaim(
                claim.status,
                claim.delivery_id,
                claim.body_hash,
                claim.event_type,
                claim.generation,
                claim.prior_result_hash,
                scope_hash,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def acquire_publication_lock(
        self, external_id: str, wait_seconds: float = 30.0
    ) -> PublicationLock:
        """Serialize current-read, evaluation, and upsert for one Check Run.

        This is a shared-database fencing lock, not a process-local mutex.  A
        later Issue delivery cannot publish and then be overwritten by an
        older, slower evaluation for the same head-scoped external id.
        """

        if not isinstance(external_id, str) or not _EXTERNAL_ID_RE.fullmatch(
            external_id
        ):
            raise DeliveryLedgerError("external_id is not deterministic FineSchema id")
        if not isinstance(wait_seconds, (int, float)) or isinstance(
            wait_seconds, bool
        ) or not 0 <= float(wait_seconds) <= 60:
            raise DeliveryLedgerError("publication lock wait is outside safe bound")
        owner_token = str(uuid.uuid4())
        deadline = time.monotonic() + float(wait_seconds)
        while True:
            now = float(self._clock())
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT owner_token, generation, lease_expires_at "
                    "FROM github_check_publication_locks WHERE external_id = ?",
                    (external_id,),
                ).fetchone()
                if row is None:
                    generation = 1
                    connection.execute(
                        "INSERT INTO github_check_publication_locks "
                        "(external_id, owner_token, generation, lease_expires_at) "
                        "VALUES (?, ?, ?, ?)",
                        (
                            external_id,
                            owner_token,
                            generation,
                            now + max(self._lease_seconds, 300),
                        ),
                    )
                    connection.commit()
                    return PublicationLock(external_id, owner_token, generation)
                if float(row["lease_expires_at"]) <= now:
                    generation = int(row["generation"]) + 1
                    connection.execute(
                        "UPDATE github_check_publication_locks SET owner_token = ?, "
                        "generation = ?, lease_expires_at = ? WHERE external_id = ?",
                        (
                            owner_token,
                            generation,
                            now + max(self._lease_seconds, 300),
                            external_id,
                        ),
                    )
                    connection.commit()
                    return PublicationLock(external_id, owner_token, generation)
                connection.rollback()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
            if time.monotonic() >= deadline:
                raise PublicationLockInProgress(
                    "head-scoped Check Run evaluation is already in progress"
                )
            time.sleep(0.01)

    def release_publication_lock(self, lock: PublicationLock) -> None:
        if not isinstance(lock, PublicationLock):
            raise DeliveryLedgerError("publication lock has invalid type")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "DELETE FROM github_check_publication_locks WHERE external_id = ? "
                "AND owner_token = ? AND generation = ?",
                (lock.external_id, lock.owner_token, lock.generation),
            )
            if cursor.rowcount != 1:
                raise DeliveryLedgerError("publication lock lost its generation")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def renew_publication_lock(self, lock: PublicationLock) -> None:
        """Fence the next publication step to the current lock generation."""

        if not isinstance(lock, PublicationLock):
            raise DeliveryLedgerError("publication lock has invalid type")
        now = float(self._clock())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE github_check_publication_locks SET lease_expires_at = ? "
                "WHERE external_id = ? AND owner_token = ? AND generation = ? "
                "AND lease_expires_at > ?",
                (
                    now + max(self._lease_seconds, 300),
                    lock.external_id,
                    lock.owner_token,
                    lock.generation,
                    now,
                ),
            )
            if cursor.rowcount != 1:
                raise DeliveryLedgerError("publication lock lost its active generation")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def prepare_publication(
        self,
        claim: DeliveryClaim,
        result_hash: str,
        external_id: str,
        publication_lock: PublicationLock,
    ) -> bool:
        result_hash = self._digest(result_hash, "result_hash")
        if not isinstance(publication_lock, PublicationLock):
            raise DeliveryLedgerError("publication lock has invalid type")
        if not isinstance(external_id, str) or not _EXTERNAL_ID_RE.fullmatch(
            external_id
        ):
            raise DeliveryLedgerError("external_id is not deterministic FineSchema id")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            lock_row = connection.execute(
                "SELECT 1 FROM github_check_publication_locks "
                "WHERE external_id = ? AND owner_token = ? AND generation = ? "
                "AND lease_expires_at > ?",
                (
                    publication_lock.external_id,
                    publication_lock.owner_token,
                    publication_lock.generation,
                    float(self._clock()),
                ),
            ).fetchone()
            if publication_lock.external_id != external_id or lock_row is None:
                raise DeliveryLedgerError(
                    "publication outbox lost its head-scoped fence"
                )
            row = connection.execute(
                "SELECT scope_hash "
                "FROM github_webhook_deliveries WHERE delivery_id = ? "
                "AND state = 'IN_PROGRESS' AND generation = ?",
                (claim.delivery_id, claim.generation),
            ).fetchone()
            if (
                row is None
                or not claim.scope_hash
                or row["scope_hash"] != claim.scope_hash
            ):
                raise DeliveryLedgerError("publication has no active scope-bound lease")
            existing = connection.execute(
                "SELECT result_hash, state FROM github_check_publications "
                "WHERE delivery_id = ? AND external_id = ?",
                (claim.delivery_id, external_id),
            ).fetchone()
            if existing is not None and existing["result_hash"] != result_hash:
                raise DeliveryLedgerError("prepared publication changed on retry")
            if existing is None:
                connection.execute(
                    "INSERT INTO github_check_publications "
                    "(delivery_id, external_id, result_hash, state) "
                    "VALUES (?, ?, ?, 'PENDING')",
                    (claim.delivery_id, external_id, result_hash),
                )
            connection.commit()
            return existing is None or existing["state"] == "PENDING"
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def mark_publication_published(
        self,
        claim: DeliveryClaim,
        result_hash: str,
        external_id: str,
        publication_lock: PublicationLock,
    ) -> None:
        result_hash = self._digest(result_hash, "result_hash")
        if not isinstance(publication_lock, PublicationLock):
            raise DeliveryLedgerError("publication lock has invalid type")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            lock_row = connection.execute(
                "SELECT 1 FROM github_check_publication_locks "
                "WHERE external_id = ? AND owner_token = ? AND generation = ? "
                "AND lease_expires_at > ?",
                (
                    publication_lock.external_id,
                    publication_lock.owner_token,
                    publication_lock.generation,
                    float(self._clock()),
                ),
            ).fetchone()
            if publication_lock.external_id != external_id or lock_row is None:
                raise DeliveryLedgerError(
                    "published outbox update lost its head-scoped fence"
                )
            active = connection.execute(
                "SELECT scope_hash FROM github_webhook_deliveries "
                "WHERE delivery_id = ? AND state = 'IN_PROGRESS' AND generation = ?",
                (claim.delivery_id, claim.generation),
            ).fetchone()
            if active is None or active["scope_hash"] != claim.scope_hash:
                raise DeliveryLedgerError("publication lost its scope-bound generation")
            cursor = connection.execute(
                "UPDATE github_check_publications SET state = 'PUBLISHED' "
                "WHERE delivery_id = ? AND external_id = ? AND result_hash = ? "
                "AND state IN ('PENDING','PUBLISHED')",
                (claim.delivery_id, external_id, result_hash),
            )
            if cursor.rowcount != 1:
                raise DeliveryLedgerError("publication outbox entry was not prepared")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete(
        self,
        claim: DeliveryClaim,
        result_hash: str,
    ) -> None:
        result_hash = self._digest(result_hash, "result_hash")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                "SELECT scope_hash FROM github_webhook_deliveries "
                "WHERE delivery_id = ? AND state = 'IN_PROGRESS' AND generation = ?",
                (claim.delivery_id, claim.generation),
            ).fetchone()
            if active is None:
                raise DeliveryLedgerError("delivery completion lost its active generation")
            if claim.scope_hash and active["scope_hash"] != claim.scope_hash:
                raise DeliveryLedgerError("delivery completion scope changed")
            pending = connection.execute(
                "SELECT COUNT(*) FROM github_check_publications "
                "WHERE delivery_id = ? AND state != 'PUBLISHED'",
                (claim.delivery_id,),
            ).fetchone()[0]
            if pending:
                raise DeliveryLedgerError("delivery has unpublished Check Run outbox entries")
            published_hashes = tuple(
                row["result_hash"]
                for row in connection.execute(
                    "SELECT result_hash FROM github_check_publications "
                    "WHERE delivery_id = ? ORDER BY result_hash",
                    (claim.delivery_id,),
                ).fetchall()
            )
            if published_hashes:
                expected_result_hash = canonical_hash(
                    {
                        "delivery_body_hash": claim.body_hash,
                        "event_type": claim.event_type,
                        "scope_hash": active["scope_hash"],
                        "check_result_hashes": list(published_hashes),
                    }
                )
                if result_hash != expected_result_hash:
                    raise DeliveryLedgerError(
                        "delivery result does not bind scope and publications"
                    )
            cursor = connection.execute(
                "UPDATE github_webhook_deliveries SET state = 'COMPLETED', "
                "result_hash = ?, publication_state = CASE "
                "WHEN EXISTS(SELECT 1 FROM github_check_publications p "
                "WHERE p.delivery_id = github_webhook_deliveries.delivery_id) "
                "THEN 'PUBLISHED' ELSE 'NONE' END, terminal_code = 'COMPLETED' "
                "WHERE delivery_id = ? AND state = 'IN_PROGRESS' "
                "AND generation = ?",
                (result_hash, claim.delivery_id, claim.generation),
            )
            if cursor.rowcount != 1:
                raise DeliveryLedgerError("delivery completion lost its active generation")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def fail(self, claim: DeliveryClaim, terminal_code: str) -> None:
        if not isinstance(terminal_code, str) or not re.fullmatch(
            r"[A-Z][A-Z0-9_]{0,79}", terminal_code
        ):
            terminal_code = "SYSTEM_ERROR"
        connection = self._connect()
        try:
            cursor = connection.execute(
                "UPDATE github_webhook_deliveries SET state = 'FAILED', "
                "terminal_code = ? WHERE delivery_id = ? "
                "AND state = 'IN_PROGRESS' AND generation = ?",
                (terminal_code, claim.delivery_id, claim.generation),
            )
            if cursor.rowcount != 1:
                raise DeliveryLedgerError("delivery failure lost its active generation")
            connection.commit()
        finally:
            connection.close()


__all__ = [
    "DeliveryClaim",
    "DeliveryInProgress",
    "DeliveryLedger",
    "DeliveryLedgerError",
    "PublicationLock",
    "PublicationLockInProgress",
]
