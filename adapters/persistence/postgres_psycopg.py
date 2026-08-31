"""Optional Psycopg deployment boundary for FineSchema v9.3.

The module intentionally has no top-level ``psycopg`` import.  A missing
optional driver is an observable readiness state, not an application import
failure.  Connection strings are retained only inside the callable factory
and are never included in its audit document.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional
from urllib.parse import urlsplit

from fineschema.canonical import canonical_json


POSTGRES_DRIVER_UNAVAILABLE = "POSTGRES_DRIVER_UNAVAILABLE"
DRIVER_NAME = "psycopg"
DRIVER_VERSION = "3.2.13"
DRIVER_REQUIREMENT = "psycopg[binary]==3.2.13"
DEPENDENCY_FILE = "requirements.txt"
DEPENDENCY_FILE_BYTES = (DRIVER_REQUIREMENT + "\n").encode("utf-8")
DEPENDENCY_POLICY = "OPTIONAL_DEPLOYMENT_ADAPTER_EXACT_PIN"


class PostgresDriverUnavailable(RuntimeError):
    pass


class PostgresConfigurationError(RuntimeError):
    pass


def driver_available() -> bool:
    """Return whether the optional deployment driver can be resolved."""

    try:
        return importlib.util.find_spec(DRIVER_NAME) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def dependency_declared() -> bool:
    """Return whether the deployment manifest contains only the exact pin."""

    path = Path(__file__).resolve().parents[2] / DEPENDENCY_FILE
    try:
        return path.is_file() and path.read_bytes() == DEPENDENCY_FILE_BYTES
    except OSError:
        return False


def dependency_manifest() -> dict:
    """Value-free exact dependency decision for audit/readiness output."""

    body = {
        "schema_version": "FineSchemaPostgresDependency/1.0",
        "driver_name": DRIVER_NAME,
        "driver_version": DRIVER_VERSION,
        "requirement": DRIVER_REQUIREMENT,
        "wheel_mode": "BINARY_WHEEL_PREFERRED_DEPLOYMENT_ADAPTER_ONLY",
        "python_baseline": "3.9",
        "runtime_python": "%d.%d" % sys.version_info[:2],
        "core_dependency_policy": "STDLIB_ONLY",
        "adapter_dependency_policy": DEPENDENCY_POLICY,
        "dependency_file": DEPENDENCY_FILE,
        "dependency_lock_hash": "sha256:" + hashlib.sha256(
            DEPENDENCY_FILE_BYTES
        ).hexdigest(),
        "declared_in_repository_dependency_file": dependency_declared(),
        "installed": driver_available(),
        "secret_values_exposed": False,
    }
    body["dependency_hash"] = "sha256:" + hashlib.sha256(
        canonical_json(body)
    ).hexdigest()
    return body


def _validate_database_url(value: str) -> str:
    normalized = str(value or "").strip()
    try:
        parsed = urlsplit(normalized)
    except ValueError as exc:
        raise PostgresConfigurationError("DATABASE_URL is invalid") from exc
    if parsed.scheme not in ("postgres", "postgresql"):
        raise PostgresConfigurationError("DATABASE_URL must use PostgreSQL")
    if not parsed.hostname or not parsed.path or parsed.path == "/":
        raise PostgresConfigurationError("DATABASE_URL is incomplete")
    if parsed.username is None:
        raise PostgresConfigurationError("DATABASE_URL has no user reference")
    return normalized


@dataclass(frozen=True)
class PostgresConnectionFactory:
    """Bounded, per-operation DB-API connection factory.

    The v9.2 persistence and budget adapters own transaction commit/rollback
    and always close the returned connection.  No connection is retained
    between requests by this object.
    """

    _database_url: str
    connect_timeout_seconds: int = 5
    statement_timeout_ms: int = 15_000
    application_name: str = "fineschema-v93"

    def __post_init__(self) -> None:
        object.__setattr__(self, "_database_url", _validate_database_url(self._database_url))
        if not 1 <= int(self.connect_timeout_seconds) <= 30:
            raise PostgresConfigurationError("connect timeout is out of bounds")
        if not 100 <= int(self.statement_timeout_ms) <= 120_000:
            raise PostgresConfigurationError("statement timeout is out of bounds")
        if not str(self.application_name or "").strip():
            raise PostgresConfigurationError("application name is required")

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str]
    ) -> "PostgresConnectionFactory":
        # The pooled URL is preferred for request-time serverless work.  The
        # unpooled URL is reserved for explicit migration commands.
        return cls(str(environment.get("DATABASE_URL", "") or ""))

    @classmethod
    def migration_from_environment(
        cls, environment: Mapping[str, str]
    ) -> "PostgresConnectionFactory":
        value = environment.get("DATABASE_URL_UNPOOLED") or environment.get(
            "DATABASE_URL", ""
        )
        return cls(str(value or ""), application_name="fineschema-v93-migrate")

    def __call__(self):
        if not driver_available():
            raise PostgresDriverUnavailable(POSTGRES_DRIVER_UNAVAILABLE)
        module = importlib.import_module(DRIVER_NAME)
        connection = None
        try:
            connection = module.connect(
                self._database_url,
                connect_timeout=int(self.connect_timeout_seconds),
                application_name=self.application_name,
                autocommit=False,
                sslmode="require",
            )
            # PgBouncer-backed serverless endpoints can reject or stall on the
            # PostgreSQL startup ``options`` parameter.  Apply the same bounded
            # timeout after connecting so pooled and direct endpoints share one
            # fail-closed policy without weakening the limit.
            cursor = connection.cursor()
            try:
                cursor.execute(
                    "SELECT set_config('statement_timeout', %s, false)",
                    (str(int(self.statement_timeout_ms)),),
                )
            finally:
                cursor.close()
        except Exception as exc:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            # Never include the driver exception: it may echo a DSN.
            raise PostgresConfigurationError("PostgreSQL connection failed") from None
        return connection

    def audit_json(self) -> dict:
        return {
            "schema_version": "FineSchemaPostgresConnectionPolicy/1.0",
            "driver": DRIVER_NAME,
            "driver_version": DRIVER_VERSION,
            "database_configured": True,
            "pooled_request_url_preferred": True,
            "connect_timeout_seconds": int(self.connect_timeout_seconds),
            "statement_timeout_ms": int(self.statement_timeout_ms),
            "transaction_owner": "CALLING_ADAPTER",
            "tls_mode": "REQUIRED",
            "connection_lifetime": "ONE_BOUNDED_OPERATION",
            "connection_value_exposed": False,
        }


__all__ = [
    "DEPENDENCY_POLICY",
    "DEPENDENCY_FILE",
    "DRIVER_NAME",
    "DRIVER_REQUIREMENT",
    "DRIVER_VERSION",
    "POSTGRES_DRIVER_UNAVAILABLE",
    "PostgresConfigurationError",
    "PostgresConnectionFactory",
    "PostgresDriverUnavailable",
    "dependency_manifest",
    "dependency_declared",
    "driver_available",
]
