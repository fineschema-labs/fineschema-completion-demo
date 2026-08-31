"""Public webhook-only Vercel ingress for the FineSchema GitHub App.

The function deliberately exposes no product UI, arbitrary proxy, database
view, or debug route.  Signature verification consumes the exact raw body and
precedes persistence and JSON parsing.
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit


_ROOT = Path(__file__).resolve().parents[1]
for _source_root in (_ROOT, _ROOT / "core", _ROOT / "adapters"):
    if str(_source_root) not in sys.path:
        sys.path.insert(0, str(_source_root))

from adapters.github_app.checks import canonical_hash
from adapters.github_app.delivery import DeliveryInProgress, DeliveryLedgerError
from adapters.github_app.parsing import parse_webhook_json
from adapters.github_app.persistence_delivery import PersistenceDeliveryLedger
from adapters.github_app.security import (
    MAX_WEBHOOK_BODY_BYTES,
    WebhookSecurityError,
    WebhookVerifier,
)
from adapters.persistence.postgres_psycopg import (
    PostgresConfigurationError,
    PostgresConnectionFactory,
)
from apps.runtime_v92.postgres_persistence import PostgresDurablePersistence


_HEALTH = "/health"
_WEBHOOK = "/api/github/webhook"
_MANIFEST_START = "/api/github/app/manifest/start"
_MANIFEST_CALLBACK = "/api/github/app/manifest/callback"
_SETUP = "/api/github/app/setup"
_ALLOWED_GET = frozenset((_HEALTH, _MANIFEST_START, _MANIFEST_CALLBACK, _SETUP))
_ALLOWED_POST = frozenset((_WEBHOOK, _MANIFEST_CALLBACK))


def _runtime():
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if not isinstance(secret, str) or not 32 <= len(secret) <= 512:
        raise RuntimeError("GITHUB_INGRESS_CONFIGURATION_REQUIRED")
    factory = PostgresConnectionFactory.from_environment(os.environ)
    persistence = PostgresDurablePersistence(factory, dialect="postgres")
    return WebhookVerifier(secret.encode("utf-8")), PersistenceDeliveryLedger(
        persistence
    ), persistence


class handler(BaseHTTPRequestHandler):
    server_version = "FineSchemaGitHubIngress/1.0"

    def log_message(self, format, *args):
        # Request paths, headers, bodies, exceptions, and secrets are excluded.
        return None

    def _send(self, code: int, document: dict, extra_headers=None):
        body = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for key, value in tuple((extra_headers or {}).items()):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self):
        self._send(
            404,
            {
                "schema_version": "FineSchemaGitHubIngressError/1.0",
                "status": "ROUTE_NOT_AVAILABLE",
                "secret_values_exposed": False,
            },
        )

    def _health(self):
        try:
            verifier, ledger, persistence = _runtime()
            del verifier, ledger
            integrity_head = persistence.verify_integrity()
            configured = True
            backend = persistence.backend_id
            chain_verified = integrity_head.startswith("sha256:")
        except Exception:
            configured = False
            backend = "NOT_READY"
            chain_verified = False
        code = 200 if configured and chain_verified else 503
        self._send(
            code,
            {
                "schema_version": "FineSchemaGitHubIngressHealth/1.0",
                "status": "READY" if code == 200 else "NOT_READY",
                "ingress_mode": "PUBLIC_WEBHOOK_ONLY",
                "https_required": True,
                "raw_body_signature_before_parse": True,
                "body_limit_bytes": MAX_WEBHOOK_BODY_BYTES,
                "durable_delivery_backend": backend,
                "durable_chain_verified": chain_verified,
                "webhook_secret_configured": configured,
                "private_key_configured": bool(os.environ.get("GITHUB_APP_PRIVATE_KEY")),
                "app_id_configured": bool(os.environ.get("GITHUB_APP_ID")),
                "debug_routes_exposed": False,
                "product_routes_exposed": False,
                "secret_values_exposed": False,
                "production_fineschema_promoted": False,
            },
        )

    def _bounded_body(self) -> bytes:
        transfer_encoding = tuple(self.headers.get_all("Transfer-Encoding") or ())
        if transfer_encoding:
            raise WebhookSecurityError("transfer encoding is not accepted")
        lengths = tuple(self.headers.get_all("Content-Length") or ())
        if len(lengths) != 1:
            raise WebhookSecurityError("exactly one content length is required")
        try:
            length = int(lengths[0])
        except (TypeError, ValueError):
            raise WebhookSecurityError("content length is invalid")
        if length < 0 or length > MAX_WEBHOOK_BODY_BYTES:
            raise WebhookSecurityError("webhook body exceeds configured bound")
        body = self.rfile.read(length)
        if len(body) != length:
            raise WebhookSecurityError("webhook body is truncated")
        return body

    def _webhook(self):
        claim = None
        try:
            body = self._bounded_body()
            verifier, ledger, _persistence = _runtime()
            required = {
                "X-Hub-Signature-256": tuple(
                    self.headers.get_all("X-Hub-Signature-256") or ()
                ),
                "X-GitHub-Delivery": tuple(
                    self.headers.get_all("X-GitHub-Delivery") or ()
                ),
                "X-GitHub-Event": tuple(
                    self.headers.get_all("X-GitHub-Event") or ()
                ),
            }
            if any(len(values) != 1 for values in required.values()):
                raise WebhookSecurityError("duplicate or missing required header")
            verified = verifier.verify(
                {key: values[0] for key, values in required.items()}, body
            )
            claim = ledger.begin(
                verified.delivery_id, verified.body_hash, verified.event
            )
            if claim.status == "REPLAY":
                self._send(
                    200,
                    {
                        "schema_version": "FineSchemaGitHubWebhookReceipt/1.0",
                        "status": "IDEMPOTENT_REPLAY",
                        "delivery_id": claim.delivery_id,
                        "body_hash": claim.body_hash,
                        "result_hash": claim.prior_result_hash,
                        "publication_performed": False,
                        "secret_values_exposed": False,
                    },
                )
                return
            payload = parse_webhook_json(body)
            safe_scope = canonical_hash(
                {
                    "schema_version": "FineSchemaGitHubIngressScope/1.0",
                    "event": verified.event,
                    "installation_id": (
                        (payload.get("installation") or {}).get("id")
                        if isinstance(payload.get("installation"), dict)
                        else None
                    ),
                    "repository_id": (
                        (payload.get("repository") or {}).get("id")
                        if isinstance(payload.get("repository"), dict)
                        else None
                    ),
                }
            )
            claim = ledger.bind_scope(claim, safe_scope)
            status = (
                "PING_ACCEPTED"
                if verified.event == "ping"
                else "SIGNED_EVENT_DURABLY_ACCEPTED_WIRING_PENDING"
            )
            result_hash = canonical_hash(
                {
                    "schema_version": "FineSchemaGitHubIngressResult/1.0",
                    "body_hash": verified.body_hash,
                    "event": verified.event,
                    "scope_hash": safe_scope,
                    "status": status,
                }
            )
            ledger.complete(claim, result_hash)
            self._send(
                202,
                {
                    "schema_version": "FineSchemaGitHubWebhookReceipt/1.0",
                    "status": status,
                    "delivery_id": claim.delivery_id,
                    "body_hash": claim.body_hash,
                    "scope_hash": safe_scope,
                    "result_hash": result_hash,
                    "body_persisted": False,
                    "publication_performed": False,
                    "secret_values_exposed": False,
                },
            )
        except WebhookSecurityError:
            self._send(
                401,
                {
                    "schema_version": "FineSchemaGitHubWebhookReceipt/1.0",
                    "status": "WEBHOOK_AUTHENTICATION_FAILED",
                    "domain_write_performed": False,
                    "queue_enqueue_performed": False,
                    "provider_call_performed": False,
                    "secret_values_exposed": False,
                },
            )
        except DeliveryInProgress:
            self._send(
                409,
                {
                    "schema_version": "FineSchemaGitHubWebhookReceipt/1.0",
                    "status": "DELIVERY_IN_PROGRESS",
                    "secret_values_exposed": False,
                },
                {"Retry-After": "5"},
            )
        except (DeliveryLedgerError, PostgresConfigurationError, RuntimeError):
            if claim is not None:
                try:
                    ledger.fail(claim, "INGRESS_PROCESSING_FAILED")
                except Exception:
                    pass
            self._send(
                503,
                {
                    "schema_version": "FineSchemaGitHubWebhookReceipt/1.0",
                    "status": "INGRESS_FAIL_CLOSED",
                    "publication_performed": False,
                    "secret_values_exposed": False,
                },
                {"Retry-After": "30"},
            )
        except Exception:
            if claim is not None:
                try:
                    ledger.fail(claim, "UNEXPECTED_INGRESS_FAILURE")
                except Exception:
                    pass
            self._send(
                500,
                {
                    "schema_version": "FineSchemaGitHubWebhookReceipt/1.0",
                    "status": "INGRESS_INTERNAL_ERROR",
                    "publication_performed": False,
                    "secret_values_exposed": False,
                },
            )

    def do_GET(self):
        path = urlsplit(self.path).path
        if path not in _ALLOWED_GET:
            return self._not_found()
        if path == _HEALTH:
            return self._health()
        self._send(
            503,
            {
                "schema_version": "FineSchemaGitHubAppSetup/1.0",
                "status": "REGISTRATION_NOT_ACTIVE",
                "secret_values_exposed": False,
            },
        )

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in _ALLOWED_POST:
            return self._not_found()
        if path == _WEBHOOK:
            return self._webhook()
        self._send(
            503,
            {
                "schema_version": "FineSchemaGitHubAppSetup/1.0",
                "status": "MANIFEST_CALLBACK_NOT_ACTIVE",
                "secret_values_exposed": False,
            },
        )
