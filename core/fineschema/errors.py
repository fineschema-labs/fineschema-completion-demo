"""Error taxonomy.

Invariant violations raise. They are never returned as a status the caller can
ignore, because every ignore-path in a verification system eventually becomes a
false completion.
"""
from __future__ import annotations


class FineSchemaError(Exception):
    """Base class."""


class CanonicalizationError(FineSchemaError):
    """A value could not be serialized deterministically."""


class InvariantViolation(FineSchemaError):
    """A PART II core invariant was violated by a caller.

    Carries the invariant id (e.g. "I-01") so tests and audit logs can assert on
    *which* invariant was defended, not just that something failed.
    """

    def __init__(self, invariant: str, message: str) -> None:
        super().__init__("[%s] %s" % (invariant, message))
        self.invariant = invariant
        self.message = message


class SchemaValidationError(FineSchemaError):
    """A payload did not conform to its JSON Schema."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__("%s: %s" % (path or "<root>", message))
        self.path = path
        self.message = message


class LedgerIntegrityError(FineSchemaError):
    """The append-only hash chain does not verify."""


class CoverageGap(FineSchemaError):
    """Mandatory artifacts or requirements have no check bound to them."""

    def __init__(self, gaps):
        super().__init__("COVERAGE_GAP: %d uncovered obligation(s)" % len(gaps))
        self.gaps = list(gaps)


class ClarificationRequired(FineSchemaError):
    """Intent compilation hit a blocking ambiguity."""

    def __init__(self, questions):
        super().__init__("REQUEST_MINIMAL_CLARIFICATION: %d question(s)" % len(questions))
        self.questions = list(questions)
