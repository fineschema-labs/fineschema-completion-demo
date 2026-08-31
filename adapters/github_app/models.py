"""Transport-neutral models for the GitHub Completion Gate adapter.

Nothing in this module talks to GitHub.  The models deliberately carry only
the minimum repository, installation, decision, and receipt metadata needed
to build a Check Run request.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Optional, Tuple


_REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_AUTHORITY_RECEIPT_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
CANONICAL_CHECK_NAME = "FineSchema Completion Gate"
CANONICAL_ACCEPTANCE_HEADING = "Acceptance Criteria"
_DECISION_STATES = frozenset(
    {
        "VERIFIED_COMPLETE",
        "BLOCKED_INCOMPLETE",
        "HUMAN_REVIEW_REQUIRED",
        "SYSTEM_ERROR",
        "UNKNOWN",
        "INCOMPLETE",
        "FAILED",
        "BLOCKED",
        "MACHINE_VERIFIED_ONLY",
    }
)


class GitHubAppContractError(ValueError):
    """An authenticated GitHub request violates the adapter contract."""


def _bounded_text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise GitHubAppContractError("%s must be text" % field)
    forbidden_bidi = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or 0xD800 <= ord(character) <= 0xDFFF
        or ord(character) in forbidden_bidi
        or ord(character) in (0x200E, 0x200F, 0x2028, 0x2029, 0xFEFF)
        for character in value
    ):
        raise GitHubAppContractError("%s contains control or bidi characters" % field)
    # Only HTTP/YAML-style ASCII OWS is normalized. General str.strip() would
    # erase Unicode separators or C1 controls before identity validation.
    normalized = value.strip(" \t")
    if not normalized:
        raise GitHubAppContractError("%s must not be empty" % field)
    if len(normalized) > maximum:
        raise GitHubAppContractError("%s exceeds %d characters" % (field, maximum))
    return normalized


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class Tenant:
    """One FineSchema tenant bound to one GitHub App installation."""

    tenant_id: str
    installation_id: int
    repositories: Tuple[str, ...]
    repository_ids: Tuple[int, ...]

    def __post_init__(self) -> None:
        tenant_id = _bounded_text(self.tenant_id, "tenant_id", 128)
        if not _IDENTIFIER_RE.fullmatch(tenant_id):
            raise GitHubAppContractError("tenant_id has invalid characters")
        if not isinstance(self.installation_id, int) or isinstance(
            self.installation_id, bool
        ) or self.installation_id <= 0:
            raise GitHubAppContractError("installation_id must be a positive integer")
        if not self.repositories:
            raise GitHubAppContractError("tenant must allow at least one repository")
        repository_ids = tuple(self.repository_ids)
        if len(repository_ids) != len(self.repositories) or any(
            not isinstance(repository_id, int)
            or isinstance(repository_id, bool)
            or repository_id <= 0
            for repository_id in repository_ids
        ):
            raise GitHubAppContractError(
                "tenant repository ids must positively and exactly bind repositories"
            )
        if len(set(repository_ids)) != len(repository_ids):
            raise GitHubAppContractError("tenant repository ids must be unique")
        normalized = []
        for repository in self.repositories:
            repository = _bounded_text(repository, "repository", 201)
            if not _REPOSITORY_RE.fullmatch(repository):
                raise GitHubAppContractError("invalid repository name")
            normalized.append(repository.lower())
        if len(set(normalized)) != len(normalized):
            raise GitHubAppContractError("tenant repositories must be unique")
        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "repositories", tuple(normalized))
        object.__setattr__(self, "repository_ids", repository_ids)

    def permits(self, repository: str, repository_id: int) -> bool:
        return (repository.lower(), repository_id) in tuple(
            zip(self.repositories, self.repository_ids)
        )


class TenantRegistry:
    """Immutable installation registry with fail-closed repository matching."""

    def __init__(self, tenants: Iterable[Tenant]) -> None:
        by_installation: Dict[int, Tenant] = {}
        repository_owners: Dict[int, str] = {}
        repository_names: Dict[str, str] = {}
        for tenant in tenants:
            if tenant.installation_id in by_installation:
                raise GitHubAppContractError("duplicate installation_id")
            for repository, repository_id in zip(
                tenant.repositories, tenant.repository_ids
            ):
                if repository_id in repository_owners:
                    raise GitHubAppContractError(
                        "repository id is assigned to multiple tenants"
                    )
                if repository in repository_names:
                    raise GitHubAppContractError(
                        "repository name is assigned to multiple tenants"
                    )
                repository_owners[repository_id] = tenant.tenant_id
                repository_names[repository] = tenant.tenant_id
            by_installation[tenant.installation_id] = tenant
        self._by_installation = by_installation

    def resolve(
        self, installation_id: int, repository_id: int, repository: str
    ) -> Tenant:
        tenant = self._by_installation.get(installation_id)
        if tenant is None:
            raise GitHubAppContractError("installation is not registered")
        if not tenant.permits(repository, repository_id):
            raise GitHubAppContractError("repository is not permitted for installation")
        return tenant


@dataclass(frozen=True)
class PullRequestContext:
    repository: str
    repository_id: int
    installation_id: int
    number: int
    head_sha: str
    base_ref: str
    base_sha: str
    action: str
    issue_number: int

    def __post_init__(self) -> None:
        repository = _bounded_text(self.repository, "repository", 201).lower()
        if not _REPOSITORY_RE.fullmatch(repository):
            raise GitHubAppContractError("invalid repository name")
        if not isinstance(self.repository_id, int) or isinstance(
            self.repository_id, bool
        ) or self.repository_id <= 0:
            raise GitHubAppContractError("repository_id must be a positive integer")
        if not isinstance(self.installation_id, int) or isinstance(
            self.installation_id, bool
        ) or self.installation_id <= 0:
            raise GitHubAppContractError("installation_id must be a positive integer")
        if not isinstance(self.number, int) or isinstance(self.number, bool) or self.number <= 0:
            raise GitHubAppContractError("pull request number must be positive")
        if not isinstance(self.issue_number, int) or isinstance(
            self.issue_number, bool
        ) or self.issue_number <= 0:
            raise GitHubAppContractError("issue number must be positive")
        head_sha = _bounded_text(self.head_sha, "head_sha", 64).lower()
        if not _COMMIT_RE.fullmatch(head_sha):
            raise GitHubAppContractError("head_sha must be a full hexadecimal commit id")
        base_ref = _bounded_text(self.base_ref, "base_ref", 255)
        base_sha = _bounded_text(self.base_sha, "base_sha", 64).lower()
        if not _COMMIT_RE.fullmatch(base_sha):
            raise GitHubAppContractError("base_sha must be a full hexadecimal commit id")
        action = _bounded_text(self.action, "action", 64)
        object.__setattr__(self, "repository", repository)
        object.__setattr__(self, "head_sha", head_sha)
        object.__setattr__(self, "base_ref", base_ref)
        object.__setattr__(self, "base_sha", base_sha)
        object.__setattr__(self, "action", action)


@dataclass(frozen=True)
class AcceptanceCriterion:
    criterion_id: str
    text: str
    issue_checked: bool = False

    def __post_init__(self) -> None:
        criterion_id = _bounded_text(self.criterion_id, "criterion_id", 128)
        if not _IDENTIFIER_RE.fullmatch(criterion_id):
            raise GitHubAppContractError("criterion_id has invalid characters")
        text = _bounded_text(self.text, "criterion text", 2000)
        if not isinstance(self.issue_checked, bool):
            raise GitHubAppContractError("issue_checked must be boolean")
        object.__setattr__(self, "criterion_id", criterion_id)
        object.__setattr__(self, "text", text)


@dataclass(frozen=True)
class ContractRequirement:
    requirement_id: str
    text: str
    mandatory: bool = True

    def __post_init__(self) -> None:
        requirement_id = _bounded_text(self.requirement_id, "requirement_id", 128)
        if not _IDENTIFIER_RE.fullmatch(requirement_id):
            raise GitHubAppContractError("requirement_id has invalid characters")
        text = _bounded_text(self.text, "requirement text", 2000)
        if not isinstance(self.mandatory, bool):
            raise GitHubAppContractError("mandatory must be boolean")
        object.__setattr__(self, "requirement_id", requirement_id)
        object.__setattr__(self, "text", text)


@dataclass(frozen=True)
class ContractSpec:
    schema_version: str
    requirements: Tuple[ContractRequirement, ...]

    def __post_init__(self) -> None:
        if isinstance(self.requirements, (str, bytes)):
            raise GitHubAppContractError("contract requirements must be a sequence")
        requirements = tuple(self.requirements)
        schema_version = _bounded_text(self.schema_version, "schema_version", 128)
        if schema_version != "FineSchemaGitHubContract/1.0":
            raise GitHubAppContractError("unsupported contract schema_version")
        if not requirements:
            raise GitHubAppContractError("contract requirements must not be empty")
        if len(requirements) > 200:
            raise GitHubAppContractError("contract has more than 200 requirements")
        if not all(isinstance(item, ContractRequirement) for item in requirements):
            raise GitHubAppContractError("contract requirement has invalid type")
        identifiers = [item.requirement_id for item in requirements]
        if len(set(identifiers)) != len(identifiers):
            raise GitHubAppContractError("contract requirement ids must be unique")
        if not any(item.mandatory for item in requirements):
            raise GitHubAppContractError("contract must contain a mandatory requirement")
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "requirements", requirements)

    @property
    def mandatory_ids(self) -> Tuple[str, ...]:
        return tuple(item.requirement_id for item in self.requirements if item.mandatory)


@dataclass(frozen=True)
class FineSchemaConfig:
    version: int
    check_name: str
    contract_path: str
    acceptance_heading: str
    unknown_conclusion: str = "failure"
    system_error_conclusion: str = "failure"

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or isinstance(
            self.version, bool
        ) or self.version != 1:
            raise GitHubAppContractError("unsupported fineschema.yml version")
        check_name = _bounded_text(self.check_name, "check_name", 100)
        if check_name != CANONICAL_CHECK_NAME:
            raise GitHubAppContractError("check_name is fixed by server policy")
        contract_path = _bounded_text(self.contract_path, "contract_path", 512)
        if contract_path.startswith(("/", "\\")):
            raise GitHubAppContractError("contract_path must be repository-relative")
        components = contract_path.replace("\\", "/").split("/")
        if any(part in ("", ".", "..") for part in components):
            raise GitHubAppContractError("contract_path contains an unsafe component")
        if any(not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", part) for part in components):
            raise GitHubAppContractError("contract_path contains an invalid component")
        if not contract_path.lower().endswith((".json", ".yaml", ".yml")):
            raise GitHubAppContractError("contract_path must be JSON or YAML")
        acceptance_heading = _bounded_text(
            self.acceptance_heading, "acceptance_heading", 160
        )
        if acceptance_heading != CANONICAL_ACCEPTANCE_HEADING:
            raise GitHubAppContractError(
                "acceptance_heading is fixed by server policy"
            )
        if self.unknown_conclusion not in ("failure", "action_required"):
            raise GitHubAppContractError(
                "unknown_conclusion must be failure or action_required"
            )
        if self.system_error_conclusion not in ("failure", "timed_out"):
            raise GitHubAppContractError(
                "system_error_conclusion must be failure or timed_out"
            )
        object.__setattr__(self, "check_name", check_name)
        object.__setattr__(self, "contract_path", "/".join(components))
        object.__setattr__(self, "acceptance_heading", acceptance_heading)


@dataclass(frozen=True)
class CriterionResult:
    criterion_id: str
    status: str
    admissible_evidence_hashes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.admissible_evidence_hashes, (str, bytes)):
            raise GitHubAppContractError("admissible evidence hashes must be a sequence")
        evidence_hashes = tuple(self.admissible_evidence_hashes)
        criterion_id = _bounded_text(self.criterion_id, "criterion_id", 128)
        status = _bounded_text(self.status, "criterion status", 64).upper()
        allowed = {
            "PASS",
            "FAIL",
            "UNKNOWN",
            "NOT_RUN",
            "PENDING_HUMAN_REVIEW",
            "NOT_APPLICABLE",
            "WAIVED",
        }
        if status not in allowed:
            raise GitHubAppContractError("unsupported criterion status")
        for digest in evidence_hashes:
            if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                raise GitHubAppContractError(
                    "admissible evidence hash must be canonical sha256"
                )
        if len(set(evidence_hashes)) != len(evidence_hashes):
            raise GitHubAppContractError("admissible evidence hashes must be unique")
        object.__setattr__(self, "criterion_id", criterion_id)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "admissible_evidence_hashes", evidence_hashes)


@dataclass(frozen=True)
class CompletionAssessment:
    """Output supplied by the existing FineSchema decision authority.

    ``authority_verified`` is descriptive, not sufficient authority.  A
    success-capable assessment also carries the exact Core decision hash and a
    bridge receipt.  ``CheckRunAdapter`` verifies that receipt through a
    separately injected trusted authority bridge before it can emit success.
    A model sentence, PR description, or self-asserted boolean therefore cannot
    produce a success conclusion.
    """

    decision_state: str
    decision_id: str
    decision_hash: str
    tenant_id: str
    installation_id: int
    repository: str
    repository_id: int
    head_sha: str
    pull_request_number: int
    issue_number: int
    base_ref: str
    base_sha: str
    contract_hash: str
    criteria_hash: str
    authority_type: str
    authority_verified: bool
    criterion_results: Tuple[CriterionResult, ...]
    reasons: Tuple[str, ...] = ()
    core_decision_hash: str = ""
    authority_receipt_key_id: str = ""
    authority_receipt: str = ""

    @staticmethod
    def _decision_payload(
        decision_state: str,
        decision_id: str,
        tenant_id: str,
        installation_id: int,
        repository: str,
        repository_id: int,
        head_sha: str,
        pull_request_number: int,
        issue_number: int,
        base_ref: str,
        base_sha: str,
        contract_hash: str,
        criteria_hash: str,
        authority_type: str,
        authority_verified: bool,
        criterion_results: Tuple[CriterionResult, ...],
        reasons: Tuple[str, ...],
        core_decision_hash: str,
        authority_receipt_key_id: str,
    ) -> Mapping[str, object]:
        return {
            "schema_version": "FineSchemaGitHubDecisionBinding/1.0",
            "decision_state": decision_state,
            "decision_id": decision_id,
            "tenant_id": tenant_id,
            "installation_id": installation_id,
            "repository": repository,
            "repository_id": repository_id,
            "head_sha": head_sha,
            "pull_request_number": pull_request_number,
            "issue_number": issue_number,
            "base_ref": base_ref,
            "base_sha": base_sha,
            "contract_hash": contract_hash,
            "criteria_hash": criteria_hash,
            "authority_type": authority_type,
            "authority_verified": authority_verified,
            "core_decision_hash": core_decision_hash,
            "authority_receipt_key_id": authority_receipt_key_id,
            "criterion_results": [
                {
                    "criterion_id": item.criterion_id,
                    "status": item.status,
                    "admissible_evidence_hashes": list(
                        item.admissible_evidence_hashes
                    ),
                }
                for item in criterion_results
            ],
            "reasons": list(reasons),
        }

    def __post_init__(self) -> None:
        if isinstance(self.criterion_results, (str, bytes)):
            raise GitHubAppContractError("criterion_results must be a sequence")
        criterion_results = tuple(self.criterion_results)
        if isinstance(self.reasons, (str, bytes)):
            raise GitHubAppContractError("reasons must be a sequence")
        reasons = tuple(self.reasons)
        state = _bounded_text(self.decision_state, "decision_state", 64).upper()
        if state not in _DECISION_STATES:
            raise GitHubAppContractError("unsupported decision_state")
        decision_id = _bounded_text(self.decision_id, "decision_id", 200)
        if not _IDENTIFIER_RE.fullmatch(decision_id):
            raise GitHubAppContractError("decision_id has invalid characters")
        if not isinstance(self.decision_hash, str) or not _SHA256_RE.fullmatch(
            self.decision_hash
        ):
            raise GitHubAppContractError("decision_hash must be canonical sha256")
        if not isinstance(self.contract_hash, str) or not _SHA256_RE.fullmatch(
            self.contract_hash
        ):
            raise GitHubAppContractError("contract_hash must be canonical sha256")
        if not isinstance(self.criteria_hash, str) or not _SHA256_RE.fullmatch(
            self.criteria_hash
        ):
            raise GitHubAppContractError("criteria_hash must be canonical sha256")
        tenant_id = _bounded_text(self.tenant_id, "tenant_id", 128)
        if not _IDENTIFIER_RE.fullmatch(tenant_id):
            raise GitHubAppContractError("tenant_id has invalid characters")
        if not isinstance(self.installation_id, int) or isinstance(
            self.installation_id, bool
        ) or self.installation_id <= 0:
            raise GitHubAppContractError("installation_id must be positive")
        repository = _bounded_text(self.repository, "repository", 201).lower()
        if not _REPOSITORY_RE.fullmatch(repository):
            raise GitHubAppContractError("invalid repository name")
        if not isinstance(self.repository_id, int) or isinstance(
            self.repository_id, bool
        ) or self.repository_id <= 0:
            raise GitHubAppContractError("repository_id must be positive")
        head_sha = _bounded_text(self.head_sha, "head_sha", 64).lower()
        if not _COMMIT_RE.fullmatch(head_sha):
            raise GitHubAppContractError("head_sha must be a full commit id")
        if not isinstance(self.pull_request_number, int) or isinstance(
            self.pull_request_number, bool
        ) or self.pull_request_number <= 0:
            raise GitHubAppContractError("pull_request_number must be positive")
        if not isinstance(self.issue_number, int) or isinstance(
            self.issue_number, bool
        ) or self.issue_number <= 0:
            raise GitHubAppContractError("issue_number must be positive")
        base_ref = _bounded_text(self.base_ref, "base_ref", 255)
        base_sha = _bounded_text(self.base_sha, "base_sha", 64).lower()
        if not _COMMIT_RE.fullmatch(base_sha):
            raise GitHubAppContractError("base_sha must be a full commit id")
        authority_type = _bounded_text(self.authority_type, "authority_type", 80)
        if authority_type not in ("CompletionDecision", "GitHubAdapterSystem"):
            raise GitHubAppContractError("unsupported authority_type")
        if not isinstance(self.authority_verified, bool):
            raise GitHubAppContractError("authority_verified must be boolean")
        core_decision_hash = self.core_decision_hash
        receipt_key_id = self.authority_receipt_key_id
        authority_receipt = self.authority_receipt
        if authority_type == "CompletionDecision":
            if not isinstance(core_decision_hash, str) or not _SHA256_RE.fullmatch(
                core_decision_hash
            ):
                raise GitHubAppContractError(
                    "CompletionDecision assessment requires a canonical core_decision_hash"
                )
            receipt_key_id = _bounded_text(
                receipt_key_id, "authority_receipt_key_id", 128
            )
            if not _IDENTIFIER_RE.fullmatch(receipt_key_id):
                raise GitHubAppContractError(
                    "authority_receipt_key_id has invalid characters"
                )
            if not isinstance(authority_receipt, str) or not _AUTHORITY_RECEIPT_RE.fullmatch(
                authority_receipt
            ):
                raise GitHubAppContractError(
                    "CompletionDecision assessment requires an authority receipt"
                )
        elif core_decision_hash or receipt_key_id or authority_receipt:
            raise GitHubAppContractError(
                "system assessments must not carry CompletionDecision authority"
            )
        if len(criterion_results) > 200:
            raise GitHubAppContractError("too many criterion results")
        if not all(isinstance(item, CriterionResult) for item in criterion_results):
            raise GitHubAppContractError("criterion result has invalid type")
        result_ids = [item.criterion_id for item in criterion_results]
        if len(set(result_ids)) != len(result_ids):
            raise GitHubAppContractError("criterion result ids must be unique")
        normalized_reasons = []
        for reason in reasons:
            normalized_reasons.append(_bounded_text(reason, "reason", 1000))
        object.__setattr__(self, "decision_state", state)
        object.__setattr__(self, "decision_id", decision_id)
        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "repository", repository)
        object.__setattr__(self, "head_sha", head_sha)
        object.__setattr__(self, "base_ref", base_ref)
        object.__setattr__(self, "base_sha", base_sha)
        object.__setattr__(self, "authority_type", authority_type)
        object.__setattr__(self, "core_decision_hash", core_decision_hash)
        object.__setattr__(self, "authority_receipt_key_id", receipt_key_id)
        object.__setattr__(self, "authority_receipt", authority_receipt)
        object.__setattr__(self, "criterion_results", criterion_results)
        object.__setattr__(self, "reasons", tuple(normalized_reasons))

        expected_hash = _canonical_hash(
            self._decision_payload(
                state,
                decision_id,
                tenant_id,
                self.installation_id,
                repository,
                self.repository_id,
                head_sha,
                self.pull_request_number,
                self.issue_number,
                base_ref,
                base_sha,
                self.contract_hash,
                self.criteria_hash,
                authority_type,
                self.authority_verified,
                tuple(self.criterion_results),
                tuple(normalized_reasons),
                core_decision_hash,
                receipt_key_id,
            )
        )
        if self.decision_hash != expected_hash:
            raise GitHubAppContractError("decision_hash does not bind assessment")

    @classmethod
    def create(
        cls,
        *,
        decision_state: str,
        decision_id: str,
        tenant_id: str,
        installation_id: int,
        repository: str,
        repository_id: int,
        head_sha: str,
        pull_request_number: int,
        issue_number: int,
        base_ref: str,
        base_sha: str,
        contract_hash: str,
        criteria_hash: str,
        authority_type: str,
        authority_verified: bool,
        criterion_results: Tuple[CriterionResult, ...],
        reasons: Tuple[str, ...] = (),
        core_decision_hash: str = "",
        authority_receipt_key_id: str = "",
        authority_receipt: str = "",
    ) -> "CompletionAssessment":
        normalized_state = str(decision_state).strip(" \t").upper()
        normalized_repository = str(repository).strip(" \t").lower()
        normalized_head = str(head_sha).strip(" \t").lower()
        normalized_reasons = tuple(str(item).strip(" \t") for item in reasons)
        results = tuple(criterion_results)
        decision_hash = _canonical_hash(
            cls._decision_payload(
                normalized_state,
                str(decision_id).strip(" \t"),
                str(tenant_id).strip(" \t"),
                installation_id,
                normalized_repository,
                repository_id,
                normalized_head,
                pull_request_number,
                issue_number,
                str(base_ref).strip(" \t"),
                str(base_sha).strip(" \t").lower(),
                contract_hash,
                criteria_hash,
                str(authority_type).strip(" \t"),
                authority_verified,
                results,
                normalized_reasons,
                str(core_decision_hash).strip(" \t"),
                str(authority_receipt_key_id).strip(" \t"),
            )
        )
        return cls(
            decision_state=normalized_state,
            decision_id=decision_id,
            decision_hash=decision_hash,
            tenant_id=tenant_id,
            installation_id=installation_id,
            repository=normalized_repository,
            repository_id=repository_id,
            head_sha=normalized_head,
            pull_request_number=pull_request_number,
            issue_number=issue_number,
            base_ref=base_ref,
            base_sha=base_sha,
            contract_hash=contract_hash,
            criteria_hash=criteria_hash,
            authority_type=authority_type,
            authority_verified=authority_verified,
            criterion_results=results,
            reasons=normalized_reasons,
            core_decision_hash=core_decision_hash,
            authority_receipt_key_id=authority_receipt_key_id,
            authority_receipt=authority_receipt,
        )

    @classmethod
    def system_error(
        cls,
        code: str,
        tenant: Tenant,
        pull_request: PullRequestContext,
        contract_hash: str,
        criteria_hash: str,
    ) -> "CompletionAssessment":
        code = _bounded_text(code, "system error code", 80)
        if not _IDENTIFIER_RE.fullmatch(code):
            code = "SYSTEM_ERROR"
        return cls.create(
            decision_state="SYSTEM_ERROR",
            decision_id="github-adapter-system-error",
            tenant_id=tenant.tenant_id,
            installation_id=tenant.installation_id,
            repository=pull_request.repository,
            repository_id=pull_request.repository_id,
            head_sha=pull_request.head_sha,
            pull_request_number=pull_request.number,
            issue_number=pull_request.issue_number,
            base_ref=pull_request.base_ref,
            base_sha=pull_request.base_sha,
            contract_hash=contract_hash,
            criteria_hash=criteria_hash,
            authority_type="GitHubAdapterSystem",
            authority_verified=True,
            criterion_results=(),
            reasons=(code,),
        )


@dataclass(frozen=True)
class CheckRunRequest:
    tenant_id: str
    installation_id: int
    repository: str
    repository_id: int
    payload: Mapping[str, object]
    result_hash: str
    publication_mode: str = "UPSERT_BY_EXTERNAL_ID"

    def __post_init__(self) -> None:
        tenant_id = _bounded_text(self.tenant_id, "tenant_id", 128)
        if not _IDENTIFIER_RE.fullmatch(tenant_id):
            raise GitHubAppContractError("tenant_id has invalid characters")
        if not isinstance(self.installation_id, int) or isinstance(
            self.installation_id, bool
        ) or self.installation_id <= 0:
            raise GitHubAppContractError("installation_id must be positive")
        repository = _bounded_text(self.repository, "repository", 201).lower()
        if not _REPOSITORY_RE.fullmatch(repository):
            raise GitHubAppContractError("invalid repository name")
        if not isinstance(self.repository_id, int) or isinstance(
            self.repository_id, bool
        ) or self.repository_id <= 0:
            raise GitHubAppContractError("repository_id must be positive")
        if not isinstance(self.result_hash, str) or not _SHA256_RE.fullmatch(
            self.result_hash
        ):
            raise GitHubAppContractError("result_hash must be canonical sha256")
        if self.publication_mode != "UPSERT_BY_EXTERNAL_ID":
            raise GitHubAppContractError("Check Run publication must be idempotent upsert")
        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "repository", repository)


@dataclass(frozen=True)
class WebhookOutcome:
    status: str
    delivery_id: str
    body_hash: str
    publication_performed: bool
    check_run: Optional[CheckRunRequest] = None
    check_runs: Tuple[CheckRunRequest, ...] = ()
    prior_result_hash: Optional[str] = None
