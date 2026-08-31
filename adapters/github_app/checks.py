"""FineSchema CompletionDecision to GitHub Check Run projection."""
from __future__ import annotations

import hashlib
import json
from typing import Dict, Mapping, Optional, Protocol, Sequence, Tuple

from .models import (
    AcceptanceCriterion,
    CheckRunRequest,
    CompletionAssessment,
    ContractSpec,
    FineSchemaConfig,
    PullRequestContext,
    Tenant,
)


_FIXED_CONCLUSIONS = {
    "VERIFIED_COMPLETE": "success",
    "BLOCKED_INCOMPLETE": "failure",
    "INCOMPLETE": "failure",
    "FAILED": "failure",
    "BLOCKED": "failure",
    "HUMAN_REVIEW_REQUIRED": "action_required",
    "MACHINE_VERIFIED_ONLY": "action_required",
}


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def contract_binding_hash(contract: ContractSpec) -> str:
    return canonical_hash(
        {
            "schema_version": contract.schema_version,
            "requirements": [
                {
                    "id": item.requirement_id,
                    "text": item.text,
                    "mandatory": item.mandatory,
                }
                for item in contract.requirements
            ],
        }
    )


def criteria_binding_hash(criteria: Sequence[AcceptanceCriterion]) -> str:
    # Checkbox state is deliberately absent: it is planning metadata, not
    # completion evidence.  Identifier and exact Issue text remain bound.
    return canonical_hash(
        {
            "criteria": [
                {"id": item.criterion_id, "text": item.text}
                for item in criteria
            ]
        }
    )


def check_external_id(tenant: Tenant, pull_request: PullRequestContext) -> str:
    """Return the one deterministic head-scoped Check Run identity."""

    return "fineschema:" + canonical_hash(
        {
            "tenant_id": tenant.tenant_id,
            "installation_id": tenant.installation_id,
            "repository": pull_request.repository,
            "repository_id": pull_request.repository_id,
            "head_sha": pull_request.head_sha,
            "check_name": "FineSchema Completion Gate",
        }
    ).split(":", 1)[1]


def conclusion_for_state(state: str, config: FineSchemaConfig) -> str:
    """Map decision state without ever producing GitHub's neutral conclusion."""

    normalized = str(state).strip(" \t").upper()
    if normalized == "SYSTEM_ERROR":
        return config.system_error_conclusion
    if normalized == "UNKNOWN":
        return config.unknown_conclusion
    return _FIXED_CONCLUSIONS.get(normalized, config.unknown_conclusion)


class ReceiptRenderer:
    """Render a bounded, value-minimized Check Run receipt.

    Free-form model prose and Issue descriptions are intentionally excluded.
    The receipt shows identifiers, decision status, check status, and hashes.
    """

    MAX_TEXT = 60000

    @staticmethod
    def _escape(value: str) -> str:
        return (
            value.replace("\\", "\\\\")
            .replace("`", "&#96;")
            .replace("|", "\\|")
            .replace("\n", " ")
        )

    def render(
        self,
        criteria: Sequence[AcceptanceCriterion],
        contract: ContractSpec,
        assessment: CompletionAssessment,
        conclusion: str,
    ) -> Tuple[str, str]:
        results = {item.criterion_id: item for item in assessment.criterion_results}
        receipt = {
            "schema_version": "FineSchemaGitHubReceipt/1.0",
            "decision": {
                "id": assessment.decision_id,
                "state": assessment.decision_state,
                "hash": assessment.decision_hash,
                "core_decision_hash": assessment.core_decision_hash,
                "authority_receipt_key_id": assessment.authority_receipt_key_id,
                "authority_type": assessment.authority_type,
                "authority_verified": assessment.authority_verified,
                "contract_hash": assessment.contract_hash,
                "criteria_hash": assessment.criteria_hash,
                "tenant_id": assessment.tenant_id,
                "installation_id": assessment.installation_id,
                "repository": assessment.repository,
                "repository_id": assessment.repository_id,
                "head_sha": assessment.head_sha,
                "pull_request_number": assessment.pull_request_number,
                "issue_number": assessment.issue_number,
                "base_ref": assessment.base_ref,
                "base_sha": assessment.base_sha,
            },
            "conclusion": conclusion,
            "contract_schema_version": contract.schema_version,
            "contract_requirement_ids": [item.requirement_id for item in contract.requirements],
            "issue_criterion_ids": [item.criterion_id for item in criteria],
            "criterion_results": [
                {
                    "id": item.criterion_id,
                    "status": item.status,
                    "admissible_evidence_hashes": list(
                        item.admissible_evidence_hashes
                    ),
                }
                for item in assessment.criterion_results
            ],
        }
        receipt_hash = canonical_hash(receipt)
        status_counts = {
            status: sum(
                1
                for result in assessment.criterion_results
                if result.status == status
            )
            for status in (
                "PASS",
                "FAIL",
                "UNKNOWN",
                "NOT_RUN",
                "PENDING_HUMAN_REVIEW",
                "NOT_APPLICABLE",
                "WAIVED",
            )
        }
        lines = [
            "### FineSchema Completion Gate",
            "",
            "- Decision: `%s`" % self._escape(assessment.decision_state),
            "- Conclusion: `%s`" % self._escape(conclusion),
            "- Authority: `%s` (verified: `%s`)"
            % (self._escape(assessment.authority_type), str(assessment.authority_verified).lower()),
            "- Decision receipt: `%s`" % assessment.decision_hash,
            "- Core decision: `%s`" % (
                assessment.core_decision_hash or "NOT_APPLICABLE"
            ),
            "- Contract: `%s` (`%s`)"
            % (self._escape(contract.schema_version), assessment.contract_hash),
            "- Results: proven `%d` · missing/unknown `%d` · failed `%d` · not run `%d`"
            % (
                status_counts["PASS"],
                status_counts["UNKNOWN"]
                + status_counts["PENDING_HUMAN_REVIEW"],
                status_counts["FAIL"],
                status_counts["NOT_RUN"],
            ),
            "- Evidence binding receipt: `%s`" % receipt_hash,
            "- Re-run action: `NOT_AVAILABLE_INTERNAL_SCAFFOLD`",
            "",
            "| Acceptance criterion | Result | Evidence |",
            "| --- | --- | ---: |",
        ]
        for criterion in criteria:
            result = results.get(criterion.criterion_id)
            status = result.status if result else "NOT_REPORTED"
            evidence_count = len(result.admissible_evidence_hashes) if result else 0
            lines.append(
                "| `%s` | `%s` | %d |"
                % (
                    self._escape(criterion.criterion_id),
                    self._escape(status),
                    evidence_count,
                )
            )
        rendered = "\n".join(lines)
        if len(rendered.encode("utf-8")) > self.MAX_TEXT:
            raise ValueError("rendered GitHub receipt exceeds safe output bound")
        return rendered, receipt_hash


class _AuthorityReceiptVerifier(Protocol):
    def verify(self, assessment: CompletionAssessment) -> bool:
        ...


class CheckRunAdapter:
    """Build a GitHub ``POST /check-runs`` body; perform no network I/O."""

    def __init__(
        self,
        renderer: ReceiptRenderer = None,
        authority_verifier: Optional[_AuthorityReceiptVerifier] = None,
    ) -> None:
        self._renderer = renderer or ReceiptRenderer()
        self._authority_verifier = authority_verifier

    def build(
        self,
        tenant: Tenant,
        pull_request: PullRequestContext,
        config: FineSchemaConfig,
        criteria: Sequence[AcceptanceCriterion],
        contract: ContractSpec,
        assessment: CompletionAssessment,
    ) -> CheckRunRequest:
        if tenant.installation_id != pull_request.installation_id:
            raise ValueError("tenant installation does not match pull request")
        if not tenant.permits(
            pull_request.repository, pull_request.repository_id
        ):
            raise ValueError("tenant does not permit pull request repository")
        conclusion = conclusion_for_state(assessment.decision_state, config)

        issue_ids = tuple(item.criterion_id for item in criteria)
        contract_ids = tuple(item.requirement_id for item in contract.requirements)
        receipt_valid = False
        if self._authority_verifier is not None:
            try:
                receipt_valid = (
                    self._authority_verifier.verify(assessment) is True
                )
            except Exception:
                receipt_valid = False
        authority_valid = (
            assessment.authority_type == "CompletionDecision"
            and assessment.authority_verified
            and receipt_valid
        )
        result_ids = tuple(item.criterion_id for item in assessment.criterion_results)
        exact_coverage = (
            len(issue_ids) == len(contract_ids) == len(result_ids)
            and set(issue_ids) == set(contract_ids) == set(result_ids)
        )
        results_complete = all(
            item.status == "PASS" and bool(item.admissible_evidence_hashes)
            for item in assessment.criterion_results
        )
        bindings_valid = (
            assessment.contract_hash == contract_binding_hash(contract)
            and assessment.criteria_hash == criteria_binding_hash(criteria)
            and assessment.tenant_id == tenant.tenant_id
            and assessment.installation_id == tenant.installation_id
            and assessment.repository == pull_request.repository
            and assessment.repository_id == pull_request.repository_id
            and assessment.head_sha == pull_request.head_sha
            and assessment.pull_request_number == pull_request.number
            and assessment.issue_number == pull_request.issue_number
            and assessment.base_ref == pull_request.base_ref
            and assessment.base_sha == pull_request.base_sha
        )
        requirements_by_id = {
            item.requirement_id: item for item in contract.requirements
        }
        meaning_bound = exact_coverage and all(
            requirements_by_id[item.criterion_id].mandatory
            and requirements_by_id[item.criterion_id].text == item.text
            for item in criteria
        )
        if assessment.decision_state == "VERIFIED_COMPLETE" and not (
            authority_valid
            and exact_coverage
            and results_complete
            and bindings_valid
            and meaning_bound
        ):
            # An unverified object, incomplete result set, unbound contract, or
            # model sentence can never produce a success conclusion.
            conclusion = "failure"
        if not exact_coverage or not meaning_bound:
            # Dropping either an Issue criterion, contract requirement, or
            # assessment result is an adapter-integrity error and fails closed.
            conclusion = "failure"

        receipt, receipt_hash = self._renderer.render(
            criteria, contract, assessment, conclusion
        )
        if conclusion == "success":
            title = "FineSchema verified the defined scope"
        elif conclusion == "action_required":
            title = "FineSchema requires human action"
        elif conclusion == "timed_out":
            title = "FineSchema verification timed out"
        else:
            title = "FineSchema does not verify completion"
        summary = (
            "CompletionDecision `%s` mapped to `%s`; %d acceptance criteria are bound."
            % (assessment.decision_state, conclusion, len(criteria))
        )
        external_id = check_external_id(tenant, pull_request)
        payload: Dict[str, object] = {
            "name": config.check_name,
            "head_sha": pull_request.head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "external_id": external_id,
            "output": {
                "title": title,
                "summary": summary,
                "text": receipt,
            },
        }
        result_hash = canonical_hash(
            {
                "tenant_id": tenant.tenant_id,
                "installation_id": tenant.installation_id,
                "repository": pull_request.repository,
                "repository_id": pull_request.repository_id,
                "pull_request": pull_request.number,
                "payload": payload,
                "receipt_hash": receipt_hash,
            }
        )
        return CheckRunRequest(
            tenant_id=tenant.tenant_id,
            installation_id=tenant.installation_id,
            repository=pull_request.repository,
            repository_id=pull_request.repository_id,
            payload=payload,
            result_hash=result_hash,
        )


__all__ = [
    "CheckRunAdapter",
    "ReceiptRenderer",
    "canonical_hash",
    "canonical_json",
    "check_external_id",
    "conclusion_for_state",
    "contract_binding_hash",
    "criteria_binding_hash",
]
