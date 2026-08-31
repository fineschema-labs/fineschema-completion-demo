"""Bounded parsers for GitHub Issue criteria and FineSchema contracts.

YAML support is intentionally a documented subset, not a claim of YAML 1.2
conformance.  It accepts only the flat ``fineschema.yml`` mapping and the
contract's root scalars plus ``requirements`` list-of-mappings shape.  Anchors,
aliases, tags, merge keys, block scalars, flow collections, and arbitrary
nesting are rejected.
"""
from __future__ import annotations

import json
import math
import re
from typing import Dict, Iterable, List, Mapping, MutableMapping, Tuple

from .models import (
    AcceptanceCriterion,
    ContractRequirement,
    ContractSpec,
    FineSchemaConfig,
    GitHubAppContractError,
    PullRequestContext,
)


MAX_CONFIG_BYTES = 32 * 1024
MAX_CONTRACT_BYTES = 256 * 1024
MAX_ISSUE_BYTES = 256 * 1024
MAX_JSON_DEPTH = 20
MAX_JSON_NODES = 10000
MAX_LINES = 4096
MAX_LINE_LENGTH = 4096
MAX_NUMBER_LEXEME_LENGTH = 128
MAX_INTEGER_BITS = 512

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_HEADING_RE = re.compile(r"^(#{1,6}) +(.+?) *$")
_INDENTED_HEADING_RE = re.compile(r"^ {1,3}#{1,6} +")
_CRITERION_RE = re.compile(
    r"^[-*] {1,4}\[([ xX])\] +"
    r"(?:\[([A-Za-z0-9][A-Za-z0-9._-]{0,127})\]|"
    r"([A-Za-z0-9][A-Za-z0-9._-]{0,127}))"
    r": +(.+?) *$"
)
_ANY_TASK_RE = re.compile(r"\[[ xX]\]")
_ISSUE_REFERENCE_RE = re.compile(
    r"^FineSchema-Issue: #([1-9][0-9]{0,9})$"
)
_RAW_HTML_BLOCK_RE = re.compile(
    r"<(?:/?[A-Za-z][A-Za-z0-9-]*(?:[ />]|$)|[!?])",
    re.IGNORECASE,
)
_SETEXT_UNDERLINE_RE = re.compile(r"^ {0,3}(?:=+|-+) *$")
_FORBIDDEN_BIDI = (
    set(range(0x202A, 0x202F))
    | set(range(0x2066, 0x206A))
    | {0x200E, 0x200F}
)
_PLAIN_YAML_FORBIDDEN_INITIAL = frozenset("-?:,[]{}#&*!|>'\"%@`")


def _has_forbidden_text_character(text: str) -> bool:
    for character in text:
        codepoint = ord(character)
        if codepoint < 0x20 and character not in ("\t", "\r", "\n"):
            return True
        if 0x7F <= codepoint <= 0x9F:
            return True
        if 0xD800 <= codepoint <= 0xDFFF:
            return True
        if codepoint in _FORBIDDEN_BIDI or codepoint in (0x2028, 0x2029, 0xFEFF):
            return True
    return False


def _bounded_source(text: object, maximum: int, label: str) -> str:
    if not isinstance(text, str):
        raise GitHubAppContractError("%s must be UTF-8 text" % label)
    if _has_forbidden_text_character(text):
        raise GitHubAppContractError(
            "%s contains control, line-separator, or bidi characters" % label
        )
    if len(text.encode("utf-8")) > maximum:
        raise GitHubAppContractError("%s exceeds byte bound" % label)
    # CommonMark recognizes CR/LF line endings.  Normalize only those; Python's
    # splitlines() also treats several non-Markdown separators as line breaks.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    if len(lines) > MAX_LINES:
        raise GitHubAppContractError("%s exceeds line bound" % label)
    if any(len(line) > MAX_LINE_LENGTH for line in lines):
        raise GitHubAppContractError("%s contains an overlong line" % label)
    return text


def _unique_object(pairs: Iterable[Tuple[str, object]]) -> Dict[str, object]:
    result: Dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GitHubAppContractError("JSON contains a duplicate key")
        result[key] = value
    return result


def _bounded_json_int(raw: str) -> int:
    if len(raw) > MAX_NUMBER_LEXEME_LENGTH:
        raise GitHubAppContractError("JSON integer exceeds numeric bound")
    value = int(raw)
    if value.bit_length() > MAX_INTEGER_BITS:
        raise GitHubAppContractError("JSON integer exceeds numeric bound")
    return value


def _bounded_json_float(raw: str) -> float:
    if len(raw) > MAX_NUMBER_LEXEME_LENGTH:
        raise GitHubAppContractError("JSON number exceeds numeric bound")
    value = float(raw)
    if not math.isfinite(value):
        raise GitHubAppContractError("JSON number must be finite")
    return value


def _reject_json_constant(raw: str) -> object:
    raise GitHubAppContractError("JSON non-finite constants are not supported")


def _validate_json_tree(value: object, validate_text_characters: bool = True) -> None:
    stack: List[Tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise GitHubAppContractError("JSON exceeds node bound")
        if depth > MAX_JSON_DEPTH:
            raise GitHubAppContractError("JSON exceeds depth bound")
        if isinstance(current, dict):
            for key, child in current.items():
                if (
                    not isinstance(key, str)
                    or len(key) > MAX_LINE_LENGTH
                    or (
                        validate_text_characters
                        and _has_forbidden_text_character(key)
                    )
                ):
                    raise GitHubAppContractError("JSON object key is invalid")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str):
            if len(current) > MAX_CONTRACT_BYTES:
                raise GitHubAppContractError("JSON string exceeds bound")
            if validate_text_characters and _has_forbidden_text_character(current):
                raise GitHubAppContractError("JSON string contains unsafe characters")
        elif isinstance(current, bool) or current is None:
            continue
        elif isinstance(current, int):
            if current.bit_length() > MAX_INTEGER_BITS:
                raise GitHubAppContractError("JSON integer exceeds numeric bound")
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise GitHubAppContractError("JSON number must be finite")
        elif not isinstance(current, str):
            raise GitHubAppContractError("JSON contains an unsupported value")


def _parse_json_object(
    text: str, label: str, validate_text_characters: bool = True
) -> Mapping[str, object]:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_int=_bounded_json_int,
            parse_float=_bounded_json_float,
            parse_constant=_reject_json_constant,
        )
    except GitHubAppContractError:
        raise
    except (ValueError, RecursionError) as exc:
        raise GitHubAppContractError("%s is malformed JSON" % label) from exc
    _validate_json_tree(value, validate_text_characters)
    if not isinstance(value, dict):
        raise GitHubAppContractError("%s root must be an object" % label)
    return value


def _parse_scalar(raw: str, label: str) -> object:
    value = raw.strip()
    if not value:
        raise GitHubAppContractError("%s has an empty scalar" % label)
    if value.startswith('"'):
        try:
            parsed = json.loads(
                value,
                parse_int=_bounded_json_int,
                parse_float=_bounded_json_float,
                parse_constant=_reject_json_constant,
            )
        except ValueError as exc:
            raise GitHubAppContractError("%s has invalid quoted text" % label) from exc
        if not isinstance(parsed, str):
            raise GitHubAppContractError("%s quoted scalar must be text" % label)
        if _has_forbidden_text_character(parsed):
            raise GitHubAppContractError(
                "%s quoted scalar contains unsafe characters" % label
            )
        return parsed
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise GitHubAppContractError("%s has invalid single-quoted text" % label)
        inner = value[1:-1]
        decoded: List[str] = []
        index = 0
        while index < len(inner):
            if inner[index] == "'":
                if index + 1 >= len(inner) or inner[index + 1] != "'":
                    raise GitHubAppContractError(
                        "%s has invalid single-quoted text" % label
                    )
                decoded.append("'")
                index += 2
            else:
                decoded.append(inner[index])
                index += 1
        return "".join(decoded)
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        if len(value) > MAX_NUMBER_LEXEME_LENGTH:
            raise GitHubAppContractError("%s integer exceeds numeric bound" % label)
        parsed = int(value)
        if parsed.bit_length() > MAX_INTEGER_BITS:
            raise GitHubAppContractError("%s integer exceeds numeric bound" % label)
        return parsed
    if lowered in (
        ".nan",
        ".inf",
        "+.inf",
        "-.inf",
        "nan",
        "infinity",
        "+infinity",
        "-infinity",
    ):
        raise GitHubAppContractError("%s uses a non-finite scalar" % label)
    if value[0] in _PLAIN_YAML_FORBIDDEN_INITIAL or value in (
        "null",
        "Null",
        "NULL",
        "~",
    ):
        raise GitHubAppContractError("%s uses unsupported YAML syntax" % label)
    if re.search(r":(?:[ \t]|$)", value):
        raise GitHubAppContractError("%s uses ambiguous YAML mapping syntax" % label)
    if " #" in value or value.startswith("#"):
        raise GitHubAppContractError("inline YAML comments are not supported")
    return value


def _meaningful_yaml_lines(text: str, label: str) -> List[Tuple[int, str]]:
    lines: List[Tuple[int, str]] = []
    for number, raw in enumerate(text.split("\n"), 1):
        if "\t" in raw:
            raise GitHubAppContractError("%s line %d contains a tab" % (label, number))
        stripped = raw.strip()
        if stripped in ("---", "..."):
            raise GitHubAppContractError("YAML document markers are not supported")
        if not stripped or stripped.startswith("#"):
            continue
        if "<<:" in raw:
            raise GitHubAppContractError("YAML merge keys are not supported")
        lines.append((number, raw.rstrip()))
    return lines


def _split_pair(text: str, label: str) -> Tuple[str, str]:
    if ":" not in text:
        raise GitHubAppContractError("%s must be a key/value pair" % label)
    key, value = text.split(":", 1)
    key = key.strip()
    if not _KEY_RE.fullmatch(key):
        raise GitHubAppContractError("%s has an invalid key" % label)
    return key, value.strip()


def parse_fineschema_config(text: str) -> FineSchemaConfig:
    """Parse the documented flat ``fineschema.yml`` subset."""

    text = _bounded_source(text, MAX_CONFIG_BYTES, "fineschema.yml")
    values: Dict[str, object] = {}
    for number, raw in _meaningful_yaml_lines(text, "fineschema.yml"):
        if raw.startswith(" "):
            raise GitHubAppContractError(
                "fineschema.yml line %d uses unsupported nesting" % number
            )
        key, scalar = _split_pair(raw, "fineschema.yml line %d" % number)
        if key in values:
            raise GitHubAppContractError("fineschema.yml contains a duplicate key")
        values[key] = _parse_scalar(scalar, "fineschema.yml %s" % key)
    allowed = {
        "version",
        "check_name",
        "contract_path",
        "acceptance_heading",
        "unknown_conclusion",
        "system_error_conclusion",
    }
    unexpected = sorted(set(values) - allowed)
    if unexpected:
        raise GitHubAppContractError("unknown fineschema.yml key: %s" % unexpected[0])
    required = {"version", "check_name", "contract_path", "acceptance_heading"}
    missing = sorted(required - set(values))
    if missing:
        raise GitHubAppContractError("missing fineschema.yml key: %s" % missing[0])
    return FineSchemaConfig(
        version=values["version"],  # type: ignore[arg-type]
        check_name=values["check_name"],  # type: ignore[arg-type]
        contract_path=values["contract_path"],  # type: ignore[arg-type]
        acceptance_heading=values["acceptance_heading"],  # type: ignore[arg-type]
        unknown_conclusion=values.get("unknown_conclusion", "failure"),  # type: ignore[arg-type]
        system_error_conclusion=values.get("system_error_conclusion", "failure"),  # type: ignore[arg-type]
    )


def _contract_mapping(value: Mapping[str, object]) -> ContractSpec:
    allowed = {"schema_version", "requirements"}
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise GitHubAppContractError("unknown contract key: %s" % unexpected[0])
    if set(value) != allowed:
        raise GitHubAppContractError("contract requires schema_version and requirements")
    raw_requirements = value["requirements"]
    if not isinstance(raw_requirements, list):
        raise GitHubAppContractError("contract requirements must be a list")
    requirements = []
    for index, item in enumerate(raw_requirements):
        if not isinstance(item, dict):
            raise GitHubAppContractError("contract requirement must be an object")
        unexpected_item = sorted(set(item) - {"id", "text", "mandatory"})
        if unexpected_item:
            raise GitHubAppContractError(
                "unknown requirement key: %s" % unexpected_item[0]
            )
        if "id" not in item or "text" not in item:
            raise GitHubAppContractError(
                "contract requirement %d requires id and text" % index
            )
        requirements.append(
            ContractRequirement(
                requirement_id=item["id"],  # type: ignore[arg-type]
                text=item["text"],  # type: ignore[arg-type]
                mandatory=item.get("mandatory", True),  # type: ignore[arg-type]
            )
        )
    return ContractSpec(
        schema_version=value["schema_version"],  # type: ignore[arg-type]
        requirements=tuple(requirements),
    )


def _parse_contract_yaml(text: str) -> Mapping[str, object]:
    root: Dict[str, object] = {}
    requirements: List[MutableMapping[str, object]] = []
    current: MutableMapping[str, object] = {}
    in_requirements = False
    for number, raw in _meaningful_yaml_lines(text, "contract YAML"):
        if not raw.startswith(" "):
            key, scalar = _split_pair(raw, "contract YAML line %d" % number)
            if key in root:
                raise GitHubAppContractError("contract YAML contains a duplicate key")
            if key == "requirements":
                if scalar:
                    raise GitHubAppContractError(
                        "contract requirements must use a block list"
                    )
                root[key] = requirements
                in_requirements = True
            else:
                if in_requirements:
                    raise GitHubAppContractError(
                        "contract root keys must precede requirements"
                    )
                root[key] = _parse_scalar(scalar, "contract YAML %s" % key)
            continue
        if not in_requirements:
            raise GitHubAppContractError(
                "contract YAML line %d uses unsupported nesting" % number
            )
        if raw.startswith("  - "):
            current = {}
            requirements.append(current)
            key, scalar = _split_pair(raw[4:], "contract YAML line %d" % number)
        elif raw.startswith("    ") and not raw.startswith("     ") and current:
            key, scalar = _split_pair(raw[4:], "contract YAML line %d" % number)
        else:
            raise GitHubAppContractError(
                "contract YAML line %d has invalid indentation" % number
            )
        if key in current:
            raise GitHubAppContractError("contract requirement contains a duplicate key")
        current[key] = _parse_scalar(scalar, "contract requirement %s" % key)
    return root


def parse_contract(text: str, source_path: str) -> ContractSpec:
    """Parse an explicit JSON contract or the bounded YAML contract subset."""

    text = _bounded_source(text, MAX_CONTRACT_BYTES, "contract")
    if not isinstance(source_path, str):
        raise GitHubAppContractError("contract source path must be text")
    lowered = source_path.lower()
    if lowered.endswith(".json"):
        mapping = _parse_json_object(text, "contract")
    elif lowered.endswith((".yaml", ".yml")):
        mapping = _parse_contract_yaml(text)
    else:
        raise GitHubAppContractError("contract source must end in .json, .yaml, or .yml")
    return _contract_mapping(mapping)


def _visible_markdown_lines(text: str, label: str) -> List[Tuple[int, str]]:
    """Return a conservative block-visible Markdown subset.

    This adapter deliberately does not claim CommonMark conformance.  HTML
    comments and fenced blocks are rejected globally; raw HTML block starters
    and ambiguous 1--3-space ATX headings are also rejected.  This smaller
    subset is easier to compare with GitHub without hidden-block differentials.
    """

    if "<!--" in text or "-->" in text:
        raise GitHubAppContractError(
            "%s contains unsupported HTML comment syntax" % label
        )
    visible: List[Tuple[int, str]] = []
    for number, original in enumerate(text.split("\n"), 1):
        if re.match(r"^ {0,3}(?:`{3,}|~{3,})", original):
            raise GitHubAppContractError(
                "%s contains unsupported fenced-block syntax" % label
            )
        if _RAW_HTML_BLOCK_RE.search(original):
            raise GitHubAppContractError(
                "raw HTML blocks are not allowed in %s" % label
            )
        if _SETEXT_UNDERLINE_RE.fullmatch(original):
            raise GitHubAppContractError(
                "%s contains unsupported Setext/thematic syntax" % label
            )
        if _INDENTED_HEADING_RE.match(original):
            raise GitHubAppContractError(
                "%s contains an ambiguous indented heading" % label
            )
        visible.append((number, original))
    return visible


def _heading_parts(line: str) -> Tuple[int, str]:
    match = _HEADING_RE.fullmatch(line)
    if not match:
        return 0, ""
    title = match.group(2).rstrip(" ")
    closing = re.fullmatch(r"(.+?) +#+", title)
    if closing:
        title = closing.group(1).rstrip(" ")
    return len(match.group(1)), title.casefold()


def parse_acceptance_criteria(
    issue_body: str, heading: str = "Acceptance Criteria"
) -> Tuple[AcceptanceCriterion, ...]:
    """Parse the strict, column-zero acceptance checklist subset.

    Checkbox state is retained for display only; it is never treated as
    verification evidence or as CompletionDecision authority.  Nonblank
    continuation prose or noncanonical/nested task items inside the selected
    section are rejected so no visible obligation can be silently omitted.
    """

    issue_body = _bounded_source(issue_body, MAX_ISSUE_BYTES, "issue body")
    if "\t" in issue_body:
        raise GitHubAppContractError("issue body contains an ambiguous tab")
    if not isinstance(heading, str) or not heading.strip():
        raise GitHubAppContractError("acceptance heading must be text")
    normalized_heading = heading.strip().casefold()
    visible_lines = _visible_markdown_lines(issue_body, "acceptance Issue")

    matching_headings = []
    all_headings = []
    for index, (_number, line) in enumerate(visible_lines):
        level, title = _heading_parts(line)
        if not level:
            continue
        all_headings.append((index, level, title))
        if title == normalized_heading:
            matching_headings.append((index, level))
    if not matching_headings:
        raise GitHubAppContractError("acceptance heading was not found")
    if len(matching_headings) != 1:
        raise GitHubAppContractError("acceptance heading is duplicated")
    section_start, section_level = matching_headings[0]
    section_end = len(visible_lines)
    for index, level, _title in all_headings:
        if index > section_start and level <= section_level:
            section_end = index
            break

    criteria = []
    for number, line in visible_lines[section_start + 1 : section_end]:
        if not line.strip():
            continue
        match = _CRITERION_RE.fullmatch(line)
        if not match:
            detail = "task item" if _ANY_TASK_RE.search(line) else "content"
            raise GitHubAppContractError(
                "noncanonical acceptance %s at issue line %d" % (detail, number)
            )
        criterion_id = match.group(2) or match.group(3)
        criteria.append(
            AcceptanceCriterion(
                criterion_id=criterion_id,
                text=match.group(4),
                issue_checked=match.group(1).lower() == "x",
            )
        )
    if not criteria:
        raise GitHubAppContractError("acceptance criteria section is empty")
    if len(criteria) > 200:
        raise GitHubAppContractError("issue has more than 200 acceptance criteria")
    identifiers = [item.criterion_id for item in criteria]
    if len(set(identifiers)) != len(identifiers):
        raise GitHubAppContractError("acceptance criterion ids must be unique")
    return tuple(criteria)


def parse_issue_reference(pull_request_body: object) -> int:
    pull_request_body = _bounded_source(
        pull_request_body, MAX_ISSUE_BYTES, "pull request body"
    )
    if "\t" in pull_request_body:
        raise GitHubAppContractError("pull request body contains an ambiguous tab")
    visible = _visible_markdown_lines(pull_request_body, "pull request body")
    matches = []
    for _number, line in visible:
        match = _ISSUE_REFERENCE_RE.fullmatch(line)
        if match:
            matches.append(match.group(1))
    # Reject hidden/ambiguous duplicates as well as a hidden sole reference.
    if pull_request_body.count("FineSchema-Issue") != 1 or len(matches) != 1:
        raise GitHubAppContractError(
            "pull request body must contain exactly one visible canonical "
            "FineSchema-Issue reference"
        )
    return int(matches[0])


def parse_webhook_json(body: bytes) -> Mapping[str, object]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GitHubAppContractError("webhook body must be UTF-8 JSON") from exc
    # Free-form collaborator text in an authenticated webhook is only trigger
    # material. Rejecting an unrelated title/body character here could prevent
    # an edit event from overwriting a prior success. Structural/resource
    # bounds remain global; each consumed authority field is validated by its
    # dedicated parser/model below.
    return _parse_json_object(
        text, "webhook body", validate_text_characters=False
    )


def parse_pull_request_context(
    payload: Mapping[str, object], fail_closed_issue_placeholder: bool = False
) -> PullRequestContext:
    try:
        installation = payload["installation"]
        repository = payload["repository"]
        pull_request = payload["pull_request"]
        action = payload["action"]
        number = payload["number"]
        if not isinstance(installation, dict) or not isinstance(repository, dict):
            raise TypeError
        if not isinstance(pull_request, dict):
            raise TypeError
        head = pull_request["head"]
        base = pull_request["base"]
        if not isinstance(head, dict) or not isinstance(base, dict):
            raise TypeError
        installation_id = installation["id"]
        repository_id = repository["id"]
        repository_name = repository["full_name"]
        head_sha = head["sha"]
        base_ref = base["ref"]
        base_sha = base["sha"]
    except (KeyError, TypeError) as exc:
        raise GitHubAppContractError("pull_request payload is missing required fields") from exc
    if not isinstance(installation_id, int) or isinstance(installation_id, bool):
        raise GitHubAppContractError("installation id must be an integer")
    if not isinstance(repository_id, int) or isinstance(
        repository_id, bool
    ) or repository_id <= 0:
        raise GitHubAppContractError("repository id must be a positive integer")
    try:
        issue_number = parse_issue_reference(pull_request.get("body", ""))
    except GitHubAppContractError:
        if not fail_closed_issue_placeholder:
            raise
        # A PR edit that removes/corrupts the link must still overwrite the
        # prior head-scoped success with a system failure. PR number is only a
        # positive, deterministic placeholder; it is never evaluated as Issue
        # authority on this path.
        issue_number = number
    return PullRequestContext(
        repository=repository_name,  # type: ignore[arg-type]
        repository_id=repository_id,
        installation_id=installation_id,
        number=number,  # type: ignore[arg-type]
        head_sha=head_sha,  # type: ignore[arg-type]
        base_ref=base_ref,  # type: ignore[arg-type]
        base_sha=base_sha,  # type: ignore[arg-type]
        action=action,  # type: ignore[arg-type]
        issue_number=issue_number,
    )


def parse_issue_event_context(
    payload: Mapping[str, object]
) -> Tuple[int, int, str, int, str]:
    try:
        installation = payload["installation"]
        repository = payload["repository"]
        issue = payload["issue"]
        if not isinstance(installation, dict) or not isinstance(repository, dict):
            raise TypeError
        if not isinstance(issue, dict):
            raise TypeError
        installation_id = installation["id"]
        repository_id = repository["id"]
        repository_name = repository["full_name"]
        issue_number = issue["number"]
        issue_body = issue.get("body", "")
    except (KeyError, TypeError) as exc:
        raise GitHubAppContractError("issues payload is missing required fields") from exc
    if not isinstance(installation_id, int) or isinstance(installation_id, bool):
        raise GitHubAppContractError("installation id must be an integer")
    if not isinstance(repository_id, int) or isinstance(
        repository_id, bool
    ) or repository_id <= 0:
        raise GitHubAppContractError("repository id must be a positive integer")
    if not isinstance(repository_name, str):
        raise GitHubAppContractError("repository full_name must be text")
    # Tenant.resolve and PullRequestContext perform the full repository check;
    # this lightweight event path still rejects malformed owner/name values.
    if _has_forbidden_text_character(repository_name):
        raise GitHubAppContractError("repository full_name contains unsafe characters")
    repository_name = repository_name.strip(" \t").lower()
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}",
        repository_name,
    ):
        raise GitHubAppContractError("invalid repository name")
    if not isinstance(issue_number, int) or isinstance(issue_number, bool) or issue_number <= 0:
        raise GitHubAppContractError("issue number must be positive")
    if issue_body is None:
        issue_body = ""
    # The event copy is deliberately not parsed or character-validated. It is
    # only a trigger and may be stale; the handler reads and validates the
    # current tenant-bound Issue while holding the publication lock.
    if not isinstance(issue_body, str):
        issue_body = ""
    return installation_id, repository_id, repository_name, issue_number, issue_body
