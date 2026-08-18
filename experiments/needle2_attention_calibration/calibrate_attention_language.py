"""Measure a frozen Cantor Needle runtime through its route-only public boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


CONFIG_PROFILE = "cantor-attention-calibration-config/0.1"
CORPUS_PROFILE = "cantor-attention-language-corpus/0.1"
CORPUS_PROFILE_V2 = "cantor-attention-language-corpus/0.2"
SUPPORTED_CORPUS_PROFILES = {CORPUS_PROFILE, CORPUS_PROFILE_V2}
CONTRACT_SNAPSHOT_PROFILE = "cantor-attention-calibration-contract-snapshot/0.1"
DEPLOYMENT_PROFILE = "cantor-attention-calibration-deployment/0.1"
RESULT_PROFILE = "cantor-attention-calibration-result/0.1"
EVIDENCE_PROFILE = "cantor-attention-calibration-evidence/0.1"
MANIFEST_PROFILE = "cantor-attention-calibration-evidence-manifest/0.1"
CHECKPOINT_COMMIT = "b0e27bbff1874e8637cbec619f79e360dac38f14"
MAX_CORPUS_BYTES = 1_048_576
MAX_CASES = 128
MAX_STIMULUS_BYTES = 16_384
CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
FORM_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
CANONICAL_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

PROCEDURE_ARGUMENTS = {
    "attention.resolve_sop_subject": ("subject",),
    "attention.inspect_identity_boundary": ("subject", "claim"),
    "attention.review_attention_transition": (
        "subject",
        "before_frame",
        "after_frame",
    ),
}
FAMILY_PROCEDURE = {
    "resolve_subject": "attention.resolve_sop_subject",
    "inspect_identity": "attention.inspect_identity_boundary",
    "review_transition": "attention.review_attention_transition",
    "negative": None,
}
DISPOSITIONS = {
    "exact_match",
    "procedure_match_argument_mismatch",
    "wrong_procedure",
    "positive_refusal",
    "correct_negative_refusal",
    "unexpected_negative_call",
    "infrastructure_fault",
}
SELECTION_REFUSAL_CODES = {
    "ambiguous_procedure_selection",
    "effect_not_permitted",
    "invalid_arguments",
    "low_selection_confidence",
    "needle_generation_rejected",
    "needle_grounding_rejected",
    "needle_invalid_call",
    "needle_invalid_envelope",
    "needle_argument_binding_mismatch",
    "needle_argument_ungrounded",
    "needle_declaration_invalid",
    "no_procedure_selected",
    "uncalibrated_selection",
    "unknown_procedure",
}


class CalibrationFault(Exception):
    """A typed fail-closed calibration fault."""

    def __init__(self, code: str, message: str, detail: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.detail is not None:
            result["detail"] = self.detail
        return result


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(131_072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CalibrationFault("json_duplicate_key", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json_bytes(raw: bytes, code: str) -> Any:
    try:
        text = raw.decode("utf-8")
        return json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except CalibrationFault:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CalibrationFault(code, "input is not unique-key UTF-8 JSON") from exc


def require_exact_fields(
    value: Mapping[str, Any], expected: set[str], code: str, subject: str
) -> None:
    actual = set(value)
    if actual != expected:
        raise CalibrationFault(
            code,
            f"{subject} fields differ from the closed schema",
            {"missing": sorted(expected - actual), "extra": sorted(actual - expected)},
        )


def canonical_uuid(value: Any, code: str) -> str:
    if not isinstance(value, str) or not CANONICAL_UUID_RE.fullmatch(value):
        raise CalibrationFault(code, "identity is not a canonical lowercase UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise CalibrationFault(code, "identity is not a UUID") from exc
    if str(parsed) != value:
        raise CalibrationFault(code, "identity is not canonical")
    return value


def resolve_contained(root: Path, relative: Any, code: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise CalibrationFault(code, "path must be a nonempty relative path")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise CalibrationFault(code, "path escapes the calibration root") from exc
    return candidate


def read_bounded(path: Path, maximum: int, code: str) -> bytes:
    if not path.is_file():
        raise CalibrationFault(code, f"required file is missing: {path}")
    size = path.stat().st_size
    if size > maximum:
        raise CalibrationFault(code, f"file exceeds {maximum} bytes")
    return path.read_bytes()


def validate_arguments(procedure_id: str, value: Any, code: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise CalibrationFault(code, "expected_arguments must be an object")
    expected_keys = PROCEDURE_ARGUMENTS[procedure_id]
    require_exact_fields(value, set(expected_keys), code, "expected_arguments")
    normalized: dict[str, str] = {}
    for key in expected_keys:
        item = value[key]
        if not isinstance(item, str) or not item.strip():
            raise CalibrationFault(code, f"argument {key} must be nonempty text")
        if len(item.encode("utf-8")) > 4096:
            raise CalibrationFault(code, f"argument {key} exceeds bounds")
        normalized[key] = item
    return normalized


def validate_expected_against_schema(
    procedure_id: str, arguments: Mapping[str, str], schemas: Mapping[str, Mapping[str, Any]]
) -> None:
    schema = schemas.get(procedure_id)
    if schema is None:
        raise CalibrationFault("corpus_schema_mismatch", "expected procedure has no pinned schema")
    properties = schema["properties"]
    if set(arguments) != set(schema["required"]):
        raise CalibrationFault("corpus_schema_mismatch", "expected argument fields violate schema")
    for name, value in arguments.items():
        definition = properties[name]
        if "enum" in definition and value not in definition["enum"]:
            raise CalibrationFault(
                "corpus_schema_mismatch", f"expected argument {name} violates enum"
            )
        if len(value) < definition.get("minLength", 0) or len(value) > definition.get(
            "maxLength", MAX_STIMULUS_BYTES
        ):
            raise CalibrationFault(
                "corpus_schema_mismatch", f"expected argument {name} violates length"
            )


def validate_corpus(
    path: Path,
    expected_checkpoint: str = CHECKPOINT_COMMIT,
    contract_schemas: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[dict[str, Any], str, bytes]:
    raw = read_bounded(path, MAX_CORPUS_BYTES, "corpus_missing_or_large")
    value = parse_json_bytes(raw, "corpus_invalid_json")
    if not isinstance(value, dict):
        raise CalibrationFault("corpus_invalid", "corpus root must be an object")
    require_exact_fields(
        value,
        {"profile", "corpus_id", "designed_against_commit", "cases"},
        "corpus_invalid",
        "corpus",
    )
    if value["profile"] not in SUPPORTED_CORPUS_PROFILES:
        raise CalibrationFault("corpus_profile_mismatch", "corpus profile is unsupported")
    canonical_uuid(value["corpus_id"], "corpus_identity_invalid")
    if value["designed_against_commit"] != expected_checkpoint:
        raise CalibrationFault(
            "corpus_checkpoint_mismatch", "corpus was not designed against the frozen checkpoint"
        )
    cases = value["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise CalibrationFault("corpus_invalid", "cases must contain one through 128 records")
    seen: set[str] = set()
    families: Counter[str] = Counter()
    forms: set[str] = set()
    normalized_cases: list[dict[str, Any]] = []
    case_fields = {
        "case_id",
        "family",
        "form",
        "stimulus",
        "expected_procedure_id",
        "expected_arguments",
    }
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise CalibrationFault("corpus_case_invalid", f"case {index} is not an object")
        require_exact_fields(case, case_fields, "corpus_case_invalid", f"case {index}")
        case_id = case["case_id"]
        if not isinstance(case_id, str) or not CASE_ID_RE.fullmatch(case_id):
            raise CalibrationFault("corpus_case_invalid", f"case {index} has invalid case_id")
        if case_id in seen:
            raise CalibrationFault("corpus_duplicate_case", f"duplicate case_id: {case_id}")
        seen.add(case_id)
        family = case["family"]
        if family not in FAMILY_PROCEDURE:
            raise CalibrationFault("corpus_case_invalid", f"case {case_id} has unknown family")
        form = case["form"]
        if not isinstance(form, str) or not FORM_RE.fullmatch(form):
            raise CalibrationFault("corpus_case_invalid", f"case {case_id} has invalid form")
        stimulus = case["stimulus"]
        if not isinstance(stimulus, str) or not stimulus.strip():
            raise CalibrationFault("corpus_case_invalid", f"case {case_id} has empty stimulus")
        if len(stimulus.encode("utf-8")) > MAX_STIMULUS_BYTES:
            raise CalibrationFault("corpus_case_invalid", f"case {case_id} exceeds stimulus bound")
        expected_procedure = FAMILY_PROCEDURE[family]
        if case["expected_procedure_id"] != expected_procedure:
            raise CalibrationFault(
                "corpus_case_invalid", f"case {case_id} procedure conflicts with family"
            )
        if expected_procedure is None:
            if case["expected_arguments"] is not None:
                raise CalibrationFault(
                    "corpus_case_invalid", f"negative case {case_id} must have null arguments"
                )
            arguments = None
        else:
            arguments = validate_arguments(
                expected_procedure, case["expected_arguments"], "corpus_case_invalid"
            )
            if contract_schemas is not None:
                validate_expected_against_schema(expected_procedure, arguments, contract_schemas)
        families[family] += 1
        forms.add(form)
        normalized_cases.append(
            {
                "case_id": case_id,
                "family": family,
                "form": form,
                "stimulus": stimulus,
                "expected_procedure_id": expected_procedure,
                "expected_arguments": arguments,
            }
        )
    if set(families) != set(FAMILY_PROCEDURE):
        raise CalibrationFault("corpus_coverage_missing", "all four families are required")
    if len(forms) < 3:
        raise CalibrationFault("corpus_coverage_missing", "at least three ingress forms are required")
    normalized = {
        "profile": value["profile"],
        "corpus_id": value["corpus_id"],
        "designed_against_commit": expected_checkpoint,
        "cases": normalized_cases,
    }
    return normalized, sha256_bytes(raw), raw


def load_config(path: Path) -> tuple[Path, dict[str, Any]]:
    path = path.resolve()
    root = path.parent
    raw = read_bounded(path, 65_536, "config_missing_or_large")
    value = parse_json_bytes(raw, "config_invalid_json")
    if not isinstance(value, dict):
        raise CalibrationFault("config_invalid", "configuration root must be an object")
    require_exact_fields(
        value,
        {
            "profile",
            "checkpoint_commit",
            "corpus_design_commit",
            "corpus",
            "contract_snapshot",
            "deployment_manifest",
            "deployment_manifest_sha256",
            "evidence_directory",
            "runtime",
        },
        "config_invalid",
        "configuration",
    )
    if value["profile"] != CONFIG_PROFILE:
        raise CalibrationFault("config_invalid", "configuration profile is unsupported")
    checkpoint_commit = value["checkpoint_commit"]
    if not isinstance(checkpoint_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", checkpoint_commit):
        raise CalibrationFault("config_invalid", "checkpoint commit is invalid")
    corpus_design_commit = value["corpus_design_commit"]
    if not isinstance(corpus_design_commit, str) or not re.fullmatch(
        r"[0-9a-f]{40}", corpus_design_commit
    ):
        raise CalibrationFault("config_invalid", "corpus design commit is invalid")
    for field in ("corpus", "contract_snapshot", "deployment_manifest", "evidence_directory"):
        resolve_contained(root, value[field], "config_invalid_path")
    digest = value["deployment_manifest_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise CalibrationFault("config_invalid", "deployment manifest digest is invalid")
    runtime = value["runtime"]
    if not isinstance(runtime, dict):
        raise CalibrationFault("config_invalid", "runtime must be an object")
    require_exact_fields(
        runtime,
        {
            "root",
            "python",
            "controller",
            "config",
            "timeout_seconds",
            "expected_catalogue_digest",
            "expected_deployment_manifest_sha256",
            "expected_procedures",
        },
        "config_invalid",
        "runtime",
    )
    runtime_root = Path(runtime["root"])
    if not runtime_root.is_absolute():
        raise CalibrationFault("config_invalid", "runtime root must be absolute")
    for field in ("python", "controller", "config"):
        relative = runtime[field]
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            raise CalibrationFault("config_invalid", f"runtime {field} must be relative")
    timeout = runtime["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 120:
        raise CalibrationFault("config_invalid", "runtime timeout must be 1 through 120 seconds")
    for field in ("expected_catalogue_digest", "expected_deployment_manifest_sha256"):
        if not isinstance(runtime[field], str) or not re.fullmatch(
            r"[0-9a-f]{64}", runtime[field]
        ):
            raise CalibrationFault("config_invalid", f"runtime {field} is invalid")
    procedures = runtime["expected_procedures"]
    if procedures != list(PROCEDURE_ARGUMENTS):
        raise CalibrationFault("config_invalid", "expected procedure order or identity differs")
    return root, value


def validate_contract_schema(procedure_id: str, schema: Any) -> dict[str, Any]:
    if not isinstance(schema, dict):
        raise CalibrationFault("contract_snapshot_invalid", "input schema must be an object")
    require_exact_fields(
        schema,
        {"type", "additionalProperties", "properties", "required"},
        "contract_snapshot_invalid",
        "input schema",
    )
    if schema["type"] != "object" or schema["additionalProperties"] is not False:
        raise CalibrationFault("contract_snapshot_invalid", "input schema must be closed")
    properties = schema["properties"]
    required = schema["required"]
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise CalibrationFault("contract_snapshot_invalid", "schema properties or required invalid")
    if tuple(required) != PROCEDURE_ARGUMENTS[procedure_id] or set(properties) != set(required):
        raise CalibrationFault("contract_snapshot_invalid", "schema fields differ from procedure")
    clean_properties: dict[str, Any] = {}
    for name in required:
        definition = properties[name]
        if not isinstance(definition, dict) or definition.get("type") != "string":
            raise CalibrationFault("contract_snapshot_invalid", "only string fields are supported")
        allowed = {"type", "enum", "minLength", "maxLength", "description"}
        if set(definition) - allowed:
            raise CalibrationFault("contract_snapshot_invalid", "unsupported schema keyword")
        if "enum" in definition and (
            not isinstance(definition["enum"], list)
            or not definition["enum"]
            or any(not isinstance(item, str) for item in definition["enum"])
        ):
            raise CalibrationFault("contract_snapshot_invalid", "schema enum is invalid")
        for boundary in ("minLength", "maxLength"):
            if boundary in definition and (
                isinstance(definition[boundary], bool)
                or not isinstance(definition[boundary], int)
                or definition[boundary] < 0
            ):
                raise CalibrationFault("contract_snapshot_invalid", "schema length is invalid")
        clean_properties[name] = dict(definition)
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": clean_properties,
        "required": list(required),
    }


def load_contract_snapshot(root: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    path = resolve_contained(root, config["contract_snapshot"], "config_invalid_path")
    raw = read_bounded(path, 262_144, "contract_snapshot_missing")
    value = parse_json_bytes(raw, "contract_snapshot_invalid_json")
    if not isinstance(value, dict):
        raise CalibrationFault("contract_snapshot_invalid", "snapshot root must be an object")
    require_exact_fields(
        value,
        {"profile", "catalogue_digest", "catalogue_file_sha256", "procedures"},
        "contract_snapshot_invalid",
        "contract snapshot",
    )
    if value["profile"] != CONTRACT_SNAPSHOT_PROFILE:
        raise CalibrationFault("contract_snapshot_invalid", "snapshot profile is unsupported")
    if value["catalogue_digest"] != config["runtime"]["expected_catalogue_digest"]:
        raise CalibrationFault("contract_snapshot_mismatch", "snapshot catalogue digest differs")
    if not isinstance(value["catalogue_file_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", value["catalogue_file_sha256"]
    ):
        raise CalibrationFault("contract_snapshot_invalid", "catalogue file digest is invalid")
    procedures = value["procedures"]
    if not isinstance(procedures, list) or len(procedures) != len(PROCEDURE_ARGUMENTS):
        raise CalibrationFault("contract_snapshot_invalid", "procedure set is incomplete")
    schemas: dict[str, Any] = {}
    observed_order: list[str] = []
    for item in procedures:
        if not isinstance(item, dict):
            raise CalibrationFault("contract_snapshot_invalid", "procedure entry must be object")
        require_exact_fields(
            item,
            {"procedure_id", "input_schema"},
            "contract_snapshot_invalid",
            "procedure entry",
        )
        procedure_id = item["procedure_id"]
        if procedure_id not in PROCEDURE_ARGUMENTS or procedure_id in schemas:
            raise CalibrationFault("contract_snapshot_invalid", "procedure identity is invalid")
        observed_order.append(procedure_id)
        schemas[procedure_id] = validate_contract_schema(procedure_id, item["input_schema"])
    if observed_order != list(PROCEDURE_ARGUMENTS):
        raise CalibrationFault("contract_snapshot_invalid", "procedure order differs")
    return {
        "profile": CONTRACT_SNAPSHOT_PROFILE,
        "catalogue_digest": value["catalogue_digest"],
        "catalogue_file_sha256": value["catalogue_file_sha256"],
        "file_sha256": sha256_bytes(raw),
        "schemas": schemas,
    }


def verify_deployment(root: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    path = resolve_contained(root, config["deployment_manifest"], "config_invalid_path")
    raw = read_bounded(path, 262_144, "deployment_manifest_missing")
    observed_digest = sha256_bytes(raw)
    if observed_digest != config["deployment_manifest_sha256"]:
        raise CalibrationFault(
            "deployment_manifest_digest_mismatch", "calibration deployment manifest changed"
        )
    value = parse_json_bytes(raw, "deployment_manifest_invalid_json")
    if not isinstance(value, dict):
        raise CalibrationFault("deployment_manifest_invalid", "manifest root must be an object")
    require_exact_fields(
        value, {"profile", "files"}, "deployment_manifest_invalid", "deployment manifest"
    )
    if value["profile"] != DEPLOYMENT_PROFILE or not isinstance(value["files"], list):
        raise CalibrationFault("deployment_manifest_invalid", "manifest profile or files invalid")
    seen: set[str] = set()
    checked: list[dict[str, Any]] = []
    for entry in value["files"]:
        if not isinstance(entry, dict):
            raise CalibrationFault("deployment_manifest_invalid", "file entry must be object")
        require_exact_fields(
            entry, {"path", "bytes", "sha256"}, "deployment_manifest_invalid", "file entry"
        )
        relative = entry["path"]
        if relative in seen:
            raise CalibrationFault("deployment_manifest_invalid", "duplicate deployment path")
        seen.add(relative)
        file_path = resolve_contained(root, relative, "deployment_manifest_invalid")
        if not file_path.is_file():
            raise CalibrationFault("deployment_file_missing", f"missing deployment file: {relative}")
        size = file_path.stat().st_size
        digest = sha256_file(file_path)
        if entry["bytes"] != size or entry["sha256"] != digest:
            raise CalibrationFault("deployment_file_mismatch", f"changed deployment file: {relative}")
        checked.append({"path": relative, "bytes": size, "sha256": digest})
    if not checked:
        raise CalibrationFault("deployment_manifest_invalid", "manifest file set is empty")
    return {
        "profile": DEPLOYMENT_PROFILE,
        "manifest_sha256": observed_digest,
        "file_count": len(checked),
        "files": checked,
    }


def runtime_paths(config: Mapping[str, Any]) -> tuple[Path, Path, Path]:
    runtime = config["runtime"]
    root = Path(runtime["root"]).resolve()
    paths: list[Path] = []
    for field in ("python", "controller", "config"):
        candidate = (root / runtime[field]).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise CalibrationFault("runtime_path_invalid", f"runtime {field} escapes root") from exc
        if not candidate.is_file():
            raise CalibrationFault("runtime_file_missing", f"runtime {field} is missing")
        paths.append(candidate)
    return paths[0], paths[1], paths[2]


def build_runtime_command(config: Mapping[str, Any], command: str, stimulus: str | None = None) -> list[str]:
    python, controller, runtime_config = runtime_paths(config)
    result = [str(python), str(controller), "--config", str(runtime_config), command]
    if command == "run":
        if stimulus is None:
            raise CalibrationFault("internal_error", "run command requires stimulus")
        result.extend(["--text", stimulus, "--route-only"])
    elif stimulus is not None:
        raise CalibrationFault("internal_error", "stimulus supplied for non-run command")
    return result


Runner = Callable[[Sequence[str], int], tuple[int, str, str]]


def subprocess_runner(command: Sequence[str], timeout_seconds: int) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except subprocess.TimeoutExpired as exc:
        raise CalibrationFault("runtime_timeout", "runtime subprocess timed out") from exc
    except OSError as exc:
        raise CalibrationFault("runtime_launch_failed", "runtime subprocess could not start") from exc
    return completed.returncode, completed.stdout, completed.stderr


def parse_machine_result(stdout: str) -> dict[str, Any]:
    if len(stdout.encode("utf-8")) > 1_048_576:
        raise CalibrationFault("runtime_output_too_large", "runtime stdout exceeds bounds")
    try:
        value = json.loads(stdout.strip(), object_pairs_hook=reject_duplicate_keys)
    except CalibrationFault:
        raise
    except json.JSONDecodeError as exc:
        raise CalibrationFault("runtime_invalid_json", "runtime did not return one JSON value") from exc
    if not isinstance(value, dict):
        raise CalibrationFault("runtime_invalid_result", "runtime result must be an object")
    forbidden = {
        "cantor",
        "cantor_result",
        "attention_frame",
        "provider",
        "provider_response",
        "articulation",
    }
    if forbidden.intersection(value):
        raise CalibrationFault("route_only_boundary_breached", "post-selection stage appeared")
    return value


def verify_runtime_health(
    config: Mapping[str, Any], runner: Runner = subprocess_runner
) -> dict[str, Any]:
    timeout = config["runtime"]["timeout_seconds"]
    code, stdout, stderr = runner(build_runtime_command(config, "health"), timeout)
    if code != 0:
        raise CalibrationFault(
            "runtime_health_failed", "runtime health command failed", {"exit_code": code}
        )
    result = parse_machine_result(stdout)
    runtime = config["runtime"]
    if result.get("status") != "healthy":
        raise CalibrationFault("runtime_health_failed", "runtime did not report healthy")
    if result.get("catalogue_digest") != runtime["expected_catalogue_digest"]:
        raise CalibrationFault("runtime_identity_mismatch", "catalogue digest changed")
    if result.get("procedures") != runtime["expected_procedures"]:
        raise CalibrationFault("runtime_identity_mismatch", "procedure identity or order changed")
    deployment = result.get("deployment")
    if not isinstance(deployment, dict) or deployment.get("manifest_sha256") != runtime[
        "expected_deployment_manifest_sha256"
    ]:
        raise CalibrationFault("runtime_identity_mismatch", "runtime deployment manifest changed")
    return {
        "status": "healthy",
        "catalogue_digest": result["catalogue_digest"],
        "procedures": result["procedures"],
        "deployment_manifest_sha256": deployment["manifest_sha256"],
        "deployment_file_count": deployment.get("file_count"),
        "needle": result.get("needle"),
        "llama": result.get("llama"),
        "stderr_present": bool(stderr.strip()),
    }


def finite_confidence(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    converted = float(value)
    if not math.isfinite(converted) or not 0.0 <= converted <= 1.0:
        return None
    return converted


def normalize_route_observation(
    case: Mapping[str, Any], exit_code: int, result: Mapping[str, Any]
) -> dict[str, Any]:
    status = result.get("status")
    run_id: str | None = None
    observed_procedure: str | None = None
    observed_arguments: dict[str, Any] | None = None
    confidence = finite_confidence(result.get("needle_confidence"))
    fault_code: str | None = None
    if status == "route_selected":
        if exit_code != 0:
            raise CalibrationFault("runtime_result_inconsistent", "selected route has nonzero exit")
        run_id = canonical_uuid(result.get("run_id"), "runtime_result_invalid")
        observed_procedure = result.get("procedure_id")
        observed_arguments = result.get("arguments")
        if observed_procedure not in PROCEDURE_ARGUMENTS or not isinstance(observed_arguments, dict):
            raise CalibrationFault("runtime_result_invalid", "selected route shape is invalid")
        if confidence is None:
            raise CalibrationFault("runtime_result_invalid", "selected route lacks finite confidence")
    elif status == "fault":
        fault = result.get("fault")
        if not isinstance(fault, dict) or not isinstance(fault.get("code"), str):
            raise CalibrationFault("runtime_result_invalid", "fault result shape is invalid")
        fault_code = fault["code"]
        detail = fault.get("detail") if isinstance(fault.get("detail"), dict) else {}
        candidate_id = detail.get("run_id")
        if candidate_id is not None:
            run_id = canonical_uuid(candidate_id, "runtime_result_invalid")
        if confidence is None:
            confidence = finite_confidence(detail.get("needle_confidence"))
    else:
        raise CalibrationFault("runtime_result_invalid", "runtime status is not route-only")

    expected_procedure = case["expected_procedure_id"]
    if status == "route_selected":
        if expected_procedure is None:
            disposition = "unexpected_negative_call"
        elif observed_procedure != expected_procedure:
            disposition = "wrong_procedure"
        elif observed_arguments == case["expected_arguments"]:
            disposition = "exact_match"
        else:
            disposition = "procedure_match_argument_mismatch"
    elif fault_code in SELECTION_REFUSAL_CODES:
        disposition = (
            "correct_negative_refusal" if expected_procedure is None else "positive_refusal"
        )
    else:
        disposition = "infrastructure_fault"
    return {
        "case_id": case["case_id"],
        "family": case["family"],
        "form": case["form"],
        "expected_procedure_id": expected_procedure,
        "expected_arguments": case["expected_arguments"],
        "runtime_exit_code": exit_code,
        "run_id": run_id,
        "observed_status": status,
        "observed_procedure_id": observed_procedure,
        "observed_arguments": observed_arguments,
        "needle_confidence": confidence,
        "fault_code": fault_code,
        "disposition": disposition,
    }


def ratio_record(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "ratio": round(numerator / denominator, 6) if denominator else None,
    }


def confidence_summary(values: Sequence[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "minimum": None, "maximum": None, "median": None, "mean": None}
    return {
        "count": len(values),
        "minimum": round(min(values), 6),
        "maximum": round(max(values), 6),
        "median": round(statistics.median(values), 6),
        "mean": round(statistics.fmean(values), 6),
    }


def build_report(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not observations:
        raise CalibrationFault("report_invalid", "cannot report an empty observation set")
    dispositions = Counter(item["disposition"] for item in observations)
    if not set(dispositions).issubset(DISPOSITIONS):
        raise CalibrationFault("report_invalid", "unknown observation disposition")
    positives = [item for item in observations if item["expected_procedure_id"] is not None]
    negatives = [item for item in observations if item["expected_procedure_id"] is None]
    exact = sum(item["disposition"] == "exact_match" for item in positives)
    procedure_match = sum(
        item["disposition"] in {"exact_match", "procedure_match_argument_mismatch"}
        for item in positives
    )
    correct_negative = sum(
        item["disposition"] == "correct_negative_refusal" for item in negatives
    )
    by_family: dict[str, Any] = {}
    family_exact_ratios: list[float] = []
    for family in FAMILY_PROCEDURE:
        members = [item for item in observations if item["family"] == family]
        exact_count = sum(item["disposition"] == "exact_match" for item in members)
        procedure_count = sum(
            item["disposition"] in {"exact_match", "procedure_match_argument_mismatch"}
            for item in members
        )
        by_family[family] = {
            "count": len(members),
            "exact": ratio_record(exact_count, len(members)),
            "procedure_match": ratio_record(procedure_count, len(members)),
            "dispositions": dict(sorted(Counter(item["disposition"] for item in members).items())),
        }
        if family != "negative" and members:
            family_exact_ratios.append(exact_count / len(members))
    by_form: dict[str, Any] = {}
    grouped_forms: defaultdict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in observations:
        grouped_forms[item["form"]].append(item)
    for form in sorted(grouped_forms):
        members = grouped_forms[form]
        by_form[form] = {
            "count": len(members),
            "dispositions": dict(sorted(Counter(item["disposition"] for item in members).items())),
        }
    confusion: Counter[str] = Counter()
    confidence_by_disposition: defaultdict[str, list[float]] = defaultdict(list)
    for item in observations:
        expected = item["expected_procedure_id"] or "refusal"
        if item["observed_status"] == "route_selected":
            observed = item["observed_procedure_id"]
        elif item["disposition"] == "infrastructure_fault":
            observed = "infrastructure_fault"
        else:
            observed = "refusal"
        confusion[f"{expected} -> {observed}"] += 1
        confidence = item.get("needle_confidence")
        if confidence is not None:
            confidence_by_disposition[item["disposition"]].append(confidence)
    return {
        "case_count": len(observations),
        "positive_count": len(positives),
        "negative_count": len(negatives),
        "dispositions": dict(sorted(dispositions.items())),
        "exact_accuracy": ratio_record(exact, len(positives)),
        "procedure_accuracy": ratio_record(procedure_match, len(positives)),
        "negative_specificity": ratio_record(correct_negative, len(negatives)),
        "macro_family_exact": {
            "family_count": len(family_exact_ratios),
            "ratio": round(statistics.fmean(family_exact_ratios), 6)
            if family_exact_ratios
            else None,
        },
        "by_family": by_family,
        "by_form": by_form,
        "confusion": dict(sorted(confusion.items())),
        "confidence_by_disposition": {
            key: confidence_summary(values)
            for key, values in sorted(confidence_by_disposition.items())
        },
    }


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_json(value) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_evidence_manifest(root: Path, calibration_id: str, status: str) -> dict[str, Any]:
    expected_paths = ["00_corpus.json", "01_observations.json", "02_report.json"]
    files: list[dict[str, Any]] = []
    for relative in expected_paths:
        path = root / relative
        if not path.is_file():
            raise CalibrationFault("evidence_incomplete", f"missing evidence file: {relative}")
        files.append({"path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
    manifest = {
        "profile": MANIFEST_PROFILE,
        "calibration_id": calibration_id,
        "status": status,
        "files": files,
    }
    atomic_write_json(root / "manifest.json", manifest)
    return manifest


def verify_evidence_directory(root: Path, calibration_id: str) -> dict[str, Any]:
    canonical_uuid(calibration_id, "evidence_identity_invalid")
    if not root.is_dir():
        raise CalibrationFault("evidence_missing", "calibration evidence directory is missing")
    manifest_path = root / "manifest.json"
    manifest = parse_json_bytes(
        read_bounded(manifest_path, 262_144, "evidence_manifest_missing"),
        "evidence_manifest_invalid_json",
    )
    if not isinstance(manifest, dict):
        raise CalibrationFault("evidence_manifest_invalid", "manifest root must be object")
    require_exact_fields(
        manifest,
        {"profile", "calibration_id", "status", "files"},
        "evidence_manifest_invalid",
        "evidence manifest",
    )
    if manifest["profile"] != MANIFEST_PROFILE or manifest["calibration_id"] != calibration_id:
        raise CalibrationFault("evidence_manifest_invalid", "manifest identity mismatch")
    files = manifest["files"]
    if not isinstance(files, list) or len(files) != 3:
        raise CalibrationFault("evidence_manifest_invalid", "manifest must bind exactly three files")
    expected = {"00_corpus.json", "01_observations.json", "02_report.json"}
    actual_disk = {path.name for path in root.iterdir() if path.is_file()}
    if actual_disk != expected | {"manifest.json"}:
        raise CalibrationFault("evidence_file_set_mismatch", "evidence has missing or extra files")
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise CalibrationFault("evidence_manifest_invalid", "file entry must be object")
        require_exact_fields(
            entry, {"path", "bytes", "sha256"}, "evidence_manifest_invalid", "file entry"
        )
        relative = entry["path"]
        if relative not in expected or relative in seen:
            raise CalibrationFault("evidence_manifest_invalid", "file set is invalid")
        seen.add(relative)
        path = root / relative
        if path.stat().st_size != entry["bytes"] or sha256_file(path) != entry["sha256"]:
            raise CalibrationFault("evidence_file_mismatch", f"evidence changed: {relative}")
    corpus_record = parse_json_bytes((root / "00_corpus.json").read_bytes(), "evidence_invalid")
    observations = parse_json_bytes(
        (root / "01_observations.json").read_bytes(), "evidence_invalid"
    )
    report = parse_json_bytes((root / "02_report.json").read_bytes(), "evidence_invalid")
    for record in (corpus_record, observations, report):
        if not isinstance(record, dict) or record.get("calibration_id") != calibration_id:
            raise CalibrationFault("evidence_identity_mismatch", "evidence identity differs")
        if record.get("status") != manifest["status"]:
            raise CalibrationFault("evidence_status_mismatch", "evidence status differs")
    if observations.get("case_count") != len(observations.get("observations", [])):
        raise CalibrationFault("evidence_invalid", "observation count differs")
    if report.get("report", {}).get("case_count") != observations.get("case_count"):
        raise CalibrationFault("evidence_invalid", "report count differs")
    return {
        "profile": RESULT_PROFILE,
        "status": "verified",
        "calibration_id": calibration_id,
        "evidence_status": manifest["status"],
        "manifest_sha256": sha256_file(manifest_path),
        "files": files,
    }


def calibration_health(
    config_path: Path, runner: Runner = subprocess_runner
) -> dict[str, Any]:
    root, config = load_config(config_path)
    deployment = verify_deployment(root, config)
    snapshot = load_contract_snapshot(root, config)
    corpus_path = resolve_contained(root, config["corpus"], "config_invalid_path")
    corpus, corpus_sha256, _ = validate_corpus(
        corpus_path, config["corpus_design_commit"], snapshot["schemas"]
    )
    runtime = verify_runtime_health(config, runner)
    return {
        "profile": RESULT_PROFILE,
        "status": "healthy",
        "checkpoint_commit": config["checkpoint_commit"],
        "corpus_design_commit": config["corpus_design_commit"],
        "deployment": deployment,
        "corpus_id": corpus["corpus_id"],
        "corpus_sha256": corpus_sha256,
        "case_count": len(corpus["cases"]),
        "contract_snapshot_sha256": snapshot["file_sha256"],
        "runtime": runtime,
    }


def execute_calibration(
    config_path: Path, runner: Runner = subprocess_runner
) -> dict[str, Any]:
    started = time.time()
    root, config = load_config(config_path)
    deployment = verify_deployment(root, config)
    snapshot = load_contract_snapshot(root, config)
    corpus_path = resolve_contained(root, config["corpus"], "config_invalid_path")
    corpus, corpus_sha256, raw_corpus = validate_corpus(
        corpus_path, config["corpus_design_commit"], snapshot["schemas"]
    )
    runtime_health = verify_runtime_health(config, runner)
    calibration_id = str(uuid.uuid4())
    evidence_root = resolve_contained(root, config["evidence_directory"], "config_invalid_path")
    output_root = evidence_root / calibration_id
    if output_root.exists():
        raise CalibrationFault("evidence_collision", "calibration evidence identity already exists")
    status = "completed"
    observations: list[dict[str, Any]] = []
    infrastructure_fault: dict[str, Any] | None = None
    timeout = config["runtime"]["timeout_seconds"]
    for case in corpus["cases"]:
        try:
            command = build_runtime_command(config, "run", case["stimulus"])
            if command[-1] != "--route-only" or command.count("run") != 1:
                raise CalibrationFault("route_only_command_invalid", "route-only command is malformed")
            exit_code, stdout, _stderr = runner(command, timeout)
            machine_result = parse_machine_result(stdout)
            observation = normalize_route_observation(case, exit_code, machine_result)
            observations.append(observation)
            if observation["disposition"] == "infrastructure_fault":
                status = "incomplete"
                infrastructure_fault = {
                    "code": observation["fault_code"] or "runtime_infrastructure_fault",
                    "case_id": case["case_id"],
                }
                break
        except CalibrationFault as fault:
            status = "incomplete"
            infrastructure_fault = {**fault.as_dict(), "case_id": case["case_id"]}
            observations.append(
                {
                    "case_id": case["case_id"],
                    "family": case["family"],
                    "form": case["form"],
                    "expected_procedure_id": case["expected_procedure_id"],
                    "expected_arguments": case["expected_arguments"],
                    "runtime_exit_code": None,
                    "run_id": None,
                    "observed_status": "infrastructure_fault",
                    "observed_procedure_id": None,
                    "observed_arguments": None,
                    "needle_confidence": None,
                    "fault_code": fault.code,
                    "disposition": "infrastructure_fault",
                }
            )
            break
    report = build_report(observations)
    common = {"profile": EVIDENCE_PROFILE, "calibration_id": calibration_id, "status": status}
    atomic_write_json(
        output_root / "00_corpus.json",
        {
            **common,
            "checkpoint_commit": config["checkpoint_commit"],
            "corpus_design_commit": config["corpus_design_commit"],
            "corpus_id": corpus["corpus_id"],
            "corpus_raw_sha256": corpus_sha256,
            "corpus_raw_bytes": len(raw_corpus),
            "corpus": corpus,
            "deployment_manifest_sha256": deployment["manifest_sha256"],
            "contract_snapshot_sha256": snapshot["file_sha256"],
            "runtime_identity": runtime_health,
        },
    )
    atomic_write_json(
        output_root / "01_observations.json",
        {
            **common,
            "case_count": len(observations),
            "planned_case_count": len(corpus["cases"]),
            "infrastructure_fault": infrastructure_fault,
            "observations": observations,
        },
    )
    atomic_write_json(
        output_root / "02_report.json",
        {
            **common,
            "corpus_id": corpus["corpus_id"],
            "corpus_raw_sha256": corpus_sha256,
            "report": report,
            "elapsed_milliseconds": int((time.time() - started) * 1000),
            "limitations": [
                "same-project post-checkpoint corpus, not independent benchmark authorship",
                "single observation per prompt, not a variance estimate",
                "route-only learned selection and extraction, not semantic truth or final articulation quality",
                "results become evaluation history after this first execution",
            ],
        },
    )
    manifest = write_evidence_manifest(output_root, calibration_id, status)
    return {
        "profile": RESULT_PROFILE,
        "status": status,
        "calibration_id": calibration_id,
        "corpus_id": corpus["corpus_id"],
        "corpus_raw_sha256": corpus_sha256,
        "observed_cases": len(observations),
        "planned_cases": len(corpus["cases"]),
        "report": report,
        "manifest_sha256": sha256_bytes(canonical_json(manifest) + b"\n"),
    }


def verify_evidence(config_path: Path, calibration_id: str) -> dict[str, Any]:
    root, config = load_config(config_path)
    verify_deployment(root, config)
    evidence_root = resolve_contained(root, config["evidence_directory"], "config_invalid_path")
    return verify_evidence_directory(evidence_root / canonical_uuid(calibration_id, "evidence_identity_invalid"), calibration_id)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.json", help="calibration configuration")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("health", help="verify calibration and frozen runtime identity")
    subparsers.add_parser("run", help="execute the corpus once and archive observations")
    verify_parser = subparsers.add_parser("verify", help="verify one calibration evidence record")
    verify_parser.add_argument("--id", required=True, help="canonical calibration UUID")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config_path = Path(args.config)
        if args.command == "health":
            result = calibration_health(config_path)
        elif args.command == "run":
            result = execute_calibration(config_path)
        else:
            result = verify_evidence(config_path, args.id)
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
        return 0 if result.get("status") != "incomplete" else 4
    except CalibrationFault as fault:
        print(
            json.dumps(
                {"profile": RESULT_PROFILE, "status": "fault", "fault": fault.as_dict()},
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return 2
    except Exception:
        print(
            json.dumps(
                {
                    "profile": RESULT_PROFILE,
                    "status": "fault",
                    "fault": {"code": "internal_error", "message": "unexpected internal fault"},
                },
                separators=(",", ":"),
            )
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
