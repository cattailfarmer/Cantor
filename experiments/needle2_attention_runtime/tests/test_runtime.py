import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "cantor_needle_runtime.py"
SPEC = importlib.util.spec_from_file_location("cantor_needle_runtime", MODULE_PATH)
runtime = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = runtime
SPEC.loader.exec_module(runtime)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.fixture_root = Path(__file__).resolve().parents[1]
        self.catalogue_path = self.fixture_root / "contracts" / "procedure_catalogue.json"

    def test_catalogue_is_verified_and_deterministic(self):
        first = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        second = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        self.assertEqual(3, len(first.procedures))
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(64, len(first.digest))
        self.assertEqual(
            ["resolve_sop_subject", "inspect_identity_boundary", "review_attention_transition"],
            [item["name"] for item in first.tool_schemas()],
        )

    def test_catalogue_rejects_tampered_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "contracts").mkdir()
            catalogue = json.loads(self.catalogue_path.read_text(encoding="utf-8"))
            for item in catalogue["procedures"]:
                source = self.fixture_root / item["source_ref"]
                target = root / item["source_ref"]
                target.write_bytes(source.read_bytes())
            (root / catalogue["procedures"][0]["source_ref"]).write_text(
                "tampered", encoding="utf-8"
            )
            target_catalogue = root / "contracts" / "procedure_catalogue.json"
            target_catalogue.write_text(json.dumps(catalogue), encoding="utf-8")
            with self.assertRaisesRegex(runtime.RuntimeFault, "source digest"):
                runtime.load_verified_catalogue(root, target_catalogue)

    def test_catalogue_rejects_tampered_procedure_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "contracts").mkdir()
            catalogue = json.loads(self.catalogue_path.read_text(encoding="utf-8"))
            for item in catalogue["procedures"]:
                source = self.fixture_root / item["source_ref"]
                (root / item["source_ref"]).write_bytes(source.read_bytes())
            catalogue["procedures"][0]["description"] += " changed"
            target_catalogue = root / "contracts" / "procedure_catalogue.json"
            target_catalogue.write_text(json.dumps(catalogue), encoding="utf-8")
            with self.assertRaisesRegex(runtime.RuntimeFault, "procedure digest"):
                runtime.load_verified_catalogue(root, target_catalogue)

    def test_selection_accepts_one_known_call(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        response = {
            "type": "call",
            "success": True,
            "error": None,
            "confidence": 0.91,
            "function_calls": [
                {
                    "name": "resolve_sop_subject",
                    "arguments": {"subject": "cantor"},
                }
            ],
        }
        procedure, arguments, _ = runtime.select_procedure(catalogue, response, 0.65)
        self.assertEqual("attention.resolve_sop_subject", procedure["procedure_id"])
        self.assertEqual("cantor", arguments["subject"])

    def test_selection_rejects_low_confidence_unknown_and_multiple(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        base = {
            "type": "call",
            "success": True,
            "error": None,
            "confidence": 0.2,
            "function_calls": [
                {
                    "name": "resolve_sop_subject",
                    "arguments": {"subject": "cantor"},
                }
            ],
        }
        with self.assertRaisesRegex(runtime.RuntimeFault, "below"):
            runtime.select_procedure(catalogue, base, 0.65)
        unknown = copy.deepcopy(base)
        unknown["confidence"] = 0.9
        unknown["function_calls"][0]["name"] = "unregistered"
        with self.assertRaisesRegex(runtime.RuntimeFault, "unregistered"):
            runtime.select_procedure(catalogue, unknown, 0.65)
        multiple = copy.deepcopy(base)
        multiple["confidence"] = 0.9
        multiple["function_calls"].append(copy.deepcopy(multiple["function_calls"][0]))
        with self.assertRaisesRegex(runtime.RuntimeFault, "exactly one"):
            runtime.select_procedure(catalogue, multiple, 0.65)

    def test_selection_rejects_failed_or_ungrounded_generation(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        failed = {
            "type": "call",
            "success": False,
            "error": "truncated",
            "error_code": "truncated",
            "function_calls": [],
            "confidence": 0.0,
        }
        with self.assertRaisesRegex(runtime.RuntimeFault, "successful selection"):
            runtime.select_procedure(catalogue, failed, 0.65)
        ungrounded = {
            "type": "call",
            "success": True,
            "error": None,
            "confidence": 0.95,
            "validation": {"ungrounded": ["claim"], "negation": False},
            "function_calls": [
                {
                    "name": "resolve_sop_subject",
                    "arguments": {"subject": "cantor"},
                }
            ],
        }
        with self.assertRaisesRegex(runtime.RuntimeFault, "ungrounded"):
            runtime.select_procedure(catalogue, ungrounded, 0.65)

    def test_argument_schema_is_closed(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        schema = catalogue.by_tool_name["resolve_sop_subject"]["input_schema"]
        with self.assertRaisesRegex(runtime.RuntimeFault, "unknown"):
            runtime.validate_arguments(
                schema,
                {"subject": "cantor", "effects": "yes"},
            )

    def test_llama_second_pass_contains_no_tools(self):
        request = runtime.build_llama_request(
            "What is Cantor?",
            {"profile": runtime.FRAME_PROFILE},
            {"model": "local-reflection", "max_tokens": 256},
        )
        self.assertNotIn("tools", request)
        self.assertNotIn("tool_choice", request)
        self.assertNotIn("parallel_tool_calls", request)
        self.assertNotIn("thinking", request)
        self.assertEqual({"enable_thinking": False}, request["chat_template_kwargs"])
        self.assertEqual("none", request["reasoning_effort"])
        self.assertEqual(
            {"type": "json_object", "schema": runtime.ARTICULATION_SCHEMA},
            request["response_format"],
        )

    def test_structured_articulation_requires_canonical_dimensions(self):
        raw_articulation = {
            "conclusion": "conflicting",
            "findings": [
                {"dimension": "preserved", "statement": "Cantor remains the named subject."},
                {
                    "dimension": "conflicting",
                    "statement": "Unsigned authority conflicts with the signed fixture boundary.",
                },
            ],
        }
        response = {"choices": [{"message": {"content": json.dumps(raw_articulation)}}]}
        parsed = runtime.parse_articulation(response, "attention.inspect_identity_boundary")
        self.assertEqual(["Cantor remains the named subject."], parsed["preserved"])
        self.assertEqual(
            ["Unsigned authority conflicts with the signed fixture boundary."],
            parsed["conflicting"],
        )
        self.assertEqual([], parsed["unresolved"])

    def test_structured_articulation_rejects_extra_and_malformed_content(self):
        response = {"choices": [{"message": {"content": "not-json"}}]}
        with self.assertRaisesRegex(runtime.RuntimeFault, "not valid structured JSON"):
            runtime.parse_articulation(response, "attention.resolve_sop_subject")
        articulation = {
            "conclusion": "preserved",
            "findings": [{"dimension": "preserved", "statement": "statement"}],
        }
        articulation["extra"] = "not admitted"
        response["choices"][0]["message"]["content"] = json.dumps(articulation)
        with self.assertRaisesRegex(runtime.RuntimeFault, "not canonical"):
            runtime.parse_articulation(response, "attention.resolve_sop_subject")

    def test_attention_frame_omits_provider_irrelevant_proof_internals(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        procedure = catalogue.by_tool_name["resolve_sop_subject"]
        cantor_response = {
            "result": {
                "value": {
                    "resolved_subjects": ["unit:cantor_demo"],
                    "records": ["bulky record"],
                    "verified_quotes": [{"verified": True, "quote": "Cantor is a fixture."}],
                    "boundary_account": {"admitted": ["unit:cantor_demo"]},
                    "deterministic_contributions": ["bulky score trace"],
                    "proof": {"package_proofs": ["bulky proof"]},
                    "result_digest": {"algorithm": "sha256", "value": "a" * 64},
                }
            }
        }
        frame = runtime.build_attention_frame(
            catalogue, procedure, {"subject": "cantor"}, cantor_response, "What is Cantor?"
        )
        projection = frame["cantor_projection"]
        self.assertNotIn("records", projection)
        self.assertNotIn("deterministic_contributions", projection)
        self.assertNotIn("package_proofs", projection)

    def test_pinned_runtime_artifacts_reject_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime_dir = root / "runtime"
            runtime_dir.mkdir()
            artifacts = {
                "cantor_executable": runtime_dir / "cantor.exe",
                "cantor_environment": runtime_dir / "environment.json",
                "query.json": runtime_dir / "query.json",
            }
            for name, path in artifacts.items():
                path.write_bytes(name.encode("utf-8"))
            config = {
                "cantor_executable": "runtime/cantor.exe",
                "cantor_environment": "runtime/environment.json",
                "query_templates": {"query.json": "runtime/query.json"},
                "artifact_sha256": {
                    name: runtime.sha256_file(path) for name, path in artifacts.items()
                },
            }
            observed = runtime.verify_runtime_artifacts(root, config)
            self.assertEqual(config["artifact_sha256"], observed)
            artifacts["query.json"].write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(runtime.RuntimeFault, "digest does not match"):
                runtime.verify_runtime_artifacts(root, config)

    def test_deployment_manifest_rejects_partial_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deployed = root / "controller.py"
            deployed.write_text("original", encoding="utf-8")
            manifest = {
                "profile": "cantor-needle-deployment-manifest/0.1",
                "files": [
                    {
                        "path": "controller.py",
                        "bytes": deployed.stat().st_size,
                        "sha256": runtime.sha256_file(deployed),
                    }
                ],
            }
            manifest_path = root / "deployment_manifest.json"
            runtime.atomic_write_json(manifest_path, manifest)
            config = {
                "deployment_manifest": "deployment_manifest.json",
                "deployment_manifest_sha256": runtime.sha256_file(manifest_path),
            }
            self.assertEqual(1, runtime.verify_deployment_manifest(root, config)["file_count"])
            deployed.write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(runtime.RuntimeFault, "deployment file changed"):
                runtime.verify_deployment_manifest(root, config)

    def test_evidence_manifest_binds_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime.atomic_write_json(root / "00_input.json", {"stimulus": "test"})
            runtime.atomic_write_json(root / "result.json", {"status": "success"})
            runtime.write_evidence_manifest(root, "run:test", "success")
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(runtime.EVIDENCE_PROFILE, manifest["profile"])
            self.assertEqual(["00_input.json", "result.json"], [x["name"] for x in manifest["files"]])
            self.assertTrue(all(len(x["sha256"]) == 64 for x in manifest["files"]))

    def test_evidence_verifier_accepts_bound_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_id = "11111111-1111-4111-8111-111111111111"
            run_root = root / run_id
            runtime.atomic_write_json(run_root / "00_input.json", {"stimulus": "test"})
            runtime.atomic_write_json(
                run_root / "result.json", {"run_id": run_id, "status": "route_selected"}
            )
            runtime.write_evidence_manifest(run_root, run_id, "route_selected")
            result = runtime.verify_evidence_directory(root, run_id, "run")
            self.assertEqual("verified", result["status"])
            self.assertEqual("route_selected", result["recorded_status"])

    def test_evidence_verifier_rejects_tamper_and_extra_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_id = "22222222-2222-4222-8222-222222222222"
            run_root = root / run_id
            runtime.atomic_write_json(
                run_root / "result.json", {"run_id": run_id, "status": "fault"}
            )
            runtime.write_evidence_manifest(run_root, run_id, "fault")
            runtime.atomic_write_json(run_root / "extra.json", {"not": "manifested"})
            with self.assertRaisesRegex(runtime.RuntimeFault, "unmanifested"):
                runtime.verify_evidence_directory(root, run_id, "run")
            (run_root / "extra.json").unlink()
            (run_root / "result.json").write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(runtime.RuntimeFault, "changed"):
                runtime.verify_evidence_directory(root, run_id, "run")

    def test_evidence_verifier_rejects_noncanonical_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(runtime.RuntimeFault, "canonical UUID"):
                runtime.verify_evidence_directory(Path(directory), "../escape", "run")

    def test_needle_worker_rejects_noncanonical_envelope(self):
        with self.assertRaisesRegex(runtime.RuntimeFault, "unexpected Needle worker envelope"):
            runtime.run_needle_worker({"profile": "wrong"})

    def test_needle_parent_enforces_timeout(self):
        config = {
            "engine": "runtime/libneedle.dll",
            "engine_sha256": "a" * 64,
            "package_version": "2.0.6",
            "max_new_tokens": 256,
            "timeout_seconds": 1,
        }
        with mock.patch.object(runtime, "verify_needle_dependency", return_value={}), mock.patch.object(
            runtime, "resolve_contained", return_value=Path(__file__)
        ), mock.patch.object(
            runtime.subprocess,
            "run",
            side_effect=runtime.subprocess.TimeoutExpired(cmd="needle-worker", timeout=1),
        ):
            with self.assertRaisesRegex(runtime.RuntimeFault, "deadline"):
                runtime.invoke_needle(Path.cwd(), [], "What is Cantor?", config)

    def test_model_transport_preserves_declared_schema_order(self):
        value = {"name": "tool", "description": "use", "parameters": {"type": "object"}}
        encoded = runtime.model_transport_json(value).decode("utf-8")
        self.assertLess(encoded.index('"name"'), encoded.index('"description"'))
        self.assertLess(encoded.index('"description"'), encoded.index('"parameters"'))
        self.assertNotEqual(runtime.canonical_json(value), runtime.model_transport_json(value))

    def test_cantor_proof_binding_is_required(self):
        envelope = {
            "protocol_version": "cantor-protocol/0.1",
            "operation": "query",
            "status": "success",
            "exit_class": "success",
            "result": {
                "outcome": "query",
                "value": {
                    "faults": [],
                    "verified_quotes": [{"verified": True}],
                    "result_digest": {"algorithm": "sha256", "value": "a" * 64},
                },
            },
            "faults": [],
            "proof": {
                "expected_package_set_verified": True,
                "core_result_digest": {"algorithm": "sha256", "value": "b" * 64},
            },
        }
        with self.assertRaisesRegex(runtime.RuntimeFault, "binding"):
            runtime.verify_cantor_response(envelope)

    def test_evaluation_suite_is_bounded_and_canonical(self):
        suite = runtime.load_evaluation_suite(
            self.fixture_root, self.fixture_root / "evaluation_cases.json"
        )
        self.assertEqual("cantor-needle-evaluation-suite/0.1", suite["profile"])
        self.assertEqual(6, len(suite["cases"]))
        self.assertEqual(25, sum(item["trials"] for item in suite["cases"]))

    def test_evaluation_suite_rejects_path_escape(self):
        with self.assertRaisesRegex(runtime.RuntimeFault, "inside the runtime root"):
            runtime.load_evaluation_suite(self.fixture_root, self.fixture_root.parent / "outside.json")

    def test_evaluation_suite_rejects_digest_drift(self):
        config = {
            "evaluation_suite": "evaluation_cases.json",
            "evaluation_suite_sha256": "0" * 64,
        }
        with self.assertRaisesRegex(runtime.RuntimeFault, "digest does not match"):
            runtime.verify_evaluation_suite(self.fixture_root, config)

    def test_evaluation_observation_matching_is_exact(self):
        selected = {"status": "route_selected", "procedure_id": "attention.resolve_sop_subject"}
        self.assertTrue(runtime.evaluation_observation_matches(selected, dict(selected)))
        self.assertFalse(
            runtime.evaluation_observation_matches(
                selected,
                {"status": "route_selected", "procedure_id": "attention.inspect_identity_boundary"},
            )
        )
        selected_with_arguments = {
            **selected,
            "arguments": {"subject": "cantor"},
        }
        self.assertTrue(
            runtime.evaluation_observation_matches(
                selected_with_arguments,
                {**selected, "arguments": {"subject": "cantor"}},
            )
        )
        self.assertFalse(
            runtime.evaluation_observation_matches(
                selected_with_arguments,
                {**selected, "arguments": {"subject": "other"}},
            )
        )
        rejected = {"status": "fault", "fault_codes": ["no_procedure_selected"]}
        self.assertTrue(
            runtime.evaluation_observation_matches(
                rejected, {"status": "fault", "fault_code": "no_procedure_selected"}
            )
        )
        self.assertFalse(
            runtime.evaluation_observation_matches(
                rejected, {"status": "fault", "fault_code": "low_selection_confidence"}
            )
        )

    def test_calibration_summary_preserves_outcomes_and_confidence(self):
        observations = [
            {
                "status": "route_selected",
                "procedure_id": "attention.resolve_sop_subject",
                "needle_confidence": 0.8,
            },
            {
                "status": "route_selected",
                "procedure_id": "attention.resolve_sop_subject",
                "needle_confidence": 0.9,
            },
            {
                "status": "fault",
                "fault_code": "no_procedure_selected",
                "needle_confidence": None,
            },
        ]
        summary = runtime.summarize_evaluation_observations(observations)
        self.assertEqual(
            {"fault:no_procedure_selected": 1, "route:attention.resolve_sop_subject": 2},
            summary["outcomes"],
        )
        self.assertEqual(
            {"count": 2, "minimum": 0.8, "maximum": 0.9, "mean": 0.85},
            summary["confidence"],
        )

    def test_calibrated_confidence_rejects_nonfinite_bool_and_range(self):
        self.assertEqual(0.8154, runtime.calibrated_confidence(0.8154))
        self.assertIsNone(runtime.calibrated_confidence(True))
        self.assertIsNone(runtime.calibrated_confidence(float("nan")))
        self.assertIsNone(runtime.calibrated_confidence(1.1))

    def test_sanitize_removes_private_reasoning_fields_recursively(self):
        value = {
            "reasoning": "private",
            "choices": [{"message": {"content": "public", "reasoning_content": "private"}}],
        }
        clean = runtime.sanitize(value)
        self.assertNotIn("reasoning", clean)
        self.assertNotIn("reasoning_content", clean["choices"][0]["message"])


if __name__ == "__main__":
    unittest.main()
