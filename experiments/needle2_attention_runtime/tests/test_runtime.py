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
        procedure, arguments, _ = runtime.select_procedure(
            catalogue, response, 0.65, "What is Cantor?"
        )
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
            runtime.select_procedure(catalogue, base, 0.65, "What is Cantor?")
        unknown = copy.deepcopy(base)
        unknown["confidence"] = 0.9
        unknown["function_calls"][0]["name"] = "unregistered"
        with self.assertRaisesRegex(runtime.RuntimeFault, "unregistered"):
            runtime.select_procedure(catalogue, unknown, 0.65, "What is Cantor?")
        multiple = copy.deepcopy(base)
        multiple["confidence"] = 0.9
        multiple["function_calls"].append(copy.deepcopy(multiple["function_calls"][0]))
        with self.assertRaisesRegex(runtime.RuntimeFault, "exactly one"):
            runtime.select_procedure(catalogue, multiple, 0.65, "What is Cantor?")

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
            runtime.select_procedure(catalogue, failed, 0.65, "What is Cantor?")
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
            runtime.select_procedure(catalogue, ungrounded, 0.65, "What is Cantor?")

    def test_grounding_normalization_accepts_case_unicode_whitespace_and_delimiters(self):
        self.assertTrue(runtime.grounded_literal_phrase('subject: "CANTOR".', "cantor"))
        self.assertTrue(runtime.grounded_literal_phrase("before_frame: signed\tquery", "signed query"))
        self.assertTrue(runtime.grounded_literal_phrase("Ｃａｎｔｏｒ boundary", "cantor"))
        self.assertTrue(runtime.grounded_literal_phrase("claim=unsigned oracle;", "unsigned oracle"))

    def test_grounding_rejects_absence_and_larger_word_substrings(self):
        self.assertFalse(runtime.grounded_literal_phrase("subject: weaver", "cantor"))
        self.assertFalse(runtime.grounded_literal_phrase("cantorian mapping", "cantor"))
        self.assertFalse(runtime.grounded_literal_phrase("recantorized mapping", "cantor"))
        self.assertFalse(runtime.grounded_literal_phrase("only whitespace", " \t "))

    def test_grounding_checks_every_field_and_discloses_names_only(self):
        arguments = {
            "subject": "cantor",
            "before_frame": "signed query",
            "after_frame": "unsigned authority",
        }
        with self.assertRaises(runtime.RuntimeFault) as caught:
            runtime.enforce_argument_grounding(
                "Cantor moved from something else to unsigned authority", arguments
            )
        self.assertEqual("needle_argument_ungrounded", caught.exception.code)
        self.assertEqual(["before_frame"], caught.exception.detail)
        self.assertNotIn("signed query", str(caught.exception.as_dict()))

    def test_selection_rejects_schema_valid_subject_absent_from_caller(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        response = {
            "type": "call",
            "success": True,
            "error": None,
            "confidence": 0.96,
            "function_calls": [
                {"name": "resolve_sop_subject", "arguments": {"subject": "cantor"}}
            ],
        }
        with self.assertRaises(runtime.RuntimeFault) as caught:
            runtime.select_procedure(catalogue, response, 0.65, "Resolve the SOP subject Weaver.")
        self.assertEqual("needle_argument_ungrounded", caught.exception.code)
        self.assertEqual(["subject"], caught.exception.detail)

    def test_grounding_preserves_original_schema_valid_argument_values(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        response = {
            "type": "call",
            "success": True,
            "error": None,
            "confidence": 0.91,
            "function_calls": [
                {
                    "name": "inspect_identity_boundary",
                    "arguments": {"subject": "cantor", "claim": "Signed  Query"},
                }
            ],
        }
        _procedure, arguments, _sanitized = runtime.select_procedure(
            catalogue, response, 0.65, "For CANTOR, inspect claim: Signed   Query."
        )
        self.assertEqual({"subject": "cantor", "claim": "Signed  Query"}, arguments)

    def test_delimited_declarations_accept_bounded_separator_and_value_forms(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        identity = catalogue.by_tool_name["inspect_identity_boundary"]
        parsed = runtime.parse_declared_arguments(
            'Context only; SUBJECT = "Cantor"; claim: Signed query.', identity
        )
        self.assertEqual({"subject": "Cantor", "claim": "Signed query"}, parsed)
        transition = catalogue.by_tool_name["review_attention_transition"]
        parsed = runtime.parse_declared_arguments(
            "subject: cantor\nbefore_frame='unsupported claim.'\nafter_frame: cited claim.",
            transition,
        )
        self.assertEqual(
            {
                "subject": "cantor",
                "before_frame": "unsupported claim.",
                "after_frame": "cited claim",
            },
            parsed,
        )

    def test_unlabeled_text_retains_fallback_and_partial_declaration_binds_locally(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        identity = catalogue.by_tool_name["inspect_identity_boundary"]
        self.assertIsNone(
            runtime.parse_declared_arguments("Inspect subject: cantor", identity)
        )
        self.assertEqual(
            {"subject": "cantor"},
            runtime.parse_declared_arguments("subject: cantor; inspect signed query", identity),
        )
        response = {
            "type": "call",
            "success": True,
            "error": None,
            "confidence": 0.9,
            "function_calls": [
                {
                    "name": "inspect_identity_boundary",
                    "arguments": {"subject": "cantor", "claim": "signed query"},
                }
            ],
        }
        procedure, arguments, _ = runtime.select_procedure(
            catalogue, response, 0.65, "Inspect subject: cantor for a signed query."
        )
        self.assertEqual("attention.inspect_identity_boundary", procedure["procedure_id"])
        self.assertEqual("signed query", arguments["claim"])

        mismatched = copy.deepcopy(response)
        mismatched["function_calls"][0]["arguments"]["claim"] = "signed"
        with self.assertRaises(runtime.RuntimeFault) as caught:
            runtime.select_procedure(
                catalogue,
                mismatched,
                0.65,
                "Inspect cantor; claim: signed query; the word signed is present.",
            )
        self.assertEqual("needle_argument_binding_mismatch", caught.exception.code)
        self.assertEqual(["claim"], caught.exception.detail)

    def test_complete_declarations_require_all_field_equality_and_hide_values(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        response = {
            "type": "call",
            "success": True,
            "error": None,
            "confidence": 0.81,
            "function_calls": [
                {
                    "name": "review_attention_transition",
                    "arguments": {
                        "subject": "cantor",
                        "before_frame": "unsupported",
                        "after_frame": "cited",
                    },
                }
            ],
        }
        stimulus = (
            "Attention transition review for cantor; before_frame: unsupported claim; "
            "after_frame: cited claim."
        )
        with self.assertRaises(runtime.RuntimeFault) as caught:
            runtime.select_procedure(catalogue, response, 0.65, stimulus)
        self.assertEqual("needle_argument_binding_mismatch", caught.exception.code)
        self.assertEqual(["after_frame", "before_frame"], caught.exception.detail)
        serialized = str(caught.exception.as_dict())
        self.assertNotIn("unsupported claim", serialized)
        self.assertNotIn("cited claim", serialized)

    def test_successful_exact_binding_preserves_selected_argument_bytes(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        response = {
            "type": "call",
            "success": True,
            "error": None,
            "confidence": 0.91,
            "function_calls": [
                {
                    "name": "inspect_identity_boundary",
                    "arguments": {"subject": "cantor", "claim": "Signed  Query"},
                }
            ],
        }
        _procedure, arguments, _ = runtime.select_procedure(
            catalogue,
            response,
            0.65,
            "subject: CANTOR; claim: Signed   Query.",
        )
        self.assertEqual({"subject": "cantor", "claim": "Signed  Query"}, arguments)

    def test_duplicate_selected_declaration_fails_even_when_set_is_incomplete(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        identity = catalogue.by_tool_name["inspect_identity_boundary"]
        with self.assertRaises(runtime.RuntimeFault) as caught:
            runtime.parse_declared_arguments(
                "subject: cantor; subject=weaver; no claim here", identity
            )
        self.assertEqual("needle_declaration_invalid", caught.exception.code)
        self.assertEqual(["subject"], caught.exception.detail)

    def test_json_declarations_accept_closed_exact_object_and_procedure_name(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        identity = catalogue.by_tool_name["inspect_identity_boundary"]
        stimulus = json.dumps(
            {
                "procedure": "inspect_identity_boundary",
                "subject": "cantor",
                "claim": "signed query",
            }
        )
        self.assertEqual(
            {"subject": "cantor", "claim": "signed query"},
            runtime.parse_declared_arguments(stimulus, identity),
        )

    def test_json_declarations_fail_closed_on_invalid_shapes(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        identity = catalogue.by_tool_name["inspect_identity_boundary"]
        invalid = {
            "duplicate": '{"subject":"cantor","subject":"weaver","claim":"x"}',
            "unknown": '{"subject":"cantor","claim":"x","effect":"yes"}',
            "incomplete": '{"subject":"cantor"}',
            "non_string": '{"subject":"cantor","claim":7}',
            "conflict": (
                '{"procedure":"resolve_sop_subject","subject":"cantor","claim":"x"}'
            ),
            "malformed": '{"subject":"cantor","claim":"x"',
        }
        for label, stimulus in invalid.items():
            with self.subTest(label=label):
                with self.assertRaises(runtime.RuntimeFault) as caught:
                    runtime.parse_declared_arguments(stimulus, identity)
                self.assertEqual("needle_declaration_invalid", caught.exception.code)

    def test_admission_account_distinguishes_literal_partial_and_json_surfaces(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        resolve = catalogue.by_tool_name["resolve_sop_subject"]
        literal = runtime.build_admission_account(
            "What is Cantor?", catalogue.digest, resolve, {"subject": "cantor"}
        )
        self.assertEqual(runtime.ADMISSION_ACCOUNT_PROFILE, literal["profile"])
        self.assertEqual("literal_only", literal["declaration_surface"])
        self.assertEqual([], literal["declared_fields"])
        self.assertEqual(["subject"], literal["undeclared_fields"])
        self.assertEqual("not_applicable", literal["gates"]["declared_binding"])

        identity = catalogue.by_tool_name["inspect_identity_boundary"]
        partial = runtime.build_admission_account(
            "Inspect cantor; claim: Highly Secret Value 8241.",
            catalogue.digest,
            identity,
            {"subject": "cantor", "claim": "Highly Secret Value 8241"},
        )
        self.assertEqual("delimited", partial["declaration_surface"])
        self.assertEqual(["claim"], partial["declared_fields"])
        self.assertEqual(["subject"], partial["undeclared_fields"])
        self.assertEqual("passed", partial["gates"]["declared_binding"])
        self.assertNotIn("Highly Secret Value 8241", json.dumps(partial))

        stimulus = json.dumps(
            {
                "procedure": "inspect_identity_boundary",
                "subject": "cantor",
                "claim": "closed claim",
            }
        )
        closed = runtime.build_admission_account(
            stimulus,
            catalogue.digest,
            identity,
            {"subject": "cantor", "claim": "closed claim"},
        )
        self.assertEqual("json", closed["declaration_surface"])
        self.assertEqual(["subject", "claim"], closed["declared_fields"])
        self.assertEqual([], closed["undeclared_fields"])

    def test_admission_account_is_deterministic_value_private_and_field_exact(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        identity = catalogue.by_tool_name["inspect_identity_boundary"]
        stimulus = "subject: cantor; claim: Private phrase 73919."
        arguments = {"subject": "cantor", "claim": "Private phrase 73919"}
        first = runtime.build_admission_account(
            stimulus, catalogue.digest, identity, arguments
        )
        second = runtime.build_admission_account(
            stimulus, catalogue.digest, identity, arguments
        )
        self.assertEqual(runtime.canonical_json(first), runtime.canonical_json(second))
        self.assertEqual(
            runtime.sha256_bytes(runtime.canonical_json(first)),
            runtime.sha256_bytes(runtime.canonical_json(second)),
        )
        serialized = json.dumps(first)
        self.assertNotIn("Private phrase 73919", serialized)
        self.assertNotIn(runtime.sha256_bytes(b"Private phrase 73919"), serialized)
        with self.assertRaises(runtime.RuntimeFault) as caught:
            runtime.build_admission_account(
                stimulus, catalogue.digest, identity, {"subject": "cantor"}
            )
        self.assertEqual("admission_account_invalid", caught.exception.code)

    def test_route_success_emits_account_and_rejection_does_not(self):
        catalogue = runtime.load_verified_catalogue(self.fixture_root, self.catalogue_path)
        admitted = {
            "type": "call",
            "success": True,
            "error": None,
            "confidence": 0.9,
            "function_calls": [
                {"name": "resolve_sop_subject", "arguments": {"subject": "cantor"}}
            ],
        }
        rejected = copy.deepcopy(admitted)
        rejected["function_calls"][0]["arguments"]["subject"] = "cantor"
        config = {
            "catalogue": "contracts/procedure_catalogue.json",
            "evidence_directory": "runs",
            "needle": {"minimum_confidence": 0.65},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(runtime, "load_config", return_value=(root, config)), mock.patch.object(
                runtime, "verify_deployment_manifest", return_value={}
            ), mock.patch.object(
                runtime, "load_verified_catalogue", return_value=catalogue
            ), mock.patch.object(
                runtime, "verify_runtime_artifacts", return_value={}
            ), mock.patch.object(
                runtime, "invoke_needle", return_value=admitted
            ):
                result = runtime.execute_run(
                    Path("unused.json"), "What is Cantor?", route_only=True
                )
            run_root = root / "runs" / result["run_id"]
            account = json.loads((run_root / "01_admission.json").read_text(encoding="utf-8"))
            self.assertEqual(account, result["admission_account"])
            self.assertEqual(
                runtime.sha256_bytes(runtime.canonical_json(account)),
                result["admission_account_digest"],
            )

            with mock.patch.object(runtime, "load_config", return_value=(root, config)), mock.patch.object(
                runtime, "verify_deployment_manifest", return_value={}
            ), mock.patch.object(
                runtime, "load_verified_catalogue", return_value=catalogue
            ), mock.patch.object(
                runtime, "verify_runtime_artifacts", return_value={}
            ), mock.patch.object(
                runtime, "invoke_needle", return_value=rejected
            ):
                with self.assertRaises(runtime.RuntimeFault):
                    runtime.execute_run(
                        Path("unused.json"), "Resolve the SOP subject Weaver.", route_only=True
                    )
            rejected_roots = [
                item for item in (root / "runs").iterdir() if item.name != result["run_id"]
            ]
            self.assertEqual(1, len(rejected_roots))
            self.assertFalse((rejected_roots[0] / "01_admission.json").exists())

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
