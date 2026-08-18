import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "calibrate_attention_language.py"
SPEC = importlib.util.spec_from_file_location("attention_calibration", MODULE_PATH)
cal = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(cal)


class CalibrationTests(unittest.TestCase):
    def minimal_cases(self):
        return [
            {
                "case_id": "resolve-one",
                "family": "resolve_subject",
                "form": "natural_question",
                "stimulus": "Resolve Cantor.",
                "expected_procedure_id": "attention.resolve_sop_subject",
                "expected_arguments": {"subject": "cantor"},
            },
            {
                "case_id": "identity-one",
                "family": "inspect_identity",
                "form": "key_value",
                "stimulus": "subject=cantor; claim=changed",
                "expected_procedure_id": "attention.inspect_identity_boundary",
                "expected_arguments": {"subject": "cantor", "claim": "changed"},
            },
            {
                "case_id": "transition-one",
                "family": "review_transition",
                "form": "json_like",
                "stimulus": "transition cantor from before to after",
                "expected_procedure_id": "attention.review_attention_transition",
                "expected_arguments": {
                    "subject": "cantor",
                    "before_frame": "before",
                    "after_frame": "after",
                },
            },
            {
                "case_id": "negative-one",
                "family": "negative",
                "form": "unrelated_question",
                "stimulus": "Weather?",
                "expected_procedure_id": None,
                "expected_arguments": None,
            },
        ]

    def corpus(self, cases=None):
        return {
            "profile": cal.CORPUS_PROFILE,
            "corpus_id": "38ad871d-6378-44f8-bbc2-37cb6cda8b7d",
            "designed_against_commit": cal.CHECKPOINT_COMMIT,
            "cases": cases if cases is not None else self.minimal_cases(),
        }

    def write_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def contract_snapshot(self):
        snapshot = json.loads(
            (MODULE_PATH.parent / "runtime_contract_snapshot.json").read_text(encoding="utf-8")
        )
        snapshot["catalogue_digest"] = "0" * 64
        snapshot["catalogue_file_sha256"] = "2" * 64
        return snapshot

    def make_environment(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        runtime = root / "runtime"
        runtime.mkdir()
        for relative in ("python.exe", "controller.py", "config.json"):
            (runtime / relative).write_text("fixture", encoding="utf-8")
        corpus_path = root / "held_out_cases.json"
        self.write_json(corpus_path, self.corpus())
        self.write_json(root / "runtime_contract_snapshot.json", self.contract_snapshot())
        marker = root / "marker.txt"
        marker.write_text("deployment", encoding="utf-8")
        deployment = {
            "profile": cal.DEPLOYMENT_PROFILE,
            "files": [
                {
                    "path": "marker.txt",
                    "bytes": marker.stat().st_size,
                    "sha256": cal.sha256_file(marker),
                }
            ],
        }
        deployment_path = root / "deployment_manifest.json"
        deployment_path.write_bytes(cal.canonical_json(deployment) + b"\n")
        config = {
            "profile": cal.CONFIG_PROFILE,
            "checkpoint_commit": cal.CHECKPOINT_COMMIT,
            "corpus_design_commit": cal.CHECKPOINT_COMMIT,
            "corpus": "held_out_cases.json",
            "contract_snapshot": "runtime_contract_snapshot.json",
            "deployment_manifest": "deployment_manifest.json",
            "deployment_manifest_sha256": cal.sha256_file(deployment_path),
            "evidence_directory": "evidence",
            "runtime": {
                "root": str(runtime.resolve()),
                "python": "python.exe",
                "controller": "controller.py",
                "config": "config.json",
                "timeout_seconds": 5,
                "expected_catalogue_digest": "0" * 64,
                "expected_deployment_manifest_sha256": "1" * 64,
                "expected_procedures": list(cal.PROCEDURE_ARGUMENTS),
            },
        }
        config_path = root / "config.json"
        self.write_json(config_path, config)
        return config_path, config

    def health_result(self):
        return {
            "status": "healthy",
            "catalogue_digest": "0" * 64,
            "procedures": list(cal.PROCEDURE_ARGUMENTS),
            "deployment": {"manifest_sha256": "1" * 64, "file_count": 10},
            "needle": {"package_version": "2.0.6"},
            "llama": {"status": "ok"},
        }

    def test_repository_corpus_is_valid_and_has_declared_coverage(self):
        corpus, digest, raw = cal.validate_corpus(MODULE_PATH.parent / "held_out_cases.json")
        self.assertEqual(len(corpus["cases"]), 36)
        self.assertEqual(digest, cal.sha256_bytes(raw))
        self.assertEqual({case["family"] for case in corpus["cases"]}, set(cal.FAMILY_PROCEDURE))
        self.assertGreaterEqual(len({case["form"] for case in corpus["cases"]}), 3)

    def test_active_corpus_compiles_against_pinned_snapshot(self):
        root = MODULE_PATH.parent
        config = json.loads((root / "config.json").read_text(encoding="utf-8"))
        snapshot = cal.load_contract_snapshot(root, config)
        corpus, _digest, _raw = cal.validate_corpus(
            root / config["corpus"], config["corpus_design_commit"], snapshot["schemas"]
        )
        self.assertEqual(corpus["profile"], cal.CORPUS_PROFILE_V2)
        self.assertEqual(len(corpus["cases"]), 36)
        self.assertEqual(
            {case["expected_arguments"]["subject"] for case in corpus["cases"] if case["expected_arguments"]},
            {"cantor"},
        )

    def test_runtime_and_corpus_design_checkpoints_are_independent(self):
        with tempfile.TemporaryDirectory() as folder:
            config_path, config = self.make_environment(Path(folder))
            config["checkpoint_commit"] = "a" * 40
            config["corpus_design_commit"] = cal.CHECKPOINT_COMMIT
            self.write_json(config_path, config)
            _root, loaded = cal.load_config(config_path)
            snapshot = cal.load_contract_snapshot(config_path.parent, loaded)
            corpus, _digest, _raw = cal.validate_corpus(
                config_path.parent / loaded["corpus"],
                loaded["corpus_design_commit"],
                snapshot["schemas"],
            )
            self.assertEqual("a" * 40, loaded["checkpoint_commit"])
            self.assertEqual(cal.CHECKPOINT_COMMIT, corpus["designed_against_commit"])

    def test_schema_compiler_rejects_unsupported_expected_subject(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "corpus.json"
            value = self.corpus()
            value["cases"][0]["expected_arguments"]["subject"] = "weaver"
            self.write_json(path, value)
            config_path, config = self.make_environment(root / "environment")
            snapshot = cal.load_contract_snapshot(config_path.parent, config)
            with self.assertRaises(cal.CalibrationFault) as caught:
                cal.validate_corpus(path, cal.CHECKPOINT_COMMIT, snapshot["schemas"])
            self.assertEqual(caught.exception.code, "corpus_schema_mismatch")

    def test_contract_snapshot_rejects_catalogue_and_schema_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config_path, config = self.make_environment(root)
            snapshot_path = root / "runtime_contract_snapshot.json"
            value = self.contract_snapshot()
            value["catalogue_digest"] = "f" * 64
            self.write_json(snapshot_path, value)
            with self.assertRaises(cal.CalibrationFault) as caught:
                cal.load_contract_snapshot(root, config)
            self.assertEqual(caught.exception.code, "contract_snapshot_mismatch")
            value["catalogue_digest"] = "0" * 64
            value["procedures"][0]["input_schema"]["properties"]["subject"]["enum"] = ["weaver"]
            self.write_json(snapshot_path, value)
            snapshot = cal.load_contract_snapshot(root, config)
            with self.assertRaises(cal.CalibrationFault) as caught:
                cal.validate_corpus(root / "held_out_cases.json", cal.CHECKPOINT_COMMIT, snapshot["schemas"])
            self.assertEqual(caught.exception.code, "corpus_schema_mismatch")
            self.assertTrue(config_path.is_file())

    def test_corpus_rejects_duplicate_case_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "corpus.json"
            cases = self.minimal_cases()
            cases[1]["case_id"] = cases[0]["case_id"]
            self.write_json(path, self.corpus(cases))
            with self.assertRaisesRegex(cal.CalibrationFault, "duplicate case_id"):
                cal.validate_corpus(path)

    def test_corpus_rejects_checkpoint_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "corpus.json"
            value = self.corpus()
            value["designed_against_commit"] = "f" * 40
            self.write_json(path, value)
            with self.assertRaises(cal.CalibrationFault) as caught:
                cal.validate_corpus(path)
            self.assertEqual(caught.exception.code, "corpus_checkpoint_mismatch")

    def test_corpus_rejects_unknown_fields_and_missing_coverage(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "corpus.json"
            value = self.corpus()
            value["extra"] = True
            self.write_json(path, value)
            with self.assertRaises(cal.CalibrationFault) as caught:
                cal.validate_corpus(path)
            self.assertEqual(caught.exception.code, "corpus_invalid")
            self.write_json(path, self.corpus(self.minimal_cases()[:3]))
            with self.assertRaises(cal.CalibrationFault) as caught:
                cal.validate_corpus(path)
            self.assertEqual(caught.exception.code, "corpus_coverage_missing")

    def test_json_duplicate_key_is_rejected(self):
        with self.assertRaises(cal.CalibrationFault) as caught:
            cal.parse_json_bytes(b'{"a":1,"a":2}', "bad_json")
        self.assertEqual(caught.exception.code, "json_duplicate_key")

    def test_route_command_has_one_route_only_process_shape(self):
        with tempfile.TemporaryDirectory() as folder:
            config_path, config = self.make_environment(Path(folder))
            command = cal.build_runtime_command(config, "run", "literal ; $() data")
            self.assertEqual(command[-3:], ["--text", "literal ; $() data", "--route-only"])
            self.assertEqual(command.count("run"), 1)
            self.assertEqual(len(command), 8)
            self.assertTrue(config_path.is_file())

    def test_exact_argument_mismatch_and_wrong_route_are_distinct(self):
        case = self.minimal_cases()[0]
        base = {
            "status": "route_selected",
            "run_id": "b7c0cd64-dbea-49dd-9150-6639f3ce9f0b",
            "procedure_id": "attention.resolve_sop_subject",
            "arguments": {"subject": "cantor"},
            "needle_confidence": 0.8,
        }
        self.assertEqual(cal.normalize_route_observation(case, 0, base)["disposition"], "exact_match")
        mismatch = {**base, "arguments": {"subject": "cantor subject"}}
        self.assertEqual(
            cal.normalize_route_observation(case, 0, mismatch)["disposition"],
            "procedure_match_argument_mismatch",
        )
        wrong = {
            **base,
            "procedure_id": "attention.inspect_identity_boundary",
            "arguments": {"subject": "cantor", "claim": "changed"},
        }
        self.assertEqual(cal.normalize_route_observation(case, 0, wrong)["disposition"], "wrong_procedure")

    def test_positive_and_negative_refusal_are_distinct(self):
        fault = {
            "status": "fault",
            "fault": {"code": "no_procedure_selected", "detail": {"needle_confidence": 0.98}},
        }
        positive = cal.normalize_route_observation(self.minimal_cases()[0], 2, fault)
        negative = cal.normalize_route_observation(self.minimal_cases()[-1], 2, fault)
        self.assertEqual(positive["disposition"], "positive_refusal")
        self.assertEqual(negative["disposition"], "correct_negative_refusal")
        self.assertEqual(negative["needle_confidence"], 0.98)
        grounded_fault = {
            "status": "fault",
            "fault": {"code": "needle_argument_ungrounded", "detail": {"needle_confidence": 0.9}},
        }
        grounded_negative = cal.normalize_route_observation(
            self.minimal_cases()[-1], 2, grounded_fault
        )
        self.assertEqual(grounded_negative["disposition"], "correct_negative_refusal")
        binding_fault = {
            "status": "fault",
            "fault": {
                "code": "needle_argument_binding_mismatch",
                "detail": {"needle_confidence": 0.8},
            },
        }
        binding_positive = cal.normalize_route_observation(
            self.minimal_cases()[0], 2, binding_fault
        )
        self.assertEqual(binding_positive["disposition"], "positive_refusal")
        self.assertEqual(binding_positive["needle_confidence"], 0.8)

    def test_negative_call_and_nonselection_fault_are_not_refusals(self):
        selected = {
            "status": "route_selected",
            "run_id": "b7c0cd64-dbea-49dd-9150-6639f3ce9f0b",
            "procedure_id": "attention.resolve_sop_subject",
            "arguments": {"subject": "weather"},
            "needle_confidence": 0.9,
        }
        self.assertEqual(
            cal.normalize_route_observation(self.minimal_cases()[-1], 0, selected)["disposition"],
            "unexpected_negative_call",
        )
        infrastructure = {"status": "fault", "fault": {"code": "needle_selection_timeout"}}
        self.assertEqual(
            cal.normalize_route_observation(self.minimal_cases()[0], 2, infrastructure)["disposition"],
            "infrastructure_fault",
        )

    def test_machine_result_rejects_malformed_and_post_selection_content(self):
        with self.assertRaises(cal.CalibrationFault):
            cal.parse_machine_result("diagnostic\n{}")
        with self.assertRaises(cal.CalibrationFault) as caught:
            cal.parse_machine_result('{"status":"route_selected","cantor_result":{}}')
        self.assertEqual(caught.exception.code, "route_only_boundary_breached")

    def test_report_exposes_counts_ratios_confusion_forms_and_confidence(self):
        cases = self.minimal_cases()
        selected = [
            {
                "status": "route_selected",
                "run_id": "b7c0cd64-dbea-49dd-9150-6639f3ce9f0b",
                "procedure_id": cases[0]["expected_procedure_id"],
                "arguments": cases[0]["expected_arguments"],
                "needle_confidence": 0.8,
            },
            {"status": "fault", "fault": {"code": "low_selection_confidence"}},
            {
                "status": "route_selected",
                "run_id": "9373c007-84bd-47b6-8f8e-f0ad653a78be",
                "procedure_id": cases[2]["expected_procedure_id"],
                "arguments": {**cases[2]["expected_arguments"], "after_frame": "different"},
                "needle_confidence": 0.7,
            },
            {"status": "fault", "fault": {"code": "no_procedure_selected"}},
        ]
        observations = [
            cal.normalize_route_observation(case, 0 if value["status"] == "route_selected" else 2, value)
            for case, value in zip(cases, selected)
        ]
        report = cal.build_report(observations)
        self.assertEqual(report["exact_accuracy"], {"numerator": 1, "denominator": 3, "ratio": 0.333333})
        self.assertEqual(report["procedure_accuracy"]["numerator"], 2)
        self.assertEqual(report["negative_specificity"]["ratio"], 1.0)
        self.assertIn("natural_question", report["by_form"])
        self.assertTrue(report["confusion"])
        self.assertEqual(report["confidence_by_disposition"]["exact_match"]["mean"], 0.8)

    def test_runtime_health_is_exactly_identity_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            _path, config = self.make_environment(Path(folder))

            def runner(command, timeout):
                self.assertEqual(command[-1], "health")
                return 0, json.dumps(self.health_result()), ""

            result = cal.verify_runtime_health(config, runner)
            self.assertEqual(result["deployment_manifest_sha256"], "1" * 64)
            changed = self.health_result()
            changed["catalogue_digest"] = "f" * 64
            with self.assertRaises(cal.CalibrationFault) as caught:
                cal.verify_runtime_health(config, lambda _c, _t: (0, json.dumps(changed), ""))
            self.assertEqual(caught.exception.code, "runtime_identity_mismatch")

    def test_subprocess_timeout_is_typed(self):
        with mock.patch.object(
            subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["fixture"], timeout=1),
        ):
            with self.assertRaises(cal.CalibrationFault) as caught:
                cal.subprocess_runner(["fixture"], 1)
        self.assertEqual(caught.exception.code, "runtime_timeout")

    def test_deployment_rejects_partial_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            _path, config = self.make_environment(root)
            cal.verify_deployment(root, config)
            (root / "marker.txt").write_text("changed", encoding="utf-8")
            with self.assertRaises(cal.CalibrationFault) as caught:
                cal.verify_deployment(root, config)
            self.assertEqual(caught.exception.code, "deployment_file_mismatch")

    def test_full_fake_calibration_and_strict_evidence_verification(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config_path, _config = self.make_environment(root)
            cases = self.minimal_cases()
            by_stimulus = {case["stimulus"]: case for case in cases}

            def runner(command, timeout):
                if command[-1] == "health":
                    return 0, json.dumps(self.health_result()), ""
                self.assertEqual(command[-1], "--route-only")
                case = by_stimulus[command[-2]]
                if case["expected_procedure_id"] is None:
                    return 2, json.dumps(
                        {"status": "fault", "fault": {"code": "no_procedure_selected"}}
                    ), ""
                return 0, json.dumps(
                    {
                        "status": "route_selected",
                        "run_id": "b7c0cd64-dbea-49dd-9150-6639f3ce9f0b",
                        "procedure_id": case["expected_procedure_id"],
                        "arguments": case["expected_arguments"],
                        "needle_confidence": 0.75,
                    }
                ), ""

            result = cal.execute_calibration(config_path, runner)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["report"]["exact_accuracy"]["ratio"], 1.0)
            verified = cal.verify_evidence(config_path, result["calibration_id"])
            self.assertEqual(verified["status"], "verified")
            evidence = root / "evidence" / result["calibration_id"]
            corpus_record = json.loads(
                (evidence / "00_corpus.json").read_text(encoding="utf-8")
            )
            self.assertEqual(cal.CHECKPOINT_COMMIT, corpus_record["checkpoint_commit"])
            self.assertEqual(
                cal.CHECKPOINT_COMMIT, corpus_record["corpus_design_commit"]
            )
            (evidence / "extra.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(cal.CalibrationFault) as caught:
                cal.verify_evidence(config_path, result["calibration_id"])
            self.assertEqual(caught.exception.code, "evidence_file_set_mismatch")

    def test_infrastructure_fault_stops_remaining_cases_and_publishes_incomplete(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config_path, _config = self.make_environment(root)
            calls = 0

            def runner(command, timeout):
                nonlocal calls
                if command[-1] == "health":
                    return 0, json.dumps(self.health_result()), ""
                calls += 1
                return 2, json.dumps(
                    {"status": "fault", "fault": {"code": "needle_selection_timeout"}}
                ), ""

            result = cal.execute_calibration(config_path, runner)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["observed_cases"], 1)
            self.assertEqual(calls, 1)
            verified = cal.verify_evidence(config_path, result["calibration_id"])
            self.assertEqual(verified["evidence_status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
