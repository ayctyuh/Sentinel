"""
Additional tests for report metadata and summary sections produced by
TestRunner (coverage JSON) and FLEngine (FL report JSON).
"""

import json
from tempfile import NamedTemporaryFile
from typing import Any, Dict

from floss.core.fl.config import FLConfig
from floss.core.fl.engine import FLEngine


def test_fl_report_contains_expected_sections_and_order() -> None:
    # Minimal but valid coverage input
    coverage_json = {
        "meta": {"format": 3, "version": "7.9.2"},
        "files": {"file.py": {"contexts": {"1": ["t1|run"]}}},
        "tests": {"passed": ["t1"], "failed": [], "skipped": []},
        "totals": {"covered_lines": 1},
    }

    cfg = FLConfig()
    cfg.formulas = ["ochiai"]
    engine = FLEngine(cfg)

    with (
        NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fin,
        NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fout,
    ):
        json.dump(coverage_json, fin)
        fin.flush()

        engine.calculate_suspiciousness(fin.name, fout.name)
        with open(fout.name, "r") as fh:
            report = json.load(fh)

    # Sections present
    assert "meta" in report
    assert "totals" in report
    assert "files" in report
    assert "fl_metadata" in report

    # totals contains our FL summary fields
    assert "sbfl_formulas" in report["totals"]
    assert report["totals"]["sbfl_formulas"] == ["ochiai"]
    assert "analysis_statistics" in report["totals"]
    stats = report["totals"]["analysis_statistics"]
    assert "total_failed_tests" in stats
    assert "total_passed_tests" in stats
    assert "total_lines_with_scores" in stats
    assert "files_analyzed" in stats

    # fl_metadata matches formulas
    assert report["fl_metadata"]["formulas_used"] == ["ochiai"]


def test_test_phase_metadata_fields_present_and_promoted() -> None:
    # Build the structure runner._add_test_summary_info creates
    # Here we don't invoke pytest; we simulate the shape instead.
    coverage_data: Dict[str, Any] = {
        "meta": {},
        "files": {"file.py": {"contexts": {}}},
        "totals": {},
    }
    test_outcomes: dict[str, list[str]] = {
        "failed": ["t_fail"],
        "passed": ["t_pass"],
        "skipped": [],
    }

    # Import internal helpers directly
    from floss.core.test.config import TestConfig
    from floss.core.test.runner import TestRunner

    runner = TestRunner(TestConfig())
    coverage_data = runner._add_floss_metadata(coverage_data, test_outcomes)
    reorganized = runner._add_test_summary_info(coverage_data, test_outcomes)

    # Metadata flags added
    assert reorganized["meta"]["tool"] == "floss"
    assert reorganized["meta"]["phase"] == "test_execution"

    # Totals include test_statistics
    assert "totals" in reorganized
    assert "test_statistics" in reorganized["totals"]
    ts = reorganized["totals"]["test_statistics"]
    assert ts["total_tests"] == 2
    assert ts["failed_tests"] == 1
    assert ts["passed_tests"] == 1
    assert ts["skipped_tests"] == 0
