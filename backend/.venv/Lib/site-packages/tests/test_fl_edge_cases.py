"""
Edge case and performance tests for fault localization.
"""

import json
import os
import tempfile
import time
from typing import Any, Dict

from floss.core.fl.config import FLConfig
from floss.core.fl.data import CoverageData
from floss.core.fl.engine import FLEngine


class TestFLEdgeCases:
    """Test edge cases for fault localization."""

    def test_no_failed_tests(self) -> None:
        """Test FL when all tests pass."""
        coverage_json = {
            "tests": {"passed": ["test1", "test2"], "failed": []},
            "files": {
                "file.py": {"contexts": {"1": ["test1|run"], "2": ["test2|run"]}}
            },
        }

        data = CoverageData.from_json(coverage_json)

        # All lines should have 0 suspiciousness when no tests fail
        n_cf, n_nf, n_cp, n_np = data.get_sbfl_params("file.py:1")
        assert n_cf == 0  # no failed tests
        assert n_nf == 0  # no failed tests
        assert n_cp == 1  # test1 passed and covers
        assert n_np == 1  # test2 passed and doesn't cover

    def test_no_passed_tests(self) -> None:
        """Test FL when all tests fail."""
        coverage_json = {
            "tests": {"passed": [], "failed": ["test1", "test2"]},
            "files": {
                "file.py": {"contexts": {"1": ["test1|run"], "2": ["test2|run"]}}
            },
        }

        data = CoverageData.from_json(coverage_json)

        n_cf, n_nf, n_cp, n_np = data.get_sbfl_params("file.py:1")
        assert n_cf == 1  # test1 failed and covers
        assert n_nf == 1  # test2 failed and doesn't cover
        assert n_cp == 0  # no passed tests
        assert n_np == 0  # no passed tests

    def test_line_covered_by_no_tests(self) -> None:
        """Test line that appears in contexts but with empty context list."""
        coverage_json = {
            "tests": {"passed": ["test1"], "failed": ["test2"]},
            "files": {
                "file.py": {
                    "contexts": {"1": [], "2": ["test1|run"]}  # Empty context list
                }
            },
        }

        data = CoverageData.from_json(coverage_json)

        # Line 1 should not be in coverage due to empty context
        assert "file.py:1" not in data.line_coverage
        assert "file.py:2" in data.line_coverage

    def test_malformed_context_strings(self) -> None:
        """Test handling of malformed context strings."""
        coverage_json = {
            "tests": {"passed": ["test1"], "failed": []},
            "files": {
                "file.py": {
                    "contexts": {
                        "1": ["test1"],  # Missing |run suffix
                        "2": ["test1|run"],  # Correct format
                        "3": ["test1|setup"],  # Different suffix
                        "4": ["test1|run|extra"],  # Extra parts
                    }
                }
            },
        }

        data = CoverageData.from_json(coverage_json)

        # Only line 2 and 4 should be covered (contain |run)
        assert "file.py:1" not in data.line_coverage
        assert "file.py:2" in data.line_coverage
        assert "file.py:3" not in data.line_coverage
        assert "file.py:4" in data.line_coverage

    def test_missing_test_outcomes(self) -> None:
        """Test handling when test outcomes are missing."""
        coverage_json = {
            "files": {"file.py": {"contexts": {"1": ["unknown_test|run"]}}}
        }

        data = CoverageData.from_json(coverage_json)

        # Unknown test should be treated as passed (default)
        assert data.test_outcomes.get("unknown_test", True) is True

        n_cf, n_nf, n_cp, n_np = data.get_sbfl_params("file.py:1")
        assert n_cf == 0  # no failed tests
        assert n_cp == 1  # unknown_test defaults to passed

    def test_engine_with_no_formulas(self) -> None:
        """Test engine behavior when no valid formulas are configured."""
        config = FLConfig()
        config.formulas = ["invalid_formula1", "invalid_formula2"]

        engine = FLEngine(config)

        # Should have empty formulas dict
        assert len(engine.formulas) == 0

    def test_large_number_of_tests(self) -> None:
        """Test performance with many tests."""
        # Create coverage data with many tests
        num_tests = 1000
        passed_tests = [f"test_pass_{i}" for i in range(num_tests // 2)]
        failed_tests = [f"test_fail_{i}" for i in range(num_tests // 2)]

        coverage_json = {
            "tests": {"passed": passed_tests, "failed": failed_tests},
            "files": {
                "file.py": {
                    "contexts": {
                        "1": [
                            f"{test}|run" for test in passed_tests[:10]
                        ],  # 10 passing tests
                        "2": [
                            f"{test}|run" for test in failed_tests[:5]
                        ],  # 5 failing tests
                    }
                }
            },
        }

        start_time = time.time()
        data = CoverageData.from_json(coverage_json)

        # Should handle large number of tests efficiently
        n_cf, n_nf, n_cp, n_np = data.get_sbfl_params("file.py:1")

        assert n_cf == 0  # no failed tests cover line 1
        assert n_nf == num_tests // 2  # all failed tests don't cover line 1
        assert n_cp == 10  # 10 passed tests cover line 1
        assert n_np == (num_tests // 2) - 10  # remaining passed tests don't cover

        elapsed = time.time() - start_time
        assert elapsed < 1.0  # Should be fast

    def test_duplicate_test_names_in_contexts(self) -> None:
        """Test handling of duplicate test names in same context."""
        coverage_json = {
            "tests": {"passed": ["test1"], "failed": []},
            "files": {
                "file.py": {
                    "contexts": {
                        "1": ["test1|run", "test1|run", "test1|run"]  # Duplicates
                    }
                }
            },
        }

        data = CoverageData.from_json(coverage_json)

        # Should deduplicate automatically due to set usage
        assert len(data.line_coverage["file.py:1"]) == 1
        assert "test1" in data.line_coverage["file.py:1"]

    def test_unicode_file_paths(self) -> None:
        """Test handling of unicode characters in file paths."""
        coverage_json = {
            "tests": {"passed": ["test1"], "failed": []},
            "files": {
                "src\\测试文件.py": {  # Chinese characters
                    "contexts": {"1": ["test1|run"]}
                },
                "src\\файл.py": {  # Cyrillic characters
                    "contexts": {"1": ["test1|run"]}
                },
            },
        }

        data = CoverageData.from_json(coverage_json)

        assert "src\\测试文件.py:1" in data.line_coverage
        assert "src\\файл.py:1" in data.line_coverage

    def test_very_large_line_numbers(self) -> None:
        """Test handling of very large line numbers."""
        coverage_json = {
            "tests": {"passed": ["test1"], "failed": []},
            "files": {
                "file.py": {
                    "contexts": {
                        "999999": ["test1|run"],  # Very large line number
                        "1000000": ["test1|run"],
                    }
                }
            },
        }

        data = CoverageData.from_json(coverage_json)

        assert "file.py:999999" in data.line_coverage
        assert "file.py:1000000" in data.line_coverage


class TestFLPerformance:
    """Performance tests for fault localization."""

    def test_performance_many_files(self) -> None:
        """Test performance with many files."""
        num_files = 100
        coverage_json: Dict[str, Any] = {
            "tests": {"passed": ["test_pass"], "failed": ["test_fail"]},
            "files": {},
        }

        # Create many files
        for i in range(num_files):
            coverage_json["files"][f"file_{i}.py"] = {
                "contexts": {"1": ["test_pass|run"], "2": ["test_fail|run"]}
            }

        start_time = time.time()

        config = FLConfig()
        config.formulas = ["ochiai"]
        engine = FLEngine(config)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as input_file:
            json.dump(coverage_json, input_file)
            input_file.flush()

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as output_file:
                try:
                    engine.calculate_suspiciousness(input_file.name, output_file.name)

                    elapsed = time.time() - start_time
                    assert elapsed < 5.0  # Should complete within 5 seconds

                    # Verify correctness
                    with open(output_file.name, "r") as f:
                        result = json.load(f)

                    assert (
                        result["fl_metadata"]["total_lines_analyzed"] == num_files * 2
                    )

                finally:
                    try:
                        os.unlink(input_file.name)
                        os.unlink(output_file.name)
                    except PermissionError:
                        pass  # Ignore permission errors on Windows

    def test_performance_many_formulas(self) -> None:
        """Test performance with all available formulas."""
        coverage_json = {
            "tests": {"passed": ["test1", "test2"], "failed": ["test3", "test4"]},
            "files": {
                "file.py": {
                    "contexts": {
                        "1": ["test1|run", "test3|run"],
                        "2": ["test2|run", "test4|run"],
                        "3": ["test1|run", "test2|run"],
                    }
                }
            },
        }

        config = FLConfig()
        config.formulas = list(FLEngine.AVAILABLE_FORMULAS.keys())  # All formulas

        start_time = time.time()
        engine = FLEngine(config)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as input_file:
            json.dump(coverage_json, input_file)
            input_file.flush()

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as output_file:
                try:
                    engine.calculate_suspiciousness(input_file.name, output_file.name)

                    elapsed = time.time() - start_time
                    assert elapsed < 2.0  # Should be fast even with all formulas

                    # Verify all formulas were used
                    with open(output_file.name, "r") as f:
                        result = json.load(f)

                    formulas_used = result["fl_metadata"]["formulas_used"]
                    assert len(formulas_used) == len(FLEngine.AVAILABLE_FORMULAS)

                finally:
                    try:
                        os.unlink(input_file.name)
                        os.unlink(output_file.name)
                    except PermissionError:
                        pass  # Ignore permission errors on Windows
