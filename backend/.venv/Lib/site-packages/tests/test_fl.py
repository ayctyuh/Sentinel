"""
Tests for fault localization functionality.
"""

import json
import os
import tempfile

import pytest

from floss.core.fl.config import FLConfig
from floss.core.fl.data import CoverageData
from floss.core.fl.engine import FLEngine


class TestFLConfig:
    """Test FLConfig class."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = FLConfig()
        assert config.input_file == "coverage.json"
        assert config.output_file == "report.json"
        assert config.formulas == ["ochiai", "tarantula", "jaccard", "dstar2"]

    def test_from_file_nonexistent(self) -> None:
        """Test loading config from non-existent file."""
        config = FLConfig.from_file("nonexistent.conf")
        assert config.input_file == "coverage.json"
        assert config.output_file == "report.json"
        assert config.formulas == ["ochiai", "tarantula", "jaccard", "dstar2"]

    def test_from_file_with_fl_section(self) -> None:
        """Test loading config from file with FL section."""
        config_content = """
[fl]
input_file = test_coverage.json
output_file = test_report.json
formulas = ochiai, dstar2
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(config_content)
            f.flush()

            config = FLConfig.from_file(f.name)
            assert config.input_file == "test_coverage.json"
            assert config.output_file == "test_report.json"
            assert config.formulas == ["ochiai", "dstar2"]

        # Clean up file after use
        try:
            os.unlink(f.name)
        except PermissionError:
            pass  # Ignore permission errors on Windows

    def test_from_file_without_fl_section(self) -> None:
        """Test loading config from file without FL section."""
        config_content = """
[test]
source_dir = src
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(config_content)
            f.flush()

            config = FLConfig.from_file(f.name)
            assert config.input_file == "coverage.json"
            assert config.output_file == "report.json"
            assert config.formulas == ["ochiai", "tarantula", "jaccard", "dstar2"]

        # Clean up file after use
        try:
            os.unlink(f.name)
        except PermissionError:
            pass  # Ignore permission errors on Windows


class TestCoverageData:
    """Test CoverageData class."""

    def test_from_json_simple(self) -> None:
        """Test creating CoverageData from simple JSON."""
        coverage_json = {
            "tests": {"passed": ["test1", "test2"], "failed": ["test3"]},
            "files": {
                "file1.py": {
                    "contexts": {"1": ["test1|run", "test2|run"], "2": ["test3|run"]}
                }
            },
        }

        data = CoverageData.from_json(coverage_json)

        # Check test outcomes
        assert data.test_outcomes["test1"] is True
        assert data.test_outcomes["test2"] is True
        assert data.test_outcomes["test3"] is False

        # Check line coverage
        assert "file1.py:1" in data.line_coverage
        assert "test1" in data.line_coverage["file1.py:1"]
        assert "test2" in data.line_coverage["file1.py:1"]
        assert "file1.py:2" in data.line_coverage
        assert "test3" in data.line_coverage["file1.py:2"]

    def test_from_json_empty_contexts(self) -> None:
        """Test handling empty contexts."""
        coverage_json = {
            "tests": {"passed": ["test1"], "failed": []},
            "files": {
                "file1.py": {
                    "contexts": {"1": [""], "2": ["test1|run"]}  # Empty context
                }
            },
        }

        data = CoverageData.from_json(coverage_json)

        # Line 1 should not be in coverage (empty context)
        assert "file1.py:1" not in data.line_coverage
        # Line 2 should be in coverage
        assert "file1.py:2" in data.line_coverage
        assert "test1" in data.line_coverage["file1.py:2"]

    def test_get_sbfl_params(self) -> None:
        """Test SBFL parameter calculation."""
        data = CoverageData(
            line_coverage={
                "file1.py:1": {"test1", "test2"},  # 1 passed, 1 failed
                "file1.py:2": {"test3"},  # 1 failed
            },
            test_outcomes={
                "test1": True,  # passed
                "test2": False,  # failed
                "test3": False,  # failed
                "test4": True,  # passed (not covering any line)
            },
        )

        # Line 1: 1 failed covering, 1 failed not covering,
        # 1 passed covering, 1 passed not covering
        n_cf, n_nf, n_cp, n_np = data.get_sbfl_params("file1.py:1")
        assert n_cf == 1  # test2 failed and covers
        assert n_nf == 1  # test3 failed and doesn't cover
        assert n_cp == 1  # test1 passed and covers
        assert n_np == 1  # test4 passed and doesn't cover

        # Line 2: 1 failed covering, 1 failed not covering,
        # 0 passed covering, 2 passed not covering
        n_cf, n_nf, n_cp, n_np = data.get_sbfl_params("file1.py:2")
        assert n_cf == 1  # test3 failed and covers
        assert n_nf == 1  # test2 failed and doesn't cover
        assert n_cp == 0  # no passed tests cover
        assert n_np == 2  # test1, test4 passed and don't cover

    def test_get_sbfl_params_nonexistent_line(self) -> None:
        """Test SBFL parameters for non-existent line."""
        data = CoverageData(
            line_coverage={}, test_outcomes={"test1": True, "test2": False}
        )

        n_cf, n_nf, n_cp, n_np = data.get_sbfl_params("nonexistent:1")
        assert n_cf == 0  # no failed tests cover
        assert n_nf == 1  # test2 failed and doesn't cover
        assert n_cp == 0  # no passed tests cover
        assert n_np == 1  # test1 passed and doesn't cover


class TestFLEngine:
    """Test FLEngine class."""

    def test_init_default_formulas(self) -> None:
        """Test initialization with default formulas."""
        config = FLConfig()
        engine = FLEngine(config)

        expected_formulas = ["ochiai", "tarantula", "jaccard", "dstar2"]
        assert list(engine.formulas.keys()) == expected_formulas

    def test_init_custom_formulas(self) -> None:
        """Test initialization with custom formulas."""
        config = FLConfig()
        config.formulas = ["ochiai", "dstar3"]
        engine = FLEngine(config)

        assert list(engine.formulas.keys()) == ["ochiai", "dstar3"]

    def test_init_invalid_formulas_filtered(self) -> None:
        """Test that invalid formulas are filtered out."""
        config = FLConfig()
        config.formulas = ["ochiai", "invalid_formula", "tarantula"]
        engine = FLEngine(config)

        assert list(engine.formulas.keys()) == ["ochiai", "tarantula"]

    def test_calculate_suspiciousness_integration(self) -> None:
        """Test complete suspiciousness calculation."""
        # Create test coverage data
        coverage_json = {
            "tests": {"passed": ["test_pass"], "failed": ["test_fail"]},
            "files": {
                "test_file.py": {
                    "contexts": {
                        "1": ["test_pass|run", "test_fail|run"],
                        "2": ["test_fail|run"],
                    },
                    "summary": {"covered_lines": 2},
                }
            },
        }

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

                    # Read the result
                    with open(output_file.name, "r") as f:
                        result = json.load(f)

                    # Check structure
                    assert "files" in result
                    assert "test_file.py" in result["files"]
                    assert "suspiciousness" in result["files"]["test_file.py"]
                    assert "fl_metadata" in result

                    # Check suspiciousness scores
                    suspiciousness = result["files"]["test_file.py"]["suspiciousness"]
                    assert "1" in suspiciousness
                    assert "2" in suspiciousness
                    assert "ochiai" in suspiciousness["1"]
                    assert "ochiai" in suspiciousness["2"]

                    # Check metadata
                    assert result["fl_metadata"]["formulas_used"] == ["ochiai"]
                    assert result["fl_metadata"]["total_lines_analyzed"] == 2

                finally:
                    try:
                        os.unlink(input_file.name)
                        os.unlink(output_file.name)
                    except PermissionError:
                        pass  # Ignore permission errors on Windows

    def test_calculate_suspiciousness_multiple_formulas(self) -> None:
        """Test with multiple formulas."""
        coverage_json = {
            "tests": {"passed": ["test1"], "failed": ["test2"]},
            "files": {"file.py": {"contexts": {"1": ["test1|run", "test2|run"]}}},
        }

        config = FLConfig()
        config.formulas = ["ochiai", "tarantula", "jaccard"]
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

                    with open(output_file.name, "r") as f:
                        result = json.load(f)

                    suspiciousness = result["files"]["file.py"]["suspiciousness"]["1"]
                    assert "ochiai" in suspiciousness
                    assert "tarantula" in suspiciousness
                    assert "jaccard" in suspiciousness

                    # All scores should be the same for this case
                    # (1 pass, 1 fail both covering)
                    # n_cf=1, n_nf=0, n_cp=1, n_np=0
                    # Ochiai: 1/sqrt(1*2) = 1/1.414 = 0.707
                    # Tarantula: (1/1) / ((1/1) + (1/1)) = 1/2 = 0.5
                    # Jaccard: 1/(1+0+1) = 1/2 = 0.5
                    assert abs(suspiciousness["ochiai"] - 0.7071067811865475) < 1e-10
                    assert suspiciousness["tarantula"] == 0.5
                    assert suspiciousness["jaccard"] == 0.5

                finally:
                    try:
                        os.unlink(input_file.name)
                        os.unlink(output_file.name)
                    except PermissionError:
                        pass  # Ignore permission errors on Windows

    def test_calculate_suspiciousness_file_not_found(self) -> None:
        """Test error handling for missing input file."""
        config = FLConfig()
        engine = FLEngine(config)

        with pytest.raises(FileNotFoundError):
            engine.calculate_suspiciousness("nonexistent.json", "output.json")

    def test_calculate_suspiciousness_preserves_original_data(self) -> None:
        """Test that original coverage data is preserved in output."""
        coverage_json = {
            "meta": {"version": "7.9.2"},
            "tests": {"passed": ["test1"], "failed": []},
            "files": {
                "file.py": {
                    "contexts": {"1": ["test1|run"]},
                    "summary": {"covered_lines": 1},
                    "executed_lines": [1],
                }
            },
            "totals": {"covered_lines": 1},
        }

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

                    with open(output_file.name, "r") as f:
                        result = json.load(f)

                    # Check that original data is preserved
                    assert result["meta"]["version"] == "7.9.2"
                    assert result["totals"]["covered_lines"] == 1
                    assert result["files"]["file.py"]["executed_lines"] == [1]
                    assert result["files"]["file.py"]["summary"]["covered_lines"] == 1

                    # Check that new data is added
                    assert "suspiciousness" in result["files"]["file.py"]
                    assert "fl_metadata" in result

                finally:
                    try:
                        os.unlink(input_file.name)
                        os.unlink(output_file.name)
                    except PermissionError:
                        pass  # Ignore permission errors on Windows


# Integration test using actual formulas
class TestFLIntegration:
    """Integration tests for fault localization."""

    def test_real_world_scenario(self) -> None:
        """Test with a realistic coverage scenario."""
        # Simulate a scenario where:
        # - Line 5: covered by 1 passing test and 1 failing test
        # - Line 10: covered only by 1 failing test
        # - Line 15: covered only by 1 passing test
        coverage_json = {
            "tests": {
                "passed": ["test_pass_1", "test_pass_2"],
                "failed": ["test_fail_1"],
            },
            "files": {
                "buggy_module.py": {
                    "contexts": {
                        "5": ["test_pass_1|run", "test_fail_1|run"],
                        "10": ["test_fail_1|run"],
                        "15": ["test_pass_1|run", "test_pass_2|run"],
                    }
                }
            },
        }

        config = FLConfig()
        config.formulas = ["ochiai", "tarantula"]
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

                    with open(output_file.name, "r") as f:
                        result = json.load(f)

                    susp = result["files"]["buggy_module.py"]["suspiciousness"]

                    # Line 10 should have highest suspiciousness
                    # (only covered by failing test)
                    assert susp["10"]["ochiai"] > susp["5"]["ochiai"]
                    assert susp["10"]["ochiai"] > susp["15"]["ochiai"]
                    assert susp["10"]["tarantula"] > susp["5"]["tarantula"]
                    assert susp["10"]["tarantula"] > susp["15"]["tarantula"]

                    # Line 15 should have lowest suspiciousness
                    # (only covered by passing tests)
                    assert susp["15"]["ochiai"] == 0.0
                    assert susp["15"]["tarantula"] == 0.0

                finally:
                    try:
                        os.unlink(input_file.name)
                        os.unlink(output_file.name)
                    except PermissionError:
                        pass  # Ignore permission errors on Windows
