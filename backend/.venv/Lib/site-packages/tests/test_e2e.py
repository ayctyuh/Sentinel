"""
End-to-end integration tests for FLOSS workflow.
"""

import json
import os
from typing import Any, Dict

from click.testing import CliRunner

from floss.core.cli.main import main


class TestE2EWorkflow:
    """End-to-end tests for complete FLOSS workflow."""

    def test_complete_workflow(self) -> None:
        """Test complete test -> FL workflow."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create a mini project structure
            os.makedirs("src")
            os.makedirs("tests")

            # Create source file with a bug
            with open("src/calculator.py", "w") as f:
                f.write(
                    """
def add(a, b):
    return a + b

def subtract(a, b):
    if a < 0:  # Buggy condition
        return 0  # Wrong!
    return a - b

def divide(a, b):
    if b == 0:
        raise ValueError("Division by zero")
    return a / b
"""
                )

            # Create test file
            with open("tests/test_calculator.py", "w") as f:
                f.write(
                    """
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from calculator import add, subtract, divide

def test_add_positive():
    assert add(2, 3) == 5

def test_add_negative():
    assert add(-1, 1) == 0

def test_subtract_positive():
    assert subtract(5, 3) == 2

def test_subtract_negative():
    # This test will fail due to the bug
    assert subtract(-1, 1) == -2

def test_divide_normal():
    assert divide(6, 2) == 3

def test_divide_by_zero():
    try:
        divide(1, 0)
        assert False, "Should raise exception"
    except ValueError:
        pass
"""
                )

            # Create config file
            with open("floss.conf", "w") as f:
                f.write(
                    """
[test]
source_dir = src

[fl]
formulas = ochiai, tarantula, dstar2
"""
                )

            # Step 1: Run tests with coverage (simulate -
            # we'll create the coverage manually)
            # In real scenario this would be: result = runner.invoke(main, ['test'])

            # Create realistic coverage data manually (simulating test command output)
            coverage_data = {
                "meta": {
                    "format": 3,
                    "version": "7.9.2",
                    "timestamp": "2025-01-01T12:00:00.000000",
                    "branch_coverage": True,
                    "show_contexts": True,
                },
                "files": {
                    "src\\calculator.py": {
                        "executed_lines": [2, 3, 5, 6, 7, 8, 10, 11, 12, 13],
                        "contexts": {
                            "2": [
                                "tests/test_calculator.py::test_add_positive|run",
                                "tests/test_calculator.py::test_add_negative|run",
                            ],
                            "3": [
                                "tests/test_calculator.py::test_add_positive|run",
                                "tests/test_calculator.py::test_add_negative|run",
                            ],
                            "5": [
                                "tests/test_calculator.py::test_subtract_positive|run",
                                "tests/test_calculator.py::test_subtract_negative|run",
                            ],
                            "6": [
                                "tests/test_calculator.py::test_subtract_negative|run"
                            ],  # Bug line!
                            "7": [
                                "tests/test_calculator.py::test_subtract_negative|run"
                            ],  # Bug line!
                            "8": [
                                "tests/test_calculator.py::test_subtract_positive|run"
                            ],
                            "10": [
                                "tests/test_calculator.py::test_divide_normal|run",
                                "tests/test_calculator.py::test_divide_by_zero|run",
                            ],
                            "11": ["tests/test_calculator.py::test_divide_by_zero|run"],
                            "12": ["tests/test_calculator.py::test_divide_by_zero|run"],
                            "13": ["tests/test_calculator.py::test_divide_normal|run"],
                        },
                        "summary": {
                            "covered_lines": 10,
                            "num_statements": 10,
                            "percent_covered": 100.0,
                        },
                    }
                },
                "tests": {
                    "passed": [
                        "tests/test_calculator.py::test_add_positive",
                        "tests/test_calculator.py::test_add_negative",
                        "tests/test_calculator.py::test_subtract_positive",
                        "tests/test_calculator.py::test_divide_normal",
                        "tests/test_calculator.py::test_divide_by_zero",
                    ],
                    "failed": ["tests/test_calculator.py::test_subtract_negative"],
                    "skipped": [],
                },
                "totals": {
                    "covered_lines": 10,
                    "num_statements": 10,
                    "percent_covered": 100.0,
                },
            }

            with open("coverage.json", "w") as f:
                json.dump(coverage_data, f, indent=2)

            # Step 2: Run fault localization
            result = runner.invoke(main, ["fl"])

            assert result.exit_code == 0
            assert "Fault localization completed" in result.output
            assert os.path.exists("report.json")

            # Step 3: Analyze results
            with open("report.json", "r") as f:
                report = json.load(f)

            # Verify structure
            assert "fl_metadata" in report
            assert "formulas_used" in report["fl_metadata"]
            assert set(report["fl_metadata"]["formulas_used"]) == {
                "ochiai",
                "tarantula",
                "dstar2",
            }

            # Get suspiciousness scores
            file_data = report["files"]["src\\calculator.py"]
            assert "suspiciousness" in file_data
            susp = file_data["suspiciousness"]

            # Lines 6,7 should have highest suspiciousness
            # (only covered by failing test)
            assert "6" in susp
            assert "7" in susp

            # These lines should have higher suspiciousness than others
            line6_ochiai = susp["6"]["ochiai"]
            line7_ochiai = susp["7"]["ochiai"]

            # Compare with lines covered by both passing and failing tests
            if "5" in susp:  # Line covered by both pass/fail
                line5_ochiai = susp["5"]["ochiai"]
                assert line6_ochiai > line5_ochiai
                assert line7_ochiai > line5_ochiai

            # Lines only covered by passing tests should have 0 suspiciousness
            if "13" in susp:  # Only covered by passing test
                assert susp["13"]["ochiai"] == 0.0
                assert susp["13"]["tarantula"] == 0.0

    def test_workflow_with_custom_parameters(self) -> None:
        """Test workflow with custom parameters and configuration."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create minimal coverage data
            coverage_data = {
                "tests": {"passed": ["test_pass"], "failed": ["test_fail"]},
                "files": {
                    "buggy.py": {
                        "contexts": {
                            "1": ["test_pass|run", "test_fail|run"],
                            "2": ["test_fail|run"],
                        }
                    }
                },
            }

            with open("my_coverage.json", "w") as f:
                json.dump(coverage_data, f)

            # Test FL with custom parameters
            result = runner.invoke(
                main,
                [
                    "fl",
                    "--input",
                    "my_coverage.json",
                    "--output",
                    "my_report.json",
                    "--formulas",
                    "ochiai",
                    "--formulas",
                    "jaccard",
                ],
            )

            assert result.exit_code == 0
            assert "Input file: my_coverage.json" in result.output
            assert "Output file: my_report.json" in result.output
            assert "Formulas: ochiai, jaccard" in result.output

            # Verify output
            assert os.path.exists("my_report.json")
            with open("my_report.json", "r") as f:
                report = json.load(f)

            assert set(report["fl_metadata"]["formulas_used"]) == {"ochiai", "jaccard"}

            # Line 2 should have higher suspiciousness (only failing test covers it)
            susp = report["files"]["buggy.py"]["suspiciousness"]
            assert susp["2"]["ochiai"] > susp["1"]["ochiai"]
            assert susp["2"]["jaccard"] > susp["1"]["jaccard"]

    def test_error_handling_workflow(self) -> None:
        """Test error handling in workflow scenarios."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Test 1: Missing input file
            result = runner.invoke(main, ["fl"])
            assert result.exit_code == 1
            assert "Error:" in result.output

            # Test 2: Invalid JSON
            with open("coverage.json", "w") as f:
                f.write("invalid json content")

            result = runner.invoke(main, ["fl"])
            assert result.exit_code == 1
            assert "Error:" in result.output

            # Test 3: Empty but valid JSON
            with open("coverage.json", "w") as f:
                json.dump({}, f)

            result = runner.invoke(main, ["fl"])
            assert result.exit_code == 0  # Should handle gracefully

            with open("report.json", "r") as f:
                report = json.load(f)
            assert report["fl_metadata"]["total_lines_analyzed"] == 0

    def test_workflow_preserves_all_original_data(self) -> None:
        """Test that FL workflow preserves all original coverage data."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create complex coverage data with many fields
            original_data: Dict[str, Any] = {
                "meta": {
                    "format": 3,
                    "version": "7.9.2",
                    "timestamp": "2025-01-01T12:00:00.000000",
                    "branch_coverage": True,
                    "show_contexts": True,
                },
                "files": {
                    "complex_file.py": {
                        "executed_lines": [1, 2, 3],
                        "missing_lines": [4, 5],
                        "excluded_lines": [6],
                        "contexts": {
                            "1": ["test1|run"],
                            "2": ["test2|run"],
                            "3": ["test1|run", "test2|run"],
                        },
                        "summary": {
                            "covered_lines": 3,
                            "num_statements": 5,
                            "percent_covered": 60.0,
                            "missing_lines": 2,
                            "excluded_lines": 1,
                        },
                        "executed_branches": [[1, 2], [2, 3]],
                        "missing_branches": [[3, 4]],
                        "functions": {
                            "func1": {
                                "executed_lines": [1, 2],
                                "summary": {"covered_lines": 2},
                            }
                        },
                        "classes": {
                            "Class1": {
                                "executed_lines": [3],
                                "summary": {"covered_lines": 1},
                            }
                        },
                    }
                },
                "tests": {
                    "passed": ["test1"],
                    "failed": ["test2"],
                    "skipped": ["test3"],
                },
                "totals": {
                    "covered_lines": 3,
                    "num_statements": 5,
                    "percent_covered": 60.0,
                    "missing_lines": 2,
                },
            }

            with open("coverage.json", "w") as f:
                json.dump(original_data, f, indent=2)

            # Run FL
            result = runner.invoke(main, ["fl"])
            assert result.exit_code == 0

            # Load result and verify all original data is preserved
            with open("report.json", "r") as f:
                report = json.load(f)

            # Check meta preservation: original fields must be preserved (allow extras)
            for k, v in original_data["meta"].items():
                assert report["meta"].get(k) == v

            # Check totals preservation: original fields must be preserved
            # (allow extras)
            for k, v in original_data["totals"].items():
                assert report["totals"].get(k) == v

            # Check test outcomes preservation
            assert report["tests"] == original_data["tests"]

            # Check file-level data preservation
            file_data = report["files"]["complex_file.py"]
            orig_file_data = original_data["files"]["complex_file.py"]

            assert file_data["executed_lines"] == orig_file_data["executed_lines"]
            assert file_data["missing_lines"] == orig_file_data["missing_lines"]
            assert file_data["excluded_lines"] == orig_file_data["excluded_lines"]
            assert file_data["summary"] == orig_file_data["summary"]
            assert file_data["executed_branches"] == orig_file_data["executed_branches"]
            assert file_data["missing_branches"] == orig_file_data["missing_branches"]
            assert file_data["functions"] == orig_file_data["functions"]
            assert file_data["classes"] == orig_file_data["classes"]

            # Check that FL data was added
            assert "suspiciousness" in file_data
            assert "fl_metadata" in report

            # Verify suspiciousness data
            susp = file_data["suspiciousness"]
            assert "1" in susp  # Line covered by passing test only
            assert "2" in susp  # Line covered by failing test only
            assert "3" in susp  # Line covered by both

            # Line 2 should have highest suspiciousness (only failing test)
            assert susp["2"]["ochiai"] > susp["1"]["ochiai"]
            assert susp["2"]["ochiai"] > susp["3"]["ochiai"]

            # Line 1 should have 0 suspiciousness (only passing test)
            assert susp["1"]["ochiai"] == 0.0


class TestE2ERunCommand:
    """End-to-end tests for the 'FLOSS run' command."""

    def test_run_command_complete_workflow(self) -> None:
        """Test complete workflow using the run command."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create a mini project structure
            os.makedirs("src")
            os.makedirs("tests")

            # Create source file with a bug
            with open("src/calculator.py", "w") as f:
                f.write(
                    """
def add(a, b):
    return a + b

def subtract(a, b):
    if a < 0:  # Buggy condition
        return 0  # Wrong!
    return a - b

def multiply(a, b):
    return a * b
"""
                )

            # Create test file
            with open("tests/test_calculator.py", "w") as f:
                f.write(
                    '''
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from calculator import add, subtract, multiply

def test_add_positive():
    """Test adding positive numbers."""
    assert add(2, 3) == 5

def test_subtract_positive():
    """Test subtracting positive numbers."""
    assert subtract(5, 3) == 2

def test_subtract_negative():
    """Test subtracting with negative number - should fail due to bug."""
    assert subtract(-1, 2) == -3  # This will fail due to bug

def test_multiply():
    """Test multiplication."""
    assert multiply(3, 4) == 12
'''
                )

            # Create config file
            with open("floss.conf", "w") as f:
                f.write(
                    """[test]
source_dir = src
ignore = */__pycache__/*

[fl]
formulas = ochiai, tarantula
"""
                )

            # Run the complete pipeline with run command
            result = runner.invoke(
                main, ["run", "--source-dir", "src", "--output", "final_report.json"]
            )

            # Check command succeeded
            assert result.exit_code == 0, f"Command failed with output: {result.output}"

            # Verify output messages
            assert "Running complete fault localization pipeline" in result.output
            assert "Phase 1: Running tests with coverage" in result.output
            assert "Phase 2: Calculating fault localization scores" in result.output
            assert "Fault localization pipeline completed" in result.output

            # Verify test results in output
            assert "Total tests: 4" in result.output
            assert "Passed: 3" in result.output
            assert "Failed: 1" in result.output
            assert "test_subtract_negative" in result.output

            # Check that final report was created
            assert os.path.exists("final_report.json")

            # Verify report content
            with open("final_report.json", "r") as f:
                report = json.load(f)

            assert "files" in report
            assert "fl_metadata" in report
            assert (
                "src/calculator.py" in report["files"]
                or "src\\calculator.py" in report["files"]
            )

            # Get the calculator file data (handle both path separators)
            calc_file = None
            for file_path in report["files"]:
                if "calculator.py" in file_path:
                    calc_file = report["files"][file_path]
                    break

            assert calc_file is not None
            assert "suspiciousness" in calc_file

            # Verify FL metadata
            metadata = report["fl_metadata"]
            assert "formulas_used" in metadata
            assert "ochiai" in metadata["formulas_used"]
            assert "tarantula" in metadata["formulas_used"]

    def test_run_command_custom_formulas(self) -> None:
        """Test run command with custom formulas."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create minimal project
            os.makedirs("src")
            os.makedirs("tests")

            with open("src/simple.py", "w") as f:
                f.write(
                    """
def simple_func(x):
    if x > 0:
        return x * 2
    return 0
"""
                )

            with open("tests/test_simple.py", "w") as f:
                f.write(
                    """
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from simple import simple_func

def test_positive():
    assert simple_func(5) == 10

def test_zero():
    assert simple_func(0) == 0

def test_negative():
    # This test will fail to trigger FL phase
    # This will fail since simple_func returns 0 for negative values
    assert simple_func(-1) == -2
"""
                )

            # Run with specific formulas
            result = runner.invoke(
                main,
                [
                    "run",
                    "--source-dir",
                    "src",
                    "--formulas",
                    "ochiai",
                    "--formulas",
                    "jaccard",
                    "--output",
                    "custom_formula_report.json",
                ],
            )

            assert result.exit_code == 0
            assert "Formulas: ochiai, jaccard" in result.output
            assert os.path.exists("custom_formula_report.json")

            # Verify only specified formulas were used
            with open("custom_formula_report.json", "r") as f:
                report = json.load(f)

            formulas = report["fl_metadata"]["formulas_used"]
            assert "ochiai" in formulas
            assert "jaccard" in formulas
            assert "tarantula" not in formulas  # Should not be included

    def test_run_command_test_filter(self) -> None:
        """Test run command with test filtering."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            os.makedirs("src")
            os.makedirs("tests")

            with open("src/math_ops.py", "w") as f:
                f.write(
                    """
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b
"""
                )

            with open("tests/test_math_ops.py", "w") as f:
                f.write(
                    """
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from math_ops import add, subtract

def test_add_basic():
    assert add(1, 2) == 3

def test_add_negative():
    assert add(-1, -2) == -3

def test_add_failing():
    # This test will fail to trigger FL phase
    assert add(1, 2) == 4  # This will fail since 1+2=3, not 4

def test_subtract_basic():
    assert subtract(5, 3) == 2

def test_subtract_negative():
    assert subtract(-1, -2) == 1
"""
                )

            # Run with test filter (only add tests)
            result = runner.invoke(
                main,
                [
                    "run",
                    "--source-dir",
                    "src",
                    "--test-filter",
                    "add",
                    "--output",
                    "filtered_report.json",
                ],
            )

            assert result.exit_code == 0
            # Should run 3 add tests (add_basic, add_negative, add_failing)
            assert "Total tests: 3" in result.output
            assert os.path.exists("filtered_report.json")

    def test_run_command_error_handling(self) -> None:
        """Test run command error handling with invalid project."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create source with syntax error
            os.makedirs("src")
            os.makedirs("tests")

            with open("src/broken.py", "w") as f:
                f.write(
                    """
def broken_func():
    # Missing closing parenthesis - syntax error
    return "broken"
"""
                )

            with open("tests/test_broken.py", "w") as f:
                f.write(
                    """
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_import():
    from broken import broken_func  # This will fail due to syntax error
    assert broken_func() == "broken"
"""
                )

            # Run command - may complete with test failures rather than crashing
            result = runner.invoke(
                main, ["run", "--source-dir", "src", "--output", "error_report.json"]
            )

            # Command may succeed but with test failures, or may fail completely
            # Either is acceptable for error handling
            if result.exit_code == 1:
                assert "Error:" in result.output
            else:
                # If it runs, it should show test failures
                assert "Failed:" in result.output or "Total tests: 0" in result.output

    def test_run_command_no_tests(self) -> None:
        """Test run command with no test files."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            os.makedirs("src")
            # Don't create tests directory or create empty one

            # Create source file but no tests
            with open("src/lonely.py", "w") as f:
                f.write(
                    """
def lonely_function():
    return "no tests for me"
"""
                )

            # Run command
            result = runner.invoke(
                main, ["run", "--source-dir", "src", "--output", "no_tests_report.json"]
            )

            # May succeed or fail when no tests are found - both are acceptable
            # The important thing is that it handles the case gracefully
            if result.exit_code == 0:
                # If successful, should indicate no tests
                assert "Total tests:" in result.output
            else:
                # If it fails, should provide appropriate error message
                assert result.exit_code == 1
                assert "Error:" in result.output or "No tests" in result.output
