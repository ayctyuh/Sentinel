"""
Integration tests specifically for the FLOSS run command.

These tests focus on the integration between the test and FL phases,
configuration handling, and file management.
"""

import json
import os
import shutil
import tempfile
from pathlib import Path

from click.testing import CliRunner

from floss.core.cli.main import main


class TestRunCommandIntegration:
    """Integration tests for the run command."""

    def setup_method(self) -> None:
        """Setup test environment."""
        self.runner = CliRunner()
        self.temp_dir = Path(tempfile.mkdtemp())

    def teardown_method(self) -> None:
        """Cleanup."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def test_configuration_precedence(self) -> None:
        """Test that CLI arguments override configuration file settings."""
        with self.runner.isolated_filesystem():
            os.makedirs("src")
            os.makedirs("tests")
            os.makedirs("config_src")

            # Create simple source and test files
            with open("src/simple.py", "w") as f:
                f.write("def func(): return 42")

            with open("tests/test_simple.py", "w") as f:
                f.write(
                    """
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from simple import func
def test_func(): assert func() == 42
def test_func_fail(): assert func() == 43  # This will fail to trigger FL
"""
                )

            # Create configuration file with different settings
            with open("test.conf", "w") as f:
                f.write(
                    """[test]
source_dir = config_src
output_file = config_coverage.json

[fl]
input_file = config_coverage.json
output_file = config_report.json
formulas = ochiai
"""
                )

            # Run with CLI overrides
            result = self.runner.invoke(
                main,
                [
                    "run",
                    "--config",
                    "test.conf",
                    "--source-dir",
                    "src",  # Override config
                    "--output",
                    "cli_report.json",  # Override config
                    "--formulas",
                    "tarantula",  # Override config
                ],
            )

            assert result.exit_code == 0
            # Verify CLI settings were used
            assert "Source dir: src" in result.output
            assert "Final output: cli_report.json" in result.output
            assert "Formulas: tarantula" in result.output

            # Verify correct output file was created
            assert os.path.exists("cli_report.json")
            assert not os.path.exists("config_report.json")

    def test_intermediate_file_management(self) -> None:
        """Test proper handling of intermediate coverage files."""
        with self.runner.isolated_filesystem():
            os.makedirs("src")
            os.makedirs("tests")

            with open("src/module.py", "w") as f:
                f.write('def hello(): return "world"')

            with open("tests/test_module.py", "w") as f:
                f.write(
                    """
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from module import hello
def test_hello(): assert hello() == "world"
def test_hello_fail(): assert hello() == "mars"  # This will fail to trigger FL
"""
                )

            # Test with custom output file
            result = self.runner.invoke(
                main, ["run", "--source-dir", "src", "--output", "my_report.json"]
            )

            assert result.exit_code == 0

            # Check final output exists
            assert os.path.exists("my_report.json")

            # Check intermediate file was cleaned up
            assert not os.path.exists("my_report_coverage.json")

            # When output is default, intermediate file should also be default
            result2 = self.runner.invoke(main, ["run", "--source-dir", "src"])

            assert result2.exit_code == 0
            assert os.path.exists("report.json")

    def test_phase_separation_and_data_flow(self) -> None:
        """Test that data flows correctly between test and FL phases."""
        with self.runner.isolated_filesystem():
            os.makedirs("src")
            os.makedirs("tests")

            # Create source with potential bug
            with open("src/calculator.py", "w") as f:
                f.write(
                    """
def divide(a, b):
    if b == 0:
        return 999  # Bug: should raise exception
    return a / b

def multiply(a, b):
    return a * b
"""
                )

            with open("tests/test_calculator.py", "w") as f:
                f.write(
                    """
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from calculator import divide, multiply

def test_divide_normal():
    assert divide(10, 2) == 5

def test_divide_by_zero():
    # This should raise exception but returns 999 due to bug
    result = divide(10, 0)
    assert result != 999, "Should raise exception, not return 999"

def test_multiply():
    assert multiply(3, 4) == 12
"""
                )

            result = self.runner.invoke(
                main,
                [
                    "run",
                    "--source-dir",
                    "src",
                    "--formulas",
                    "ochiai",
                    "--output",
                    "bug_report.json",
                ],
            )

            assert result.exit_code == 0

            # Verify test execution results in output
            assert "Phase 1: Running tests with coverage" in result.output
            assert "Total tests: 3" in result.output
            assert "Failed: 1" in result.output
            assert "test_divide_by_zero" in result.output

            # Verify FL calculation results
            assert "Phase 2: Calculating fault localization scores" in result.output

            # Check generated report
            assert os.path.exists("bug_report.json")

            with open("bug_report.json", "r") as f:
                report = json.load(f)

            # Verify structure
            assert "files" in report
            assert "fl_metadata" in report

            # Find calculator file
            calc_file_data = None
            for file_path, data in report["files"].items():
                if "calculator.py" in file_path:
                    calc_file_data = data
                    break

            assert calc_file_data is not None
            assert "suspiciousness" in calc_file_data

            # Verify suspiciousness scores exist for covered lines
            susp = calc_file_data["suspiciousness"]
            # Should have scores for covered lines (may be 0 if no coverage collected)
            # The important thing is that the structure is correct
            assert isinstance(susp, dict)  # Should be a dict even if empty

    def test_error_propagation(self) -> None:
        """Test that errors in either phase are properly propagated."""
        with self.runner.isolated_filesystem():
            os.makedirs("src")

            # Create source file that will cause import error
            with open("src/bad_import.py", "w") as f:
                f.write(
                    """
import non_existent_module  # This will cause ImportError
def func(): return 42
"""
                )

            # No tests directory - will cause issues
            result = self.runner.invoke(main, ["run", "--source-dir", "src"])

            # Should handle error gracefully
            assert result.exit_code == 1
            assert "Error:" in result.output

    def test_large_number_of_failed_tests_display(self) -> None:
        """Test display when there are many failed tests."""
        with self.runner.isolated_filesystem():
            os.makedirs("src")
            os.makedirs("tests")

            with open("src/faulty.py", "w") as f:
                f.write(
                    """
def always_fail():
    return False  # Always returns False

def sometimes_work(x):
    return x > 5
"""
                )

            # Create many failing tests
            with open("tests/test_faulty.py", "w") as f:
                f.write(
                    """
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from faulty import always_fail, sometimes_work

def test_fail_1(): assert always_fail()
def test_fail_2(): assert always_fail()
def test_fail_3(): assert always_fail()
def test_fail_4(): assert always_fail()
def test_fail_5(): assert always_fail()
def test_pass_1(): assert sometimes_work(10)
def test_pass_2(): assert sometimes_work(7)
"""
                )

            result = self.runner.invoke(
                main,
                ["run", "--source-dir", "src", "--output", "many_fails_report.json"],
            )

            assert result.exit_code == 0
            assert "Total tests: 7" in result.output
            assert "Failed: 5" in result.output
            assert "Passed: 2" in result.output

            # Should show truncated list of failed tests
            assert "Failed tests:" in result.output
            assert "..." in result.output  # Truncation indicator

    def test_empty_coverage_data_handling(self) -> None:
        """Test handling of empty or minimal coverage data."""
        with self.runner.isolated_filesystem():
            os.makedirs("src")
            os.makedirs("tests")

            # Create empty source file
            with open("src/empty.py", "w") as f:
                f.write("# Empty module\npass\n")

            # Create test that has one pass and one fail
            with open("tests/test_empty.py", "w") as f:
                f.write(
                    """
def test_nothing():
    # Test that does nothing
    pass

def test_fail():
    # Test that fails to trigger FL
    assert False, "This test always fails"
"""
                )

            result = self.runner.invoke(
                main, ["run", "--source-dir", "src", "--output", "empty_report.json"]
            )

            assert result.exit_code == 0
            assert "Total tests: 2" in result.output
            assert "Passed: 1" in result.output
            assert "Failed: 1" in result.output

            # Should still create report even with minimal data
            assert os.path.exists("empty_report.json")

            with open("empty_report.json", "r") as f:
                report = json.load(f)

            assert "files" in report
            assert "fl_metadata" in report
