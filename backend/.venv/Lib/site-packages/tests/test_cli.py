"""
Test suite for the new CLI implementation.

This module tests the simplified CLI with only the 'test' command.
"""

import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

from floss.core.cli import main
from floss.core.test.runner import TestResult


class TestCLITestCommand:
    """Test cases for the 'FLOSS test' command."""

    def setup_method(self) -> None:
        """Setup test environment."""
        self.runner = CliRunner()
        self.temp_dir = Path(tempfile.mkdtemp())

        # Create test directory structure
        self.source_dir = self.temp_dir / "src"
        self.test_dir = self.temp_dir / "tests"
        self.source_dir.mkdir()
        self.test_dir.mkdir()

        # Create sample files
        self.create_sample_files()

    def teardown_method(self) -> None:
        """Cleanup."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def create_sample_files(self) -> None:
        """Create sample source and test files."""
        # Sample source file
        (self.source_dir / "calculator.py").write_text(
            """
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b
"""
        )

        # Sample test file
        (self.test_dir / "test_calculator.py").write_text(
            """
import sys
sys.path.insert(0, 'src')
from calculator import add, subtract

def test_add():
    assert add(2, 3) == 5

def test_subtract():
    assert subtract(5, 3) == 2
"""
        )

        # Sample config file
        (self.temp_dir / "floss.conf").write_text(
            """[test]
source_dir = src
output_file = test_coverage.json
"""
        )

    def test_help_command(self) -> None:
        """Test that help command works."""
        result = self.runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "FLOSS: Fault Localization with Spectrum-based Scoring" in result.output

    def test_test_command_help(self) -> None:
        """Test that test command help works."""
        result = self.runner.invoke(main, ["test", "--help"])
        assert result.exit_code == 0
        assert "Run tests with coverage collection" in result.output
        assert "--source-dir" in result.output
        assert "--output" in result.output

    @patch("floss.core.test.runner.TestRunner.run_tests")
    def test_test_command_basic(self, mock_run_tests: Mock) -> None:
        """Test basic test command execution."""
        # Mock the test runner
        mock_result = TestResult(
            coverage_data={
                "meta": {},
                "files": {},
                "tests": {"failed": [], "passed": ["test1"], "skipped": []},
            },
            failed_tests=[],
            passed_tests=["test1"],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            # Create minimal structure
            os.makedirs("src")
            result = self.runner.invoke(main, ["test", "--source-dir", "src"])

            assert result.exit_code == 0
            assert "Running tests with coverage collection" in result.output
            assert "Test execution completed" in result.output
            assert "Total tests: 1" in result.output
            assert "Passed: 1" in result.output

    @patch("floss.core.test.runner.TestRunner.run_tests")
    def test_test_command_with_failures(self, mock_run_tests: Mock) -> None:
        """Test test command with failed tests."""
        # Mock the test runner with failures
        mock_result = TestResult(
            coverage_data={
                "meta": {},
                "files": {},
                "tests": {
                    "failed": ["test_fail"],
                    "passed": ["test_pass"],
                    "skipped": [],
                },
            },
            failed_tests=["tests/test_calc.py::test_fail"],
            passed_tests=["tests/test_calc.py::test_pass"],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(main, ["test", "--source-dir", "src"])

            assert result.exit_code == 0
            assert "Failed: 1" in result.output
            assert "Failed tests:" in result.output
            assert "tests/test_calc.py::test_fail" in result.output

    def test_test_command_with_custom_output(self) -> None:
        """Test test command with custom output file."""
        with patch("floss.core.test.runner.TestRunner.run_tests") as mock_run_tests:
            mock_result = TestResult(
                coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
                failed_tests=[],
                passed_tests=[],
                skipped_tests=[],
            )
            mock_run_tests.return_value = mock_result

            with self.runner.isolated_filesystem():
                os.makedirs("src")
                result = self.runner.invoke(
                    main, ["test", "--source-dir", "src", "--output", "custom.json"]
                )

                assert result.exit_code == 0
                assert "Output file: custom.json" in result.output

    def test_test_command_with_test_filter(self) -> None:
        """Test test command with test filter."""
        with patch("floss.core.test.runner.TestRunner.run_tests") as mock_run_tests:
            mock_result = TestResult(
                coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
                failed_tests=[],
                passed_tests=[],
                skipped_tests=[],
            )
            mock_run_tests.return_value = mock_result

            with self.runner.isolated_filesystem():
                os.makedirs("src")
                result = self.runner.invoke(
                    main, ["test", "--source-dir", "src", "--test-filter", "test_add"]
                )

                assert result.exit_code == 0
                # Verify that test filter was passed to runner
                mock_run_tests.assert_called_once_with("test_add")

    def test_test_command_with_ignore_patterns(self) -> None:
        """Test test command with additional ignore patterns."""
        with patch("floss.core.test.runner.TestRunner.run_tests") as mock_run_tests:
            mock_result = TestResult(
                coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
                failed_tests=[],
                passed_tests=[],
                skipped_tests=[],
            )
            mock_run_tests.return_value = mock_result

            with self.runner.isolated_filesystem():
                os.makedirs("src")
                result = self.runner.invoke(
                    main,
                    [
                        "test",
                        "--source-dir",
                        "src",
                        "--ignore",
                        "*/migrations/*",
                        "--ignore",
                        "*/temp/*",
                    ],
                )

                assert result.exit_code == 0

    def test_test_command_with_omit_patterns(self) -> None:
        """Test test command with additional omit patterns."""
        with patch("floss.core.test.runner.TestRunner.run_tests") as mock_run_tests:
            mock_result = TestResult(
                coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
                failed_tests=[],
                passed_tests=[],
                skipped_tests=[],
            )
            mock_run_tests.return_value = mock_result

            with self.runner.isolated_filesystem():
                os.makedirs("src")
                result = self.runner.invoke(
                    main,
                    [
                        "test",
                        "--source-dir",
                        "src",
                        "--omit",
                        "*/test_utils.py",
                        "--omit",
                        "*/conftest.py",
                    ],
                )

                assert result.exit_code == 0

    @patch("floss.core.test.runner.TestRunner.run_tests")
    def test_test_command_error_handling(self, mock_run_tests: Mock) -> None:
        """Test test command error handling."""
        # Mock an exception
        mock_run_tests.side_effect = RuntimeError("Test execution failed")

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(main, ["test", "--source-dir", "src"])

            assert result.exit_code == 1
            assert "Error:" in result.output
            assert "Test execution failed" in result.output

    @patch("floss.core.test.runner.TestRunner.run_tests")
    def test_test_command_verbose_error(self, mock_run_tests: Mock) -> None:
        """Test test command error handling with verbose mode."""
        # Mock an exception
        mock_run_tests.side_effect = RuntimeError("Test execution failed")

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(
                main, ["--verbose", "test", "--source-dir", "src"]
            )

            assert result.exit_code == 1
            assert "Error:" in result.output

    def test_configuration_file_loading(self) -> None:
        """Test that configuration file is loaded correctly."""
        with patch("floss.core.test.runner.TestRunner.run_tests") as mock_run_tests:
            mock_result = TestResult(
                coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
                failed_tests=[],
                passed_tests=[],
                skipped_tests=[],
            )
            mock_run_tests.return_value = mock_result

            with self.runner.isolated_filesystem():
                os.makedirs("app")  # Different from default "src"

                # Create config file
                with open("custom.conf", "w") as f:
                    f.write(
                        """[test]
source_dir = app
output_file = app_coverage.json
"""
                    )

                result = self.runner.invoke(main, ["test", "--config", "custom.conf"])

                assert result.exit_code == 0
                assert "Source dir: app" in result.output
                assert "Output file: app_coverage.json" in result.output

    def test_command_line_override_config_file(self) -> None:
        """Test that command line arguments override config file."""
        with patch("floss.core.test.runner.TestRunner.run_tests") as mock_run_tests:
            mock_result = TestResult(
                coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
                failed_tests=[],
                passed_tests=[],
                skipped_tests=[],
            )
            mock_run_tests.return_value = mock_result

            with self.runner.isolated_filesystem():
                os.makedirs("src")
                os.makedirs("custom_src")

                # Create config file with different values
                with open("test.conf", "w") as f:
                    f.write(
                        """[test]
source_dir = src
output_file = config_coverage.json
"""
                    )

                # Override with command line
                result = self.runner.invoke(
                    main,
                    [
                        "test",
                        "--config",
                        "test.conf",
                        "--source-dir",
                        "custom_src",
                        "--output",
                        "cli_coverage.json",
                    ],
                )

                assert result.exit_code == 0
                assert "Source dir: custom_src" in result.output
                assert "Output file: cli_coverage.json" in result.output


class TestCLIMainGroup:
    """Test cases for the main CLI group."""

    def setup_method(self) -> None:
        """Setup test environment."""
        self.runner = CliRunner()

    def test_main_group_help(self) -> None:
        """Test main group help output."""
        result = self.runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "FLOSS: Fault Localization with Spectrum-based Scoring" in result.output
        assert "Commands:" in result.output
        assert "test" in result.output

    def test_verbose_flag(self) -> None:
        """Test verbose flag functionality."""
        result = self.runner.invoke(main, ["--verbose", "--help"])
        assert result.exit_code == 0

    def test_unknown_command(self) -> None:
        """Test handling of unknown commands."""
        result = self.runner.invoke(main, ["unknown-command"])
        assert result.exit_code != 0
        assert "No such command" in result.output

    def test_no_command(self) -> None:
        """Test behavior when no command is provided."""
        result = self.runner.invoke(main, [])
        # Click returns exit code 2 when no command is provided and shows help
        assert result.exit_code == 2 or "Commands:" in result.output


class TestCLIIntegration:
    """Integration tests for CLI functionality."""

    def setup_method(self) -> None:
        """Setup test environment."""
        self.runner = CliRunner()

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("builtins.open", create=True)
    def test_full_workflow_mock(self, mock_open: Mock, mock_run_tests: Mock) -> None:
        """Test full workflow with mocked file operations."""
        # Mock the test result
        mock_coverage_data = {
            "meta": {"version": "7.9.2"},
            "files": {"src/calculator.py": {"executed_lines": [1, 2, 3]}},
            "totals": {"covered_lines": 3},
            "tests": {
                "failed": ["tests/test_calc.py::test_fail"],
                "passed": [
                    "tests/test_calc.py::test_pass1",
                    "tests/test_calc.py::test_pass2",
                ],
                "skipped": [],
            },
        }

        mock_result = TestResult(
            coverage_data=mock_coverage_data,
            failed_tests=["tests/test_calc.py::test_fail"],
            passed_tests=[
                "tests/test_calc.py::test_pass1",
                "tests/test_calc.py::test_pass2",
            ],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        # Mock file writing
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(main, ["test", "--source-dir", "src"])

            assert result.exit_code == 0
            assert "Test execution completed" in result.output
            assert "Total tests: 3" in result.output
            assert "Passed: 2" in result.output
            assert "Failed: 1" in result.output

            # Verify that JSON was written
            mock_open.assert_called_with("coverage.json", "w")

    def test_config_file_precedence(self) -> None:
        """Test configuration file precedence and merging."""
        with patch("floss.core.test.runner.TestRunner.run_tests") as mock_run_tests:
            mock_result = TestResult(
                coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
                failed_tests=[],
                passed_tests=[],
                skipped_tests=[],
            )
            mock_run_tests.return_value = mock_result

            with self.runner.isolated_filesystem():
                os.makedirs("config_src")
                os.makedirs("cli_src")

                # Create config file
                with open("floss.conf", "w") as f:
                    f.write(
                        """[test]
source_dir = config_src
test_dir = config_tests
output_file = config.json
ignore = */__init__.py, */config_ignore/*
omit = */__init__.py, */config_omit/*
"""
                    )

                # Test with partial CLI override
                result = self.runner.invoke(
                    main,
                    [
                        "test",
                        "--source-dir",
                        "cli_src",  # Override source dir
                        "--ignore",
                        "*/cli_ignore/*",  # Add to ignore patterns
                        "--omit",
                        "*/cli_omit/*",  # Add to omit patterns
                    ],
                )

                assert result.exit_code == 0
                assert "Source dir: cli_src" in result.output  # CLI override
                assert "Output file: config.json" in result.output  # From config file


class TestCLIRunCommand:
    """Test cases for the 'FLOSS run' command."""

    def setup_method(self) -> None:
        """Setup test environment."""
        self.runner = CliRunner()
        self.temp_dir = Path(tempfile.mkdtemp())

        # Create test directory structure
        self.source_dir = self.temp_dir / "src"
        self.test_dir = self.temp_dir / "tests"
        self.source_dir.mkdir()
        self.test_dir.mkdir()

        # Create sample files
        self.create_sample_files()

    def teardown_method(self) -> None:
        """Cleanup."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def create_sample_files(self) -> None:
        """Create sample source and test files."""
        # Sample source file
        (self.source_dir / "calculator.py").write_text(
            """
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b
"""
        )

        # Sample test file
        (self.test_dir / "test_calculator.py").write_text(
            """
import sys
sys.path.insert(0, 'src')
from calculator import add, subtract

def test_add():
    assert add(2, 3) == 5

def test_subtract():
    assert subtract(5, 3) == 2
"""
        )

        # Sample config file
        (self.temp_dir / "floss.conf").write_text(
            """[test]
source_dir = src
output_file = coverage.json

[fl]
input_file = coverage.json
output_file = report.json
formulas = ochiai, tarantula
"""
        )

    def test_run_command_help(self) -> None:
        """Test that run command help works."""
        result = self.runner.invoke(main, ["run", "--help"])
        assert result.exit_code == 0
        assert "Run complete fault localization pipeline" in result.output
        assert "--source-dir" in result.output
        assert "--output" in result.output
        assert "--formulas" in result.output

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("floss.core.fl.engine.FLEngine.calculate_suspiciousness")
    def test_run_command_basic(
        self, mock_calculate: Mock, mock_run_tests: Mock
    ) -> None:
        """Test basic run command execution with failed tests."""
        # Mock the test runner with some failed tests to trigger FL
        mock_result = TestResult(
            coverage_data={
                "meta": {},
                "files": {},
                "tests": {"failed": ["test_fail"], "passed": ["test1"], "skipped": []},
            },
            failed_tests=["test_fail"],
            passed_tests=["test1"],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(main, ["run", "--source-dir", "src"])

            assert result.exit_code == 0
            assert "Running complete fault localization pipeline" in result.output
            assert "Phase 1: Running tests with coverage" in result.output
            assert "Phase 2: Calculating fault localization scores" in result.output
            assert "Fault localization pipeline completed" in result.output
            assert "Total tests: 2" in result.output
            assert "Passed: 1" in result.output
            assert "Failed: 1" in result.output

            # Verify both phases were called
            mock_run_tests.assert_called_once()
            mock_calculate.assert_called_once()

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("floss.core.fl.engine.FLEngine.calculate_suspiciousness")
    def test_run_command_with_failures(
        self, mock_calculate: Mock, mock_run_tests: Mock
    ) -> None:
        """Test run command with failed tests."""
        mock_result = TestResult(
            coverage_data={
                "meta": {},
                "files": {},
                "tests": {
                    "failed": ["test_fail"],
                    "passed": ["test_pass"],
                    "skipped": [],
                },
            },
            failed_tests=["tests/test_calc.py::test_fail"],
            passed_tests=["tests/test_calc.py::test_pass"],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(main, ["run", "--source-dir", "src"])

            assert result.exit_code == 0
            assert "Failed: 1" in result.output
            assert "Failed tests:" in result.output
            assert "tests/test_calc.py::test_fail" in result.output

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("floss.core.fl.engine.FLEngine.calculate_suspiciousness")
    def test_run_command_custom_output(
        self, mock_calculate: Mock, mock_run_tests: Mock
    ) -> None:
        """Test run command with custom output file."""
        mock_result = TestResult(
            coverage_data={
                "tests": {"failed": ["test_fail"], "passed": [], "skipped": []}
            },
            failed_tests=["test_fail"],
            passed_tests=[],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(
                main, ["run", "--source-dir", "src", "--output", "custom_report.json"]
            )

            assert result.exit_code == 0
            assert "Final output: custom_report.json" in result.output
            assert "Report saved to: custom_report.json" in result.output

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("floss.core.fl.engine.FLEngine.calculate_suspiciousness")
    def test_run_command_custom_formulas(
        self, mock_calculate: Mock, mock_run_tests: Mock
    ) -> None:
        """Test run command with custom formulas."""
        mock_result = TestResult(
            coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
            failed_tests=[],
            passed_tests=[],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(
                main,
                [
                    "run",
                    "--source-dir",
                    "src",
                    "--formulas",
                    "ochiai",
                    "--formulas",
                    "tarantula",
                ],
            )

            assert result.exit_code == 0
            assert "Formulas: ochiai, tarantula" in result.output

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("floss.core.fl.engine.FLEngine.calculate_suspiciousness")
    def test_run_command_with_test_filter(
        self, mock_calculate: Mock, mock_run_tests: Mock
    ) -> None:
        """Test run command with test filter."""
        mock_result = TestResult(
            coverage_data={
                "tests": {"failed": [], "passed": ["test_add"], "skipped": []}
            },
            failed_tests=[],
            passed_tests=["test_add"],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(
                main, ["run", "--source-dir", "src", "--test-filter", "add"]
            )

            assert result.exit_code == 0
            # Verify the test filter was passed through
            mock_run_tests.assert_called_once_with("add")

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("floss.core.fl.engine.FLEngine.calculate_suspiciousness")
    def test_run_command_ignore_and_omit_patterns(
        self, mock_calculate: Mock, mock_run_tests: Mock
    ) -> None:
        """Test run command with ignore and omit patterns."""
        mock_result = TestResult(
            coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
            failed_tests=[],
            passed_tests=[],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(
                main,
                [
                    "run",
                    "--source-dir",
                    "src",
                    "--ignore",
                    "*/temp/*",
                    "--omit",
                    "*/build/*",
                ],
            )

            assert result.exit_code == 0
            # Verify patterns were added to configuration
            mock_run_tests.assert_called_once()

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("floss.core.fl.engine.FLEngine.calculate_suspiciousness")
    @patch("os.remove")
    def test_run_command_intermediate_file_cleanup(
        self, mock_remove: Mock, mock_calculate: Mock, mock_run_tests: Mock
    ) -> None:
        """Test that intermediate files are cleaned up."""
        mock_result = TestResult(
            coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
            failed_tests=[],
            passed_tests=[],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            os.makedirs("src")

            # Mock os.path.exists to return True for intermediate file
            with patch("os.path.exists", return_value=True):
                result = self.runner.invoke(
                    main,
                    ["run", "--source-dir", "src", "--output", "final_report.json"],
                )

            assert result.exit_code == 0
            # Verify intermediate file was cleaned up
            mock_remove.assert_called_once_with("final_report_coverage.json")

    @patch("floss.core.test.runner.TestRunner.run_tests")
    def test_run_command_test_phase_error(self, mock_run_tests: Mock) -> None:
        """Test run command handles test phase errors gracefully."""
        mock_run_tests.side_effect = Exception("Test execution failed")

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(main, ["run", "--source-dir", "src"])

            assert result.exit_code == 1
            assert "Error: Test execution failed" in result.output

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("floss.core.fl.engine.FLEngine.calculate_suspiciousness")
    def test_run_command_fl_phase_error(
        self, mock_calculate: Mock, mock_run_tests: Mock
    ) -> None:
        """Test run command handles FL phase errors gracefully."""
        mock_result = TestResult(
            coverage_data={
                "tests": {"failed": ["test_fail"], "passed": [], "skipped": []}
            },
            failed_tests=["test_fail"],
            passed_tests=[],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result
        mock_calculate.side_effect = Exception("FL calculation failed")

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(main, ["run", "--source-dir", "src"])

            assert result.exit_code == 1
            assert "Error: FL calculation failed" in result.output

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("floss.core.fl.engine.FLEngine.calculate_suspiciousness")
    def test_run_command_config_file_integration(
        self, mock_calculate: Mock, mock_run_tests: Mock
    ) -> None:
        """Test run command loads and merges configurations correctly."""
        mock_result = TestResult(
            coverage_data={"tests": {"failed": [], "passed": [], "skipped": []}},
            failed_tests=[],
            passed_tests=[],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            os.makedirs("custom_tests")

            # Create config file
            with open("custom.conf", "w") as f:
                f.write(
                    """[test]
source_dir = config_src
test_dir = config_tests
ignore = */config_ignore/*

[fl]
formulas = ochiai, jaccard
"""
                )

            result = self.runner.invoke(
                main,
                [
                    "run",
                    "--config",
                    "custom.conf",
                    "--source-dir",
                    "src",  # Override config
                    "--formulas",
                    "tarantula",  # Override config
                ],
            )

            assert result.exit_code == 0
            assert "Source dir: src" in result.output  # CLI override
            assert "Formulas: tarantula" in result.output  # CLI override

    @patch("floss.core.test.runner.TestRunner.run_tests")
    @patch("floss.core.fl.engine.FLEngine.calculate_suspiciousness")
    def test_run_command_skips_fl_when_all_tests_pass(
        self, mock_calculate: Mock, mock_run_tests: Mock
    ) -> None:
        """Test that FL is skipped when all tests pass."""
        mock_result = TestResult(
            coverage_data={
                "tests": {"failed": [], "passed": ["test1", "test2"], "skipped": []}
            },
            failed_tests=[],  # No failed tests
            passed_tests=["test1", "test2"],
            skipped_tests=[],
        )
        mock_run_tests.return_value = mock_result

        with self.runner.isolated_filesystem():
            os.makedirs("src")
            result = self.runner.invoke(main, ["run", "--source-dir", "src"])

            assert result.exit_code == 0
            assert "All tests passed - fault localization not needed" in result.output
            assert "Pipeline completed successfully" in result.output

            # Verify FL was NOT called
            mock_run_tests.assert_called_once()
            mock_calculate.assert_not_called()
