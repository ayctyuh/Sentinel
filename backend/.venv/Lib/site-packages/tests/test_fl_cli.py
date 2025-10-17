"""
Tests for fault localization CLI commands.
"""

import json
import os
from typing import Any, Dict

from click.testing import CliRunner

from floss.core.cli.main import main


class TestFLCLI:
    """Test fault localization CLI commands."""

    def test_fl_command_help(self) -> None:
        """Test FL command help."""
        runner = CliRunner()
        result = runner.invoke(main, ["fl", "--help"])

        assert result.exit_code == 0
        assert "Calculate fault localization suspiciousness scores" in result.output
        assert "--input" in result.output
        assert "--output" in result.output
        assert "--formulas" in result.output

    def test_fl_command_basic(self) -> None:
        """Test basic FL command execution."""
        # Create test coverage data
        coverage_data = {
            "tests": {"passed": ["test1"], "failed": ["test2"]},
            "files": {"test_file.py": {"contexts": {"1": ["test1|run", "test2|run"]}}},
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Write coverage file
            with open("coverage.json", "w") as f:
                json.dump(coverage_data, f)

            # Run FL command
            result = runner.invoke(main, ["fl"])

            assert result.exit_code == 0
            assert "Calculating fault localization scores" in result.output
            assert "Fault localization completed" in result.output
            assert "Report saved to: report.json" in result.output

            # Check output file exists
            assert os.path.exists("report.json")

            # Verify output content
            with open("report.json", "r") as f:
                report = json.load(f)

            assert "files" in report
            assert "fl_metadata" in report
            assert "suspiciousness" in report["files"]["test_file.py"]

    def test_fl_command_custom_files(self) -> None:
        """Test FL command with custom input/output files."""
        coverage_data = {
            "tests": {"passed": ["test1"], "failed": []},
            "files": {"file.py": {"contexts": {"1": ["test1|run"]}}},
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Write coverage file with custom name
            with open("custom_coverage.json", "w") as f:
                json.dump(coverage_data, f)

            # Run FL command with custom files
            result = runner.invoke(
                main,
                [
                    "fl",
                    "--input",
                    "custom_coverage.json",
                    "--output",
                    "custom_report.json",
                ],
            )

            assert result.exit_code == 0
            assert "Input file: custom_coverage.json" in result.output
            assert "Output file: custom_report.json" in result.output
            assert os.path.exists("custom_report.json")

    def test_fl_command_custom_formulas(self) -> None:
        """Test FL command with custom formulas."""
        coverage_data = {
            "tests": {"passed": ["test1"], "failed": ["test2"]},
            "files": {"file.py": {"contexts": {"1": ["test1|run", "test2|run"]}}},
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("coverage.json", "w") as f:
                json.dump(coverage_data, f)

            # Run with specific formulas
            result = runner.invoke(
                main, ["fl", "--formulas", "ochiai", "--formulas", "dstar3"]
            )

            assert result.exit_code == 0
            assert "Formulas: ochiai, dstar3" in result.output

            # Verify only specified formulas are used
            with open("report.json", "r") as f:
                report = json.load(f)

            formulas_used = report["fl_metadata"]["formulas_used"]
            assert set(formulas_used) == {"ochiai", "dstar3"}

            susp = report["files"]["file.py"]["suspiciousness"]["1"]
            assert "ochiai" in susp
            assert "dstar3" in susp
            assert "tarantula" not in susp

    def test_fl_command_with_config(self) -> None:
        """Test FL command with configuration file."""
        coverage_data = {
            "tests": {"passed": ["test1"], "failed": []},
            "files": {"file.py": {"contexts": {"1": ["test1|run"]}}},
        }

        config_content = """
[fl]
input_file = my_coverage.json
output_file = my_report.json
formulas = ochiai, jaccard
"""

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Write files
            with open("my_coverage.json", "w") as f:
                json.dump(coverage_data, f)

            with open("test.conf", "w") as f:
                f.write(config_content)

            # Run with config
            result = runner.invoke(main, ["fl", "--config", "test.conf"])

            assert result.exit_code == 0
            assert "Input file: my_coverage.json" in result.output
            assert "Output file: my_report.json" in result.output
            assert "Formulas: ochiai, jaccard" in result.output
            assert os.path.exists("my_report.json")

    def test_fl_command_file_not_found(self) -> None:
        """Test FL command with non-existent input file."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(main, ["fl", "--input", "nonexistent.json"])

            assert result.exit_code == 1
            assert "Error:" in result.output
            assert "No such file or directory" in result.output

    def test_fl_command_invalid_json(self) -> None:
        """Test FL command with invalid JSON input."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            # Write invalid JSON
            with open("invalid.json", "w") as f:
                f.write("{ invalid json")

            result = runner.invoke(main, ["fl", "--input", "invalid.json"])

            assert result.exit_code == 1
            assert "Error:" in result.output

    def test_fl_command_verbose(self) -> None:
        """Test FL command with verbose output."""
        coverage_data = {
            "tests": {"passed": ["test1"], "failed": []},
            "files": {"file.py": {"contexts": {"1": ["test1|run"]}}},
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("coverage.json", "w") as f:
                json.dump(coverage_data, f)

            result = runner.invoke(main, ["--verbose", "fl"])

            assert result.exit_code == 0
            assert "Calculating fault localization scores" in result.output

    def test_fl_command_empty_coverage(self) -> None:
        """Test FL command with empty coverage data."""
        coverage_data: Dict[str, Any] = {
            "tests": {"passed": [], "failed": []},
            "files": {},
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("coverage.json", "w") as f:
                json.dump(coverage_data, f)

            result = runner.invoke(main, ["fl"])

            assert result.exit_code == 0
            assert 'total_lines_analyzed": 0' in open("report.json").read()

    def test_main_command_shows_fl(self) -> None:
        """Test that main help shows FL command."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "fl" in result.output
        assert "Calculate fault localization suspiciousness scores" in result.output


class TestFLCLIIntegration:
    """Integration tests for FL CLI with real data."""

    def test_complete_workflow_simulation(self) -> None:
        """Test complete test->FL workflow simulation."""
        # Simulate coverage data as would be generated by test command
        realistic_coverage = {
            "meta": {
                "format": 3,
                "version": "7.9.2",
                "timestamp": "2025-01-01T12:00:00.000000",
                "branch_coverage": True,
                "show_contexts": True,
            },
            "files": {
                "src\\calculator.py": {
                    "executed_lines": [1, 4, 5, 7, 10, 12],
                    "contexts": {
                        "1": [""],
                        "4": [""],
                        "5": [
                            "tests/test_calc.py::test_add_positive|run",
                            "tests/test_calc.py::test_add_negative|run",
                        ],
                        "7": [
                            "tests/test_calc.py::test_add_positive|run",
                            "tests/test_calc.py::test_add_negative|run",
                        ],
                        "10": ["tests/test_calc.py::test_divide_by_zero|run"],
                        "12": ["tests/test_calc.py::test_divide_by_zero|run"],
                    },
                    "summary": {
                        "covered_lines": 6,
                        "num_statements": 6,
                        "percent_covered": 100.0,
                        "missing_lines": 0,
                    },
                }
            },
            "tests": {
                "passed": ["tests/test_calc.py::test_add_positive"],
                "failed": [
                    "tests/test_calc.py::test_add_negative",
                    "tests/test_calc.py::test_divide_by_zero",
                ],
                "skipped": [],
            },
            "totals": {
                "covered_lines": 6,
                "num_statements": 6,
                "percent_covered": 100.0,
            },
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Write realistic coverage data
            with open("coverage.json", "w") as f:
                json.dump(realistic_coverage, f, indent=2)

            # Create config file
            with open("floss.conf", "w") as f:
                f.write(
                    """
[fl]
formulas = ochiai, tarantula, jaccard, dstar2, dstar3
"""
                )

            # Run FL command
            result = runner.invoke(main, ["fl"])

            assert result.exit_code == 0
            assert os.path.exists("report.json")

            # Verify output
            with open("report.json", "r") as f:
                report = json.load(f)

            # Check structure preservation
            assert report["meta"]["version"] == "7.9.2"
            assert report["totals"]["covered_lines"] == 6

            # Check FL additions
            assert "fl_metadata" in report
            assert len(report["fl_metadata"]["formulas_used"]) == 5

            file_data = report["files"]["src\\calculator.py"]
            assert "suspiciousness" in file_data

            # Lines 10,12 should have higher suspiciousness (only in failing tests)
            susp = file_data["suspiciousness"]

            # Lines covered by both pass/fail tests should have medium suspiciousness
            assert "5" in susp
            assert "7" in susp

            # Lines covered only by failing tests should have highest suspiciousness
            assert "10" in susp
            assert "12" in susp

            # Verify all formulas calculated scores
            for line in ["5", "7", "10", "12"]:
                assert "ochiai" in susp[line]
                assert "tarantula" in susp[line]
                assert "jaccard" in susp[line]
                assert "dstar2" in susp[line]
                assert "dstar3" in susp[line]
