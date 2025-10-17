"""
Documentation and help tests for the FLOSS run command.

These tests ensure that the command provides proper help and documentation.
"""

from click.testing import CliRunner

from floss.core.cli.main import main


class TestRunCommandDocumentation:
    """Tests for run command help and documentation."""

    def test_main_help_includes_run_command(self) -> None:
        """Test that main help lists the run command."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "run" in result.output
        assert "Run complete fault localization pipeline" in result.output

    def test_run_command_help_completeness(self) -> None:
        """Test that run command help is complete and informative."""
        runner = CliRunner()
        result = runner.invoke(main, ["run", "--help"])

        assert result.exit_code == 0

        # Check command description
        assert "Run complete fault localization pipeline" in result.output
        assert (
            "Executes tests with coverage collection and calculates fault localization"
            in result.output
        )
        assert "suspiciousness scores in a single command" in result.output

        # Check all options are documented
        options = [
            "--source-dir",
            "-s",
            "--test-dir",
            "-t",
            "--output",
            "-o",
            "--test-filter",
            "-k",
            "--ignore",
            "--omit",
            "--formulas",
            "-f",
            "--config",
            "-c",
        ]

        for option in options:
            assert option in result.output

        # Check option descriptions
        assert "Source code directory to analyze" in result.output
        assert "Test directory" in result.output
        assert "Output file for fault localization report" in result.output
        assert "Filter tests using pytest -k pattern" in result.output
        assert "Additional file patterns to ignore" in result.output
        assert "Additional file patterns to omit from coverage" in result.output
        assert "SBFL formulas to use" in result.output
        assert "Configuration file" in result.output

        # Check default values are shown
        assert "(default: .)" in result.output  # source-dir default
        assert (
            "report.json)" in result.output
        )  # output default (may be on multiple lines)
        assert "(default: floss.conf)" in result.output  # config default

    def test_run_command_examples_in_help(self) -> None:
        """Test that help includes usage examples or clear descriptions."""
        runner = CliRunner()
        result = runner.invoke(main, ["run", "--help"])

        assert result.exit_code == 0

        # Should include helpful usage information
        assert "Options:" in result.output
        assert "--help" in result.output

    def test_all_commands_listed_in_main_help(self) -> None:
        """Test that all three commands (test, fl, run) are listed."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        assert result.exit_code == 0

        # All three commands should be listed
        assert "test" in result.output
        assert "fl" in result.output
        assert "run" in result.output

        # Check command descriptions
        assert "Run tests with coverage collection" in result.output
        assert "Calculate fault localization suspiciousness scores" in result.output
        assert "Run complete fault localization pipeline" in result.output

    def test_run_command_option_consistency(self) -> None:
        """Test that run command options are consistent with test and fl commands."""
        runner = CliRunner()

        # Get help for all three commands
        test_help = runner.invoke(main, ["test", "--help"])
        fl_help = runner.invoke(main, ["fl", "--help"])
        run_help = runner.invoke(main, ["run", "--help"])

        assert test_help.exit_code == 0
        assert fl_help.exit_code == 0
        assert run_help.exit_code == 0

        # Run command should include options from both test and fl

        # From test command
        test_options = [
            "--source-dir",
            "--test-dir",
            "--test-filter",
            "--ignore",
            "--omit",
        ]
        for option in test_options:
            assert option in test_help.output
            assert option in run_help.output

        # From fl command
        fl_options = ["--formulas"]
        for option in fl_options:
            assert option in fl_help.output
            assert option in run_help.output

        # Common options
        common_options = ["--config"]
        for option in common_options:
            assert option in test_help.output
            assert option in fl_help.output
            assert option in run_help.output

        # Run should have --output but not separate --input and --output like fl
        assert "--output" in run_help.output
        assert "--input" not in run_help.output  # This is handled internally

    def test_verbose_output_with_run_command(self) -> None:
        """Test that verbose flag works with run command."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create minimal project
            import os

            os.makedirs("src")
            os.makedirs("tests")

            with open("src/simple.py", "w") as f:
                f.write("def func(): return 42")

            with open("tests/test_simple.py", "w") as f:
                f.write(
                    """
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from simple import func
def test_func(): assert func() == 42
"""
                )

            # Test verbose output
            result = runner.invoke(main, ["-v", "run", "--source-dir", "src"])

            assert result.exit_code == 0
            # Verbose output should include the same pipeline information
            assert "Running complete fault localization pipeline" in result.output
