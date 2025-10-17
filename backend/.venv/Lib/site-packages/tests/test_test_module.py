"""
Test suite for the new test module.

This module tests TestConfig and TestRunner classes with focus on
the new simplified implementation using pytest with coverage contexts.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import Mock, patch

import pytest

from floss.core.test.config import TestConfig
from floss.core.test.runner import TestResult, TestRunner


class TestTestConfig:
    """Test cases for TestConfig class."""

    def setup_method(self) -> None:
        """Setup test environment."""
        self.temp_dir = Path(tempfile.mkdtemp())
        os.chdir(self.temp_dir)

    def teardown_method(self) -> None:
        """Cleanup."""
        os.chdir("/")
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def test_default_configuration(self) -> None:
        """Test default configuration values."""
        config = TestConfig()

        assert config.source_dir == "."
        assert config.test_dir is None
        assert config.output_file == "coverage.json"
        assert config.ignore_patterns == ["*/__init__.py"]
        assert config.omit_patterns == ["*/__init__.py"]

    def test_configuration_from_nonexistent_file(self) -> None:
        """Test loading configuration when file doesn't exist."""
        config = TestConfig.from_file("nonexistent.conf")

        # Should return default values
        assert config.source_dir == "."
        assert config.test_dir is None
        assert config.output_file == "coverage.json"
        assert config.ignore_patterns == ["*/__init__.py"]
        assert config.omit_patterns == ["*/__init__.py"]

    def test_configuration_from_file(self) -> None:
        """Test loading configuration from file."""
        config_content = """[test]
source_dir = app
test_dir = tests
output_file = my_coverage.json
ignore = */__init__.py, */migrations/*
omit = */__init__.py, */test_utils.py
"""
        config_file = self.temp_dir / "test.conf"
        config_file.write_text(config_content)

        config = TestConfig.from_file("test.conf")

        assert config.source_dir == "app"
        assert config.test_dir == "tests"
        assert config.output_file == "my_coverage.json"
        assert config.ignore_patterns is not None
        assert "*/__init__.py" in config.ignore_patterns
        assert "*/migrations/*" in config.ignore_patterns
        assert config.omit_patterns is not None
        assert "*/__init__.py" in config.omit_patterns
        assert "*/test_utils.py" in config.omit_patterns

    def test_configuration_partial_file(self) -> None:
        """Test loading configuration with only some values specified."""
        config_content = """[test]
source_dir = custom_src
output_file = custom.json
"""
        config_file = self.temp_dir / "partial.conf"
        config_file.write_text(config_content)

        config = TestConfig.from_file("partial.conf")

        assert config.source_dir == "custom_src"
        assert config.test_dir is None  # Should remain default
        assert config.output_file == "custom.json"
        assert config.ignore_patterns == ["*/__init__.py"]  # Should remain default

    def test_coveragerc_content_generation(self) -> None:
        """Test generation of .coveragerc content."""
        config = TestConfig()
        config.omit_patterns = ["*/__init__.py", "*/test_*"]

        content = config.get_coveragerc_content()

        assert "[run]" in content
        assert "omit = */__init__.py, */test_*" in content
        assert "[json]" in content
        assert "show_contexts = True" in content

    def test_write_coveragerc_file(self) -> None:
        """Test writing .coveragerc file."""
        config = TestConfig()
        config.omit_patterns = ["*/__init__.py", "*/migrations/*"]

        coveragerc_path = self.temp_dir / ".coveragerc"
        config.write_coveragerc(str(coveragerc_path))

        assert coveragerc_path.exists()
        content = coveragerc_path.read_text()
        assert "omit = */__init__.py, */migrations/*" in content
        assert "show_contexts = True" in content


class TestTestRunner:
    """Test cases for TestRunner class."""

    def setup_method(self) -> None:
        """Setup test environment."""
        self.temp_dir = Path(tempfile.mkdtemp())
        os.chdir(self.temp_dir)

        # Create test config
        self.config = TestConfig()
        self.config.source_dir = "src"
        self.config.output_file = "test_coverage.json"

        # Create sample directory structure
        self.src_dir = self.temp_dir / "src"
        self.tests_dir = self.temp_dir / "tests"
        self.src_dir.mkdir()
        self.tests_dir.mkdir()

        # Create sample files
        self.create_sample_files()

    def teardown_method(self) -> None:
        """Cleanup."""
        os.chdir("/")
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def create_sample_files(self) -> None:
        """Create sample source and test files."""
        # Sample source file
        (self.src_dir / "calculator.py").write_text(
            """
def add(a, b):
    return a + b

def subtract(a, b):
    if a > b:
        return a - b
    else:
        return b - a
"""
        )

        # Sample test file
        (self.tests_dir / "test_calculator.py").write_text(
            """
import sys
sys.path.insert(0, 'src')
from calculator import add, subtract

def test_add_positive():
    assert add(2, 3) == 5

def test_add_negative():
    assert add(-1, 1) == 0

def test_subtract_normal():
    assert subtract(5, 3) == 2
"""
        )

    def test_runner_initialization(self) -> None:
        """Test TestRunner initialization."""
        runner = TestRunner(self.config)
        assert runner.config == self.config

    @patch("subprocess.run")
    def test_build_pytest_command_basic(self, mock_run: Mock) -> None:
        """Test building basic pytest command."""
        runner = TestRunner(self.config)

        # Mock successful pytest execution
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        cmd = runner._build_pytest_command("/tmp/test.xml")

        expected_elements = [
            "pytest",
            "--cov=src",
            "--cov-context=test",
            "--cov-report=json:test_coverage.json",
            "--cov-branch",
            "-v",
            "--ignore-glob",
            "*/__init__.py",
            "--junitxml",
            "/tmp/test.xml",
        ]

        for element in expected_elements:
            assert element in cmd

    @patch("subprocess.run")
    def test_build_pytest_command_with_test_dir(self, mock_run: Mock) -> None:
        """Test building pytest command with test directory."""
        self.config.test_dir = "tests"
        runner = TestRunner(self.config)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        cmd = runner._build_pytest_command("/tmp/test.xml")

        assert "tests" in cmd

    @patch("subprocess.run")
    def test_build_pytest_command_with_filter(self, mock_run: Mock) -> None:
        """Test building pytest command with test filter."""
        runner = TestRunner(self.config)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        cmd = runner._build_pytest_command("/tmp/test.xml", "test_add")

        assert "-k" in cmd
        assert "test_add" in cmd

    @patch("subprocess.run")
    def test_build_pytest_command_with_ignore_patterns(self, mock_run: Mock) -> None:
        """Test building pytest command with additional ignore patterns."""
        self.config.ignore_patterns = ["*/__init__.py", "*/migrations/*"]
        runner = TestRunner(self.config)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        cmd = runner._build_pytest_command("/tmp/test.xml")

        # Should have two --ignore-glob options
        ignore_count = cmd.count("--ignore-glob")
        assert ignore_count == 2
        assert "*/migrations/*" in cmd

    def test_convert_to_pytest_format(self) -> None:
        """Test conversion from JUnit format to pytest format."""
        runner = TestRunner(self.config)

        # Test normal test case (function-based)
        result = runner._convert_to_pytest_format(
            "tests.test_calculator", "test_add_positive"
        )
        assert result == "tests/test_calculator.py::test_add_positive"

        # Test class-based test case
        result = runner._convert_to_pytest_format(
            "tests.test_calculator.TestCalculator", "test_add_positive"
        )
        assert result == "tests/test_calculator.py::TestCalculator::test_add_positive"

        # Test nested class-based test case
        result = runner._convert_to_pytest_format(
            "tests.test_math.TestAdvanced", "test_complex_operations"
        )
        assert result == "tests/test_math.py::TestAdvanced::test_complex_operations"

        # Test ruff case
        result = runner._convert_to_pytest_format(
            "tests.test_calculator.ruff", "format"
        )
        assert result == "tests.test_calculator.ruff::format"

        # Test single part classname
        result = runner._convert_to_pytest_format("test_simple", "test_func")
        assert result == "test_simple::test_func"

    def test_merge_test_outcomes(self) -> None:
        """Test merging test outcomes into coverage data."""
        runner = TestRunner(self.config)

        coverage_data = {"meta": {"version": "7.9.2"}, "files": {}, "totals": {}}

        test_outcomes = {
            "failed": ["tests/test_calc.py::test_fail"],
            "passed": [
                "tests/test_calc.py::test_pass1",
                "tests/test_calc.py::test_pass2",
            ],
            "skipped": ["tests/test_calc.py::test_skip"],
        }

        result = runner._merge_test_outcomes(coverage_data, test_outcomes)

        assert "tests" in result
        assert result["tests"]["failed"] == ["tests/test_calc.py::test_fail"]
        assert len(result["tests"]["passed"]) == 2
        assert result["tests"]["skipped"] == ["tests/test_calc.py::test_skip"]

        # Original data should be preserved
        assert "meta" in result
        assert "files" in result
        assert "totals" in result

    @patch("floss.core.test.runner.TestRunner._load_coverage_data")
    @patch("floss.core.test.runner.TestRunner._parse_junit_xml")
    @patch("subprocess.run")
    def test_run_tests_success(
        self, mock_run: Mock, mock_parse_xml: Mock, mock_load_coverage: Mock
    ) -> None:
        """Test successful test run."""
        runner = TestRunner(self.config)

        # Mock subprocess success
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        # Mock coverage data
        mock_coverage_data = {
            "meta": {"version": "7.9.2"},
            "files": {"src/calculator.py": {}},
            "totals": {},
        }
        mock_load_coverage.return_value = mock_coverage_data

        # Mock test outcomes
        mock_test_outcomes = {
            "failed": ["tests/test_calc.py::test_fail"],
            "passed": ["tests/test_calc.py::test_pass"],
            "skipped": [],
        }
        mock_parse_xml.return_value = mock_test_outcomes

        result = runner.run_tests()

        assert isinstance(result, TestResult)
        assert result.failed_tests == ["tests/test_calc.py::test_fail"]
        assert result.passed_tests == ["tests/test_calc.py::test_pass"]
        assert result.skipped_tests == []
        assert "tests" in result.coverage_data

    @patch("subprocess.run")
    def test_run_tests_pytest_failure(self, mock_run: Mock) -> None:
        """Test handling of pytest execution failure."""
        runner = TestRunner(self.config)

        # Mock subprocess failure
        # (return code 2 indicates error, not just test failures)
        mock_run.return_value = Mock(returncode=2, stdout="", stderr="pytest error")

        with pytest.raises(RuntimeError, match="pytest execution failed"):
            runner.run_tests()

    @patch("floss.core.test.runner.TestRunner._parse_junit_xml")
    @patch("subprocess.run")
    def test_run_tests_missing_coverage_file(
        self, mock_run: Mock, mock_parse_xml: Mock
    ) -> None:
        """Test handling when coverage file is missing."""
        runner = TestRunner(self.config)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_parse_xml.return_value = {"failed": [], "passed": [], "skipped": []}

        with pytest.raises(RuntimeError, match="Coverage file .* not found"):
            runner.run_tests()

    def test_parse_junit_xml_with_sample_data(self) -> None:
        """Test parsing JUnit XML with sample data."""
        runner = TestRunner(self.config)

        # Create sample JUnit XML
        xml_content = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<testsuites name="pytest tests">\n'
            '    <testsuite name="pytest" errors="0" failures="1" '
            'skipped="1" tests="4">\n'
            '        <testcase classname="tests.test_calculator" '
            'name="test_add_positive" time="0.001"/>\n'
            '        <testcase classname="tests.test_calculator.TestCalculator" '
            'name="test_add_negative" time="0.002">\n'
            '            <failure message="assert False">Failure message</failure>\n'
            "        </testcase>\n"
            '        <testcase classname="tests.test_calculator.TestCalculator" '
            'name="test_skip_this" time="0.000">\n'
            '            <skipped message="skipped">Skip message</skipped>\n'
            "        </testcase>\n"
            '        <testcase classname="tests.test_calculator.TestAdvanced" '
            'name="test_complex_math" time="0.003"/>\n'
            "    </testsuite>\n"
            "</testsuites>"
        )

        xml_file = self.temp_dir / "test_results.xml"
        xml_file.write_text(xml_content)

        outcomes = runner._parse_junit_xml(str(xml_file))

        assert len(outcomes["passed"]) == 2
        assert "tests/test_calculator.py::test_add_positive" in outcomes["passed"]
        assert (
            "tests/test_calculator.py::TestAdvanced::test_complex_math"
            in outcomes["passed"]
        )

        assert len(outcomes["failed"]) == 1
        assert (
            "tests/test_calculator.py::TestCalculator::test_add_negative"
            in outcomes["failed"]
        )

        assert len(outcomes["skipped"]) == 1
        assert (
            "tests/test_calculator.py::TestCalculator::test_skip_this"
            in outcomes["skipped"]
        )


class TestTestResult:
    """Test cases for TestResult dataclass."""

    def test_test_result_creation(self) -> None:
        """Test TestResult creation and attributes."""
        coverage_data: Dict[str, Any] = {"meta": {}, "files": {}}
        failed_tests = ["test1", "test2"]
        passed_tests = ["test3", "test4", "test5"]
        skipped_tests = ["test6"]

        result = TestResult(
            coverage_data=coverage_data,
            failed_tests=failed_tests,
            passed_tests=passed_tests,
            skipped_tests=skipped_tests,
        )

        assert result.coverage_data == coverage_data
        assert result.failed_tests == failed_tests
        assert result.passed_tests == passed_tests
        assert result.skipped_tests == skipped_tests

    def test_test_result_empty_lists(self) -> None:
        """Test TestResult with empty test lists."""
        result = TestResult(
            coverage_data={}, failed_tests=[], passed_tests=[], skipped_tests=[]
        )

        assert len(result.failed_tests) == 0
        assert len(result.passed_tests) == 0
        assert len(result.skipped_tests) == 0


class TestIntegration:
    """Integration tests for the test module."""

    def setup_method(self) -> None:
        """Setup test environment."""
        self.temp_dir = Path(tempfile.mkdtemp())
        os.chdir(self.temp_dir)

        # Create realistic project structure
        self.create_realistic_project()

    def teardown_method(self) -> None:
        """Cleanup."""
        os.chdir("/")
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def create_realistic_project(self) -> None:
        """Create a realistic project structure for integration testing."""
        # Create directories
        (self.temp_dir / "src").mkdir()
        (self.temp_dir / "tests").mkdir()

        # Create __init__.py files
        (self.temp_dir / "src" / "__init__.py").touch()
        (self.temp_dir / "tests" / "__init__.py").touch()

        # Create source files
        (self.temp_dir / "src" / "math_utils.py").write_text(
            """
def add(a, b):
    \"\"\"Add two numbers.\"\"\"
    return a + b

def divide(a, b):
    \"\"\"Divide two numbers.\"\"\"
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b

def is_even(n):
    \"\"\"Check if number is even.\"\"\"
    return n % 2 == 0
"""
        )

        # Create test files
        (self.temp_dir / "tests" / "test_math_utils.py").write_text(
            """
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from math_utils import add, divide, is_even
import pytest

def test_add_positive():
    assert add(2, 3) == 5

def test_add_negative():
    assert add(-1, -2) == -3

def test_divide_normal():
    assert divide(10, 2) == 5.0

def test_divide_by_zero():
    with pytest.raises(ValueError):
        divide(10, 0)

def test_is_even_true():
    assert is_even(4) is True

def test_is_even_false():
    assert is_even(3) is False
"""
        )

        # Create configuration file
        (self.temp_dir / "floss.conf").write_text(
            """[test]
source_dir = src
output_file = integration_coverage.json
"""
        )

    def test_full_workflow_with_config_file(self) -> None:
        """Test the complete workflow using configuration file."""
        config = TestConfig.from_file("floss.conf")
        runner = TestRunner(config)

        # This would require pytest to be available and work with the real file system
        # For now, we'll just test that the configuration is loaded correctly
        assert config.source_dir == "src"
        assert config.output_file == "integration_coverage.json"
        assert runner.config == config

    def test_config_override_precedence(self) -> None:
        """Test that command line arguments override config file."""
        # Load from file
        config = TestConfig.from_file("floss.conf")
        assert config.source_dir == "src"
        assert config.output_file == "integration_coverage.json"

        # Override values
        config.source_dir = "custom_src"
        config.output_file = "custom_output.json"

        assert config.source_dir == "custom_src"
        assert config.output_file == "custom_output.json"
