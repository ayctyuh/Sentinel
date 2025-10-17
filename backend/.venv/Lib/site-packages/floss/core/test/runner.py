"""Test runner for FLOSS using pytest with coverage context."""

import json
import os
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .config import TestConfig


@dataclass
class TestResult:
    """Result of test execution."""

    __test__ = False
    coverage_data: Dict[str, Any]
    failed_tests: List[str]
    passed_tests: List[str]
    skipped_tests: List[str]


class TestRunner:
    """Executes tests with pytest and coverage collection."""

    __test__ = False

    def __init__(self, config: TestConfig):
        self.config = config

    def run_tests(self, test_filter: Optional[str] = None) -> TestResult:
        """Run tests and collect coverage with context information."""

        # Create temporary files for results
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False
        ) as xml_file:
            xml_path = xml_file.name

        try:
            # Write coverage configuration with unique name
            coveragerc_file = f".coveragerc_{uuid.uuid4().hex}"
            self.config.write_coveragerc(coveragerc_file)

            # Build pytest command
            cmd = self._build_pytest_command(xml_path, test_filter, coveragerc_file)

            # Execute pytest
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=".")

            if result.returncode != 0 and result.returncode != 1:
                # Return code 1 is normal when tests fail, anything else is an error
                raise RuntimeError(f"pytest execution failed: {result.stderr}")

            # Parse results
            coverage_data = self._load_coverage_data()
            test_outcomes = self._parse_junit_xml(xml_path)

            # Remove redundant contexts from functions and classes
            coverage_data = self._remove_redundant_contexts(coverage_data)

            # Add FLOSS metadata to the meta section
            coverage_data = self._add_floss_metadata(coverage_data, test_outcomes)

            # Add summary info in the totals section and reorganize JSON structure
            coverage_data = self._add_test_summary_info(coverage_data, test_outcomes)

            # Merge test outcomes into coverage data
            coverage_data = self._merge_test_outcomes(coverage_data, test_outcomes)

            return TestResult(
                coverage_data=coverage_data,
                failed_tests=test_outcomes["failed"],
                passed_tests=test_outcomes["passed"],
                skipped_tests=test_outcomes["skipped"],
            )

        finally:
            # Cleanup temporary files
            if os.path.exists(xml_path):
                os.unlink(xml_path)
            if os.path.exists(coveragerc_file):
                os.unlink(coveragerc_file)

    def _build_pytest_command(
        self,
        xml_path: str,
        test_filter: Optional[str] = None,
        coveragerc_file: Optional[str] = None,
    ) -> List[str]:
        """Build the pytest command with all required options."""
        cmd = ["pytest"]

        # Add test directory if specified
        if self.config.test_dir:
            cmd.append(self.config.test_dir)

        # Required coverage options
        cmd.extend(
            [
                f"--cov={self.config.source_dir}",
                "--cov-context=test",
                f"--cov-report=json:{self.config.output_file}",
                "--cov-branch",
                "-v",
            ]
        )

        # Add coverage config file if specified
        if coveragerc_file:
            cmd.extend([f"--cov-config={coveragerc_file}"])

        # Add ignore patterns
        for pattern in self.config.ignore_patterns or []:
            cmd.extend(["--ignore-glob", pattern])

        # Add junit XML output
        cmd.extend(["--junitxml", xml_path])

        # Add test filter if provided
        if test_filter:
            cmd.extend(["-k", test_filter])

        return cmd

    def _load_coverage_data(self) -> Dict[str, Any]:
        """Load coverage data from JSON file."""
        try:
            with open(self.config.output_file, "r") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            raise RuntimeError(f"Coverage file {self.config.output_file} not found")
        except json.JSONDecodeError:
            raise RuntimeError(
                f"Invalid JSON in coverage file {self.config.output_file}"
            )

    def _parse_junit_xml(self, xml_path: str) -> Dict[str, List[str]]:
        """Parse JUnit XML to extract test outcomes."""
        outcomes: Dict[str, List[str]] = {"failed": [], "passed": [], "skipped": []}

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for testcase in root.iter("testcase"):
                classname = testcase.get("classname", "")
                name = testcase.get("name", "")

                # Convert to pytest context format
                # (e.g., "tests/test_file.py::test_function")
                test_name = self._convert_to_pytest_format(classname, name)

                # Check test outcome
                if testcase.find("failure") is not None:
                    outcomes["failed"].append(test_name)
                elif testcase.find("skipped") is not None:
                    outcomes["skipped"].append(test_name)
                elif testcase.find("error") is not None:
                    outcomes["error"].append(test_name)
                else:
                    outcomes["passed"].append(test_name)

            return outcomes

        except ET.ParseError:
            raise RuntimeError(f"Failed to parse JUnit XML file {xml_path}")

    def _convert_to_pytest_format(self, classname: str, name: str) -> str:
        """Convert JUnit format to pytest context format."""
        # JUnit classname is like "tests.test_file" or "tests.test_file.ClassName"
        # pytest context format is like "tests/test_file.py::test_function"
        # or "tests/test_file.py::ClassName::test_method"

        # Handle ruff and other non-test cases
        if name in ["ruff", "format"] or "ruff" in classname:
            return f"{classname}::{name}"

        # Convert dots to slashes and add .py extension
        parts = classname.split(".")
        if len(parts) >= 2:
            # Check if last part is likely a class name (starts with uppercase)
            if len(parts) >= 3 and parts[-1][0].isupper():
                # Format: tests.test_file.ClassName ->
                # tests/test_file.py::ClassName::test_method
                file_path = "/".join(parts[:-2]) + "/" + parts[-2] + ".py"
                class_name = parts[-1]
                return f"{file_path}::{class_name}::{name}"
            else:
                # Format: tests.test_file -> tests/test_file.py::test_function
                file_path = "/".join(parts[:-1]) + "/" + parts[-1] + ".py"
                return f"{file_path}::{name}"
        else:
            # Fallback format
            return f"{classname}::{name}"

    def _merge_test_outcomes(
        self, coverage_data: Dict[str, Any], test_outcomes: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Merge test outcome information into coverage data."""
        # Add tests section to coverage data
        coverage_data["tests"] = {
            "failed": test_outcomes["failed"],
            "passed": test_outcomes["passed"],
            "skipped": test_outcomes["skipped"],
        }

        return coverage_data

    def _remove_redundant_contexts(
        self, coverage_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Remove redundant context information from functions and classes.

        Problem: When pytest-cov is used with dynamic contexts enabled
        (--cov-context=test), the generated JSON report (format:3, version: 7.9.2)
        contains the same context information at three levels:
        1. File level: files[filename].contexts
        2. Function level: files[filename].functions[function_name].contexts
        3. Class level: files[filename].classes[class_name].contexts

        The contexts at function and class levels are identical to the file level
        contexts, making them completely redundant. This duplication significantly
        increases file size (observed ~97% reduction after cleanup: from 239970254
        to 7927854 bytes in the test case) and processing overhead without adding
        value.

        Solution: This function removes the redundant 'contexts' sections from all
        functions and classes while preserving the file-level contexts, which
        contain all the necessary information for fault localization analysis. The
        file-level contexts provide complete mapping of which tests executed each
        line, which is sufficient for SBFL calculations.        Args:
            coverage_data: The coverage data dictionary from pytest-cov JSON output

        Returns:
            Coverage data with redundant contexts removed from functions and classes
        """
        if "files" not in coverage_data:
            return coverage_data

        for _, file_data in coverage_data["files"].items():
            # Remove contexts from functions
            if "functions" in file_data:
                for _, func_data in file_data["functions"].items():
                    if "contexts" in func_data:
                        del func_data["contexts"]

            # Remove contexts from classes
            if "classes" in file_data:
                for _, class_data in file_data["classes"].items():
                    if "contexts" in class_data:
                        del class_data["contexts"]

        return coverage_data

    def _add_floss_metadata(
        self, coverage_data: Dict[str, Any], test_outcomes: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Add FLOSS-specific metadata to the coverage data meta section.

        Enhances the original pytest-cov meta section with FLOSS information
        including version and processing flags. Statistics are moved to totals section.
        """
        if "meta" not in coverage_data:
            coverage_data["meta"] = {}

        # Add FLOSS-specific metadata (without statistics - they go to totals)
        floss_meta = {
            "floss_version": "0.1.0",
            "tool": "floss",
            "phase": "test_execution",
            "source_dir": self.config.source_dir,
            "test_dir": self.config.test_dir,
        }

        # Merge with existing meta, preserving original pytest-cov information
        coverage_data["meta"].update(floss_meta)

        return coverage_data

    def _add_test_summary_info(
        self, coverage_data: Dict[str, Any], test_outcomes: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Enhance totals section with FLOSS statistics and reorganize JSON structure.

        Moves test statistics to totals section and reorganizes JSON so totals
        appears right after meta section.
        """
        # Enhance existing totals section with FLOSS statistics
        if "totals" not in coverage_data:
            coverage_data["totals"] = {}

        # Add test statistics to totals
        coverage_data["totals"]["test_statistics"] = {
            "total_tests": len(test_outcomes["passed"])
            + len(test_outcomes["failed"])
            + len(test_outcomes["skipped"]),
            "passed_tests": len(test_outcomes["passed"]),
            "failed_tests": len(test_outcomes["failed"]),
            "skipped_tests": len(test_outcomes["skipped"]),
        }

        # Reorganize JSON structure: meta -> totals -> files -> tests -> fl_metadata
        reorganized = {}

        # 1. Meta section first
        if "meta" in coverage_data:
            reorganized["meta"] = coverage_data["meta"]

        # 2. Totals section second
        if "totals" in coverage_data:
            reorganized["totals"] = coverage_data["totals"]

        # 3. Files section third
        if "files" in coverage_data:
            reorganized["files"] = coverage_data["files"]

        # 4. Add any other sections that might exist
        for key, value in coverage_data.items():
            if key not in ["meta", "totals", "files"]:
                reorganized[key] = value

        return reorganized
