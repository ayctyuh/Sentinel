"""
Coverage data structures for fault localization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set


@dataclass
class CoverageData:
    """Simplified coverage data for fault localization calculations."""

    # Line -> set of tests that executed it
    line_coverage: Dict[str, Set[str]]
    # Test -> outcome (True=pass, False=fail)
    test_outcomes: Dict[str, bool]

    @classmethod
    def from_json(cls, coverage_json: dict) -> "CoverageData":
        """Create coverage data from coverage.json format."""
        line_coverage: Dict[str, Set[str]] = {}
        test_outcomes: Dict[str, bool] = {}

        # Extract test outcomes
        if "tests" in coverage_json:
            for passed_test in coverage_json["tests"].get("passed", []):
                test_outcomes[passed_test] = True
            for failed_test in coverage_json["tests"].get("failed", []):
                test_outcomes[failed_test] = False

        # Extract line coverage with context information
        for file_path, file_data in coverage_json.get("files", {}).items():
            contexts = file_data.get("contexts", {})

            for line_num, test_contexts in contexts.items():
                for context in test_contexts:
                    if context and "|run" in context:
                        # Extract test name from context
                        test_name = context.split("|run")[0]
                        line_key = f"{file_path}:{line_num}"

                        if line_key not in line_coverage:
                            line_coverage[line_key] = set()
                        line_coverage[line_key].add(test_name)

        return cls(line_coverage=line_coverage, test_outcomes=test_outcomes)

    def get_sbfl_params(self, line_key: str) -> tuple[int, int, int, int]:
        """
        Get SBFL parameters for a specific line.

        Returns:
            (n_cf, n_nf, n_cp, n_np) where:
            - n_cf: failed tests covering the line
            - n_nf: failed tests NOT covering the line
            - n_cp: passed tests covering the line
            - n_np: passed tests NOT covering the line
        """
        covering_tests = self.line_coverage.get(line_key, set())

        n_cf = sum(
            1 for test in covering_tests if not self.test_outcomes.get(test, True)
        )
        n_cp = sum(1 for test in covering_tests if self.test_outcomes.get(test, True))

        all_failed = sum(1 for outcome in self.test_outcomes.values() if not outcome)
        all_passed = sum(1 for outcome in self.test_outcomes.values() if outcome)

        n_nf = all_failed - n_cf
        n_np = all_passed - n_cp

        return n_cf, n_nf, n_cp, n_np
