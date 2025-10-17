"""
Fault Localization Engine.
"""

from __future__ import annotations

import json

from ..formulas import (
    DStarFormula,
    JaccardFormula,
    Kulczynski2Formula,
    Naish1Formula,
    OchiaiFormula,
    RussellRaoFormula,
    SBIFormula,
    SorensenDiceFormula,
    TarantulaFormula,
)
from .config import FLConfig
from .data import CoverageData


class FLEngine:
    """Engine for calculating fault localization suspiciousness scores."""

    AVAILABLE_FORMULAS = {
        "ochiai": OchiaiFormula(),
        "tarantula": TarantulaFormula(),
        "jaccard": JaccardFormula(),
        "dstar2": DStarFormula(star=2),
        "dstar3": DStarFormula(star=3),
        "kulczynski2": Kulczynski2Formula(),
        "naish1": Naish1Formula(),
        "russellrao": RussellRaoFormula(),
        "sorensendice": SorensenDiceFormula(),
        "sbi": SBIFormula(),
    }

    def __init__(self, config: FLConfig):
        self.config = config
        formulas_to_use = config.formulas or [
            "ochiai",
            "tarantula",
            "jaccard",
            "dstar2",
        ]
        self.formulas = {
            name: self.AVAILABLE_FORMULAS[name]
            for name in formulas_to_use
            if name in self.AVAILABLE_FORMULAS
        }

    def calculate_suspiciousness(self, input_file: str, output_file: str) -> None:
        """Calculate suspiciousness scores and generate report."""
        # Load coverage data
        with open(input_file, "r") as f:
            coverage_json = json.load(f)

        coverage_data = CoverageData.from_json(coverage_json)

        # Calculate suspiciousness for each line
        suspiciousness_scores = {}

        for line_key in coverage_data.line_coverage:
            n_cf, n_nf, n_cp, n_np = coverage_data.get_sbfl_params(line_key)

            line_scores = {}
            for formula_name, formula in self.formulas.items():
                score = formula.calculate(n_cf, n_nf, n_cp, n_np)
                line_scores[formula_name] = score

            suspiciousness_scores[line_key] = line_scores

        # Create report
        report = coverage_json.copy()

        # Add suspiciousness scores to each file's lines
        for file_path, file_data in report.get("files", {}).items():
            contexts = file_data.get("contexts", {})

            # Add suspiciousness section to file
            file_data["suspiciousness"] = {}

            for line_num in contexts:
                line_key = f"{file_path}:{line_num}"
                if line_key in suspiciousness_scores:
                    file_data["suspiciousness"][line_num] = suspiciousness_scores[
                        line_key
                    ]

        # Enhance meta section with FLOSS FL information
        self._add_floss_fl_metadata(report, coverage_data)

        # Add fl_metadata section expected by CLI tests/consumers
        report["fl_metadata"] = {
            "formulas_used": list(self.formulas.keys()),
            "total_lines_analyzed": len(suspiciousness_scores),
        }

        # Add fl summary in the totals section and reorganize JSON structure
        self._add_fl_summary_info_and_reorganize(report, coverage_data)

        # Save report
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

    def _add_floss_fl_metadata(self, report: dict, coverage_data: CoverageData) -> None:
        """Add FLOSS-specific metadata to the FL report meta section.

        Enhances the meta section with fault localization specific information
        including phase update. Statistics are moved to totals section.
        """
        if "meta" not in report:
            report["meta"] = {}

        failed_tests = [
            test for test, passed in coverage_data.test_outcomes.items() if not passed
        ]

        # Add FLOSS FL-specific metadata (without statistics - they go to totals)
        fl_meta = {"phase": "fault_localization", "fl_ready": len(failed_tests) > 0}

        # Update existing meta while preserving test execution info
        report["meta"].update(fl_meta)

    def _add_fl_summary_info_and_reorganize(
        self, report: dict, coverage_data: CoverageData
    ) -> None:
        """Enhance totals section with FL statistics and reorganize JSON structure.

        Moves SBFL formulas and analysis statistics to totals section and reorganizes
        JSON so totals appears right after meta section.
        """
        if "totals" not in report:
            report["totals"] = {}

        # Get test statistics from coverage data
        failed_tests = [
            test for test, passed in coverage_data.test_outcomes.items() if not passed
        ]
        passed_tests = [
            test for test, passed in coverage_data.test_outcomes.items() if passed
        ]

        # Add FL-specific information to totals
        report["totals"]["sbfl_formulas"] = list(self.formulas.keys())
        report["totals"]["analysis_statistics"] = {
            "total_failed_tests": len(failed_tests),
            "total_passed_tests": len(passed_tests),
            "total_lines_with_scores": len(
                [
                    line
                    for file_data in report.get("files", {}).values()
                    for line in file_data.get("suspiciousness", {})
                ]
            ),
            "files_analyzed": len(report.get("files", {})),
        }

        # Reorganize JSON structure: meta -> totals -> files -> tests -> fl_metadata
        reorganized = {}

        # 1. Meta section first
        if "meta" in report:
            reorganized["meta"] = report["meta"]

        # 2. Totals section second
        if "totals" in report:
            reorganized["totals"] = report["totals"]

        # 3. Files section third
        if "files" in report:
            reorganized["files"] = report["files"]

        # 4. Add any other sections in order
        for key, value in report.items():
            if key not in ["meta", "totals", "files"]:
                reorganized[key] = value

        # Update the report with reorganized structure
        report.clear()
        report.update(reorganized)
