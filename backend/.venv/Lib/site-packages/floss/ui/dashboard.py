"""
Clean and minimal FLOSS dashboard for fault localization visualization.
"""

import json
import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from typing import Any, Dict, List, NamedTuple, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


class FormulaStats(NamedTuple):
    """Statistics for a specific formula."""

    min_score: float
    max_score: float
    range_score: float
    all_scores: List[float]


class FileStats(NamedTuple):
    """Statistics for a file's suspiciousness."""

    file_path: str
    max_score: float
    avg_score: float
    suspicious_statements: int
    suspicious_statements_pct: float
    suspicious_branches: int
    suspicious_branches_pct: float
    total_statements_with_coverage: int
    total_branches_with_coverage: int


def select_directory_with_dialog() -> Optional[str]:
    """Open native file dialog to select directory."""
    try:
        # Create a root window but hide it
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)  # Bring dialog to front

        # Open directory selection dialog
        directory = filedialog.askdirectory(
            title="Select Project Root Directory", mustexist=True
        )

        # Clean up
        root.destroy()

        return directory if directory else None
    except Exception as e:
        st.error(f"Error opening file dialog: {str(e)}")
        return None


def calculate_formula_statistics(data: Dict[str, Any], formula: str) -> FormulaStats:
    """Calculate and cache min/max/range statistics for a specific formula.

    This is the core optimization - all normalization calculations depend on
    these values.
    """
    files_data = data.get("files", {})
    all_scores = []

    for _, file_data in files_data.items():
        suspiciousness = file_data.get("suspiciousness", {})
        for line_scores in suspiciousness.values():
            if formula in line_scores:
                all_scores.append(float(line_scores[formula]))

    if not all_scores:
        return FormulaStats(0.0, 0.0, 1.0, [])

    min_score = min(all_scores)
    max_score = max(all_scores)
    range_score = max_score - min_score if max_score > min_score else 1.0

    return FormulaStats(min_score, max_score, range_score, all_scores)


def calculate_file_suspiciousness_stats(
    data: Dict[str, Any],
    formula: str,
    formula_stats: FormulaStats,
    threshold: Optional[float] = None,
) -> List[FileStats]:
    """Calculate and cache file-level suspiciousness statistics.

    Uses pre-calculated formula statistics to avoid redundant computations.
    If threshold is provided, also calculates threshold-based counts and percentages.

    Args:
        data: Fault localization data
        formula: Formula name to use for calculations
        formula_stats: Pre-calculated formula statistics
        threshold: Optional threshold for calculating suspicious counts
                  (actual threshold value)
    """
    files_data = data.get("files", {})
    file_suspiciousness = []

    for file_path, file_data in files_data.items():
        file_scores = []
        normalized_scores = []
        suspicious_statements_count = 0
        total_statements_with_test_coverage = 0
        suspicious_branches_count = 0
        total_branches_with_test_coverage = 0

        # Get executed lines (actual statements)
        executed_lines = file_data.get("executed_lines", [])
        contexts = file_data.get("contexts", {})
        suspiciousness = file_data.get("suspiciousness", {})

        # Get executed branches
        executed_branches = file_data.get("executed_branches", [])

        # Process only executed statements that have test coverage
        for line_num in executed_lines:
            line_str = str(line_num)

            # Check if this line has test coverage (non-empty contexts)
            line_contexts = contexts.get(line_str, [])
            has_test_coverage = any(context.strip() for context in line_contexts)

            # Check if this line has suspiciousness score
            if (
                line_str in suspiciousness
                and formula in suspiciousness[line_str]
                and has_test_coverage
            ):
                score = float(suspiciousness[line_str][formula])
                # Normalize score to 0-1 range using cached stats
                normalized_score = (
                    score - formula_stats.min_score
                ) / formula_stats.range_score
                file_scores.append(score)
                normalized_scores.append(normalized_score)
                total_statements_with_test_coverage += 1

                # Count suspicious statements if threshold is provided
                if threshold is not None and score >= threshold:
                    suspicious_statements_count += 1

        # Process executed branches that have test coverage
        for branch in executed_branches:
            if len(branch) >= 2:
                source_line = branch[0]
                source_line_str = str(source_line)

                # Check if the source line of the branch has test coverage
                line_contexts = contexts.get(source_line_str, [])
                has_test_coverage = any(context.strip() for context in line_contexts)

                # Check if the source line has suspiciousness score
                if (
                    source_line_str in suspiciousness
                    and formula in suspiciousness[source_line_str]
                    and has_test_coverage
                ):
                    total_branches_with_test_coverage += 1

                    # Count suspicious branches if threshold is provided
                    if threshold is not None:
                        score = float(suspiciousness[source_line_str][formula])
                        if score >= threshold:
                            suspicious_branches_count += 1

        if file_scores:
            avg_score = sum(normalized_scores) / len(normalized_scores)
            max_score = max(normalized_scores)

            # Calculate percentages if threshold is provided
            if threshold is not None:
                suspicious_statements_pct = (
                    (
                        suspicious_statements_count
                        / total_statements_with_test_coverage
                        * 100
                    )
                    if total_statements_with_test_coverage > 0
                    else 0
                )
                suspicious_branches_pct = (
                    (
                        suspicious_branches_count
                        / total_branches_with_test_coverage
                        * 100
                    )
                    if total_branches_with_test_coverage > 0
                    else 0
                )
            else:
                suspicious_statements_pct = 0.0
                suspicious_branches_pct = 0.0

            # Only include files with max suspiciousness > 0 (normalized)
            if max_score > 0:
                file_suspiciousness.append(
                    FileStats(
                        file_path=file_path,
                        max_score=(
                            round(max_score, 3) if threshold is not None else max_score
                        ),
                        avg_score=(
                            round(avg_score, 3) if threshold is not None else avg_score
                        ),
                        suspicious_statements=suspicious_statements_count,
                        suspicious_statements_pct=(
                            round(suspicious_statements_pct, 1)
                            if threshold is not None
                            else suspicious_statements_pct
                        ),
                        suspicious_branches=suspicious_branches_count,
                        suspicious_branches_pct=(
                            round(suspicious_branches_pct, 1)
                            if threshold is not None
                            else suspicious_branches_pct
                        ),
                        total_statements_with_coverage=(
                            total_statements_with_test_coverage
                        ),
                        total_branches_with_coverage=(
                            total_branches_with_test_coverage
                        ),
                    )
                )

    return file_suspiciousness


def build_hierarchical_data(
    data: Dict[str, Any], formula: str, min_score: float = 0.0
) -> Dict[str, List]:
    """Build hierarchical data structure for treemap and sunburst visualizations."""
    # Calculate formula statistics internally
    formula_stats = calculate_formula_statistics(data, formula)

    files_data = data.get("files", {})

    if not formula_stats.all_scores:
        return {
            "labels": [],
            "parents": [],
            "ids": [],
            "values": [],
            "colors": [],
            "hover_info": [],
        }

    # Convert normalized min_score to actual threshold using stats
    actual_min_score = formula_stats.min_score + (min_score * formula_stats.range_score)

    labels: List[str] = []
    parents: List[str] = []  # store parent ids
    ids: List[str] = []  # unique node ids
    values: List[float] = []
    colors: List[float] = []
    hover_info: List[str] = []

    # Track directory nodes for aggregation
    dir_nodes: Dict[str, Dict[str, Any]] = {}
    root_stats = {"lines": 0, "sum_score": 0.0}

    # Root node
    labels.append("Project")
    parents.append("")
    ids.append("Project")
    values.append(1)
    colors.append(0.0)

    # Root hover info
    totals = data.get("totals", {})
    project_coverage = totals.get("percent_covered", 0.0)
    total_files = totals.get("analysis_statistics", {}).get("files_analyzed", 0)
    hover_info.append(
        f"Project<br>Coverage: {project_coverage:.1f}%<br>Files: {total_files}"
    )

    # Iterate files
    for file_path, file_data in files_data.items():
        file_suspiciousness = file_data.get("suspiciousness", {})
        if not file_suspiciousness:
            continue

        # Collect normalized scores above threshold
        file_scores: List[float] = []
        for line_scores in file_suspiciousness.values():
            if formula in line_scores:
                raw_score = float(line_scores[formula])
                if raw_score >= actual_min_score:
                    norm = (raw_score - formula_stats.min_score) / (
                        formula_stats.range_score
                    )
                    file_scores.append(norm)

        if not file_scores:
            continue

        normalized_path = str(file_path).replace("\\", "/")
        parts = [p for p in normalized_path.split("/") if p]
        dir_chain = parts[:-1] if len(parts) > 1 else []

        # Ensure directory chain nodes
        parent_id = "Project"
        current_path: List[str] = []
        for seg in dir_chain:
            current_path.append(seg)
            dir_key = "/".join(current_path)
            if dir_key not in dir_nodes:
                labels.append(seg)
                parents.append(parent_id)
                ids.append(f"dir:{dir_key}")
                values.append(0)
                colors.append(0.0)
                hover_info.append("")
                dir_nodes[dir_key] = {
                    "index": len(labels) - 1,
                    "lines": 0,
                    "sum_score": 0.0,
                    "id": f"dir:{dir_key}",
                }
            parent_id = dir_nodes[dir_key]["id"]

        # File node (label = basename, hover shows full path)
        file_label = parts[-1] if parts else str(file_path)
        file_summary = file_data.get("summary", {})
        file_coverage = file_summary.get("percent_covered", 0.0)
        file_statements = file_summary.get("num_statements", 0)
        file_covered_lines = file_summary.get("covered_lines", 0)

        avg_file_score = sum(file_scores) / len(file_scores)
        file_lines_count = len(file_scores)

        labels.append(file_label)
        parents.append(parent_id)
        ids.append(f"file:{normalized_path}")
        values.append(max(file_lines_count, 1))
        colors.append(avg_file_score)
        hover_info.append(
            f"File: {normalized_path}<br>Coverage: {file_coverage:.1f}"
            f"%<br>Lines: {file_covered_lines}/{file_statements}"
        )

        # Aggregate into directory nodes
        if dir_chain:
            weight = file_lines_count
            for i in range(len(dir_chain)):
                dir_key = "/".join(dir_chain[: i + 1])
                node = dir_nodes[dir_key]
                node["lines"] += weight
                node["sum_score"] += avg_file_score * weight
                idx = node["index"]
                values[idx] = max(node["lines"], 1)
                avg_dir_score = (
                    (node["sum_score"] / node["lines"]) if node["lines"] > 0 else 0.0
                )
                colors[idx] = avg_dir_score
                hover_info[idx] = (
                    f"Directory: {dir_key}<br>Lines with data: {node['lines']}"
                    f"<br>Avg Score: {avg_dir_score:.3f}"
                )

        # Aggregate into root
        root_stats["lines"] += file_lines_count
        root_stats["sum_score"] += avg_file_score * file_lines_count

        # Classes
        classes_data = file_data.get("classes", {})
        functions_data = file_data.get("functions", {})

        for class_name, class_info in classes_data.items():
            if not class_name:
                continue
            executed_lines = class_info.get("executed_lines", [])
            class_scores: List[float] = []
            for line_num in executed_lines:
                line_str = str(line_num)
                if line_str in file_suspiciousness:
                    raw = float(file_suspiciousness[line_str].get(formula, 0.0))
                    if raw >= actual_min_score:
                        class_scores.append(
                            (raw - formula_stats.min_score)
                            / (formula_stats.range_score)
                        )
            if not class_scores:
                continue
            avg_class = sum(class_scores) / len(class_scores)
            class_count = len(class_scores)
            class_label = f"class {class_name}"
            labels.append(class_label)
            parents.append(f"file:{normalized_path}")
            ids.append(f"class:{normalized_path}:{class_name}")
            values.append(max(class_count, 1))
            colors.append(avg_class)
            hover_info.append(
                f"Class: {class_name}<br>Lines with data: {class_count}"
                f"<br>Avg Score: {avg_class:.3f}"
            )

            # Methods inside the class
            for func_name, func_info in functions_data.items():
                if not func_name.startswith(f"{class_name}."):
                    continue
                method_name = func_name.split(".")[-1]
                method_lines = func_info.get("executed_lines", [])
                method_scores: List[float] = []
                for line_num in method_lines:
                    line_str = str(line_num)
                    if line_str in file_suspiciousness:
                        raw = float(file_suspiciousness[line_str].get(formula, 0.0))
                        if raw >= actual_min_score:
                            method_scores.append(
                                (raw - formula_stats.min_score)
                                / (formula_stats.range_score)
                            )
                if not method_scores:
                    continue
                avg_method = sum(method_scores) / len(method_scores)
                method_count = len(method_scores)
                method_label = f"def {method_name}()"
                labels.append(method_label)
                parents.append(f"class:{normalized_path}:{class_name}")
                ids.append(f"method:{normalized_path}:{class_name}.{method_name}")
                values.append(max(method_count, 1))
                colors.append(avg_method)
                method_summary = func_info.get("summary", {})
                method_cov = method_summary.get("percent_covered", 0.0)
                method_stmts = method_summary.get("num_statements", 0)
                hover_info.append(
                    f"Method: {method_name}<br>Coverage: {method_cov:.1f}%"
                    f"<br>Statements: {method_stmts}"
                )

        # Standalone functions
        for func_name, func_info in functions_data.items():
            if (not func_name) or ("." in func_name):
                continue
            func_lines = func_info.get("executed_lines", [])
            func_scores: List[float] = []
            for line_num in func_lines:
                line_str = str(line_num)
                if line_str in file_suspiciousness:
                    raw = float(file_suspiciousness[line_str].get(formula, 0.0))
                    if raw >= actual_min_score:
                        func_scores.append(
                            (raw - formula_stats.min_score)
                            / (formula_stats.range_score)
                        )
            if not func_scores:
                continue
            avg_func = sum(func_scores) / len(func_scores)
            func_count = len(func_scores)
            func_label = f"def {func_name}()"
            labels.append(func_label)
            parents.append(f"file:{normalized_path}")
            ids.append(f"func:{normalized_path}:{func_name}")
            values.append(max(func_count, 1))
            colors.append(avg_func)
            func_summary = func_info.get("summary", {})
            func_cov = func_summary.get("percent_covered", 0.0)
            func_stmts = func_summary.get("num_statements", 0)
            hover_info.append(
                f"Function: {func_name}<br>Coverage: {func_cov:.1f}%"
                f"<br>Statements: {func_stmts}"
            )

    # Root color as overall average
    if root_stats["lines"] > 0:
        colors[0] = root_stats["sum_score"] / root_stats["lines"]

    return {
        "labels": labels,
        "parents": parents,
        "ids": ids,
        "values": values,
        "colors": colors,
        "hover_info": hover_info,
    }


def launch_dashboard(
    report_file: str = "report.json", port: int = 8501, auto_open: bool = True
) -> None:
    """Launch the dashboard."""
    import subprocess
    import sys

    # Set environment variable for the report file
    os.environ["FLOSS_REPORT_FILE"] = report_file

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(Path(__file__)),
        "--server.port",
        str(port),
    ]

    if not auto_open:
        cmd.extend(["--server.headless", "true"])

    print(f"Starting FLOSS Dashboard on port {port}")
    print(f"Report file: {report_file}")

    subprocess.run(cmd)


def main() -> None:
    """Main Streamlit application."""
    st.set_page_config(page_title="FLOSS Dashboard", page_icon="🔍", layout="wide")

    st.title("FLOSS Dashboard")
    st.markdown("Fault Localization Results Visualization")

    # Initialize session state
    if "data" not in st.session_state:
        st.session_state.data = None
    if "project_root" not in st.session_state:
        st.session_state.project_root = None

    # Auto-load report file
    if st.session_state.data is None:
        # Try environment variable first (from CLI)
        report_file = os.environ.get("FLOSS_REPORT_FILE", "report.json")

        try:
            with open(report_file) as f:
                st.session_state.data = json.load(f)
        except FileNotFoundError:
            st.error(f"Report file not found: {report_file}")
            st.info(
                "Please ensure report.json exists in the current directory "
                "or specify the correct path via CLI"
            )
            return
        except Exception as e:
            st.error(f"Error loading report file: {e}")
            return

    # Data is loaded, show main dashboard
    data = st.session_state.data

    # Formula selection
    formulas = data.get("totals", {}).get("sbfl_formulas", [])
    if not formulas:
        st.error("No formulas found in report")
        return

    selected_formula = st.selectbox("SBFL Formula", formulas)

    # Main dashboard tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(
        [
            "Overview",
            "Source Code",
            "Test-to-Fault Analysis",
            "Treemap",
            "Sunburst",
            "Formula Comparison",
            "Formula Performance",
        ]
    )

    with tab1:
        show_overview(data, selected_formula)

    with tab2:
        show_source_code(data, selected_formula)

    with tab3:
        show_coverage_matrix(data, selected_formula)

    with tab4:
        show_treemap_tab(data, selected_formula)

    with tab5:
        show_sunburst(data, selected_formula)

    with tab6:
        show_formula_comparison(data, formulas)

    with tab7:
        show_formula_performance(data, formulas)


def show_overview(data: Dict[str, Any], formula: str) -> None:
    """Show comprehensive overview with key metrics for fault localization."""
    st.header("Fault Localization Overview")

    # Calculate formula statistics once (cached)
    formula_stats = calculate_formula_statistics(data, formula)

    # Extract main sections from report
    # meta = data.get("meta", {})  # Unused variable
    totals = data.get("totals", {})
    test_stats = totals.get("test_statistics", {})
    analysis_stats = totals.get("analysis_statistics", {})
    files_data = data.get("files", {})

    # === TEST EXECUTION SUMMARY ===
    st.subheader("Test Execution Summary")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        total_tests = test_stats.get("total_tests", 0)
        st.metric(
            "Total Tests", total_tests, help="Total number of tests in the test suite"
        )

    with col2:
        passed_tests = test_stats.get("passed_tests", 0)
        pass_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        st.metric(
            "Passed Tests",
            passed_tests,
            delta=f"{pass_rate:.1f}%",
            help="Number and percentage of passing tests",
        )

    with col3:
        failed_tests = test_stats.get("failed_tests", 0)
        fail_rate = (failed_tests / total_tests * 100) if total_tests > 0 else 0
        st.metric(
            "Failed Tests",
            failed_tests,
            delta=f"{fail_rate:.1f}%",
            delta_color="inverse",
            help="Number and percentage of failing tests (key for FL)",
        )

    with col4:
        skipped_tests = test_stats.get("skipped_tests", 0)
        skip_rate = (skipped_tests / total_tests * 100) if total_tests > 0 else 0
        st.metric(
            "Skipped Tests",
            skipped_tests,
            delta=f"{skip_rate:.1f}%",
            help="Number and percentage of skipped tests",
        )

    # Test quality indicators
    if failed_tests > 0:
        if failed_tests >= 5:
            st.success("✅ Good test failure count for fault localization")
        elif failed_tests >= 2:
            st.warning("⚠️ Moderate test failure count - FL may be less precise")
        else:
            st.warning("⚠️ Low test failure count - FL effectiveness may be limited")
    else:
        st.error("❌ No failing tests - fault localization cannot be performed")

    st.divider()

    # === CODE COVERAGE ANALYSIS ===
    st.subheader("Code Coverage Analysis")

    col1, col2 = st.columns(2)

    with col1:
        # Statement coverage
        covered_lines = totals.get("covered_lines", 0)
        total_statements = totals.get("num_statements", 0)
        coverage_percent = totals.get("percent_covered", 0.0)

        st.metric(
            "Statement Coverage",
            f"{coverage_percent:.1f}%",
            delta=f"{covered_lines}/{total_statements} lines",
            help="Percentage of code lines executed by tests",
        )

        # Coverage quality assessment
        if coverage_percent >= 70:
            st.success("✅ High coverage - good for fault localization")
        elif coverage_percent >= 50:
            st.warning("⚠️ Moderate coverage - FL may miss some faults")
        else:
            st.error("❌ Low coverage - fault localization effectiveness limited")

    with col2:
        # Branch coverage
        covered_branches = totals.get("covered_branches", 0)
        total_branches = totals.get("num_branches", 0)
        branch_coverage = (
            (covered_branches / total_branches * 100) if total_branches > 0 else 0
        )

        st.metric(
            "Branch Coverage",
            f"{branch_coverage:.1f}%",
            delta=f"{covered_branches}/{total_branches} branches",
            help="Percentage of code branches executed by tests",
        )

        partial_branches = totals.get("num_partial_branches", 0)
        if partial_branches > 0:
            st.info(f"ℹ️ {partial_branches} partially covered branches")

    # === FILE-BY-FILE COVERAGE TABLE ===
    st.subheader("File-by-File Coverage Details")

    # Build coverage data for each file
    file_coverage_data = []
    for file_path, file_data in files_data.items():
        summary = file_data.get("summary", {})
        covered_branches = summary.get("covered_branches", 0)
        total_branches = summary.get("num_branches", 0)
        branch_coverage = (
            (covered_branches / total_branches * 100) if total_branches > 0 else 0
        )
        file_coverage_data.append(
            {
                "File": file_path,
                "Line Coverage": round(summary.get("percent_covered", 0.0), 1),
                "Covered Lines": summary.get("covered_lines", 0),
                "Total Statements": summary.get("num_statements", 0),
                "Branch Coverage": round(branch_coverage, 1),
                "Covered Branches": covered_branches,
                "Total Branches": total_branches,
                "Partial Branches": summary.get("num_partial_branches", 0),
            }
        )

    if file_coverage_data:
        coverage_df = pd.DataFrame(file_coverage_data)

        # Sort by coverage percentage descending
        coverage_df = coverage_df.sort_values("Line Coverage", ascending=False)

        # Display coverage table
        st.dataframe(
            coverage_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "File": st.column_config.TextColumn("File"),
                "Line Coverage": st.column_config.ProgressColumn(
                    "Line Coverage",
                    help="Percentage of statements covered by tests",
                    min_value=0,
                    max_value=100,
                    format="%.1f%%",
                ),
                "Covered Lines": st.column_config.NumberColumn(
                    "Covered Lines", help="Number of lines covered by tests"
                ),
                "Total Statements": st.column_config.NumberColumn(
                    "Total Statements", help="Total number of executable statements"
                ),
                "Branch Coverage": st.column_config.ProgressColumn(
                    "Branch Coverage",
                    help="Percentage of branches covered by tests",
                    min_value=0,
                    max_value=100,
                    format="%.1f%%",
                ),
                "Covered Branches": st.column_config.NumberColumn(
                    "Covered Branches", help="Number of branches covered by tests"
                ),
                "Total Branches": st.column_config.NumberColumn(
                    "Total Branches", help="Total number of conditional branches"
                ),
                "Partial Branches": st.column_config.NumberColumn(
                    "Partial Branches", help="Number of partially covered branches"
                ),
            },
        )

        # Coverage summary statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            avg_coverage = coverage_df["Line Coverage"].mean()
            st.metric("Average Line Coverage", f"{avg_coverage:.1f}%")
        with col2:
            high_coverage_files = len(coverage_df[coverage_df["Line Coverage"] >= 80])
            st.metric("Files with High Line Coverage (≥80%)", high_coverage_files)
        with col3:
            low_coverage_files = len(coverage_df[coverage_df["Line Coverage"] < 50])
            st.metric("Files with Low Line Coverage (<50%)", low_coverage_files)

    st.divider()

    # === FAULT LOCALIZATION READINESS ===
    st.subheader("Fault Localization Analysis")

    col1, col2, col3 = st.columns(3)

    with col1:
        files_analyzed = analysis_stats.get("files_analyzed", 0)
        st.metric(
            "Files Analyzed",
            files_analyzed,
            help="Number of source files included in analysis",
        )

    with col2:
        lines_with_scores = analysis_stats.get("total_lines_with_scores", 0)
        st.metric(
            "Lines with FL Scores",
            lines_with_scores,
            help="Number of code lines with suspiciousness scores",
        )

    with col3:
        formulas_available = len(totals.get("sbfl_formulas", []))
        st.metric(
            "SBFL Formulas",
            formulas_available,
            help="Number of available suspiciousness formulas",
        )

    # Show available formulas
    formulas = totals.get("sbfl_formulas", [])
    if formulas:
        st.write("**Available Formulas:**", ", ".join(f"`{f}`" for f in formulas))

    # Calculate and show top suspicious files preview using cached data
    st.divider()
    st.subheader("Most Suspicious Files")

    if not formula_stats.all_scores:
        st.warning("No suspiciousness data available for this formula")
        return

    # Add threshold control for suspicious lines (normalized)
    col1, col2 = st.columns([1, 3])
    with col1:
        st.write(f"**{formula.title()} Range:**")
        st.write(f"Min: {formula_stats.min_score:.3f}")
        st.write(f"Max: {formula_stats.max_score:.3f}")

        suspicious_threshold = st.slider(
            "Suspiciousness Threshold",
            min_value=0.0,
            max_value=1.0,
            value=0.5,
            step=0.1,
            key=f"suspicious_threshold_{formula}",
            help="Normalized threshold (0=min, 1=max) for considering lines suspicious",
        )

        # Convert normalized threshold to actual value using cached stats
        actual_threshold = formula_stats.min_score + (
            suspicious_threshold * formula_stats.range_score
        )
        st.write(f"**Actual threshold:** {actual_threshold:.3f}")

    # Calculate suspicious files with the specific threshold using cached data
    file_suspiciousness = calculate_file_suspiciousness_stats(
        data, formula, formula_stats, actual_threshold
    )

    # Create sortable dataframe
    if file_suspiciousness:
        df = pd.DataFrame([f._asdict() for f in file_suspiciousness])

        # Sort by Max Score (priority), then by Suspicious Statements count
        df = df.sort_values(
            ["max_score", "suspicious_statements"], ascending=[False, False]
        )

        # Calculate maximums for progress bars
        max_max_score = df["max_score"].max()
        max_avg_score = df["avg_score"].max()

        # Display as interactive table with progress bars
        st.dataframe(
            df[
                [
                    "file_path",
                    "max_score",
                    "avg_score",
                    "suspicious_statements",
                    "suspicious_statements_pct",
                    "suspicious_branches",
                    "suspicious_branches_pct",
                ]
            ],
            use_container_width=True,
            hide_index=True,
            column_config={
                "file_path": st.column_config.TextColumn("File"),
                "max_score": st.column_config.ProgressColumn(
                    "Max Score",
                    help="Maximum suspiciousness score in the file",
                    min_value=0,
                    max_value=max_max_score,
                    format="%.3f",
                ),
                "avg_score": st.column_config.ProgressColumn(
                    "Avg Score",
                    help="Average suspiciousness score in the file",
                    min_value=0,
                    max_value=max_avg_score,
                    format="%.3f",
                ),
                "suspicious_statements": st.column_config.NumberColumn(
                    "Suspicious Statements",
                    help="Count of suspicious statements",
                    min_value=0,
                ),
                "suspicious_statements_pct": st.column_config.ProgressColumn(
                    "Suspicious Statements (%)",
                    help=(
                        "Percentage of suspicious statements "
                        "(Suspicious Statements / Covered Statements)"
                    ),
                    min_value=0,
                    max_value=100,
                    format="%.1f%%",
                ),
                "suspicious_branches": st.column_config.NumberColumn(
                    "Suspicious Branches",
                    help="Count of suspicious branches",
                    min_value=0,
                ),
                "suspicious_branches_pct": st.column_config.ProgressColumn(
                    "Suspicious Branches (%)",
                    help=(
                        "Percentage of suspicious branches "
                        "(Suspicious Branches / Covered Branches)"
                    ),
                    min_value=0,
                    max_value=100,
                    format="%.1f%%",
                ),
            },
        )

        with col2:
            st.caption(
                "Scores normalized to 0-1 range. Files sorted by Max Score, "
                f"then by Suspicious Statements (≥{actual_threshold:.3f}). "
                "Click column headers to re-sort."
            )
            if len(df) > 0:
                st.info(
                    f"Top priority: **{df.iloc[0]['file_path']}** "
                    f"(Normalized Max Score: {df.iloc[0]['max_score']}, "
                    f"{df.iloc[0]['suspicious_statements']} suspicious statements)"
                )

    # Recommendations
    st.divider()
    st.subheader("Recommendations")

    recommendations = []

    if failed_tests < 2:
        recommendations.append(
            "**Critical**: Add more failing tests to improve fault "
            "localization precision"
        )

    if coverage_percent < 50:
        recommendations.append(
            "**Important**: Increase test coverage to improve fault detection"
        )

    if lines_with_scores < 100:
        recommendations.append(
            "**Suggestion**: More code execution needed for better analysis"
        )

    if file_suspiciousness:
        # Use same prioritization as table: sort by Max Score,
        # then by Suspicious Statements Count
        sorted_files = sorted(
            file_suspiciousness,
            key=lambda x: (x.max_score, x.suspicious_statements),
            reverse=True,
        )
        top_file = sorted_files[0]
        recommendations.append(
            f"**Priority**: Focus on `{top_file.file_path}` "
            f"(Max Score: {top_file.max_score:.3f}, "
            f"{top_file.suspicious_statements} suspicious statements)"
        )

    if not recommendations:
        recommendations.append(
            "**Good**: Project setup looks optimal for fault localization"
        )

    for i, rec in enumerate(recommendations, 1):
        st.write(f"{i}. {rec}")


def show_treemap_tab(data: Dict[str, Any], formula: str) -> None:
    """Show dedicated treemap tab with detailed hierarchical view."""
    st.header("Hierarchical Treemap")

    # Add threshold control
    col1, col2 = st.columns([1, 3])
    with col1:
        min_score = st.slider(
            "Minimum Suspiciousness Score",
            min_value=0.0,
            max_value=1.0,
            value=0.0,
            step=0.05,
            help="Filter out elements with suspiciousness score below this threshold",
        )

    hierarchy_data = build_hierarchical_data(data, formula, min_score)

    if not hierarchy_data or len(hierarchy_data["labels"]) <= 1:
        st.warning(f"No hierarchical data available with minimum score {min_score:.2f}")
        return  # Create treemap with hierarchical structure
    fig = go.Figure(
        go.Treemap(
            labels=hierarchy_data["labels"],
            parents=hierarchy_data["parents"],
            ids=hierarchy_data.get("ids", None),
            values=hierarchy_data["values"],
            textinfo="label+value",
            marker=dict(
                colors=hierarchy_data["colors"],
                colorscale="Reds",  # Scala da bianco a rosso
                colorbar=dict(title="Suspiciousness Score"),
                line=dict(width=1),
                cmin=0.0,  # Fissiamo il minimo della scala dei colori
                cmax=1.0,  # Fissiamo il massimo della scala dei colori
            ),
            hovertemplate=(
                "<b>%{label}</b><br>%{customdata}<br>"
                "Score: %{color:.3f}<extra></extra>"
            ),
            customdata=hierarchy_data["hover_info"],
            maxdepth=5,  # Allow deeper nesting in dedicated view
        )
    )

    fig.update_layout(
        height=700,
        title=f"Project Structure - Hierarchical Treemap ({formula.title()})",
        margin=dict(t=50, l=0, r=0, b=0),
    )

    st.plotly_chart(fig, use_container_width=True)

    # Add statistics
    with col2:
        st.markdown(
            f"""
        **Statistics:**
        - Total elements shown: {len(hierarchy_data['labels']) - 1}
        - Average suspiciousness: {np.mean(hierarchy_data['colors']):.3f}
        - Max suspiciousness: {max(hierarchy_data['colors']):.3f}
        """
        )

    # Add explanation
    st.markdown(
        """
    **Hierarchical Structure:**
    - **Packages/Directories**: Top-level containers organizing related files
    - **Python Files (.py)**: Individual source code files
    - **Classes**: Object-oriented code structures within files
    - **Functions/Methods**: Individual code functions and class methods

    **Visualization:**
    - **Size**: Proportional to number of lines with coverage data
    - **Color**: Suspiciousness score (blue = low, red = high)
    - **Nesting**: Shows the containment relationship (package → file → class → method)

    **Interaction**: Click on any section to drill down into that part of the hierarchy.
    """
    )


def show_treemap(data: Dict[str, Any], formula: str) -> None:
    """Create hierarchical treemap visualization based on Python project structure."""

    hierarchy_data = build_hierarchical_data(
        data, formula, min_score=0.05
    )  # Small threshold for overview

    if not hierarchy_data or len(hierarchy_data["labels"]) <= 1:
        st.warning("No hierarchical data available")
        return

    # Create treemap with hierarchical structure
    fig = go.Figure(
        go.Treemap(
            labels=hierarchy_data["labels"],
            parents=hierarchy_data["parents"],
            ids=hierarchy_data.get("ids", None),
            values=hierarchy_data["values"],
            textinfo="label+value",
            marker=dict(
                colors=hierarchy_data["colors"],
                colorscale="Reds",  # Scala da bianco a rosso
                colorbar=dict(title="Suspiciousness Score"),
                line=dict(width=1),
                cmin=0.0,  # Fissiamo il minimo della scala dei colori
                cmax=1.0,  # Fissiamo il massimo della scala dei colori
            ),
            hovertemplate=(
                "<b>%{label}</b><br>%{customdata}<br>"
                "Score: %{color:.3f}<extra></extra>"
            ),
            customdata=hierarchy_data["hover_info"],
            maxdepth=4,  # Package -> File -> Class -> Function/Method
        )
    )

    fig.update_layout(
        height=600,
        title="Project Structure - Hierarchical View",
        margin=dict(t=50, l=0, r=0, b=0),
    )

    st.plotly_chart(fig, use_container_width=True)


def show_ranking_table(susp_data: List[Dict]) -> None:
    """Show ranking table of suspicious lines."""
    if not susp_data:
        return

    df_data = []
    for i, item in enumerate(susp_data, 1):
        df_data.append(
            {
                "Rank": i,
                "File": item["file"],
                "Line": item["line"],
                "Score": item["score"],
            }
        )

    df = pd.DataFrame(df_data)

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Score": st.column_config.ProgressColumn(
                "Score", min_value=0.0, max_value=1.0, format="%.3f"
            )
        },
    )


def get_most_suspicious_file(data: Dict[str, Any], formula: str) -> Optional[str]:
    """Get the file with the highest suspiciousness score for the given formula."""
    formula_stats = calculate_formula_statistics(data, formula)
    file_stats = calculate_file_suspiciousness_stats(data, formula, formula_stats)

    if not file_stats:
        return None

    # Sort by max score (priority), then by number of statements with coverage
    sorted_files = sorted(
        file_stats,
        key=lambda x: (x.max_score, x.total_statements_with_coverage),
        reverse=True,
    )
    return sorted_files[0].file_path


def show_source_code(data: Dict[str, Any], formula: str) -> None:
    """Show source code with suspiciousness highlighting."""
    st.header("Source Code")

    files_data = data.get("files", {})
    if not files_data:
        st.warning("No file data available")
        return

    # Calculate stats for normalization in highlighting
    formula_stats = calculate_formula_statistics(data, formula)

    # Project root selection
    col1, col2 = st.columns([3, 1])

    with col1:
        # Display current project root
        st.info(f"📁 Project root: `{st.session_state.project_root or os.getcwd()}`")
        # Manual input fallback for headless environments
        manual_root = st.text_input(
            "Project root (manual)",
            value=st.session_state.project_root or "",
            placeholder="e.g., C:/path/to/project",
        )
        if manual_root and manual_root != st.session_state.project_root:
            st.session_state.project_root = manual_root
            st.rerun()
    with col2:
        # Browse button for project root
        if st.button(
            "📁 Browse Project Root", help="Select the root directory of your project"
        ):
            # Open native file dialog
            selected_directory = select_directory_with_dialog()
            if selected_directory:
                st.session_state.project_root = selected_directory
                st.rerun()

    st.divider()

    # File selection with most suspicious file as default
    file_paths = list(files_data.keys())
    most_suspicious_file = get_most_suspicious_file(data, formula)

    # Set default index to the most suspicious file if found
    default_index = 0
    if most_suspicious_file and most_suspicious_file in file_paths:
        default_index = file_paths.index(most_suspicious_file)

    selected_file = st.selectbox("Select File", file_paths, index=default_index)

    # Filtering controls for long files
    colf1, colf2, colf3 = st.columns([1.2, 1, 1])
    with colf1:
        enable_filter = st.checkbox("Show only lines ≥ threshold / Top N", value=False)
    with colf2:
        thr = st.slider(
            "Threshold (normalized)", 0.0, 1.0, 0.2, 0.05, disabled=not enable_filter
        )
    with colf3:
        topn = st.number_input(
            "Top N lines",
            min_value=1,
            max_value=1000,
            value=200,
            step=10,
            disabled=not enable_filter,
        )

    if selected_file:
        show_file_with_highlighting(
            files_data[selected_file],
            selected_file,
            formula,
            formula_stats,
            filter_enabled=enable_filter,
            threshold=thr,
            top_n=int(topn),
        )


def show_file_with_highlighting(
    file_data: Dict,
    file_path: str,
    formula: str,
    formula_stats: FormulaStats,
    *,
    filter_enabled: bool = False,
    threshold: float = 0.0,
    top_n: int = 0,
) -> None:
    """Show file content with line highlighting based on suspiciousness."""
    suspiciousness = file_data.get("suspiciousness", {})

    if not suspiciousness:
        st.warning("No suspiciousness data for this file")
        return

    # Determine the actual file path to read
    actual_file_path = file_path

    # If project root is set, try to construct the full path
    if st.session_state.project_root:
        # Try different combinations to find the file
        potential_paths = [
            os.path.join(st.session_state.project_root, file_path),  # Direct join
            os.path.join(
                st.session_state.project_root, file_path.lstrip("./")
            ),  # Remove leading ./
            os.path.join(
                st.session_state.project_root, file_path.lstrip("/\\")
            ),  # Remove leading slashes
        ]

        # If file_path is already absolute, also try it as-is
        if os.path.isabs(file_path):
            potential_paths.insert(0, file_path)

        # Find the first path that exists
        for path in potential_paths:
            if os.path.exists(path):
                actual_file_path = path
                break

    # Try to read the actual file content
    try:
        with open(actual_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    except FileNotFoundError:
        st.error(f"❌ Could not find file: `{file_path}`")
        if st.session_state.project_root:
            st.error(f"🔍 Searched in project root: `{st.session_state.project_root}`")
            # Show tried paths for debugging
            with st.expander("Show attempted paths"):
                potential_paths = [
                    os.path.join(st.session_state.project_root, file_path),
                    os.path.join(st.session_state.project_root, file_path.lstrip("./")),
                    os.path.join(
                        st.session_state.project_root, file_path.lstrip("/\\")
                    ),
                ]
                for i, path in enumerate(potential_paths, 1):
                    st.code(f"{i}. {path}")
        else:
            st.info(
                "💡 Try setting a project root directory using the "
                "'Browse Project Root' button above."
            )
        return
    except Exception as e:
        st.error(f"❌ Error reading file: {str(e)}")
        return

    st.subheader(f"File: {file_path}")
    # Color legend for normalized suspiciousness
    st.caption(
        "Highlight based on normalized suspiciousness (0–1): >0.8=🔴, >0.5=🟠, >0.2=🟡"
    )

    # Precompute normalized scores per line
    normalized_scores: Dict[int, float] = {}
    for line_str, scores in suspiciousness.items():
        raw = float(scores.get(formula, 0.0))
        norm = (raw - formula_stats.min_score) / (formula_stats.range_score or 1.0)
        normalized_scores[int(line_str)] = max(0.0, min(1.0, norm))

    # Determine which lines to display based on filters
    show_lines: Optional[set] = None
    if filter_enabled:
        # Lines above threshold
        above = {ln for ln, sc in normalized_scores.items() if sc >= threshold}
        # Top-N by score (ties not guaranteed stable)
        if top_n > 0:
            sorted_by_score = sorted(
                normalized_scores.items(), key=lambda x: x[1], reverse=True
            )
            top_set = {ln for ln, _ in sorted_by_score[:top_n]}
            candidate = above | top_set
        else:
            candidate = above
        show_lines = candidate if candidate else set()

    # Create highlighted code display with preserved indentation
    highlighted_lines = []
    for line_num, line_content in enumerate(lines, 1):
        line_str = str(line_num)
        # Filter out non-selected lines if filtering is enabled
        if show_lines is not None and line_num not in show_lines:
            continue
        # Escape HTML special characters and preserve indentation
        safe_content = (
            line_content.rstrip("\n")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        # Replace leading spaces/tabs with &nbsp; for indentation
        leading_spaces = len(line_content) - len(line_content.lstrip(" "))
        leading_tabs = len(line_content) - len(line_content.lstrip("\t"))
        indent = "&nbsp;" * leading_spaces + ("&nbsp;&nbsp;&nbsp;&nbsp;" * leading_tabs)
        stripped_content = safe_content.lstrip(" \t")
        code_html = f"{indent}{stripped_content}"
        if line_num in normalized_scores:
            score = normalized_scores[line_num]
            # Color intensity based on normalized suspiciousness
            if score > 0.8:
                color = "#ff4444"
            elif score > 0.5:
                color = "#ff8844"
            elif score > 0.2:
                color = "#ffbb44"
            else:
                color = "#ffffff"

            highlighted_lines.append(
                f'<div style="background-color: {color}; padding: 2px; '
                f'margin: 1px;">'
                f'<span style="color: #666; width: 40px; '
                f'display: inline-block;">{line_num:3d}</span> '
                f'<span style="color: #000;">{code_html}</span> '
                f'<span style="color: #999; float: right;">({score:.3f})</span>'
                f"</div>"
            )
        else:
            # No score available for this line: render plain line without score badge
            highlighted_lines.append(
                f'<div style="padding: 2px; margin: 1px;">'
                f'<span style="color: #666; width: 40px; '
                f'display: inline-block;">{line_num:3d}</span> '
                f'<span style="color: #000;">{code_html}</span>'
                f"</div>"
            )

    st.markdown(
        '<div style="font-family: monospace; font-size: 12px; '
        "background-color: rgba(240, 242, 246, 0.5); padding: 15px; "
        "border-radius: 8px; "
        'border: 1px solid rgba(49, 51, 63, 0.2);">'
        + "".join(highlighted_lines)
        + "</div>",
        unsafe_allow_html=True,
    )


def show_coverage_matrix(data: Dict[str, Any], formula: str) -> None:
    """Show intuitive test-to-fault relationship analysis."""
    st.header("Test-to-Fault Analysis")
    st.markdown(
        f"**Understand which failing tests are most informative for "
        f"finding bugs** (using `{formula}` formula)"
    )

    # Extract test and coverage information
    tests_info = data.get("tests", {})
    files_data = data.get("files", {})

    if not tests_info or not files_data:
        st.warning("No test or coverage data available")
        return

    # Get formula statistics for normalization using the selected formula
    formula_stats = calculate_formula_statistics(data, formula)

    if not formula_stats.all_scores:
        st.warning("No suspiciousness data available")
        return

    # Analyze test-line relationships
    passed_tests = set(tests_info.get("passed", []))
    failed_tests = set(tests_info.get("failed", []))

    if not failed_tests:
        st.error(
            "❌ No failing tests found. Fault localization requires "
            "failing tests to work."
        )
        return

    # Threshold control for filtering suspicious lines (normalized 0–1)
    st.divider()
    col_thr1, col_thr2 = st.columns([2, 3])
    with col_thr1:
        thr_key = f"tf_susp_threshold_{formula}"
        susp_threshold = st.slider(
            "Suspiciousness Threshold (normalized)",
            min_value=0.0,
            max_value=1.0,
            value=0.1,
            step=0.05,
            key=thr_key,
            help=(
                "Consider only lines with normalized suspiciousness above "
                "this threshold for the analysis below. Set to 0.0 to "
                "include all lines."
            ),
        )
    with col_thr2:
        st.caption(
            f"Metrics below only consider lines with suspiciousness > "
            f"{susp_threshold:.2f} (normalized)."
        )

    # Build simplified analysis data
    line_analysis = []
    test_coverage_data = {}

    for file_path, file_data in files_data.items():
        contexts = file_data.get("contexts", {})
        suspiciousness = file_data.get("suspiciousness", {})

        for line_num, test_contexts in contexts.items():
            # Get suspiciousness score
            susp_score = 0.0
            if line_num in suspiciousness and formula in suspiciousness[line_num]:
                raw_score = float(suspiciousness[line_num][formula])
                # Normalize to 0-1 range
                susp_score = (
                    raw_score - formula_stats.min_score
                ) / formula_stats.range_score

            # Only consider lines with suspiciousness above the configured threshold
            if susp_score > susp_threshold:
                # Extract test names from contexts
                covering_tests = set()
                for context in test_contexts:
                    if "::" in context:
                        test_name = context.split("|")[0]
                        covering_tests.add(test_name)

                # Categorize coverage
                failed_covering = covering_tests & failed_tests
                passed_covering = covering_tests & passed_tests

                coverage_type = "Unknown"
                if failed_covering and not passed_covering:
                    coverage_type = "Only Failed Tests"
                elif failed_covering and passed_covering:
                    coverage_type = "Mixed (Failed + Passed)"
                elif passed_covering and not failed_covering:
                    coverage_type = "Only Passed Tests"

                line_analysis.append(
                    {
                        "file": file_path,
                        "line": int(line_num),
                        "suspiciousness": susp_score,
                        "coverage_type": coverage_type,
                        "failed_tests_count": len(failed_covering),
                        "passed_tests_count": len(passed_covering),
                        "failed_tests": list(failed_covering),
                        "passed_tests": list(passed_covering),
                        "file_line": f"{file_path}:{line_num}",
                    }
                )

                # Track test coverage for each failed test
                for test in failed_covering:
                    if test not in test_coverage_data:
                        test_coverage_data[test] = {
                            "lines_covered": 0,
                            "total_suspiciousness": 0.0,
                        }
                    test_coverage_data[test]["lines_covered"] += 1
                    test_coverage_data[test]["total_suspiciousness"] += susp_score

    if not line_analysis:
        st.warning("No suspicious lines found with current data")
        return

    # Show main insights
    show_test_fault_insights(
        line_analysis, test_coverage_data, failed_tests, passed_tests
    )

    # Show detailed breakdown
    show_suspicious_lines_breakdown(line_analysis, formula)


def show_test_fault_insights(
    line_analysis: List[Dict],
    test_coverage_data: Dict,
    failed_tests: set,
    passed_tests: set,
) -> None:
    """Show key insights about test-to-fault relationships."""
    st.subheader("Key Insights")

    # Convert to DataFrame for analysis
    df = pd.DataFrame(line_analysis)

    # Calculate key metrics
    col1, col2, col3 = st.columns(3)

    with col1:
        only_failed_lines = len(df[df["coverage_type"] == "Only Failed Tests"])
        st.metric(
            "🎯 Lines Only Hit by Failed Tests",
            only_failed_lines,
            help="These lines are most suspicious - only failing tests execute them",
        )

    with col2:
        mixed_lines = len(df[df["coverage_type"] == "Mixed (Failed + Passed)"])
        st.metric(
            "⚖️ Lines Hit by Both",
            mixed_lines,
            help="Lines executed by both failing and passing tests",
        )

    with col3:
        avg_suspiciousness_failed_only = (
            df[df["coverage_type"] == "Only Failed Tests"]["suspiciousness"].mean()
            if only_failed_lines > 0
            else 0
        )
        st.metric(
            "📊 Avg Suspiciousness (Failed-Only)",
            f"{avg_suspiciousness_failed_only:.3f}",
            help="Average suspiciousness of lines hit only by failed tests",
        )

    # Show distribution of coverage types
    st.subheader("Coverage Pattern Analysis")

    col1, col2 = st.columns(2)

    with col1:
        # Pie chart of coverage types
        coverage_counts = df["coverage_type"].value_counts()

        # Custom colors for better clarity
        colors = [
            "#ff4444",
            "#ffaa44",
            "#44aa44",
        ]  # Red for failed-only, orange for mixed, green for passed-only

        fig_pie = px.pie(
            values=coverage_counts.values,
            names=coverage_counts.index,
            title="Distribution of Suspicious Lines by Coverage Type",
            color_discrete_sequence=colors,
        )

        fig_pie.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(fig_pie, use_container_width=True)

    with col2:
        # Bar chart of test informativeness
        if test_coverage_data:
            test_info_df = (
                pd.DataFrame(
                    [
                        {
                            "test": (
                                "::".join(test.split("::")[-2:])
                                if len(test.split("::")) >= 2
                                else test.split("::")[-1]
                            ),  # Include class and test name
                            "lines_covered": data["lines_covered"],
                            "total_suspiciousness": data["total_suspiciousness"],
                            "avg_suspiciousness": data["total_suspiciousness"]
                            / data["lines_covered"],
                        }
                        for test, data in test_coverage_data.items()
                    ]
                )
                .sort_values("total_suspiciousness", ascending=True)
                .tail(10)
            )  # Top 10 most informative

            fig_bar = px.bar(
                test_info_df,
                x="total_suspiciousness",
                y="test",
                orientation="h",
                title="Most Informative Failed Tests",
                labels={
                    "total_suspiciousness": "Total Suspiciousness Score",
                    "test": "Test Name",
                },
                color="avg_suspiciousness",
                color_continuous_scale="Reds",
            )

            fig_bar.update_layout(height=400)
            st.plotly_chart(fig_bar, use_container_width=True)


def show_suspicious_lines_breakdown(line_analysis: List[Dict], formula: str) -> None:
    """Show detailed breakdown of suspicious lines."""
    st.subheader("Suspicious Lines Details")

    df = pd.DataFrame(line_analysis)

    # Add a filter for coverage type
    col1, col2 = st.columns([1, 3])

    with col1:
        coverage_filter = st.selectbox(
            "Filter by Coverage",
            [
                "All",
                "Only Failed Tests",
                "Mixed (Failed + Passed)",
                "Only Passed Tests",
            ],
            help="Focus on specific types of coverage patterns",
        )

        min_suspiciousness = st.slider(
            "Min Suspiciousness",
            min_value=0.0,
            max_value=1.0,
            value=0.2,
            step=0.1,
            help="Show only lines above this suspiciousness threshold",
        )

    # Apply filters
    filtered_df = df[df["suspiciousness"] >= min_suspiciousness].copy()
    if coverage_filter != "All":
        filtered_df = filtered_df[filtered_df["coverage_type"] == coverage_filter]

    if filtered_df.empty:
        st.warning("No lines match the current filters")
        return

    # Sort by suspiciousness
    filtered_df = filtered_df.sort_values("suspiciousness", ascending=False)

    # Display table with enhanced formatting
    display_df = filtered_df[
        [
            "file",
            "line",
            "suspiciousness",
            "coverage_type",
            "failed_tests_count",
            "passed_tests_count",
        ]
    ].copy()

    with col2:
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "file": st.column_config.TextColumn("File"),
                "line": st.column_config.NumberColumn("Line"),
                "suspiciousness": st.column_config.ProgressColumn(
                    "Suspiciousness", min_value=0.0, max_value=1.0, format="%.3f"
                ),
                "coverage_type": st.column_config.TextColumn("Coverage Type"),
                "failed_tests_count": st.column_config.NumberColumn(
                    "Failed Tests", help="Number of failed tests covering this line"
                ),
                "passed_tests_count": st.column_config.NumberColumn(
                    "Passed Tests", help="Number of passed tests covering this line"
                ),
            },
        )

        st.caption(
            f"Showing {len(filtered_df)} lines sorted by suspiciousness "
            f"(using `{formula}` formula)"
        )

    # Quick stats about filtered data
    if len(filtered_df) > 0:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(
                "Average Suspiciousness", f"{filtered_df['suspiciousness'].mean():.3f}"
            )
        with col2:
            st.metric(
                "Highest Suspiciousness", f"{filtered_df['suspiciousness'].max():.3f}"
            )
        with col3:
            unique_files = filtered_df["file"].nunique()
            st.metric("Files Involved", unique_files)


def show_file_summary_heatmap(df: pd.DataFrame, max_rows: int, max_cols: int) -> None:
    """Show file-level aggregated coverage heatmap."""
    st.subheader("File-Level Coverage Summary")

    # Aggregate by file
    file_summary = (
        df.groupby(["file", "test"])
        .agg(
            {
                "covered": "sum",  # Number of lines covered
                "suspiciousness": "mean",  # Average suspiciousness
                "test_status": "first",  # Test status
            }
        )
        .reset_index()
    )

    # Create pivot for coverage counts
    pivot_coverage = file_summary.pivot_table(
        index="file", columns="test", values="covered", fill_value=0
    )

    pivot_suspiciousness = file_summary.pivot_table(
        index="file", columns="test", values="suspiciousness", fill_value=0
    )

    # Sort files by total suspiciousness
    file_priority = pivot_suspiciousness.sum(axis=1).sort_values(ascending=False)
    sorted_files = file_priority.index

    display_coverage = pivot_coverage.loc[sorted_files].iloc[:max_rows, :max_cols]
    display_suspiciousness = pivot_suspiciousness.loc[sorted_files].iloc[
        :max_rows, :max_cols
    ]

    # Create hover information
    hover_text = []
    for i in range(len(display_coverage)):
        hover_row = []
        for j in range(len(display_coverage.columns)):
            file_name = display_coverage.index[i]
            test_name = display_coverage.columns[j]
            lines_covered = display_coverage.iloc[i, j]
            avg_susp = display_suspiciousness.iloc[i, j]

            hover_row.append(
                f"File: {file_name}<br>"
                f"Test: {test_name}<br>"
                f"Lines Covered: {lines_covered}<br>"
                f"Avg Suspiciousness: {avg_susp:.3f}"
            )
        hover_text.append(hover_row)

    fig = go.Figure(
        data=go.Heatmap(
            z=display_coverage.values,
            x=display_coverage.columns,
            y=display_coverage.index,
            hovertemplate="%{customdata}<extra></extra>",
            customdata=hover_text,
            colorscale="Blues",
            colorbar=dict(title="Lines Covered"),
        )
    )

    fig.update_layout(
        height=max(300, len(display_coverage) * 30),
        xaxis_title="Tests",
        yaxis_title="Files",
        title="File-Level Coverage (number of lines covered per test)",
    )

    fig.update_xaxes(tickangle=45)

    st.plotly_chart(fig, use_container_width=True)

    # Show file statistics
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Top Files by Coverage:**")
        file_total_coverage = display_coverage.sum(axis=1).sort_values(ascending=False)
        for i, (file, coverage) in enumerate(file_total_coverage.head(5).items(), 1):
            st.write(f"{i}. `{file}`: {coverage} lines")

    with col2:
        st.write("**Top Files by Suspiciousness:**")
        file_total_susp = display_suspiciousness.sum(axis=1).sort_values(
            ascending=False
        )
        for i, (file, susp) in enumerate(file_total_susp.head(5).items(), 1):
            st.write(f"{i}. `{file}`: {susp:.3f} avg score")


def show_test_clustering_heatmap(
    df: pd.DataFrame, max_rows: int, max_cols: int
) -> None:
    """Show test clustering based on coverage patterns."""
    st.subheader("Test Clustering by Coverage Patterns")

    # Create test-line matrix
    test_line_matrix = df.pivot_table(
        index="test", columns="file_line", values="covered", fill_value=0
    )

    if test_line_matrix.empty:
        st.warning("No data for clustering")
        return

    # Simple clustering by test status and coverage similarity
    passed_tests = df[df["test_status"] == "passed"]["test"].unique()
    failed_tests = df[df["test_status"] == "failed"]["test"].unique()

    # Separate and sort tests
    passed_matrix = test_line_matrix.loc[test_line_matrix.index.isin(passed_tests)]
    failed_matrix = test_line_matrix.loc[test_line_matrix.index.isin(failed_tests)]

    # Combine with failed tests first (more important for FL)
    if not failed_matrix.empty and not passed_matrix.empty:
        ordered_matrix = pd.concat([failed_matrix, passed_matrix])
    elif not failed_matrix.empty:
        ordered_matrix = failed_matrix
    else:
        ordered_matrix = passed_matrix

    # Limit size
    display_matrix = ordered_matrix.iloc[:max_cols, :max_rows]  # Swap for tests as rows

    # Create test status colors
    test_colors = []
    for test in display_matrix.index:
        if test in failed_tests:
            test_colors.append("Failed")
        else:
            test_colors.append("Passed")

    fig = go.Figure(
        data=go.Heatmap(
            z=display_matrix.values,
            x=display_matrix.columns,
            y=[
                f"{test} ({status})"
                for test, status in zip(display_matrix.index, test_colors)
            ],
            colorscale="RdBu_r",
            colorbar=dict(title="Coverage"),
        )
    )

    fig.update_layout(
        height=max(400, len(display_matrix) * 20),
        xaxis_title="File:Line",
        yaxis_title="Tests (grouped by status)",
        title="Test Coverage Patterns (Failed tests first)",
    )

    fig.update_xaxes(tickangle=45)

    st.plotly_chart(fig, use_container_width=True)

    # Show clustering insights
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Failed Tests Coverage:**")
        if not failed_matrix.empty:
            failed_coverage = failed_matrix.sum(axis=1).sort_values(ascending=False)
            for i, (test, coverage) in enumerate(failed_coverage.head(5).items(), 1):
                st.write(f"{i}. `{test}`: {coverage} lines")
        else:
            st.write("No failed tests found")

    with col2:
        st.write("**Passed Tests Coverage:**")
        if not passed_matrix.empty:
            passed_coverage = passed_matrix.sum(axis=1).sort_values(ascending=False)
            for i, (test, coverage) in enumerate(passed_coverage.head(5).items(), 1):
                st.write(f"{i}. `{test}`: {coverage} lines")
        else:
            st.write("No passed tests found")


def show_coverage_statistics(df: pd.DataFrame, tests_info: Dict[str, Any]) -> None:
    """Show comprehensive coverage statistics."""
    st.divider()
    st.subheader("Coverage Statistics")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        total_lines = len(df["file_line"].unique())
        st.metric("Total Lines Covered", total_lines)

    with col2:
        total_tests = len(df["test"].unique())
        st.metric("Total Tests", total_tests)

    with col3:
        avg_coverage_per_test = df.groupby("test")["line"].count().mean()
        st.metric("Avg Lines per Test", f"{avg_coverage_per_test:.1f}")

    with col4:
        avg_tests_per_line = df.groupby("file_line")["test"].count().mean()
        st.metric("Avg Tests per Line", f"{avg_tests_per_line:.1f}")

    # Coverage distribution chart
    col1, col2 = st.columns(2)

    with col1:
        # Test coverage distribution
        test_coverage = df.groupby("test")["line"].count()
        fig1 = px.histogram(
            x=test_coverage.values,
            nbins=20,
            title="Distribution of Lines Covered per Test",
            labels={"x": "Lines Covered", "y": "Number of Tests"},
        )
        st.plotly_chart(fig1, use_container_width=True)

    with col2:
        # Line coverage distribution
        line_coverage = df.groupby("file_line")["test"].count()
        fig2 = px.histogram(
            x=line_coverage.values,
            nbins=20,
            title="Distribution of Tests per Line",
            labels={"x": "Tests Covering Line", "y": "Number of Lines"},
        )
        st.plotly_chart(fig2, use_container_width=True)


def show_sunburst(data: Dict[str, Any], formula: str) -> None:
    """Show sunburst visualization with hierarchical Python project structure."""
    st.header("Sunburst View")

    # Add threshold control
    col1, col2 = st.columns([1, 3])
    with col1:
        min_score = st.slider(
            "Min Suspiciousness Score",
            min_value=0.0,
            max_value=1.0,
            value=0.05,
            step=0.05,
            key=f"sunburst_threshold_{formula}",
            help="Filter out elements with suspiciousness score below this threshold",
        )

    hierarchy_data = build_hierarchical_data(data, formula, min_score)

    if not hierarchy_data or len(hierarchy_data["labels"]) <= 1:
        st.warning(f"No hierarchical data available with minimum score {min_score:.2f}")
        st.info("Try lowering the minimum score threshold")

        # Show fallback with very low threshold
        fallback_data = build_hierarchical_data(data, formula, 0.0)
        if fallback_data and len(fallback_data["labels"]) > 1:
            st.info(
                f"Available elements with threshold 0.0: {len(fallback_data['labels'])}"
            )
        return  # Scale values mildly to keep proportions while avoiding tiny slices
    try:
        vals_arr = np.array(hierarchy_data["values"], dtype=float)
        scaled = np.sqrt(vals_arr)
        fixed_values = np.maximum(
            scaled, 1
        ).tolist()  # ensure minimum size without heavy distortion
    except Exception:
        fixed_values = hierarchy_data["values"]

    # Create hierarchical sunburst
    try:
        fig = go.Figure(
            go.Sunburst(
                labels=hierarchy_data["labels"],
                parents=hierarchy_data["parents"],
                ids=hierarchy_data.get("ids", None),
                values=fixed_values,
                marker=dict(
                    colors=hierarchy_data["colors"],
                    colorscale="Reds",  # Scala da bianco a rosso
                    colorbar=dict(title="Suspiciousness Score"),
                    line=dict(width=2, color="white"),
                    cmin=0.0,  # Fissiamo il minimo della scala dei colori
                    cmax=1.0,  # Fissiamo il massimo della scala dei colori
                ),
                hovertemplate=(
                    "<b>%{label}</b><br>%{customdata}<br>"
                    "Score: %{color:.3f}<extra></extra>"
                ),
                customdata=hierarchy_data["hover_info"],
            )
        )

        fig.update_layout(
            height=700,
            title=f"Code Hierarchy - {formula.title()}",
            font_size=11,
            margin=dict(t=50, l=0, r=0, b=0),
        )

        st.plotly_chart(fig, use_container_width=True)

        # Add statistics
        with col2:
            if hierarchy_data["colors"]:
                st.markdown(
                    f"""
                **Statistics:**
                - Total elements shown: {len(hierarchy_data['labels']) - 1}
                - Average suspiciousness: {np.mean(hierarchy_data['colors']):.3f}
                - Max suspiciousness: {max(hierarchy_data['colors']):.3f}
                - Min suspiciousness: {min(hierarchy_data['colors']):.3f}
                """
                )

        # Add explanation
        st.markdown(
            """
        **Hierarchy Levels:**
        - **Center**: Project root
        - **Level 1**: Python files (.py)
        - **Level 2**: Classes within files
        - **Level 3**: Functions/Methods within classes

        **Color**: Indicates suspiciousness score (red = more suspicious)
        **Size**: Proportional to number of lines with coverage data

        **Tip**: If the sunburst appears empty, try lowering the minimum
        score threshold.
        """
        )

    except Exception as e:
        st.error(f"Error creating sunburst: {e}")

        # Fallback to simple visualization
        st.subheader("Alternative View")
        susp_data = extract_suspiciousness_data(data, formula)

        df_data = []
        for item in susp_data[:15]:  # Top 15
            df_data.append(
                {"Element": f"{item['file']}:{item['line']}", "Score": item["score"]}
            )

        if df_data:
            df = pd.DataFrame(df_data)
            fig_bar = px.bar(
                df,
                x="Score",
                y="Element",
                orientation="h",
                title=f"Top Suspicious Elements - {formula.title()}",
                color="Score",
                color_continuous_scale="Reds",
            )
            fig_bar.update_layout(height=500)
            st.plotly_chart(fig_bar, use_container_width=True)


def extract_suspiciousness_data(data: Dict[str, Any], formula: str) -> List[Dict]:
    """Extract and sort suspiciousness data for given formula."""
    files_data = data.get("files", {})
    susp_data = []

    for file_path, file_data in files_data.items():
        suspiciousness = file_data.get("suspiciousness", {})
        for line_num, scores in suspiciousness.items():
            if formula in scores:
                susp_data.append(
                    {
                        "file": file_path,
                        "line": int(line_num),
                        "score": float(scores[formula]),  # Ensure float
                    }
                )

    # Sort by score descending
    susp_data.sort(key=lambda x: x["score"], reverse=True)
    return susp_data


def get_top_suspicious_lines_for_formula(
    data: Dict[str, Any], formula: str, top_n: int = 10
) -> List[Dict]:
    """Get top N most suspicious lines for a specific formula."""
    files_data = data.get("files", {})
    all_suspicious = []

    for file_path, file_data in files_data.items():
        suspiciousness = file_data.get("suspiciousness", {})
        contexts = file_data.get("contexts", {})
        executed_lines = file_data.get("executed_lines", [])

        for line_num in executed_lines:
            line_str = str(line_num)

            # Check if this line has test coverage
            line_contexts = contexts.get(line_str, [])
            has_test_coverage = any(context.strip() for context in line_contexts)

            if (
                line_str in suspiciousness
                and formula in suspiciousness[line_str]
                and has_test_coverage
            ):
                score = float(suspiciousness[line_str][formula])
                all_suspicious.append(
                    {
                        "file": file_path,
                        "line": line_num,
                        "score": score,
                        "formula": formula,
                    }
                )

    # Sort by score descending and return top N
    all_suspicious.sort(key=lambda x: x["score"], reverse=True)
    return all_suspicious[:top_n]


def show_formula_comparison(data: Dict[str, Any], formulas: List[str]) -> None:
    """Show comparison between different SBFL formulas."""
    st.header("Formula Comparison")
    st.markdown(
        "Compare the performance and agreement between different SBFL formulas."
    )

    if len(formulas) < 2:
        st.warning("At least 2 formulas are required for comparison.")
        return

    # Formula selection for comparison
    col1, col2 = st.columns(2)

    with col1:
        formula1 = st.selectbox("First Formula", formulas, key="comp_formula1")

    with col2:
        # Filter out the first formula from second selection
        available_formulas = [f for f in formulas if f != formula1]
        if available_formulas:
            formula2 = st.selectbox(
                "Second Formula", available_formulas, key="comp_formula2"
            )
        else:
            st.warning("Please select a different formula for comparison.")
            return

    # Get top suspicious lines for both formulas
    top_n = st.slider("Number of top suspicious lines to compare", 5, 20, 10)

    top_lines_f1 = get_top_suspicious_lines_for_formula(data, formula1, top_n)
    top_lines_f2 = get_top_suspicious_lines_for_formula(data, formula2, top_n)

    if not top_lines_f1 or not top_lines_f2:
        st.warning("No suspicious lines found for the selected formulas.")
        return

    # === SIDE-BY-SIDE COMPARISON TABLE ===
    st.subheader(f"Top {top_n} Most Suspicious Lines Comparison")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"**{formula1}**")
        df1 = pd.DataFrame(top_lines_f1)
        df1["rank"] = range(1, len(df1) + 1)
        df1["file_line"] = df1["file"] + ":" + df1["line"].astype(str)
        st.dataframe(
            df1[["rank", "file_line", "score"]].rename(
                columns={"rank": "Rank", "file_line": "File:Line", "score": "Score"}
            ),
            use_container_width=True,
        )

    with col2:
        st.markdown(f"**{formula2}**")
        df2 = pd.DataFrame(top_lines_f2)
        df2["rank"] = range(1, len(df2) + 1)
        df2["file_line"] = df2["file"] + ":" + df2["line"].astype(str)
        st.dataframe(
            df2[["rank", "file_line", "score"]].rename(
                columns={"rank": "Rank", "file_line": "File:Line", "score": "Score"}
            ),
            use_container_width=True,
        )

    # === SCATTER PLOT COMPARISON ===
    st.subheader("Score Correlation Analysis")

    # Create a combined dataset for scatter plot
    files_data = data.get("files", {})
    scatter_data = []

    for file_path, file_data in files_data.items():
        suspiciousness = file_data.get("suspiciousness", {})
        contexts = file_data.get("contexts", {})
        executed_lines = file_data.get("executed_lines", [])

        for line_num in executed_lines:
            line_str = str(line_num)

            # Check if this line has test coverage
            line_contexts = contexts.get(line_str, [])
            has_test_coverage = any(context.strip() for context in line_contexts)

            if (
                line_str in suspiciousness
                and formula1 in suspiciousness[line_str]
                and formula2 in suspiciousness[line_str]
                and has_test_coverage
            ):
                score1 = float(suspiciousness[line_str][formula1])
                score2 = float(suspiciousness[line_str][formula2])

                scatter_data.append(
                    {
                        "file": file_path,
                        "line": line_num,
                        "score1": score1,
                        "score2": score2,
                        "file_line": f"{file_path}:{line_num}",
                    }
                )

    if scatter_data:
        scatter_df = pd.DataFrame(scatter_data)

        # Create scatter plot
        fig = px.scatter(
            scatter_df,
            x="score1",
            y="score2",
            hover_data=["file_line"],
            title=f"Suspiciousness Score Comparison: {formula1} vs {formula2}",
            labels={"score1": f"{formula1} Score", "score2": f"{formula2} Score"},
        )

        # Add diagonal line for perfect agreement
        max_score = max(scatter_df["score1"].max(), scatter_df["score2"].max())
        min_score = min(scatter_df["score1"].min(), scatter_df["score2"].min())

        fig.add_trace(
            go.Scatter(
                x=[min_score, max_score],
                y=[min_score, max_score],
                mode="lines",
                name="Perfect Agreement",
                line=dict(dash="dash", color="red", width=2),
            )
        )

        fig.update_layout(width=800, height=600, showlegend=True)

        st.plotly_chart(fig, use_container_width=True)

        # Calculate correlation coefficient
        correlation = scatter_df["score1"].corr(scatter_df["score2"])
        st.metric(
            "Pearson Correlation Coefficient",
            f"{correlation:.3f}",
            help=(
                "Measures linear correlation between the two formulas. "
                "Values closer to 1 indicate high agreement."
            ),
        )

        # === AGREEMENT ANALYSIS ===
        st.subheader("Agreement Analysis")

        # Find lines where formulas disagree significantly
        scatter_df["score_diff"] = abs(scatter_df["score1"] - scatter_df["score2"])
        scatter_df["avg_score"] = (scatter_df["score1"] + scatter_df["score2"]) / 2

        # Define disagreement threshold (e.g., 20% of the score range)
        score_range = max(scatter_df["score1"].max(), scatter_df["score2"].max()) - min(
            scatter_df["score1"].min(), scatter_df["score2"].min()
        )
        disagreement_threshold = score_range * 0.2

        disagreements = scatter_df[
            scatter_df["score_diff"] > disagreement_threshold
        ].copy()
        disagreements = disagreements.sort_values("score_diff", ascending=False)

        if len(disagreements) > 0:
            st.markdown(
                f"**Lines with significant disagreement** "
                f"(difference > {disagreement_threshold:.3f}):"
            )

            disagreements["diff_formatted"] = disagreements["score_diff"].round(3)
            disagreements["score1_formatted"] = disagreements["score1"].round(3)
            disagreements["score2_formatted"] = disagreements["score2"].round(3)

            st.dataframe(
                disagreements[
                    [
                        "file_line",
                        "score1_formatted",
                        "score2_formatted",
                        "diff_formatted",
                    ]
                ].rename(
                    columns={
                        "file_line": "File:Line",
                        "score1_formatted": f"{formula1} Score",
                        "score2_formatted": f"{formula2} Score",
                        "diff_formatted": "Difference",
                    }
                ),
                use_container_width=True,
            )
        else:
            st.success("No significant disagreements found between the formulas!")

        # Show summary statistics
        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Total Lines Compared", len(scatter_df))

        with col2:
            st.metric("Lines with Disagreement", len(disagreements))

        with col3:
            agreement_pct = (
                (len(scatter_df) - len(disagreements)) / len(scatter_df)
            ) * 100
            st.metric("Agreement Percentage", f"{agreement_pct:.1f}%")

    else:
        st.warning(
            "No overlapping suspicious lines found between the selected formulas."
        )


def extract_all_tests_from_data(data: Dict[str, Any]) -> List[str]:
    """Extract all unique test names from the report data."""
    all_tests = set()
    files_data = data.get("files", {})

    for file_data in files_data.values():
        contexts = file_data.get("contexts", {})
        for line_contexts in contexts.values():
            for context in line_contexts:
                if context.strip() and "::" in context:
                    # Extract test name from context
                    test_name = context.split("|")[0] if "|" in context else context
                    all_tests.add(test_name)

    return sorted(list(all_tests))


def filter_failed_tests(all_tests: List[str]) -> List[str]:
    """Filter tests to show only those that are likely failed tests."""
    # This is a heuristic - in a real implementation, we'd need the actual test results
    # For now, we'll assume tests with certain patterns might be failing
    # failed_patterns = ["test_fail", "test_error", "test_exception"]  # Unused

    failed_tests = []
    for test in all_tests:
        # Add all tests for now - in practice, you'd filter based on actual test results
        failed_tests.append(test)

    return failed_tests


def show_formula_performance(data: Dict[str, Any], formulas: List[str]) -> None:
    """Show comprehensive performance analysis for all SBFL formulas."""
    st.header("Formula Performance Analysis")
    st.markdown(
        "Comprehensive comparison of all SBFL formulas' effectiveness "
        "and characteristics."
    )

    if len(formulas) < 2:
        st.warning("At least 2 formulas are required for performance analysis.")
        return

    # Calculate statistics for all formulas
    formula_statistics = {}
    for formula in formulas:
        formula_statistics[formula] = calculate_formula_statistics(data, formula)

    # === PERFORMANCE METRICS TABLE ===
    st.subheader("Performance Metrics Summary")

    performance_data = []
    for formula in formulas:
        stats = formula_statistics[formula]
        top_lines = get_top_suspicious_lines_for_formula(data, formula, 20)

        # Calculate various metrics
        total_scored_lines = len(stats.all_scores)
        max_score = stats.max_score
        min_score = stats.min_score
        score_range = stats.range_score
        avg_score = float(np.mean(stats.all_scores) if stats.all_scores else 0.0)
        std_score = float(np.std(stats.all_scores) if stats.all_scores else 0.0)

        # Calculate score distribution percentiles
        if stats.all_scores:
            p95 = float(np.percentile(stats.all_scores, 95))
            p90 = float(np.percentile(stats.all_scores, 90))
            p75 = float(np.percentile(stats.all_scores, 75))
            median = float(np.percentile(stats.all_scores, 50))
        else:
            p95 = p90 = p75 = median = 0.0

        # Calculate concentration metric (how concentrated are high scores)
        high_score_threshold = max_score * 0.8 if max_score > 0 else 0
        high_score_count = sum(
            1 for score in stats.all_scores if score >= high_score_threshold
        )
        concentration_ratio = (
            (high_score_count / total_scored_lines * 100)
            if total_scored_lines > 0
            else 0
        )

        performance_data.append(
            {
                "Formula": formula,
                "Total Lines": total_scored_lines,
                "Max Score": round(max_score, 3),
                "Min Score": round(min_score, 3),
                "Score Range": round(score_range, 3),
                "Average Score": round(avg_score, 3),
                "Std Dev": round(std_score, 3),
                "Median": round(median, 3),
                "75th Percentile": round(p75, 3),
                "90th Percentile": round(p90, 3),
                "95th Percentile": round(p95, 3),
                "High Score Concentration (%)": round(concentration_ratio, 1),
            }
        )

    df_performance = pd.DataFrame(performance_data)
    st.dataframe(df_performance, use_container_width=True)

    # === SCORE DISTRIBUTION COMPARISON ===
    st.subheader("Score Distribution Comparison")

    # Create box plots for score distributions
    all_scores_data = []
    for formula in formulas:
        stats = formula_statistics[formula]
        for score in stats.all_scores:
            all_scores_data.append({"Formula": formula, "Score": score})

    if all_scores_data:
        df_scores = pd.DataFrame(all_scores_data)

        fig_box = px.box(
            df_scores,
            x="Formula",
            y="Score",
            title="Score Distribution by Formula",
            points="outliers",
        )
        fig_box.update_layout(height=500)
        st.plotly_chart(fig_box, use_container_width=True)

        # Violin plot for better distribution visualization
        fig_violin = px.violin(
            df_scores,
            x="Formula",
            y="Score",
            title="Score Distribution Density by Formula",
            box=True,
        )
        fig_violin.update_layout(height=500)
        st.plotly_chart(fig_violin, use_container_width=True)

    # === TOP LINES OVERLAP ANALYSIS ===
    st.subheader("Top Lines Overlap Analysis")

    # Get top 10 lines for each formula
    top_lines_by_formula = {}
    for formula in formulas:
        top_lines = get_top_suspicious_lines_for_formula(data, formula, 10)
        top_lines_by_formula[formula] = {
            f"{line['file']}:{line['line']}" for line in top_lines
        }

    # Calculate pairwise overlaps
    overlap_data = []
    for i, formula1 in enumerate(formulas):
        for j, formula2 in enumerate(formulas):
            if i <= j:  # Only calculate upper triangle
                lines1 = top_lines_by_formula[formula1]
                lines2 = top_lines_by_formula[formula2]

                if i == j:
                    overlap = len(lines1)
                    overlap_pct = 100.0
                else:
                    overlap = len(lines1.intersection(lines2))
                    overlap_pct = (
                        (overlap / len(lines1.union(lines2)) * 100)
                        if lines1.union(lines2)
                        else 0
                    )

                overlap_data.append(
                    {
                        "Formula 1": formula1,
                        "Formula 2": formula2,
                        "Overlap Count": overlap,
                        "Overlap %": round(overlap_pct, 1),
                    }
                )

    df_overlap = pd.DataFrame(overlap_data)
    st.dataframe(df_overlap, use_container_width=True)

    # === RANKING EFFECTIVENESS SIMULATION ===
    st.subheader("Ranking Effectiveness Analysis")

    st.markdown(
        """
    This analysis simulates how effective each formula would be at finding bugs
    by measuring how well they rank suspicious lines.
    """
    )

    effectiveness_data = []
    for formula in formulas:
        top_lines = get_top_suspicious_lines_for_formula(data, formula, 50)

        if top_lines:
            # Calculate some effectiveness metrics
            top_10_avg_score = np.mean([line["score"] for line in top_lines[:10]])
            top_20_avg_score = np.mean([line["score"] for line in top_lines[:20]])

            # Score decline rate (how quickly scores drop)
            if len(top_lines) >= 20:
                score_decline = (top_lines[0]["score"] - top_lines[19]["score"]) / 20
            else:
                score_decline = 0

            # Consistency metric (how consistent are the top scores)
            top_10_scores = [line["score"] for line in top_lines[:10]]
            consistency = (
                1 / (1 + np.std(top_10_scores)) if np.std(top_10_scores) > 0 else 1
            )

            effectiveness_data.append(
                {
                    "Formula": formula,
                    "Top 10 Avg Score": round(top_10_avg_score, 3),
                    "Top 20 Avg Score": round(top_20_avg_score, 3),
                    "Score Decline Rate": round(score_decline, 4),
                    "Top 10 Consistency": round(consistency, 3),
                    "Total Suspicious Lines": len(top_lines),
                }
            )

    if effectiveness_data:
        df_effectiveness = pd.DataFrame(effectiveness_data)
        st.dataframe(df_effectiveness, use_container_width=True)

        # Radar chart for multi-dimensional comparison
        fig_radar = go.Figure()

        # Normalize metrics for radar chart
        metrics = [
            "Top 10 Avg Score",
            "Top 20 Avg Score",
            "Score Decline Rate",
            "Top 10 Consistency",
        ]

        for _, row in df_effectiveness.iterrows():
            values = []
            labels = []
            for metric in metrics:
                if metric == "Score Decline Rate":
                    # For decline rate, lower is better, so invert
                    max_decline = df_effectiveness[metric].max()
                    normalized_value = (
                        1 - (row[metric] / max_decline) if max_decline > 0 else 1
                    )
                else:
                    # For other metrics, higher is better
                    max_value = df_effectiveness[metric].max()
                    normalized_value = row[metric] / max_value if max_value > 0 else 0

                values.append(normalized_value)
                labels.append(metric)

            # Close the polygon
            values.append(values[0])
            labels.append(labels[0])

            fig_radar.add_trace(
                go.Scatterpolar(
                    r=values, theta=labels, fill="toself", name=row["Formula"]
                )
            )

        fig_radar.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 1])),
            showlegend=True,
            title="Formula Performance Radar Chart (Normalized Metrics)",
        )

        st.plotly_chart(fig_radar, use_container_width=True)

    # === EXPORT OPTIONS ===
    st.subheader("Export Performance Report")

    if st.button("Generate Performance Report"):
        report_data = {
            "performance_metrics": performance_data,
            "overlap_analysis": overlap_data,
            "effectiveness_metrics": effectiveness_data if effectiveness_data else [],
            "timestamp": pd.Timestamp.now().isoformat(),
            "total_formulas_analyzed": len(formulas),
        }

        report_json = json.dumps(report_data, indent=2)
        st.download_button(
            label="Download Performance Report (JSON)",
            data=report_json,
            file_name="formula_performance_report.json",
            mime="application/json",
        )


if __name__ == "__main__":
    main()
