#!/usr/bin/env python3
"""
Script to analyze the discriminatory effectiveness of SBFL formulas.
Analyzes how well each formula can distinguish faulty lines from other lines.
"""

import json
import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import numpy as np


@dataclass
class DiscriminationMetrics:
    """Discrimination metrics for an SBFL formula"""

    formula: str
    bug_id: str
    project: str

    # Buggy vs non-buggy line scores
    buggy_scores: List[float]
    non_buggy_scores: List[float]

    # Comparative statistics
    mean_buggy_score: float
    mean_non_buggy_score: float
    median_buggy_score: float
    median_non_buggy_score: float

    # Separation
    score_separation: float  # difference between means
    overlap_ratio: float  # percentage of overlap between distributions

    # Discriminatory capability
    perfect_separation: bool  # all buggy lines have score > all non-buggy lines
    auc_roc: float  # Area Under ROC Curve (approximated)


def analyze_formula_discrimination(
    report_path: str, buggy_lines: List[Tuple[str, int]]
) -> List[DiscriminationMetrics]:
    """Analyze the discriminatory capability of each formula for a single bug"""

    if not os.path.exists(report_path):
        return []

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    # Extract suspicious lines from new structure
    suspicious_lines = []
    if "files" in report:
        for file_path, file_data in report["files"].items():
            if "suspiciousness" in file_data:
                # Normalize file path
                normalized_path = file_path.split("\\")[-1].split("/")[-1]

                for line_num_str, scores in file_data["suspiciousness"].items():
                    line_num = int(line_num_str)
                    suspicious_lines.append(
                        {"file": normalized_path, "line": line_num, "scores": scores}
                    )

    if not suspicious_lines:
        return []

    # Analyze each formula
    formulas = ["ochiai", "tarantula", "jaccard", "dstar2"]
    results = []

    for formula in formulas:
        # Filter lines that have scores for this formula
        formula_lines = [sl for sl in suspicious_lines if formula in sl["scores"]]

        if not formula_lines:
            continue

        # Separate scores of buggy lines from non-buggy lines
        buggy_scores = []
        non_buggy_scores = []

        for line_data in formula_lines:
            score = line_data["scores"][formula]
            is_buggy = any(
                line_data["file"] == buggy_file and line_data["line"] == buggy_line
                for buggy_file, buggy_line in buggy_lines
            )

            if is_buggy:
                buggy_scores.append(score)
            else:
                non_buggy_scores.append(score)

        if not buggy_scores or not non_buggy_scores:
            continue

        # Calcola le metriche di discriminazione
        metrics = calculate_discrimination_metrics(
            formula, buggy_scores, non_buggy_scores
        )
        results.append(metrics)

    return results


def calculate_discrimination_metrics(
    formula: str, buggy_scores: List[float], non_buggy_scores: List[float]
) -> DiscriminationMetrics:
    """Calcola le metriche di discriminazione per una formula"""

    # Statistiche di base
    mean_buggy = np.mean(buggy_scores)
    mean_non_buggy = np.mean(non_buggy_scores)
    median_buggy = np.median(buggy_scores)
    median_non_buggy = np.median(non_buggy_scores)

    # Separazione tra le distribuzioni
    score_separation = mean_buggy - mean_non_buggy

    # Calcola l'overlap tra le distribuzioni
    min_buggy = min(buggy_scores)
    max_buggy = max(buggy_scores)
    min_non_buggy = min(non_buggy_scores)
    max_non_buggy = max(non_buggy_scores)

    # Overlap range
    overlap_start = max(min_buggy, min_non_buggy)
    overlap_end = min(max_buggy, max_non_buggy)

    if overlap_start <= overlap_end:
        # C'è overlap - calcola la percentuale approssimativa
        overlap_buggy = sum(
            1 for score in buggy_scores if overlap_start <= score <= overlap_end
        )
        overlap_non_buggy = sum(
            1 for score in non_buggy_scores if overlap_start <= score <= overlap_end
        )
        overlap_ratio = (overlap_buggy + overlap_non_buggy) / (
            len(buggy_scores) + len(non_buggy_scores)
        )
    else:
        overlap_ratio = 0.0

    # Separazione perfetta
    perfect_separation = min_buggy > max_non_buggy

    # AUC-ROC approssimata (confronta ogni coppia buggy/non-buggy)
    correct_pairs = sum(
        1
        for b_score in buggy_scores
        for nb_score in non_buggy_scores
        if b_score > nb_score
    )
    total_pairs = len(buggy_scores) * len(non_buggy_scores)
    auc_roc = correct_pairs / total_pairs if total_pairs > 0 else 0.5

    return DiscriminationMetrics(
        formula=formula,
        bug_id="",  # Sarà riempito dopo
        project="",  # Sarà riempito dopo
        buggy_scores=buggy_scores,
        non_buggy_scores=non_buggy_scores,
        mean_buggy_score=float(mean_buggy),
        mean_non_buggy_score=float(mean_non_buggy),
        median_buggy_score=float(median_buggy),
        median_non_buggy_score=float(median_non_buggy),
        score_separation=float(score_separation),
        overlap_ratio=overlap_ratio,
        perfect_separation=perfect_separation,
        auc_roc=auc_roc,
    )


def generate_discrimination_report(all_metrics: List[DiscriminationMetrics]) -> Dict:
    """Generate a report on the discriminatory capability of formulas"""

    # Group by formula
    formula_metrics = defaultdict(list)
    for metric in all_metrics:
        formula_metrics[metric.formula].append(metric)

    report: Dict[str, Any] = {
        "discrimination_analysis": {},
        "formula_comparison": {},
        "summary": {},
    }

    # Analisi per formula
    for formula, metrics in formula_metrics.items():
        if not metrics:
            continue

        separations = [m.score_separation for m in metrics]
        overlaps = [m.overlap_ratio for m in metrics]
        aucs = [m.auc_roc for m in metrics]
        perfect_seps = [m.perfect_separation for m in metrics]

        mean_buggy_scores = [m.mean_buggy_score for m in metrics]
        mean_non_buggy_scores = [m.mean_non_buggy_score for m in metrics]

        report["discrimination_analysis"][formula] = {
            "bugs_analyzed": len(metrics),
            "score_separation": {
                "mean": np.mean(separations),
                "median": np.median(separations),
                "std": np.std(separations),
                "min": min(separations),
                "max": max(separations),
            },
            "overlap_ratio": {
                "mean": np.mean(overlaps),
                "median": np.median(overlaps),
                "std": np.std(overlaps),
                "cases_no_overlap": sum(1 for o in overlaps if o == 0),
                "cases_high_overlap": sum(1 for o in overlaps if o > 0.5),
            },
            "auc_roc": {
                "mean": np.mean(aucs),
                "median": np.median(aucs),
                "std": np.std(aucs),
                "cases_excellent": sum(1 for auc in aucs if auc > 0.9),
                "cases_good": sum(1 for auc in aucs if 0.8 <= auc <= 0.9),
                "cases_fair": sum(1 for auc in aucs if 0.7 <= auc < 0.8),
                "cases_poor": sum(1 for auc in aucs if auc < 0.7),
            },
            "perfect_separation_rate": sum(perfect_seps) / len(perfect_seps),
            "mean_scores": {
                "buggy_lines": {
                    "mean": np.mean(mean_buggy_scores),
                    "std": np.std(mean_buggy_scores),
                },
                "non_buggy_lines": {
                    "mean": np.mean(mean_non_buggy_scores),
                    "std": np.std(mean_non_buggy_scores),
                },
            },
        }

    # Confronto tra formule
    formulas = list(formula_metrics.keys())
    comparison: Dict[str, Any] = {}

    for metric_name in [
        "score_separation",
        "overlap_ratio",
        "auc_roc",
        "perfect_separation_rate",
    ]:
        comparison[metric_name] = {}
        for formula in formulas:
            if metric_name == "perfect_separation_rate":
                comparison[metric_name][formula] = report["discrimination_analysis"][
                    formula
                ][metric_name]
            else:
                comparison[metric_name][formula] = report["discrimination_analysis"][
                    formula
                ][metric_name]["mean"]

    report["formula_comparison"] = comparison

    # Determina la migliore formula per ogni metrica
    if formulas:  # Solo se ci sono formule da confrontare
        best_separation = max(formulas, key=lambda f: comparison["score_separation"][f])
        best_auc = max(formulas, key=lambda f: comparison["auc_roc"][f])
        best_no_overlap = min(formulas, key=lambda f: comparison["overlap_ratio"][f])
        best_perfect_sep = max(
            formulas, key=lambda f: comparison["perfect_separation_rate"][f]
        )

        report["summary"] = {
            "best_score_separation": {
                "formula": best_separation,
                "value": comparison["score_separation"][best_separation],
            },
            "best_auc_roc": {
                "formula": best_auc,
                "value": comparison["auc_roc"][best_auc],
            },
            "least_overlap": {
                "formula": best_no_overlap,
                "value": comparison["overlap_ratio"][best_no_overlap],
            },
            "most_perfect_separations": {
                "formula": best_perfect_sep,
                "value": comparison["perfect_separation_rate"][best_perfect_sep],
            },
        }
    else:
        report["summary"] = {"message": "No formulas analyzed"}

    return report


def main() -> None:
    """Main function for discrimination analysis"""
    print("SBFL Formula Discriminatory Capability Analysis")
    print("=" * 60)

    # Read data from previous analysis
    csv_path = "FLOSS_effectiveness_summary.csv"
    if not os.path.exists(csv_path):
        print(
            f"Errore: File {csv_path} non trovato. "
            "Esegui prima analyze_effectiveness.py"
        )
        return

    # Carica i bug e le loro informazioni
    from analyze_effectiveness import find_all_bugs

    bugs = find_all_bugs()
    all_metrics = []

    print(f"Analyzing {len(bugs)} bugs for discriminatory capability...")

    for bug in bugs:
        if not bug.buggy_lines:
            continue

        print(f"  Analyzing {bug.project}/{bug.bug_id}...")

        # Normalize buggy line paths
        normalized_buggy_lines = []
        for file_path, line_num in bug.buggy_lines:
            normalized_path = file_path.split("\\")[-1]  # Only filename
            normalized_buggy_lines.append((normalized_path, line_num))

        metrics = analyze_formula_discrimination(
            bug.report_path, normalized_buggy_lines
        )

        # Aggiungi informazioni sul bug
        for metric in metrics:
            metric.bug_id = bug.bug_id
            metric.project = bug.project
            all_metrics.append(metric)

    print(f"Raccolte {len(all_metrics)} metriche di discriminazione")

    # Genera il report
    print("Generando il report di discriminazione...")
    discrimination_report = generate_discrimination_report(all_metrics)

    # Salva il report
    output_path = "formula_discrimination_analysis.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(discrimination_report, f, indent=2, ensure_ascii=False)

    print(f"Report saved to: {output_path}")

    # Print summary
    print("\n" + "=" * 60)
    print("DISCRIMINATORY CAPABILITY SUMMARY")
    print("=" * 60)

    summary = discrimination_report["summary"]
    comparison = discrimination_report["formula_comparison"]

    if "message" in summary:
        print(summary["message"])
        return

    print(
        "Best score separation: "
        f"{summary['best_score_separation']['formula'].capitalize()} "
        f"({summary['best_score_separation']['value']:.3f})"
    )
    print(
        f"Best AUC-ROC: {summary['best_auc_roc']['formula'].capitalize()} "
        f"({summary['best_auc_roc']['value']:.3f})"
    )
    print(
        f"Least overlap: {summary['least_overlap']['formula'].capitalize()} "
        f"({summary['least_overlap']['value']:.3f})"
    )
    print(
        "Most perfect separations: "
        f"{summary['most_perfect_separations']['formula'].capitalize()} "
        f"({summary['most_perfect_separations']['value']:.1%})"
    )

    print("\nDettaglio per formula:")
    print(
        f"{'Formula':<12} {'AUC-ROC':<8} {'Separazione':<11} "
        f"{'Overlap':<8} {'Sep.Perfette':<12}"
    )
    print("-" * 60)

    for formula in ["ochiai", "tarantula", "jaccard", "dstar2"]:
        if formula in comparison.get("auc_roc", {}):
            auc = comparison["auc_roc"][formula]
            sep = comparison["score_separation"][formula]
            overlap = comparison["overlap_ratio"][formula]
            perfect = comparison["perfect_separation_rate"][formula]

            print(
                f"{formula.capitalize():<12} {auc:<8.3f} {sep:<11.3f} "
                f"{overlap:<8.3f} {perfect:<12.1%}"
            )


if __name__ == "__main__":
    main()
