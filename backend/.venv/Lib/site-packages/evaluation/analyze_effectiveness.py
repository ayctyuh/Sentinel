#!/usr/bin/env python3
"""
Script to analyze FLOSS's effectiveness in bug identification.
Analyzes fault localization reports and compares them with real bug patches.
"""

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class BugInfo:
    """Information about a specific bug"""

    project: str
    bug_id: str
    path: str
    report_path: str
    patch_path: str
    buggy_files: List[str]
    buggy_lines: List[Tuple[str, int]]


@dataclass
class EffectivenessMetrics:
    """Effectiveness metrics for fault localization"""

    bug_id: str
    project: str
    total_lines_analyzed: int
    buggy_lines_found: int

    # Top-N analysis
    top_1_hit: bool
    top_3_hit: bool
    top_5_hit: bool
    top_10_hit: bool

    # Rank statistics
    best_rank: Optional[int]
    avg_rank: Optional[float]

    # Formula-specific metrics
    ochiai_best_rank: Optional[int]
    tarantula_best_rank: Optional[int]
    jaccard_best_rank: Optional[int]
    dstar2_best_rank: Optional[int]


def find_all_bugs() -> List[BugInfo]:
    """Find all bugs in the examples"""
    bugs = []
    examples_dir = Path("examples")

    for project_dir in examples_dir.iterdir():
        if not project_dir.is_dir():
            continue

        project_name = project_dir.name
        print(f"🔍 Processing project: {project_name}")

        # Search for bugs based on project structure
        if project_name == "black":
            # Black has bug15-bug23 + multi-bugs
            for bug_dir in project_dir.iterdir():
                if bug_dir.is_dir() and bug_dir.name.startswith("bug"):
                    bug_info = extract_bug_info(project_name, bug_dir)
                    if bug_info:
                        bugs.append(bug_info)

            # Add multi-bugs for Black (subfolders)
            multi_bugs_dir = project_dir / "multi-bugs"
            if multi_bugs_dir.exists():
                for multi_bug_dir in multi_bugs_dir.iterdir():
                    if multi_bug_dir.is_dir():
                        bug_info = extract_multi_bug_info(project_name, multi_bug_dir)
                        if bug_info:
                            bugs.append(bug_info)

        if project_name == "fastapi":
            # FastAPI has bug1-bug16 + multi-bugs
            for bug_dir in project_dir.iterdir():
                if bug_dir.is_dir() and bug_dir.name.startswith("bug"):
                    bug_info = extract_bug_info(project_name, bug_dir)
                    if bug_info:
                        bugs.append(bug_info)

            # Add multi-bugs for FastAPI (direct folder)
            multi_bugs_dir = project_dir / "multi-bugs"
            if multi_bugs_dir.exists() and (multi_bugs_dir / "report.json").exists():
                bug_info = extract_multi_bug_info(
                    project_name, multi_bugs_dir, "multi-1-9-12-13-15-16"
                )
                if bug_info:
                    bugs.append(bug_info)

        elif project_name == "cookiecutter":
            # Cookiecutter has bug1 and bug2
            for bug_dir in project_dir.iterdir():
                if bug_dir.is_dir() and bug_dir.name.startswith("bug"):
                    bug_info = extract_bug_info(project_name, bug_dir)
                    if bug_info:
                        bugs.append(bug_info)

        elif project_name == "pygraphistry":
            # PyGraphistry has a single bug
            bug_info = extract_bug_info(project_name, project_dir, bug_id="main")
            if bug_info:
                bugs.append(bug_info)

        elif project_name == "dummy-example":
            # Dummy example (might not have patch)
            bug_info = extract_bug_info(project_name, project_dir, bug_id="demo")
            if bug_info:
                bugs.append(bug_info)

    return bugs


def extract_bug_info(
    project: str, bug_dir: Path, bug_id: Optional[str] = None
) -> Optional[BugInfo]:
    """Extract information about a single bug"""
    if bug_id is None:
        bug_id = bug_dir.name

    report_path = bug_dir / "report.json"
    patch_path = bug_dir / "bug_patch.txt"

    if not report_path.exists():
        print(f"Report not found for {project}/{bug_id}")
        return None

    buggy_files: list[str] = []
    buggy_lines: list[Tuple[str, int]] = []

    if patch_path.exists():
        buggy_files, buggy_lines = parse_patch_file(patch_path)
    else:
        print(f"Patch not found for {project}/{bug_id}")

    return BugInfo(
        project=project,
        bug_id=bug_id,
        path=str(bug_dir),
        report_path=str(report_path),
        patch_path=str(patch_path) if patch_path.exists() else "",
        buggy_files=buggy_files,
        buggy_lines=buggy_lines,
    )


def parse_patch_file(patch_path: Path) -> Tuple[List[str], List[Tuple[str, int]]]:
    """Analyze the patch file to extract modified files and lines"""
    buggy_files = []
    buggy_lines = []

    try:
        with open(patch_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Pattern to find modified files
        file_pattern = r"diff --git a/(.*?) b/(.*?)(?:\n|$)"
        files = re.findall(file_pattern, content)

        for old_file, new_file in files:
            # Normalize path for Windows
            normalized_file = old_file.replace("/", "\\")
            buggy_files.append(normalized_file)

        # Pattern to find modified lines
        # Search for change blocks with @@ -start,count +start,count @@
        hunk_pattern = r"@@\s*-(\d+),?\d*\s*\+(\d+),?\d*\s*@@"

        current_file = None
        lines = content.split("\n")

        # Simplified approach: analyze only removed lines
        # which represent the original buggy code
        current_file = None
        lines = content.split("\n")

        for i, line in enumerate(lines):
            if line.startswith("diff --git"):
                match = re.search(r"diff --git a/(.*?) b/", line)
                if match:
                    current_file = match.group(1).replace("/", "\\")
            elif line.startswith("@@") and current_file:
                match = re.search(hunk_pattern, line)
                if match:
                    start_line = int(match.group(1))
                    # Find removed lines (start with -)
                    j = i + 1
                    current_line = start_line
                    while (
                        j < len(lines)
                        and not lines[j].startswith("@@")
                        and not lines[j].startswith("diff")
                    ):
                        if lines[j].startswith("-") and not lines[j].startswith("---"):
                            # Removed line = buggy code
                            buggy_lines.append((current_file, current_line))
                        elif lines[j].startswith("+") and not lines[j].startswith(
                            "+++"
                        ):
                            # Linea aggiunta - per bug che aggiungono codice mancante
                            # Consideriamo la linea precedente come punto di interesse
                            if current_line > 1:
                                buggy_lines.append((current_file, current_line - 1))

                        # Increase file line number only for lines
                        # that existed in the original file
                        if not lines[j].startswith("+"):
                            current_line += 1
                        j += 1

        # Debug info
        if len(buggy_lines) == 0:
            print(f"⚠️  Nessuna linea buggy trovata in {patch_path}")
            print(f"    File modificati: {buggy_files}")

            # Debug dettagliato per capire il problema
            lines = content.split("\n")
            for i, line in enumerate(lines[:30]):  # Prime 30 linee
                if line.startswith("-") and not line.startswith("---"):
                    print(f"    Linea rimossa trovata: {line}")
                elif line.startswith("+") and not line.startswith("+++"):
                    print(f"    Linea aggiunta trovata: {line}")
        else:
            print(f"✅ Trovate {len(buggy_lines)} linee buggy in {patch_path.name}")
            for file, line_num in buggy_lines[:3]:  # Mostra solo le prime 3
                print(f"    {file}:{line_num}")

    except Exception as e:
        print(f"Errore nel parsing del patch {patch_path}: {e}")

    return buggy_files, buggy_lines


def extract_multi_bug_info(
    project: str, multi_bug_dir: Path, bug_id: Optional[str] = None
) -> Optional[BugInfo]:
    """Extract information for a multi-bug by combining patches from individual bugs"""
    if bug_id is None:
        bug_id = multi_bug_dir.name

    report_path = multi_bug_dir / "report.json"

    if not report_path.exists():
        print(f"Report not found for {project}/{bug_id}")
        return None

    # Determina quali bug singoli sono inclusi dal nome della directory o README
    individual_bugs = []
    if "17-18-19-20" in bug_id:
        individual_bugs = ["bug17", "bug18", "bug19", "bug20"]
    elif "19-22-23" in bug_id:
        individual_bugs = ["bug19", "bug22", "bug23"]
    elif "1-9-12-13-15-16" in bug_id:
        individual_bugs = ["bug1", "bug9", "bug12", "bug13", "bug15", "bug16"]
    else:
        print(f"⚠️  Impossibile determinare i bug singoli per {bug_id}")
        return BugInfo(
            project=project,
            bug_id=bug_id,
            path=str(multi_bug_dir),
            report_path=str(report_path),
            patch_path="",
            buggy_files=[],
            buggy_lines=[],
        )

    # Combina le linee buggy dai singoli bug
    combined_buggy_files = []
    combined_buggy_lines = []

    examples_dir = Path("examples")
    project_dir = examples_dir / project

    for single_bug in individual_bugs:
        single_bug_dir = project_dir / single_bug
        single_patch_path = single_bug_dir / "bug_patch.txt"

        if single_patch_path.exists():
            buggy_files, buggy_lines = parse_patch_file(single_patch_path)
            combined_buggy_files.extend(buggy_files)
            combined_buggy_lines.extend(buggy_lines)

    # Rimuovi duplicati mantenendo l'ordine
    unique_files = list(dict.fromkeys(combined_buggy_files))
    unique_lines = list(dict.fromkeys(combined_buggy_lines))

    print(f"✅ Multi-bug {bug_id}: combinati {len(individual_bugs)} bug singoli")
    print(f"    Linee buggy totali: {len(unique_lines)}")

    return BugInfo(
        project=project,
        bug_id=bug_id,
        path=str(multi_bug_dir),
        report_path=str(report_path),
        patch_path="",  # Non ha una singola patch
        buggy_files=unique_files,
        buggy_lines=unique_lines,
    )


def analyze_report_effectiveness(bug_info: BugInfo) -> Optional[EffectivenessMetrics]:
    """Analyze the tool's effectiveness for a single bug"""
    try:
        with open(bug_info.report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:
        print(f"Errore nel leggere il report {bug_info.report_path}: {e}")
        return None

    # Estrai tutte le linee con punteggi di sospetto
    suspicious_lines = []

    for file_path, file_data in report.get("files", {}).items():
        if "suspiciousness" in file_data:
            for line_num, scores in file_data["suspiciousness"].items():
                if scores:  # Se ha punteggi non vuoti
                    # Normalizza il path per il confronto
                    normalized_path = file_path.replace("/", "\\")
                    suspicious_lines.append(
                        {
                            "file": normalized_path,
                            "line": int(line_num),
                            "scores": scores,
                        }
                    )

    # Sort for each SBFL formula
    formulas = ["ochiai", "tarantula", "jaccard", "dstar2"]
    rankings = {}

    for formula in formulas:
        # Filter only lines that have a score for this formula
        formula_lines = [sl for sl in suspicious_lines if formula in sl["scores"]]
        # Sort by descending score
        formula_lines.sort(key=lambda x: x["scores"][formula], reverse=True)
        rankings[formula] = formula_lines

    # Calculate metrics
    total_lines = len(suspicious_lines)
    buggy_lines_found = 0
    ranks = []
    formula_ranks: dict[str, list[int]] = {formula: [] for formula in formulas}

    # Controlla quante linee buggy sono state trovate
    for buggy_file, buggy_line in bug_info.buggy_lines:
        for sl in suspicious_lines:
            if sl["file"] == buggy_file and sl["line"] == buggy_line:
                buggy_lines_found += 1

                # Calculate rank for each formula
                for formula in formulas:
                    if formula in rankings:
                        rank = find_line_rank(
                            rankings[formula], buggy_file, buggy_line, formula
                        )
                        if rank is not None:
                            formula_ranks[formula].append(rank)
                            if formula == "ochiai":  # Use ochiai as main reference
                                ranks.append(rank)
                break

    # Calculate top-N metrics
    top_1_hit = any(rank <= 1 for rank in ranks)
    top_3_hit = any(rank <= 3 for rank in ranks)
    top_5_hit = any(rank <= 5 for rank in ranks)
    top_10_hit = any(rank <= 10 for rank in ranks)

    best_rank = min(ranks) if ranks else None
    avg_rank = sum(ranks) / len(ranks) if ranks else None

    return EffectivenessMetrics(
        bug_id=bug_info.bug_id,
        project=bug_info.project,
        total_lines_analyzed=total_lines,
        buggy_lines_found=buggy_lines_found,
        top_1_hit=top_1_hit,
        top_3_hit=top_3_hit,
        top_5_hit=top_5_hit,
        top_10_hit=top_10_hit,
        best_rank=best_rank,
        avg_rank=avg_rank,
        ochiai_best_rank=(
            min(formula_ranks["ochiai"]) if formula_ranks["ochiai"] else None
        ),
        tarantula_best_rank=(
            min(formula_ranks["tarantula"]) if formula_ranks["tarantula"] else None
        ),
        jaccard_best_rank=(
            min(formula_ranks["jaccard"]) if formula_ranks["jaccard"] else None
        ),
        dstar2_best_rank=(
            min(formula_ranks["dstar2"]) if formula_ranks["dstar2"] else None
        ),
    )


def find_line_rank(
    ranked_lines: List[Dict], target_file: str, target_line: int, formula: str
) -> Optional[int]:
    """Trova il rank di una specifica linea nella classifica"""
    for i, line_data in enumerate(ranked_lines):
        if line_data["file"] == target_file and line_data["line"] == target_line:
            return i + 1  # Rank basato su 1
    return None


def generate_summary_report(metrics_list: List[EffectivenessMetrics]) -> Dict[str, Any]:
    """Generate a summary report of effectiveness"""
    total_bugs = len(metrics_list)

    if total_bugs == 0:
        return {"error": "No bugs analyzed"}

    # Filtra i bug che hanno patch (quindi linee buggy note)
    bugs_with_patches = [m for m in metrics_list if m.buggy_lines_found > 0]
    analyzable_bugs = len(bugs_with_patches)

    summary: Dict[str, Any] = {
        "total_bugs": total_bugs,
        "analyzable_bugs": analyzable_bugs,
        "bugs_by_project": {},
        "overall_effectiveness": {},
        "formula_effectiveness": {},
    }

    # Raggruppa per progetto
    for metric in metrics_list:
        if metric.project not in summary["bugs_by_project"]:
            summary["bugs_by_project"][metric.project] = {
                "total": 0,
                "analyzable": 0,
                "top_1_hits": 0,
                "top_3_hits": 0,
                "top_5_hits": 0,
                "top_10_hits": 0,
            }

        summary["bugs_by_project"][metric.project]["total"] += 1

        if metric.buggy_lines_found > 0:
            summary["bugs_by_project"][metric.project]["analyzable"] += 1
            if metric.top_1_hit:
                summary["bugs_by_project"][metric.project]["top_1_hits"] += 1
            if metric.top_3_hit:
                summary["bugs_by_project"][metric.project]["top_3_hits"] += 1
            if metric.top_5_hit:
                summary["bugs_by_project"][metric.project]["top_5_hits"] += 1
            if metric.top_10_hit:
                summary["bugs_by_project"][metric.project]["top_10_hits"] += 1

    # Overall effectiveness (based on Ochiai as reference formula)
    if analyzable_bugs > 0:
        summary["overall_effectiveness"] = {
            "top_1_rate": sum(1 for m in bugs_with_patches if m.top_1_hit)
            / analyzable_bugs,
            "top_3_rate": sum(1 for m in bugs_with_patches if m.top_3_hit)
            / analyzable_bugs,
            "top_5_rate": sum(1 for m in bugs_with_patches if m.top_5_hit)
            / analyzable_bugs,
            "top_10_rate": sum(1 for m in bugs_with_patches if m.top_10_hit)
            / analyzable_bugs,
            "avg_best_rank": sum(m.best_rank for m in bugs_with_patches if m.best_rank)
            / len([m for m in bugs_with_patches if m.best_rank]),
        }

    # Effectiveness analysis per individual formula
    formulas = {
        "ochiai": "ochiai_best_rank",
        "tarantula": "tarantula_best_rank",
        "jaccard": "jaccard_best_rank",
        "dstar2": "dstar2_best_rank",
    }

    for formula_name, rank_attr in formulas.items():
        # Filtra i bug che hanno rank per questa formula
        formula_bugs = [
            m for m in bugs_with_patches if getattr(m, rank_attr) is not None
        ]
        formula_count = len(formula_bugs)

        if formula_count > 0:
            # Calculate top-N metrics for this formula
            formula_ranks = [getattr(m, rank_attr) for m in formula_bugs]

            top_1_hits = sum(1 for rank in formula_ranks if rank <= 1)
            top_3_hits = sum(1 for rank in formula_ranks if rank <= 3)
            top_5_hits = sum(1 for rank in formula_ranks if rank <= 5)
            top_10_hits = sum(1 for rank in formula_ranks if rank <= 10)

            avg_rank = sum(formula_ranks) / len(formula_ranks)
            best_rank = min(formula_ranks)
            worst_rank = max(formula_ranks)

            # Calculate percentiles for better understanding of distribution
            sorted_ranks = sorted(formula_ranks)
            median_rank = sorted_ranks[len(sorted_ranks) // 2]
            p25_rank = sorted_ranks[len(sorted_ranks) // 4]
            p75_rank = sorted_ranks[3 * len(sorted_ranks) // 4]

            summary["formula_effectiveness"][formula_name] = {
                "bugs_analyzed": formula_count,
                "top_1_rate": top_1_hits / formula_count,
                "top_3_rate": top_3_hits / formula_count,
                "top_5_rate": top_5_hits / formula_count,
                "top_10_rate": top_10_hits / formula_count,
                "top_1_hits": top_1_hits,
                "top_3_hits": top_3_hits,
                "top_5_hits": top_5_hits,
                "top_10_hits": top_10_hits,
                "avg_rank": avg_rank,
                "median_rank": median_rank,
                "best_rank": best_rank,
                "worst_rank": worst_rank,
                "p25_rank": p25_rank,
                "p75_rank": p75_rank,
                "rank_distribution": {
                    "1-5": sum(1 for rank in formula_ranks if 1 <= rank <= 5),
                    "6-10": sum(1 for rank in formula_ranks if 6 <= rank <= 10),
                    "11-20": sum(1 for rank in formula_ranks if 11 <= rank <= 20),
                    "21-50": sum(1 for rank in formula_ranks if 21 <= rank <= 50),
                    "51+": sum(1 for rank in formula_ranks if rank > 50),
                },
            }
        else:
            summary["formula_effectiveness"][formula_name] = {
                "bugs_analyzed": 0,
                "message": "No bugs analyzed for this formula",
            }

    return summary


def save_results(
    metrics_list: List[EffectivenessMetrics], summary: Dict[str, Any]
) -> None:
    """Save results to CSV and JSON files"""

    # Save detailed metrics to CSV
    csv_path = "FLOSS_effectiveness_summary.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Project",
                "Bug_ID",
                "Total_Lines_Analyzed",
                "Buggy_Lines_Found",
                "Top_1_Hit",
                "Top_3_Hit",
                "Top_5_Hit",
                "Top_10_Hit",
                "Best_Rank",
                "Avg_Rank",
                "Ochiai_Best_Rank",
                "Tarantula_Best_Rank",
                "Jaccard_Best_Rank",
                "Dstar2_Best_Rank",
            ]
        )

        for metric in metrics_list:
            writer.writerow(
                [
                    metric.project,
                    metric.bug_id,
                    metric.total_lines_analyzed,
                    metric.buggy_lines_found,
                    metric.top_1_hit,
                    metric.top_3_hit,
                    metric.top_5_hit,
                    metric.top_10_hit,
                    metric.best_rank,
                    metric.avg_rank,
                    metric.ochiai_best_rank,
                    metric.tarantula_best_rank,
                    metric.jaccard_best_rank,
                    metric.dstar2_best_rank,
                ]
            )

    # Salva summary in JSON
    json_path = "FLOSS_effectiveness_analysis.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("Risultati salvati in:")
    print(f"  - {csv_path}")
    print(f"  - {json_path}")


def main() -> None:
    """Main function"""
    print("FLOSS Effectiveness Analysis")
    print("=" * 50)

    # Find all bugs
    print("1. Searching for bugs in examples...")
    bugs = find_all_bugs()
    print(f"   Found {len(bugs)} total bugs")

    # Analyze each bug
    print("\n2. Analyzing effectiveness for each bug...")
    metrics_list = []

    for bug in bugs:
        print(f"   Analyzing {bug.project}/{bug.bug_id}...")
        metrics = analyze_report_effectiveness(bug)
        if metrics:
            metrics_list.append(metrics)

    print(f"   Successfully analyzed {len(metrics_list)} bugs")

    # Generate summary report
    print("\n3. Generating summary report...")
    summary = generate_summary_report(metrics_list)

    # Save results
    print("\n4. Saving results...")
    save_results(metrics_list, summary)

    # Print summary
    print("\n" + "=" * 50)
    print("RESULTS SUMMARY")
    print("=" * 50)

    if "overall_effectiveness" in summary:
        eff = summary["overall_effectiveness"]
        print(f"Analyzable bugs: {summary['analyzable_bugs']}/{summary['total_bugs']}")
        print(f"Top-1 hit rate: {eff['top_1_rate']:.2%}")
        print(f"Top-3 hit rate: {eff['top_3_rate']:.2%}")
        print(f"Top-5 hit rate: {eff['top_5_rate']:.2%}")
        print(f"Top-10 hit rate: {eff['top_10_rate']:.2%}")
        if "avg_best_rank" in eff:
            print(f"Average best rank: {eff['avg_best_rank']:.1f}")

    print("\nBy project:")
    for project, data in summary["bugs_by_project"].items():
        if data["analyzable"] > 0:
            print(
                f"  {project}: {data['top_10_hits']}/{data['analyzable']}"
                f" bugs in top-10 ({data['top_10_hits']/data['analyzable']:.1%})"
            )

    # Print detailed formula comparison
    print("\n" + "=" * 70)
    print("SBFL INDIVIDUAL FORMULA EFFECTIVENESS COMPARISON")
    print("=" * 70)

    if "formula_effectiveness" in summary:
        # Header della tabella
        print(
            f"{'Formula':<12} {'Bug':<4} {'Top-1':<6} {'Top-3':<6} {'Top-5':<6} "
            f"{'Top-10':<6} {'Avg':<6} {'Med':<5} {'Best':<5} {'P25':<4} {'P75':<4}"
        )
        print("-" * 70)

        for formula, data in summary["formula_effectiveness"].items():
            if data["bugs_analyzed"] > 0:
                print(
                    f"{formula.capitalize():<12} "
                    f"{data['bugs_analyzed']:<4} "
                    f"{data['top_1_rate']:.1%}  "
                    f"{data['top_3_rate']:.1%}  "
                    f"{data['top_5_rate']:.1%}  "
                    f"{data['top_10_rate']:.1%}  "
                    f"{data['avg_rank']:<6.1f} "
                    f"{data['median_rank']:<5} "
                    f"{data['best_rank']:<5} "
                    f"{data['p25_rank']:<4} "
                    f"{data['p75_rank']:<4}"
                )

        print("\nDistribuzione dei rank per formula:")
        print("-" * 70)
        for formula, data in summary["formula_effectiveness"].items():
            if data["bugs_analyzed"] > 0:
                dist = data["rank_distribution"]
                print(
                    f"{formula.capitalize():<12}: "
                    f"1-5: {dist['1-5']:<2}, "
                    f"6-10: {dist['6-10']:<2}, "
                    f"11-20: {dist['11-20']:<2}, "
                    f"21-50: {dist['21-50']:<2}, "
                    f"51+: {dist['51+']:<2}"
                )

        # Find best formula for each metric
        print("\nBest formula by metric:")
        print("-" * 30)
        best_top1 = max(
            summary["formula_effectiveness"].items(),
            key=lambda x: x[1].get("top_1_rate", 0) if x[1]["bugs_analyzed"] > 0 else 0,
        )
        best_top10 = max(
            summary["formula_effectiveness"].items(),
            key=lambda x: (
                x[1].get("top_10_rate", 0) if x[1]["bugs_analyzed"] > 0 else 0
            ),
        )
        best_avg = min(
            summary["formula_effectiveness"].items(),
            key=lambda x: (
                x[1].get("avg_rank", float("inf"))
                if x[1]["bugs_analyzed"] > 0
                else float("inf")
            ),
        )

        print(
            f"Top-1 rate: {best_top1[0].capitalize()} "
            f"({best_top1[1]['top_1_rate']:.1%})"
        )
        print(
            f"Top-10 rate: {best_top10[0].capitalize()} "
            f"({best_top10[1]['top_10_rate']:.1%})"
        )
        print(
            f"Average rank: {best_avg[0].capitalize()} ({best_avg[1]['avg_rank']:.1f})"
        )


if __name__ == "__main__":
    main()
