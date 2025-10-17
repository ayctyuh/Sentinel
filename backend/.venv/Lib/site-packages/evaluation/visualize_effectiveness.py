#!/usr/bin/env python3
"""
Script to visualize FLOSS effectiveness analysis results.
Generates charts and tables to present results clearly.
"""

import json
from pathlib import Path
from typing import Any, Dict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


def load_results() -> tuple[pd.DataFrame, Dict[str, Any]]:
    """Load analysis results"""
    csv_path = "FLOSS_effectiveness_summary.csv"
    json_path = "FLOSS_effectiveness_analysis.json"

    # Load detailed data
    df = pd.read_csv(csv_path)

    # Load summary
    with open(json_path, "r", encoding="utf-8") as f:
        summary = json.load(f)

    return df, summary


def create_effectiveness_charts(df: pd.DataFrame, summary: Dict[str, Any]) -> None:
    """Create charts to show effectiveness"""

    # Configure style
    plt.style.use("default")
    sns.set_palette("husl")

    # Figure with multiple subplots
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle(
        "FLOSS: Fault Localization Effectiveness Analysis",
        fontsize=16,
        fontweight="bold",
    )

    # 1. Top-N Hit Rates (Overall)
    ax1 = axes[0, 0]
    eff = summary["overall_effectiveness"]
    top_n_rates = [
        eff["top_1_rate"],
        eff["top_3_rate"],
        eff["top_5_rate"],
        eff["top_10_rate"],
    ]
    top_n_labels = ["Top-1", "Top-3", "Top-5", "Top-10"]

    bars1 = ax1.bar(
        top_n_labels,
        [rate * 100 for rate in top_n_rates],
        color=["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4"],
    )
    ax1.set_ylabel("Success Rate (%)")
    ax1.set_title("Overall Effectiveness: Top-N Hit Rates")
    ax1.set_ylim(0, 100)

    # Add percentages above bars
    for bar, rate in zip(bars1, top_n_rates):
        height = bar.get_height()
        ax1.text(
            bar.get_x() + bar.get_width() / 2.0,
            height + 1,
            f"{rate:.1%}",
            ha="center",
            va="bottom",
            fontweight="bold",
        )

    # 2. Effectiveness by Project
    ax2 = axes[0, 1]
    projects_data = []
    for project, data in summary["bugs_by_project"].items():
        if data["analyzable"] > 0:
            projects_data.append(
                {
                    "Project": project.capitalize(),
                    "Top-1": data["top_1_hits"] / data["analyzable"] * 100,
                    "Top-3": data["top_3_hits"] / data["analyzable"] * 100,
                    "Top-5": data["top_5_hits"] / data["analyzable"] * 100,
                    "Top-10": data["top_10_hits"] / data["analyzable"] * 100,
                    "Analyzable": data["analyzable"],
                }
            )

    projects_df = pd.DataFrame(projects_data)
    x = np.arange(len(projects_df))
    width = 0.2

    ax2.bar(
        x - 1.5 * width, projects_df["Top-1"], width, label="Top-1", color="#FF6B6B"
    )
    ax2.bar(
        x - 0.5 * width, projects_df["Top-3"], width, label="Top-3", color="#4ECDC4"
    )
    ax2.bar(
        x + 0.5 * width, projects_df["Top-5"], width, label="Top-5", color="#45B7D1"
    )
    ax2.bar(
        x + 1.5 * width, projects_df["Top-10"], width, label="Top-10", color="#96CEB4"
    )

    ax2.set_xlabel("Project")
    ax2.set_ylabel("Success Rate (%)")
    ax2.set_title("Effectiveness by Project")
    ax2.set_xticks(x)
    ax2.set_xticklabels(
        [
            f"{row['Project']}\\n({row['Analyzable']} bugs)"
            for _, row in projects_df.iterrows()
        ]
    )
    ax2.legend()
    ax2.set_ylim(0, 110)

    # 3. Rank Distribution
    ax3 = axes[1, 0]
    # Filter only bugs with valid ranks
    df_with_ranks = df[df["Best_Rank"].notna()]

    if len(df_with_ranks) > 0:
        ranks = np.array(df_with_ranks["Best_Rank"].values)
        ax3.hist(ranks, bins=20, alpha=0.7, color="#45B7D1", edgecolor="black")
        ax3.axvline(
            np.median(ranks),
            color="red",
            linestyle="--",
            label=f"Mediana: {np.median(ranks):.0f}",
        )
        ax3.axvline(
            np.mean(ranks),
            color="orange",
            linestyle="--",
            label=f"Media: {np.mean(ranks):.0f}",
        )
        ax3.set_xlabel("Bug Rank (best)")
        ax3.set_ylabel("Frequency")
        ax3.set_title("Distribution of Identified Bug Ranks")
        ax3.legend()
        ax3.grid(True, alpha=0.3)

    # 4. SBFL Formula Comparison
    ax4 = axes[1, 1]
    formulas = ["Ochiai", "Tarantula", "Jaccard", "Dstar2"]
    formula_cols = [
        "Ochiai_Best_Rank",
        "Tarantula_Best_Rank",
        "Jaccard_Best_Rank",
        "Dstar2_Best_Rank",
    ]

    formula_data = []
    for i, formula in enumerate(formulas):
        col = formula_cols[i]
        valid_ranks = df[df[col].notna()][col].values
        if len(valid_ranks) > 0:
            formula_data.append(valid_ranks)
        else:
            formula_data.append(np.array([]))

    # Box plot per confrontare le formule
    bp = ax4.boxplot(formula_data, labels=formulas, patch_artist=True)
    colors = ["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4"]
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    ax4.set_ylabel("Rank del Bug")
    ax4.set_title("Confronto delle Formule SBFL")
    ax4.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig("FLOSS_effectiveness_analysis.png", dpi=300, bbox_inches="tight")
    plt.savefig("FLOSS_effectiveness_analysis.pdf", bbox_inches="tight")
    print("Grafici salvati come 'FLOSS_effectiveness_analysis.png' e '.pdf'")
    plt.show()


def create_detailed_table(df: pd.DataFrame) -> None:
    """Create a detailed results table"""

    # Filter and organize data
    display_df = df[
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
        ]
    ].copy()

    # Rename columns for display
    display_df.columns = [
        "Project",
        "Bug ID",
        "Lines Analyzed",
        "Buggy Lines Found",
        "Top-1",
        "Top-3",
        "Top-5",
        "Top-10",
        "Best Rank",
    ]

    # Convert booleans to symbols
    for col in ["Top-1", "Top-3", "Top-5", "Top-10"]:
        display_df[col] = display_df[col].map({True: "✓", False: "✗"})

    # Handle NaN in ranks
    display_df["Best Rank"] = display_df["Best Rank"].fillna("N/A")

    print("\\n" + "=" * 100)
    print("DETAILED RESULTS TABLE")
    print("=" * 100)
    print(display_df.to_string(index=False))


def generate_summary_statistics(df: pd.DataFrame, summary: Dict[str, Any]) -> None:
    """Genera statistiche riassuntive"""

    print("\\n" + "=" * 80)
    print("STATISTICHE RIASSUNTIVE")
    print("=" * 80)

    # Statistiche generali
    total_bugs = summary["total_bugs"]
    analyzable_bugs = summary["analyzable_bugs"]

    print(f"📊 Bug totali: {total_bugs}")
    print(f"📊 Bug analizzabili (con patch): {analyzable_bugs}")
    print(f"📊 Bug non analizzabili: {total_bugs - analyzable_bugs}")

    if analyzable_bugs > 0:
        eff = summary["overall_effectiveness"]
        print("\\n🎯 OVERALL EFFECTIVENESS:")
        print(
            "   • Top-1 hit rate: "
            f"{eff['top_1_rate']:.1%} ({int(eff['top_1_rate'] * analyzable_bugs)}/"
            f"{analyzable_bugs})"
        )
        print(
            f"   • Top-3 hit rate: {eff['top_3_rate']:.1%} "
            f"({int(eff['top_3_rate'] * analyzable_bugs)}/{analyzable_bugs})"
        )
        print(
            f"   • Top-5 hit rate: {eff['top_5_rate']:.1%} "
            f"({int(eff['top_5_rate'] * analyzable_bugs)}/{analyzable_bugs})"
        )
        print(
            f"   • Top-10 hit rate: {eff['top_10_rate']:.1%} "
            f"({int(eff['top_10_rate'] * analyzable_bugs)}/{analyzable_bugs})"
        )

        # Rank statistics
        df_with_ranks = df[df["Best_Rank"].notna()]
        if len(df_with_ranks) > 0:
            ranks = np.array(df_with_ranks["Best_Rank"].values)
            print("\\n📈 RANK STATISTICS:")
            print(f"   • Average rank: {np.mean(ranks):.1f}")
            print(f"   • Median rank: {np.median(ranks):.0f}")
            print(f"   • Best rank: {np.min(ranks):.0f}")
            print(f"   • Worst rank: {np.max(ranks):.0f}")

    # Project statistics
    print("\\n🏗️ EFFECTIVENESS BY PROJECT:")
    for project, data in summary["bugs_by_project"].items():
        if data["analyzable"] > 0:
            print(f"   • {project.capitalize()}:")
            print(f"     - Analyzable bugs: {data['analyzable']}/{data['total']}")
            print(
                f"     - Top-10 success: {data['top_10_hits']}/{data['analyzable']} "
                f"({data['top_10_hits']/data['analyzable']:.1%})"
            )

    # SBFL formula comparison
    print("\\n🧮 SBFL FORMULA COMPARISON:")
    formulas = ["Ochiai", "Tarantula", "Jaccard", "Dstar2"]
    formula_cols = [
        "Ochiai_Best_Rank",
        "Tarantula_Best_Rank",
        "Jaccard_Best_Rank",
        "Dstar2_Best_Rank",
    ]

    for formula, col in zip(formulas, formula_cols):
        valid_ranks = np.array(df[df[col].notna()][col].values)
        if len(valid_ranks) > 0:
            avg_rank = np.mean(valid_ranks)
            print(f"   • {formula}: average rank {avg_rank:.1f}")


def main() -> None:
    """Main function"""
    print("FLOSS Results Visualization")
    print("=" * 50)

    # Check that files exist
    if not Path("FLOSS_effectiveness_summary.csv").exists():
        print("❌ CSV file not found. Run 'analyze_effectiveness.py' first")
        return

    if not Path("FLOSS_effectiveness_analysis.json").exists():
        print("❌ JSON file not found. Run 'analyze_effectiveness.py' first")
        return

    # Load data
    df, summary = load_results()

    # Generate visualizations
    print("\\n📈 Generating charts...")
    create_effectiveness_charts(df, summary)

    # Show detailed table
    create_detailed_table(df)

    # Genera statistiche riassuntive
    generate_summary_statistics(df, summary)

    print("\\n✅ Analisi completata!")


if __name__ == "__main__":
    main()
