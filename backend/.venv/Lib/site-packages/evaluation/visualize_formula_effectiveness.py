#!/usr/bin/env python3
"""
Script to visualize SBFL formula effectiveness with detailed charts.
"""

import json
from pathlib import Path
from typing import cast

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.container import BarContainer

# Configura lo stile dei grafici
plt.style.use("seaborn-v0_8")
sns.set_palette("husl")


def load_data() -> tuple[dict, dict, pd.DataFrame]:
    """Load data from analysis"""
    # Load effectiveness data
    with open("FLOSS_effectiveness_analysis.json", "r", encoding="utf-8") as f:
        effectiveness_data = json.load(f)

    # Load discrimination data
    with open("formula_discrimination_analysis.json", "r", encoding="utf-8") as f:
        discrimination_data = json.load(f)

    # Load detailed data from CSV
    csv_data = pd.read_csv("FLOSS_effectiveness_summary.csv")

    return effectiveness_data, discrimination_data, csv_data


def create_top_n_comparison() -> None:
    """Create a Top-N comparison chart"""
    effectiveness_data, _, _ = load_data()

    # Estrai i dati delle formule
    formula_data = effectiveness_data["formula_effectiveness"]

    formulas = list(formula_data.keys())
    top_metrics = ["top_1_rate", "top_3_rate", "top_5_rate", "top_10_rate"]

    # Crea DataFrame per il plotting
    data = []
    for formula in formulas:
        for metric in top_metrics:
            if formula_data[formula]["bugs_analyzed"] > 0:
                data.append(
                    {
                        "Formula": formula.capitalize(),
                        "Metric": metric.replace("_rate", "").replace("top_", "Top-"),
                        "Success_Rate": formula_data[formula][metric] * 100,
                    }
                )

    df = pd.DataFrame(data)

    # Crea il grafico
    fig, ax = plt.subplots(figsize=(12, 8))

    # Grafico a barre raggruppate
    bar_plot = sns.barplot(data=df, x="Metric", y="Success_Rate", hue="Formula", ax=ax)

    # Personalizza il grafico
    ax.set_title(
        "SBFL Formula Effectiveness Comparison - Top-N Performance",
        fontsize=16,
        fontweight="bold",
    )
    ax.set_xlabel("Metrica Top-N", fontsize=14)
    ax.set_ylabel("Tasso di Successo (%)", fontsize=14)
    ax.legend(title="Formula SBFL", fontsize=12)

    # Aggiungi valori sulle barre
    for container in bar_plot.containers:
        ax.bar_label(cast(BarContainer, container), fmt="%.1f%%", fontsize=10)

    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    plt.tight_layout()
    plt.savefig("formula_topn_comparison.png", dpi=300, bbox_inches="tight")
    plt.show()


def create_discrimination_comparison() -> None:
    """Create a discriminatory capability comparison chart"""
    _, discrimination_data, _ = load_data()

    # Estrai i dati
    formulas = list(discrimination_data["discrimination_analysis"].keys())

    # Prepara i dati
    data = []
    for formula in formulas:
        formula_data = discrimination_data["discrimination_analysis"][formula]
        if formula_data["bugs_analyzed"] > 0:
            data.append(
                {
                    "Formula": formula.capitalize(),
                    "AUC-ROC": formula_data["auc_roc"]["mean"],
                    "Separazione_Punteggi": formula_data["score_separation"]["mean"],
                    "Overlap_Ratio": formula_data["overlap_ratio"]["mean"],
                }
            )

    df = pd.DataFrame(data)

    # Crea subplots
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))

    # AUC-ROC
    sns.barplot(data=df, x="Formula", y="AUC-ROC", ax=axes[0])
    axes[0].set_title("AUC-ROC\n(Più alto = migliore)", fontweight="bold")
    axes[0].set_ylim(0.5, 0.7)
    for i, v in enumerate(df["AUC-ROC"]):
        axes[0].text(i, v + 0.005, f"{v:.3f}", ha="center", fontweight="bold")

    # Separazione Punteggi
    sns.barplot(data=df, x="Formula", y="Separazione_Punteggi", ax=axes[1])
    axes[1].set_title("Separazione Punteggi\n(Più alto = migliore)", fontweight="bold")
    for i, v in enumerate(df["Separazione_Punteggi"]):
        axes[1].text(i, v + 0.01, f"{v:.3f}", ha="center", fontweight="bold")

    # Overlap Ratio
    sns.barplot(data=df, x="Formula", y="Overlap_Ratio", ax=axes[2])
    axes[2].set_title("Overlap Ratio\n(Più basso = migliore)", fontweight="bold")
    for i, v in enumerate(df["Overlap_Ratio"]):
        axes[2].text(i, v + 0.01, f"{v:.3f}", ha="center", fontweight="bold")

    # Personalizza
    for ax in axes:
        ax.tick_params(axis="x", rotation=45)
        ax.set_xlabel("Formula SBFL")

    plt.suptitle(
        "Capacità Discriminante delle Formule SBFL", fontsize=16, fontweight="bold"
    )
    plt.tight_layout()
    plt.savefig("formula_discrimination_comparison.png", dpi=300, bbox_inches="tight")
    plt.show()


def create_rank_distribution() -> None:
    """Crea un grafico della distribuzione dei rank"""
    effectiveness_data, _, _ = load_data()

    formula_data = effectiveness_data["formula_effectiveness"]

    # Prepara i dati per la distribuzione
    distribution_data = []
    for formula, data in formula_data.items():
        if data["bugs_analyzed"] > 0:
            rank_dist = data["rank_distribution"]
            for range_key, count in rank_dist.items():
                distribution_data.append(
                    {
                        "Formula": formula.capitalize(),
                        "Range": range_key,
                        "Count": count,
                    }
                )

    df = pd.DataFrame(distribution_data)

    # Ordina i range
    range_order = ["1-5", "6-10", "11-20", "21-50", "51+"]
    df["Range"] = pd.Categorical(df["Range"], categories=range_order, ordered=True)

    # Crea il grafico stacked
    fig, ax = plt.subplots(figsize=(12, 8))

    # Pivot per stacked bar
    pivot_df = df.pivot(index="Formula", columns="Range", values="Count")
    pivot_df = pivot_df.reindex(range_order, axis=1)

    # Grafico stacked
    pivot_df.plot(
        kind="bar",
        stacked=True,
        ax=ax,
        color=["#2E8B57", "#4682B4", "#DAA520", "#CD853F", "#DC143C"],
    )

    ax.set_title(
        "Distribuzione dei Rank per Formula SBFL", fontsize=16, fontweight="bold"
    )
    ax.set_xlabel("Formula SBFL", fontsize=14)
    ax.set_ylabel("Numero di Bug", fontsize=14)
    ax.legend(title="Range di Rank", bbox_to_anchor=(1.05, 1), loc="upper left")

    # Ruota le etichette
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("formula_rank_distribution.png", dpi=300, bbox_inches="tight")
    plt.show()


def create_project_performance() -> None:
    """Crea un grafico delle performance per progetto"""
    effectiveness_data, _, _ = load_data()

    projects_data = effectiveness_data["bugs_by_project"]

    # Prepara i dati
    data = []
    for project, stats in projects_data.items():
        if stats["analyzable"] > 0:
            success_rate = stats["top_10_hits"] / stats["analyzable"] * 100
            data.append(
                {
                    "Progetto": project.capitalize(),
                    "Success_Rate": success_rate,
                    "Analyzable_Bugs": stats["analyzable"],
                    "Total_Bugs": stats["total"],
                }
            )

    df = pd.DataFrame(data)

    # Crea il grafico
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # Success rate
    bars1 = ax1.bar(
        df["Progetto"],
        df["Success_Rate"],
        color=["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4"],
    )
    ax1.set_title("Tasso di Successo Top-10 per Progetto", fontweight="bold")
    ax1.set_ylabel("Tasso di Successo (%)")
    ax1.set_ylim(0, 110)

    # Aggiungi valori sulle barre
    for bar, rate in zip(bars1, df["Success_Rate"]):
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 2,
            f"{rate:.1f}%",
            ha="center",
            fontweight="bold",
        )

    # Numero di bug
    bars2 = ax2.bar(
        df["Progetto"],
        df["Analyzable_Bugs"],
        color=["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4"],
        alpha=0.7,
        label="Analizzabili",
    )

    ax2.set_title("Distribuzione Bug per Progetto", fontweight="bold")
    ax2.set_ylabel("Numero di Bug")
    ax2.legend()

    # Aggiungi valori
    for i, (bar, total) in enumerate(zip(bars2, df["Total_Bugs"])):
        ax2.text(
            bar.get_x() + bar.get_width() / 2,
            total + 0.2,
            f"{total}",
            ha="center",
            fontweight="bold",
        )

    plt.tight_layout()
    plt.savefig("project_performance.png", dpi=300, bbox_inches="tight")
    plt.show()


def create_summary_radar() -> None:
    """Crea un grafico radar di riepilogo"""
    effectiveness_data, discrimination_data, _ = load_data()

    # Normalizza le metriche per il radar (0-1)
    formulas = ["ochiai", "tarantula", "jaccard", "dstar2"]
    metrics = []

    for formula in formulas:
        eff_data = effectiveness_data["formula_effectiveness"][formula]
        disc_data = discrimination_data["discrimination_analysis"][formula]

        # Normalizza le metriche (inverti overlap perché più basso è meglio)
        top10_norm = eff_data["top_10_rate"]
        auc_norm = (disc_data["auc_roc"]["mean"] - 0.5) / 0.5  # da 0.5-1 a 0-1
        sep_norm = min(disc_data["score_separation"]["mean"] / 0.5, 1)  # cap a 1
        overlap_norm = 1 - disc_data["overlap_ratio"]["mean"]  # inverti
        avg_rank_norm = max(
            0, 1 - (eff_data["avg_rank"] - 100) / 300
        )  # normalizza rank

        metrics.append([top10_norm, auc_norm, sep_norm, overlap_norm, avg_rank_norm])

    # Setup radar chart
    categories = [
        "Top-10\nRate",
        "AUC-ROC",
        "Separazione\nPunteggi",
        "Basso\nOverlap",
        "Buon\nRank",
    ]

    # Calcola angoli
    angles = np.linspace(0, 2 * np.pi, len(categories), endpoint=False).tolist()
    angles += angles[:1]  # Completa il cerchio

    # Crea il grafico
    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection="polar"))

    colors = ["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4"]

    for i, (formula, metric_values) in enumerate(zip(formulas, metrics)):
        values = metric_values + metric_values[:1]  # Completa il cerchio
        ax.plot(
            angles,
            values,
            "o-",
            linewidth=2,
            label=formula.capitalize(),
            color=colors[i],
        )
        ax.fill(angles, values, alpha=0.25, color=colors[i])

    # Personalizza
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories)
    ax.set_ylim(0, 1)
    ax.set_title(
        "Multi-dimensional SBFL Formula Comparison",
        fontsize=16,
        fontweight="bold",
        y=1.08,
    )
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1))
    ax.grid(True)

    plt.tight_layout()
    plt.savefig("formula_radar_comparison.png", dpi=300, bbox_inches="tight")
    plt.show()


def main() -> None:
    """Main function to generate all charts"""
    print("Generating effectiveness analysis charts...")

    # Create folder for charts if it doesn't exist
    Path("visualizations").mkdir(exist_ok=True)

    # Generate all charts
    print("1. Top-N Performance Comparison...")
    create_top_n_comparison()

    print("2. Discriminatory Capability Comparison...")
    create_discrimination_comparison()

    print("3. Rank Distribution...")
    create_rank_distribution()

    print("4. Performance by Project...")
    create_project_performance()

    print("5. Multi-dimensional Radar Chart...")
    create_summary_radar()

    print("All charts have been generated and saved!")


if __name__ == "__main__":
    main()
