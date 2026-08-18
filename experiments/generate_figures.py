#!/usr/bin/env python3
"""
AutoPatch Phase 2 — Experimental Simulation: Figure Generation

Generates publication-grade figures for the AutoPatch vulnerability reduction study.
All figures use serif fonts (Times New Roman) and are exported as both PDF and PNG (300 DPI).

Figures:
  - Fig 2: Grouped bar chart (6 legacy images × 3 strategies)
  - Fig 3: CDF curves (vulnerability reduction %)
  - Fig 4: Heatmap (OS family × language runtime)
  - Fig 5: Ablation study bar chart (4 AutoPatch variants)
  - Fig 6: Pipeline overhead breakdown (stacked bar)

Data: experimental_data.json (simulated for demonstration)
"""

import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# Global figure styling
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman', 'DejaVu Serif']
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['xtick.labelsize'] = 9
plt.rcParams['ytick.labelsize'] = 9
plt.rcParams['legend.fontsize'] = 9
plt.rcParams['figure.dpi'] = 300

# Output directory
OUTPUT_DIR = Path(__file__).parent / 'figures'
OUTPUT_DIR.mkdir(exist_ok=True)

# Color palette for strategies
COLORS = {
    'Scan-Only': '#808080',        # Gray
    'Naïve :latest': '#FFA500',    # Orange
    'AutoPatch': '#2E7D32'         # Green
}


def load_data(json_file=None):
    """Load experimental data from JSON file or use embedded data."""
    if json_file is None:
        json_file = Path(__file__).parent / 'experimental_data.json'

    if json_file.exists():
        with open(json_file, 'r') as f:
            return json.load(f)
    else:
        print(f"Warning: {json_file} not found. Ensure JSON file exists.")
        return None


def save_figure(fig, name, tight=True):
    """Save figure as both PDF and PNG (300 DPI)."""
    if tight:
        fig.tight_layout()

    pdf_path = OUTPUT_DIR / f'{name}.pdf'
    png_path = OUTPUT_DIR / f'{name}.png'

    fig.savefig(pdf_path, format='pdf', dpi=300, bbox_inches='tight')
    fig.savefig(png_path, format='png', dpi=300, bbox_inches='tight')

    print(f"✓ Saved {name}: {pdf_path} and {png_path}")


def generate_figure_2(data):
    """
    Figure 2: Grouped bar chart — CVE counts before/after for 6 legacy images.

    Shows 3 strategies (Scan-Only, Naïve :latest, AutoPatch) overlaid.
    Uses the paper's actual reported numbers.
    """
    fig, ax = plt.subplots(figsize=(12, 6))

    legacy_images = data['legacy_images']
    image_names = [img['name'] for img in legacy_images]

    # Extract data
    scan_only = [img['scan_only_critical'] for img in legacy_images]
    naïve_latest = [img['naïve_latest_critical'] for img in legacy_images]
    autopatch = [img['autopatch_critical'] for img in legacy_images]

    x = np.arange(len(image_names))
    width = 0.25

    bars1 = ax.bar(x - width, scan_only, width, label='Scan-Only',
                   color=COLORS['Scan-Only'], edgecolor='black', linewidth=0.5)
    bars2 = ax.bar(x, naïve_latest, width, label='Naïve :latest',
                   color=COLORS['Naïve :latest'], edgecolor='black', linewidth=0.5)
    bars3 = ax.bar(x + width, autopatch, width, label='AutoPatch',
                   color=COLORS['AutoPatch'], edgecolor='black', linewidth=0.5)

    # Labels and formatting
    ax.set_ylabel('Critical Vulnerabilities', fontsize=11)
    ax.set_xlabel('Container Image', fontsize=11)
    ax.set_title('Figure 2: Critical Vulnerability Counts Across 6 Legacy Container Images',
                 fontsize=12, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(image_names, rotation=45, ha='right')
    ax.legend(loc='upper right', frameon=True, shadow=False)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)

    # Add value labels on bars for AutoPatch (cleaner visualization)
    for bar in bars3:
        height = bar.get_height()
        if height > 0:
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontsize=8)

    save_figure(fig, 'fig2_legacy_images_bar_chart')
    plt.close()


def generate_figure_3(data):
    """
    Figure 3: CDF curves — Vulnerability reduction % for all strategies.

    AutoPatch shows the paper's CDF shape (starting ~50%, rising to 100% around 88-100% reduction).
    Naïve :latest is worse, Scan-Only is at 0%.
    """
    fig, ax = plt.subplots(figsize=(11, 7))

    # Calculate reduction percentages for each image in full dataset
    reductions = [img['reduction_percentage'] for img in data['full_dataset']]

    # Generate CDF for AutoPatch (real per-image data)
    sorted_reductions = np.sort(reductions)
    cdf_autopatch = np.arange(1, len(sorted_reductions) + 1) / len(sorted_reductions)

    # Plot AutoPatch CDF from measured reductions.
    ax.plot(sorted_reductions, cdf_autopatch, linewidth=2.5,
           label='AutoPatch', color=COLORS['AutoPatch'], marker='o', markersize=4, alpha=0.8)

    # C6 fix: the previous version synthesized the Naive :latest curve by
    # multiplying AutoPatch's own measured reductions by 0.72. That is a
    # fabricated baseline and must never appear as if it were measured data.
    # Plot the Naive curve only when the dataset carries a real per-image
    # field ('naive_reduction_percentage'); otherwise omit it entirely.
    naive_vals = [
        img['naive_reduction_percentage']
        for img in data['full_dataset']
        if 'naive_reduction_percentage' in img
    ]
    if len(naive_vals) == len(reductions) and len(naive_vals) > 0:
        sorted_naive = np.sort(naive_vals)
        cdf_naive = np.arange(1, len(sorted_naive) + 1) / len(sorted_naive)
        ax.plot(sorted_naive, cdf_naive, linewidth=2.5,
               label='Naive :latest', color=COLORS['Naïve :latest'],
               marker='s', markersize=4, alpha=0.8)
    else:
        print("Figure 3: omitting Naive :latest curve "
              "(no measured per-image naive_reduction_percentage in dataset).")

    # Scan-Only performs no patching, so its reduction is 0% by definition.
    # This is a definitional line, not synthesized data.
    ax.axvline(x=0, linewidth=2.5, label='Scan-Only (0% by definition)',
              color=COLORS['Scan-Only'], linestyle='--', alpha=0.8)

    ax.set_xlabel('Vulnerability Reduction (%)', fontsize=11)
    ax.set_ylabel('Cumulative Probability', fontsize=11)
    ax.set_title('Figure 3: Cumulative Distribution of Vulnerability Reduction Across 100+ Images',
                 fontsize=12, fontweight='bold', pad=15)
    ax.set_xlim(-5, 105)
    ax.set_ylim(0, 1.05)
    ax.legend(loc='lower right', frameon=True, shadow=False)
    ax.grid(True, alpha=0.3, linestyle=':')
    ax.set_axisbelow(True)

    # Add percentile annotations for AutoPatch
    for percentile in [50, 75, 90, 95]:
        idx = int(len(sorted_reductions) * percentile / 100)
        reduction_val = sorted_reductions[idx]
        ax.plot(reduction_val, percentile/100, 'o', color=COLORS['AutoPatch'], markersize=5)
        ax.text(reduction_val + 2, percentile/100, f'{percentile}th: {reduction_val:.1f}%',
               fontsize=8, va='center')

    save_figure(fig, 'fig3_cdf_vulnerability_reduction')
    plt.close()


def generate_figure_4(data):
    """
    Figure 4: Heatmap — Reduction % by OS family × language runtime.

    Rows: Alpine, Debian, Ubuntu, RHEL
    Columns: Python, Node.js, Go, Java, Ruby, PHP, Infrastructure
    """
    fig, ax = plt.subplots(figsize=(11, 6))

    # Build matrix: OS family × language runtime
    os_families = ['Alpine', 'Debian', 'Ubuntu', 'RHEL']
    runtimes = ['Python', 'Node.js', 'Go', 'Java', 'Ruby', 'PHP', 'Infrastructure']

    # Initialize matrix with NaN
    matrix = np.full((len(os_families), len(runtimes)), np.nan)

    # Populate matrix with average reduction percentages
    for img in data['full_dataset']:
        os_idx = os_families.index(img['os_family']) if img['os_family'] in os_families else None
        rt_idx = runtimes.index(img['language_runtime']) if img['language_runtime'] in runtimes else None

        if os_idx is not None and rt_idx is not None:
            if np.isnan(matrix[os_idx, rt_idx]):
                matrix[os_idx, rt_idx] = img['reduction_percentage']
            else:
                # Average if multiple entries exist
                matrix[os_idx, rt_idx] = (matrix[os_idx, rt_idx] + img['reduction_percentage']) / 2

    # Create heatmap
    sns.heatmap(matrix, annot=True, fmt='.1f', cmap='RdYlGn', cbar_kws={'label': 'Reduction %'},
               xticklabels=runtimes, yticklabels=os_families, ax=ax,
               vmin=50, vmax=100, linewidths=0.5, linecolor='gray')

    ax.set_xlabel('Language Runtime', fontsize=11)
    ax.set_ylabel('OS Family', fontsize=11)
    ax.set_title('Figure 4: AutoPatch Vulnerability Reduction by OS Family and Language Runtime',
                 fontsize=12, fontweight='bold', pad=15)

    save_figure(fig, 'fig4_os_runtime_heatmap')
    plt.close()


def generate_figure_5(data):
    """
    Figure 5: Ablation study bar chart — 4 AutoPatch variants.

    Variants:
    - Base image upgrade only
    - Package upgrades only
    - No SBOM inference (random modern base)
    - Full AutoPatch
    """
    fig, ax = plt.subplots(figsize=(10, 6))

    ablation = data['ablation_results']
    variant_names = [item['variant'].replace(' ', '\n') for item in ablation]
    avg_reductions = [item['avg_reduction_percentage'] for item in ablation]
    std_devs = [item['std_dev'] for item in ablation]

    x = np.arange(len(variant_names))
    width = 0.6

    # Color gradient: full AutoPatch in green, others in orange/gray
    colors_ablation = [COLORS['Naïve :latest'] if i < 3 else COLORS['AutoPatch']
                       for i in range(len(variant_names))]

    bars = ax.bar(x, avg_reductions, width, yerr=std_devs,
                 color=colors_ablation, edgecolor='black', linewidth=0.5,
                 capsize=5, error_kw={'linewidth': 1.5})

    # Labels and formatting
    ax.set_ylabel('Mean Vulnerability Reduction (%)', fontsize=11)
    ax.set_xlabel('AutoPatch Variant', fontsize=11)
    ax.set_title('Figure 5: Ablation Study of AutoPatch Components',
                 fontsize=12, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(variant_names, fontsize=9)
    ax.set_ylim(0, 105)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)

    # Add value labels
    for i, bar in enumerate(bars):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + std_devs[i] + 2,
               f'{height:.1f}%',
               ha='center', va='bottom', fontsize=9, fontweight='bold')

    save_figure(fig, 'fig5_ablation_study')
    plt.close()


def generate_figure_6(data):
    """
    Figure 6: Pipeline overhead breakdown — stacked bar.

    Shows: Build, Scan, Sign, Verify, Report times.
    """
    fig, ax = plt.subplots(figsize=(10, 6))

    overhead = data['overhead_measurements']
    stages = [m['stage'] for m in overhead['measurements']]
    means = [m['mean'] for m in overhead['measurements']]
    std_devs = [m['std_dev'] for m in overhead['measurements']]

    # Define colors for each stage
    stage_colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

    # Create stacked bar
    x = [0]
    cumulative = [0]

    for i, (stage, mean) in enumerate(zip(stages, means)):
        ax.barh(x, mean, left=cumulative, label=stage, color=stage_colors[i],
               edgecolor='black', linewidth=0.5)

        # Add time labels in the middle of each segment
        ax.text(cumulative[0] + mean/2, x[0], f'{mean:.1f}s',
               ha='center', va='center', fontweight='bold', fontsize=9)

        cumulative[0] += mean

    ax.set_yticks(x)
    ax.set_yticklabels(['Total Pipeline Overhead'])
    ax.set_xlabel('Time (seconds)', fontsize=11)
    ax.set_title('Figure 6: AutoPatch Pipeline Overhead Breakdown',
                 fontsize=12, fontweight='bold', pad=15)
    ax.legend(loc='upper right', frameon=True, shadow=False, ncol=1)
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)

    # Add total time annotation
    total_time = overhead['total_mean']
    ax.text(cumulative[0] + 1, x[0], f'Total: {total_time:.1f}s',
           ha='left', va='center', fontweight='bold', fontsize=10)

    save_figure(fig, 'fig6_pipeline_overhead', tight=False)
    plt.close()


def generate_all_figures(data):
    """Generate all publication-grade figures."""
    print("\n" + "="*70)
    print("AutoPatch Phase 2 — Figure Generation")
    print("="*70)

    if data is None:
        print("ERROR: Could not load experimental data.")
        return False

    print(f"\nGenerating figures from data ({data['metadata'].get('note', '')})...")
    print(f"Dataset: {data['metadata'].get('num_images_tested', 'unknown')} images\n")

    try:
        print("Generating Figure 2: Legacy Images Bar Chart...")
        generate_figure_2(data)

        print("Generating Figure 3: CDF Curves...")
        generate_figure_3(data)

        print("Generating Figure 4: OS × Runtime Heatmap...")
        generate_figure_4(data)

        print("Generating Figure 5: Ablation Study...")
        generate_figure_5(data)

        print("Generating Figure 6: Pipeline Overhead...")
        generate_figure_6(data)

        print("\n" + "="*70)
        print(f"✓ All figures generated successfully!")
        print(f"✓ Saved to: {OUTPUT_DIR}")
        print("="*70 + "\n")

        return True

    except Exception as e:
        print(f"\n✗ Error generating figures: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point."""
    # Load data
    data = load_data()

    if data is None:
        print("\n⚠ No data file found. Using embedded sample data...")
        # Create minimal sample data structure if needed
        print("Please ensure experimental_data.json exists in the same directory.")
        return False

    # Generate all figures
    success = generate_all_figures(data)

    return success


if __name__ == '__main__':
    import sys
    success = main()
    sys.exit(0 if success else 1)
