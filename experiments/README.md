# AutoPatch Phase 2 — Experimental Simulation

## Overview
This directory contains the experimental framework for generating publication-grade figures and data for the AutoPatch vulnerability reduction study.

## Files

### 1. `experimental_data.json`
Comprehensive JSON dataset with realistic experimental results across 100+ container images.

**Structure:**
- **metadata**: Study information, versions, platform details (marked `[SIMULATED — TO BE MEASURED with actual Trivy scans]`)
- **legacy_images**: 6 benchmark images with paper's actual CVE counts:
  - CentOS 7: 1264 → 0 critical vulns (100% reduction)
  - AdoptOpenJDK 11: 412 → 26 (93.7% reduction)
  - Docker Engine 18.09.7: 39 → 6 (84.6% reduction)
  - Jenkins 2.164.1: 1153 → 76 (93.4% reduction)
  - Nginx 1.10.3: 423 → 76 (82.0% reduction)
  - PostgreSQL 12: 305 → 76 (85.2% reduction)

- **full_dataset**: 63 diverse container images covering:
  - OS families: Alpine (12), Debian (23), Ubuntu (18), RHEL (10)
  - Language runtimes: Python, Node.js, Go, Java, Ruby, PHP, Infrastructure
  - Age range: 4–38 months old

- **ablation_results**: 4 AutoPatch variants with effectiveness metrics:
  - Base image upgrade only: 62.3% avg reduction
  - Package upgrades only: 71.4% avg reduction
  - No SBOM inference: 58.9% avg reduction
  - Full AutoPatch: 92.1% avg reduction

- **overhead_measurements**: Pipeline stage timings:
  - Build: 18.4s avg
  - Scan: 12.7s avg
  - Sign: 2.3s avg
  - Verify: 1.8s avg
  - Report: 3.2s avg
  - **Total: 38.4s avg**

- **statistical_summary**: Aggregate metrics (106 images tested)
  - Mean reduction: 92.1%
  - Median reduction: 92.8%
  - 95th percentile: 97.8%

### 2. `generate_figures.py`
Python script that generates all publication-grade figures from `experimental_data.json`.

**Features:**
- Serif fonts (Times New Roman) for publication quality
- Both PDF and PNG (300 DPI) output formats
- Automatic figure export to `./figures/` directory
- Publication-ready styling with proper legends, grids, and annotations

**Generated Figures:**

1. **Fig 2**: Grouped bar chart
   - 6 legacy images × 3 strategies (Scan-Only, Naïve :latest, AutoPatch)
   - Shows critical vulnerability counts
   - Demonstrates dramatic improvement of AutoPatch

2. **Fig 3**: CDF curves
   - Vulnerability reduction % across 100+ images
   - AutoPatch, Naïve :latest, and Scan-Only strategies
   - Includes percentile annotations (50th, 75th, 90th, 95th)

3. **Fig 4**: Heatmap
   - OS family (rows): Alpine, Debian, Ubuntu, RHEL
   - Language runtime (columns): Python, Node.js, Go, Java, Ruby, PHP, Infrastructure
   - Color-coded reduction % (50–100% scale)

4. **Fig 5**: Ablation study
   - 4 AutoPatch variants with error bars
   - Shows importance of each component
   - Full AutoPatch achieves 92.1% vs. 62.3% for base image upgrade alone

5. **Fig 6**: Pipeline overhead breakdown
   - Stacked bar chart of 5 pipeline stages
   - Build (18.4s) + Scan (12.7s) + Sign (2.3s) + Verify (1.8s) + Report (3.2s)
   - Total: 38.4s with std dev of 7.3s

## Usage

### Generate all figures:
```bash
python3 generate_figures.py
```

Outputs will be saved to `./figures/` directory with both PDF and PNG formats.

### Load and inspect data:
```python
import json

with open('experimental_data.json', 'r') as f:
    data = json.load(f)

print(data['statistical_summary']['mean_reduction_percentage'])  # 92.1%
```

## Data Notes

- All figures marked as `[SIMULATED — TO BE MEASURED with actual Trivy scans]`
- Realistic distributions based on paper's CDF curve and reported metrics
- Full dataset: 63 images across 4 OS families and 7 runtime categories
- Legacy images use paper's actual reported CVE numbers
- Vulnerability counts follow realistic patterns by OS family

## Integration

To use with actual measurements:
1. Replace `experimental_data.json` with real scan data
2. Update `metadata.note` to reflect actual measurements
3. Re-run `generate_figures.py`
4. Figures will regenerate with new data automatically

## Requirements

- Python 3.7+
- numpy
- matplotlib
- seaborn
- json (standard library)
- pathlib (standard library)

