# Running Real AutoPatch Experiments on GCP

## Overview

This guide walks you through running actual Trivy scans on real Docker images on your GCP Linux instance to replace the simulated data with genuine experimental results.

**Estimated time:** 4–6 hours for ~106 images across 5 strategies
**Estimated disk:** ~50 GB (Docker images are pulled and removed per-image)
**Estimated cost:** ~$5–10 on an e2-standard-8 (8 vCPU, 32 GB RAM)

---

## Step 1: GCP Instance Setup

```bash
# If not already done, SSH into your instance
gcloud compute ssh YOUR_INSTANCE_NAME --zone YOUR_ZONE

# Update system
sudo apt-get update && sudo apt-get upgrade -y
```

### 1a. Install Docker

```bash
# Install Docker
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin

# Add your user to docker group (avoids sudo for docker commands)
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker run hello-world
```

### 1b. Install Trivy

```bash
sudo apt-get install -y wget apt-transport-https
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy

# Pre-download the vulnerability database (takes a few minutes)
trivy image --download-db-only

# Verify
trivy --version
```

### 1c. Install Cosign

```bash
# Install cosign
COSIGN_VERSION=$(curl -s https://api.github.com/repos/sigstore/cosign/releases/latest | grep tag_name | cut -d '"' -f4)
wget "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign

# Verify
cosign version
```

### 1d. Install Python 3.11+ and Dependencies

```bash
sudo apt-get install -y python3 python3-pip python3-venv git jq

# Verify Python version (need 3.11+)
python3 --version

# If < 3.11, install from deadsnakes PPA (Ubuntu) or build from source
```

### 1e. Install Copacetic (for baseline comparison)

```bash
# Install Copa
COPA_VERSION=$(curl -s https://api.github.com/repos/project-copacetic/copacetic/releases/latest | grep tag_name | cut -d '"' -f4)
wget "https://github.com/project-copacetic/copacetic/releases/download/${COPA_VERSION}/copa_${COPA_VERSION#v}_linux_amd64.tar.gz"
tar -xzf copa_*.tar.gz
sudo mv copa /usr/local/bin/
rm copa_*.tar.gz

# Copa requires buildkit
docker buildx create --name copabuildkit --use --bootstrap
export BUILDKIT_HOST=docker-container://buildx_buildkit_copabuildkit0

# Verify
copa version
```

### 1f. Install Docker Scout (for baseline comparison)

```bash
# Docker Scout is a Docker CLI plugin
curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --

# Login to Docker Hub (needed for Scout)
docker login

# Verify
docker scout version
```

---

## Step 2: Clone the Repo and Prepare Dataset

```bash
cd ~
git clone https://github.com/0xLumos/AutoPatch.git
cd AutoPatch

# Install Python dependencies
pip3 install --break-system-packages -r requirements.txt 2>/dev/null || pip3 install -r requirements.txt

# Check existing Dockerfiles
ls dockerfiles/
```

### 2a. Expand the Dockerfile Dataset to 106+

The repo has ~29 Dockerfiles. You need to add more to reach 106+. Run the dataset builder script (Step 3 below creates it), or manually add Dockerfiles for these categories:

**Missing images to add** (each is a one-liner Dockerfile):

```bash
mkdir -p dockerfiles

# Generate additional Dockerfiles
python3 experiments/generate_dataset.py
```

---

## Step 3: Create the Dataset Generator

Save this as `experiments/generate_dataset.py` (it's created for you below).

This script generates Dockerfiles for ~120 images across all categories the paper claims.

---

## Step 4: Run the Full Experiment

```bash
# Create output directory
mkdir -p experiments/real_results

# Run the 5-strategy experiment
python3 experiments/run_real_experiment.py \
    --dockerfile-dir dockerfiles/ \
    --output-dir experiments/real_results/ \
    --strategies scan-only naive copacetic scout autopatch \
    --verbose \
    2>&1 | tee experiments/experiment_log.txt
```

This will take several hours. Each image goes through:
1. **Scan-Only**: Build → Trivy scan → record baseline
2. **Naïve :latest**: Rewrite all FROM to :latest → build → scan
3. **Copacetic**: Run `copa patch` on the image → scan
4. **Docker Scout**: Run `docker scout recommendations` → apply → scan
5. **AutoPatch**: Full pipeline (SBOM → infer OS → rewrite → rebuild → rescan)

### Monitor Progress

```bash
# In another terminal, watch progress
tail -f experiments/experiment_log.txt

# Check disk usage (images are cleaned up per-run)
df -h
docker system df
```

---

## Step 5: Compute Statistics and Generate Figures

After the experiment finishes:

```bash
python3 experiments/compute_real_statistics.py \
    --results experiments/real_results/results.json \
    --output-dir experiments/real_results/

# This produces:
#   real_results/statistics.json    (mean, median, σ, Wilcoxon, Cohen's d)
#   real_results/results.csv        (flat CSV for every image × strategy)
#   figures/fig2_effectiveness.pdf  (bar chart from REAL data)
#   figures/fig3_cdf.pdf            (CDF from REAL data)
#   figures/fig4_severity_panels.pdf
```

---

## Step 6: Update the Paper

After you have `statistics.json` and `results.csv`:

1. Replace every number in the paper's evaluation section with the real measured values
2. Update Table II with real per-image VR percentages
3. Update Table III with real Wilcoxon p-values and Cohen's d
4. Regenerate all figures from real data
5. Remove the `[SIMULATED]` tag from `experimental_data.json`
6. Record the actual Trivy version (`trivy --version`) and Docker version (`docker --version`) in Section VI.A

---

## Troubleshooting

**Docker Hub rate limits:** Free accounts are limited to 100 pulls/6 hours. Login with `docker login` for 200 pulls, or use a paid account.

**Trivy DB download fails:** Run `trivy image --download-db-only` manually. If behind a proxy, set `HTTP_PROXY`.

**Copa fails on some images:** This is expected — Copa cannot patch all image types. Record the failure and move on. The failure rate IS a data point for the paper.

**Build failures:** Some old Dockerfiles won't build (expired keys, removed repos). Record as build failures. The paper already accounts for a ~3.4% exclusion rate.

**Disk space:** Run `docker system prune -f` periodically if disk fills up. The script cleans up images after each run.
