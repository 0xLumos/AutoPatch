# A/B experiment runbook (GCP)

Every command is copy-paste. Run them ON the VM unless marked local.

## 0. VM (skip if autopatch-exp still exists)

Local machine:

    gcloud compute instances create autopatch-ab \
        --zone=us-central1-a \
        --machine-type=e2-standard-4 \
        --boot-disk-size=120GB \
        --image-family=ubuntu-2404-lts-amd64 \
        --image-project=ubuntu-os-cloud

    gcloud compute ssh autopatch-ab --zone=us-central1-a

e2-standard-4 matches the corpus criterion I3 (4 vCPU). The 120 GB
disk matters: ~75 images x 2 arms x build layers adds up, and a full
disk at hour six wastes the first five.

## 1. One-time VM setup

    sudo apt-get update && sudo apt-get install -y docker.io git python3-pip python3-venv
    sudo usermod -aG docker $USER && newgrp docker

    # Trivy, pinned to the version the repo's checksums know
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sudo sh -s -- -b /usr/local/bin v0.69.3

    docker info >/dev/null && trivy --version   # both must succeed

## 2. Get the code onto the VM

Use whichever applies. The experiment must run the CURRENT code, not
the April checkout: every fix this cycle (guards, multistage graph,
resolver, metrics) changes the numbers.

    # if the repo is on GitHub and current:
    git clone <your-repo-url> AutoPatch && cd AutoPatch

    # if not, from the local machine:
    gcloud compute scp --recurse "C:\Users\Nohou\Documents\Claude\Projects\AutoPatch" \
        autopatch-ab:~/AutoPatch --zone=us-central1-a

Then:

    cd ~/AutoPatch
    python3 -m pip install -e . 2>/dev/null || python3 -m pip install pyyaml requests anthropic
    python3 -m pytest tests/ -q --ignore=tests/integration    # must be green BEFORE burning compute

## 3. Collect the corpus (both strata)

    python3 experiments/collect_real_dockerfiles.py real_repos --legacy-cutoff-years 4

Sanity-check the output line: it should report current and legacy
counts and a manifest path. Then:

    python3 -c "import json; d=json.load(open('real_repos/manifest.json')); \
        print('entries:', len(d['entries']), \
        'legacy:', sum(1 for e in d['entries'] if e['stratum']=='legacy'))"

## 4. Key for arm B

    export ANTHROPIC_API_KEY=sk-ant-...

Without it the launcher refuses a two-arm run rather than silently
producing A vs A.

## 5. Pilot BEFORE the full run

    CORPUS=real_repos LIMIT=3 TIMEOUT=1800 bash experiments/launch_ab_gcp.sh
    tail -f results/ab_*/runner.log

Three images, both arms, ~30-60 min. What to check in
results/ab_*/summary.json before going further:

- exit codes are mostly 0 (a build failure or two is normal and is data)
- arm B rows have selector-decision.json with arm=ai, not all ai-fallback
- reductions are plausible numbers, not null across the board

## 6. Full run (detached; survives SSH and any assistant session)

    CORPUS=real_repos TIMEOUT=1800 bash experiments/launch_ab_gcp.sh

    # monitor any time:
    tail -f results/ab_*/runner.log
    python3 -c "import json;print(json.dumps(json.load(open(sorted(__import__('glob').glob('results/ab_*/summary.json'))[-1])),indent=2))" | head -40

    # if the VM reboots mid-run, resume (completed pairs are skipped):
    OUT=results/ab_<stamp> CORPUS=real_repos bash experiments/launch_ab_gcp.sh

    # stop:
    kill "$(cat results/ab_*/runner.pid)"

Rough budget: ~75 entries x 2 arms x ~5-15 min per run. Expect 12 to
36 hours. The runner checkpoints after every single run.

## 7. Bring results back (local machine)

    gcloud compute scp --recurse autopatch-ab:~/AutoPatch/results/ab_* \
        "C:\Users\Nohou\Documents\Claude\Projects\AutoPatch\results\" --zone=us-central1-a

Also fetch src/ai_cache/ (the cached Claude responses) and
real_repos/manifest.json: together with results.jsonl they make the
whole experiment replayable offline (--ai-cache-only) and are part of
the published artifact.

## What the numbers replace

summary.json's arm A statistics replace every figure currently derived
from experiments/experimental_data.json, which is simulated and must
not survive into the submission. The paired delta section is the A/B
result; the stratum field splits current vs legacy. Regenerate figures
only from these files.
