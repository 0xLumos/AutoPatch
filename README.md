# 🛡️ Autopatch: Automated Vulnerability Patching for Cloud-Native Containers

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker Security](https://img.shields.io/badge/Docker-Security-blue)](#)

Autopatch is a modular, automated tool designed to scan, patch, and harden container images by upgrading their base operating system layers and package dependencies. It rewrites multi-stage Dockerfiles, upgrades vulnerable components, and signs rebuilt images for supply chain provenance.

Developed as part of a master's research project, it combines static analysis, security automation, and software supply chain best practices in a reproducible, minimal-intervention workflow.

---

## ✨ Features

- 🔍 Automatically scans containers using [Trivy](https://github.com/aquasecurity/trivy)
- 🧬 Detects base image family (Debian, Ubuntu, Alpine, RedHat)
- 🔁 Upgrades FROM image to latest compatible version
- 🧰 Injects OS-level and language-specific patch commands (`apt`, `apk`, `pip`, `npm`, `yarn`)
- 🛠️ Rebuilds the patched image and optionally pushes to a remote registry
- 📊 Generates before/after SBOMs and vulnerability reports
- 📉 Produces CVE diff: resolved, remaining, and newly introduced vulnerabilities
- 🔏 Signs rebuilt images using [Cosign](https://github.com/sigstore/cosign)
- 🧪 Supports fully automated CLI with customizable patching modes

---

## 📦 Requirements

- Python 3.7+
- Docker
- [Trivy](https://aquasecurity.github.io/trivy/)
- [Cosign](https://github.com/sigstore/cosign)
- GNU/Linux or macOS

Install Python dependencies:

pip install -r requirements.txt
🚀 Usage
bash
Copy code
python main.py --dockerfile ./Dockerfile \
               --registry localhost:5000 \
               --signing key \
               --patch-final-only
CLI Options
Argument	Description
--dockerfile	Path to the input Dockerfile (required)
--registry	Registry to push the patched image (default: localhost)
--signing	Signing mode: key, keyless, or none
--patch-final-only	Only patch the final stage of the Dockerfile

## 📂 Output Structure

```text
.
├── Dockerfile.patched        # Patched Dockerfile with upgrades
├── reports/
│   ├── before.json           # Trivy scan (original image)
│   ├── after.json            # Trivy scan (patched image)
│   ├── sbom_before.json      # CycloneDX SBOM before patching
│   └── sbom_after.json       # CycloneDX SBOM after patching
└── autopatch.log             # Full CLI execution log
```
🔬 Academic Context
This tool was developed as part of a master's thesis titled:

“SBOM-Driven AutoPatching for Secure CI/CD Container Pipelines”

It demonstrates how static SBOM analysis, Trivy scanning, and OCI signing can be combined to automate container hardening with minimal human intervention. It is intended for use in DevSecOps pipelines and secure build systems.

🤝 Contributing
Pull requests are welcome! To contribute:

Fork the repo

Create your feature branch (git checkout -b feature/foo)

Commit your changes

Push to the branch (git push origin feature/foo)

Open a pull request

📝 License
MIT License. See LICENSE for details.








