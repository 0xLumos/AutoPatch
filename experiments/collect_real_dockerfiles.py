#!/usr/bin/env python3
"""Collect the evaluation corpus of real Dockerfiles.

Selection criteria I1-I5 and the legacy-stratum rule are recorded in
the generated manifest.json (criteria_version) and justified in
paper/dataset_justification_replacement.md. This script enforces them;
it does not argue for them.

Usage:
    python experiments/collect_real_dockerfiles.py [workdir] \
        [--legacy-cutoff-years 4] [--no-legacy]
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

CRITERIA_VERSION = "2.0"

# name -> git URL. See I1-I5 above for the admission rules. Additions
# must satisfy all five; removals must be justified in the manifest.
REPOS = {
    # ── Go (multi-stage single-binary; lightweight, self-contained) ──
    "gitea":            "https://github.com/go-gitea/gitea",
    "hugo":             "https://github.com/gohugoio/hugo",
    "rclone":           "https://github.com/rclone/rclone",
    "filebrowser":      "https://github.com/filebrowser/filebrowser",
    "gotify-server":    "https://github.com/gotify/server",
    "memos":            "https://github.com/usememos/memos",
    "headscale":        "https://github.com/juanfont/headscale",
    "navidrome":        "https://github.com/navidrome/navidrome",
    "syncthing":        "https://github.com/syncthing/syncthing",
    "restic":           "https://github.com/restic/restic",
    "lazygit":          "https://github.com/jesseduffield/lazygit",
    "act":              "https://github.com/nektos/act",
    "croc":             "https://github.com/schollz/croc",
    "dive":             "https://github.com/wagoodman/dive",
    "cli":              "https://github.com/cli/cli",
    "kubo":             "https://github.com/ipfs/kubo",
    "woodpecker":       "https://github.com/woodpecker-ci/woodpecker",
    "drone":            "https://github.com/harness/drone",
    "gimlet":           "https://github.com/gimlet-io/gimlet",
    "chartmuseum":      "https://github.com/helm/chartmuseum",

    # ── Rust (multi-stage; heavier compile but self-contained) ──
    "meilisearch":      "https://github.com/meilisearch/meilisearch",
    "zola":             "https://github.com/getzola/zola",
    "bat":              "https://github.com/sharkdp/bat",
    "vaultwarden":      "https://github.com/dani-garcia/vaultwarden",

    # ── Node / TypeScript (multi-stage; npm/pnpm build) ──
    "uptime-kuma":      "https://github.com/louislam/uptime-kuma",
    "node-red":         "https://github.com/node-red/node-red",
    "excalidraw":       "https://github.com/excalidraw/excalidraw",
    "hoppscotch":       "https://github.com/hoppscotch/hoppscotch",
    "trilium":          "https://github.com/zadam/trilium",
    "wikijs":           "https://github.com/requarks/wiki",

    # ── Python (multi-stage; pip/poetry) ──
    "searxng":          "https://github.com/searxng/searxng",
    "httpie":           "https://github.com/httpie/cli",
    "netbox":           "https://github.com/netbox-community/netbox",
    "changedetection":  "https://github.com/dgtlmoon/changedetection.io",
    "flask":            "https://github.com/pallets/flask",

    # ── Java / JVM (multi-stage; maven/gradle) ──
    "spring-petclinic": "https://github.com/spring-projects/spring-petclinic",
    "jhipster-sample":  "https://github.com/jhipster/jhipster-sample-app",

    # ── PHP / Ruby (lighter app images) ──
    "firefly-iii":      "https://github.com/firefly-iii/firefly-iii",
    "snipe-it":         "https://github.com/snipe/snipe-it",

    # ═══ OS-heavy expansion (2026-08): interpreted-language apps on
    # distro/language bases with large apt/yum package surfaces, where
    # base-image remediation removes many OS-package CVEs. Same I1-I5
    # admission; collector drops any without a real Dockerfile or a
    # pre-cutoff stable tag and reports it. Not hand-curated results.
    # ── PHP (apt-heavy on php:* / debian) ──
    "freshrss":         "https://github.com/FreshRSS/FreshRSS",
    "grocy":            "https://github.com/grocy/grocy",
    "shlink":           "https://github.com/shlinkio/shlink",
    "monica":           "https://github.com/monicahq/monica",
    "pixelfed":         "https://github.com/pixelfed/pixelfed",
    "invoiceninja":     "https://github.com/invoiceninja/invoiceninja",
    "wallabag":         "https://github.com/wallabag/wallabag",
    "dolibarr":         "https://github.com/Dolibarr/dolibarr",

    # ── Python (python:* slim/debian + apt build deps) ──
    "paperless-ngx":    "https://github.com/paperless-ngx/paperless-ngx",
    "healthchecks":     "https://github.com/healthchecks/healthchecks",
    "redash":           "https://github.com/getredash/redash",
    "mlflow":           "https://github.com/mlflow/mlflow",
    "label-studio":     "https://github.com/HumanSignal/label-studio",
    "pretix":           "https://github.com/pretix/pretix",
    "authentik":        "https://github.com/goauthentik/authentik",
    "mealie":           "https://github.com/mealie-recipes/mealie",
    "weblate":          "https://github.com/WeblateOrg/weblate",

    # ── Node / TypeScript (node:* debian; npm/pnpm/yarn) ──
    "directus":         "https://github.com/directus/directus",
    "n8n":              "https://github.com/n8n-io/n8n",
    "umami":            "https://github.com/umami-software/umami",
    "outline":          "https://github.com/outline/outline",
    "etherpad":         "https://github.com/ether/etherpad-lite",
    "meshcentral":      "https://github.com/Ylianst/MeshCentral",
    "nocodb":           "https://github.com/nocodb/nocodb",
    "rocketchat":       "https://github.com/RocketChat/Rocket.Chat",

    # ── Ruby (ruby:* debian; bundler) ──
    "huginn":           "https://github.com/huginn/huginn",
    "chatwoot":         "https://github.com/chatwoot/chatwoot",
    "mastodon":         "https://github.com/mastodon/mastodon",

    # ── JVM (maven/gradle on temurin/openjdk debian) ──
    "metabase":         "https://github.com/metabase/metabase",
    "keycloak":         "https://github.com/keycloak/keycloak",
    "graylog":          "https://github.com/Graylog2/graylog2-server",

    # ═══ Go server/CLI top-up (2026-08-13): the profile the screening
    # data showed builds reliably and carries real OS-package headroom
    # (self-contained single-binary builds on pinned older Alpine).
    "cli":              "https://github.com/cli/cli",
    "k6":               "https://github.com/grafana/k6",
    "vault":            "https://github.com/hashicorp/vault",
    "consul":           "https://github.com/hashicorp/consul",
    "nomad":            "https://github.com/hashicorp/nomad",
    "terraform":        "https://github.com/hashicorp/terraform",
    "packer":           "https://github.com/hashicorp/packer",
    "cadvisor":         "https://github.com/google/cadvisor",
    "node_exporter":    "https://github.com/prometheus/node_exporter",
    "blackbox_exporter":"https://github.com/prometheus/blackbox_exporter",
    "pushgateway":      "https://github.com/prometheus/pushgateway",
    "alertmanager":     "https://github.com/prometheus/alertmanager",
    "thanos":           "https://github.com/thanos-io/thanos",
    "cortex":           "https://github.com/cortexproject/cortex",
    "telegraf":         "https://github.com/influxdata/telegraf",
    "vector":           "https://github.com/vectordotdev/vector",
    "mc":               "https://github.com/minio/mc",
    "rclone-web":       "https://github.com/rclone/rclone",
    "step-ca":          "https://github.com/smallstep/certificates",
    "step-cli":         "https://github.com/smallstep/cli",
    "cosign-cli":       "https://github.com/sigstore/cosign",
    "trivy-app":        "https://github.com/aquasecurity/trivy",
    "grype-app":        "https://github.com/anchore/grype",
    "syft":             "https://github.com/anchore/syft",
    "helm-app":         "https://github.com/helm/helm",
    "k9s":              "https://github.com/derailed/k9s",
    "kubectx":          "https://github.com/ahmetb/kubectx",
    "stern":            "https://github.com/stern/stern",
    "dive-app":         "https://github.com/wagoodman/dive",
    "lazydocker":       "https://github.com/jesseduffield/lazydocker",
    "gickup":           "https://github.com/cooperspencer/gickup",
    "gotify-cli":       "https://github.com/gotify/cli",
    "yq":               "https://github.com/mikefarah/yq",
    "gitleaks":         "https://github.com/gitleaks/gitleaks",
    "trufflehog":       "https://github.com/trufflesecurity/trufflehog",
    "wireguard-ui":     "https://github.com/ngoduykhanh/wireguard-ui",
    "tailscale":        "https://github.com/tailscale/tailscale",
    "netbird":          "https://github.com/netbirdio/netbird",
    "pocketbase":       "https://github.com/pocketbase/pocketbase",
    "dolt":             "https://github.com/dolthub/dolt",
    "immich-cli":       "https://github.com/immich-app/CLI",
    "grafana-agent":    "https://github.com/grafana/agent",
    "mimir":            "https://github.com/grafana/mimir",
    "tempo":            "https://github.com/grafana/tempo",

    # ── .NET (aspnet debian base) ──
    "jellyfin":         "https://github.com/jellyfin/jellyfin",

    # ── More Go (a few, for continued quota balance) ──
    "caddy":            "https://github.com/caddyserver/caddy",
    "traefik":          "https://github.com/traefik/traefik",
    "minio":            "https://github.com/minio/minio",
    "frp":              "https://github.com/fatedier/frp",
    "miniflux":         "https://github.com/miniflux/v2",
    "registry":         "https://github.com/distribution/distribution",
    "coredns":          "https://github.com/coredns/coredns",

    # ═══ Expansion round 2 (2026-08-12): grow the actionable pool.
    # Weighted toward the profiles that screened and admitted best:
    # Go tools on distro bases, and interpreted apps with large OS
    # package surfaces. Screening drops any without a real Dockerfile,
    # a buildable original, or base headroom, with reasons logged, so
    # over-inclusion here costs screening time, never result validity.
    # ── Go ──
    "loki":             "https://github.com/grafana/loki",
    "etcd":             "https://github.com/etcd-io/etcd",
    "nats-server":      "https://github.com/nats-io/nats-server",
    "victoriametrics":  "https://github.com/VictoriaMetrics/VictoriaMetrics",
    "ntfy":             "https://github.com/binwiederhier/ntfy",
    "gogs":             "https://github.com/gogs/gogs",
    "adguardhome":      "https://github.com/AdguardTeam/AdGuardHome",
    "seaweedfs":        "https://github.com/seaweedfs/seaweedfs",
    "rqlite":           "https://github.com/rqlite/rqlite",
    "webhook":          "https://github.com/adnanh/webhook",
    "gotenberg":        "https://github.com/gotenberg/gotenberg",
    "sftpgo":           "https://github.com/drakkan/sftpgo",
    # ── Python ──
    "saleor":           "https://github.com/saleor/saleor",
    "tandoor-recipes":  "https://github.com/TandoorRecipes/recipes",
    "superset":         "https://github.com/apache/superset",
    "wger":             "https://github.com/wger-project/wger",
    "zulip":            "https://github.com/zulip/zulip",
    "frigate":          "https://github.com/blakeblackshear/frigate",
    "openlibrary":      "https://github.com/internetarchive/openlibrary",
    # ── PHP ──
    "kimai":            "https://github.com/kimai/kimai",
    "matomo":           "https://github.com/matomo-org/matomo",
    "roundcubemail":    "https://github.com/roundcube/roundcubemail",
    "yourls":           "https://github.com/YOURLS/YOURLS",
    "leantime":         "https://github.com/Leantime/leantime",
    "cachet":           "https://github.com/cachethq/cachet",
    # ── Node / TypeScript ──
    "strapi":           "https://github.com/strapi/strapi",
    "appsmith":         "https://github.com/appsmithorg/appsmith",
    "budibase":         "https://github.com/Budibase/budibase",
    "medusa":           "https://github.com/medusajs/medusa",
    "hedgedoc":         "https://github.com/hedgedoc/hedgedoc",
    "verdaccio":        "https://github.com/verdaccio/verdaccio",
    "thelounge":        "https://github.com/thelounge/thelounge",
    # ── Rust ──
    "qdrant":           "https://github.com/qdrant/qdrant",
    "surrealdb":        "https://github.com/surrealdb/surrealdb",
    # ── Java ──
    "dependency-track": "https://github.com/DependencyTrack/dependency-track",
    "zipkin":           "https://github.com/openzipkin/zipkin",
}

# Where to look for the Dockerfile within a repo, in priority order.
CANDIDATE_PATHS = [
    "Dockerfile",
    "docker/Dockerfile",
    ".docker/Dockerfile",
    "build/Dockerfile",
    "build/package/Dockerfile",
    "deploy/Dockerfile",
    "contrib/docker/Dockerfile",
    "Dockerfile.release",
]

# Path fragments that mark a Dockerfile as NOT the real app build image
# (dev tooling, tests, examples, docs, arch-specific/dev variants).
# This is criterion I1, enforced in code.
EXCLUDE_SEGMENTS = (
    ".devcontainer", "devcontainer", "/test", "tests", "syntax-tests",
    "fixture", "example", "examples", "docs", "sample", "/dev/", "build-arm",
    "arm32", "arm64", "e2e", "ci/", "benchmark",
)

# Stable release tags only for the legacy stratum: v1.2, 1.2.3, v2.0.0.
# Pre-releases (rc, beta, alpha, dev) are excluded because a project's
# rc Dockerfile is not what it shipped.
_STABLE_TAG_RE = re.compile(r"^v?\d+(?:\.\d+)+$")


def sh(cmd, cwd=None, timeout=600):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def _is_real_build_dockerfile(rel_path: str) -> bool:
    low = "/" + rel_path.replace("\\", "/").lower()
    return not any(seg in low for seg in EXCLUDE_SEGMENTS)


def _iter_copy_sources(dockerfile_text: str):
    """Yield the source paths of every COPY/ADD instruction.

    Skips what cannot serve as filesystem evidence: ``--from=`` stage
    copies, URLs, sources containing unresolved ``$`` variables, and
    JSON-form parsing failures. Flags (``--chown``, ``--chmod``,
    ``--link``, ``--parents``, ``--exclude=...``) are stripped. The
    last operand is the destination and is not yielded.
    """
    # Join backslash continuations into logical lines.
    logical, buf = [], ""
    for raw in dockerfile_text.splitlines():
        line = raw.rstrip()
        if buf:
            buf += " " + line.strip()
        else:
            buf = line
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
            continue
        logical.append(buf)
        buf = ""
    if buf:
        logical.append(buf)

    for line in logical:
        s = line.strip()
        up = s.upper()
        if not (up.startswith("COPY ") or up.startswith("ADD ")):
            continue
        rest = s.split(None, 1)[1] if " " in s else ""
        # JSON form: COPY ["a", "b", "dest"]
        if rest.lstrip().startswith("["):
            try:
                arr = json.loads(rest[rest.index("["):])
                ops = [str(x) for x in arr]
            except (ValueError, IndexError):
                continue
        else:
            ops = rest.split()
        # Strip flags; a --from= copy references a build stage or an
        # external image, not the build context, so it is no evidence.
        if any(o.startswith("--from=") for o in ops):
            continue
        ops = [o for o in ops if not o.startswith("--")]
        if len(ops) < 2:
            continue
        for src in ops[:-1]:
            src = src.strip('"').strip("'")
            if not src or "$" in src or "://" in src:
                continue
            yield src


def infer_build_context(dockerfile: Path, repo_root: Path):
    """Choose the build context by testing COPY/ADD sources on disk.

    There is no universal answer to "what is the context of a
    subdirectory Dockerfile": huginn's ``docker/single-process/
    Dockerfile`` copies ``Gemfile.lock`` from the repo root, while
    dolibarr's ``build/docker/Dockerfile`` copies ``docker-run.sh``
    from its own directory. Any single global choice spuriously fails
    one class or the other, and a spurious baseline build failure
    silently removes that image from every downstream statistic.

    The Dockerfile itself carries the answer: its COPY/ADD sources
    resolve against exactly one of the candidate roots. Score each
    candidate by how many sources exist beneath it and take the
    winner. Sources like ``.`` that exist everywhere score nothing.
    A tie with no evidence defaults to the repo root, which matches
    the dominant convention for subdirectory Dockerfiles
    (``docker build -f docker/Dockerfile .``), and the ambiguity is
    recorded in the manifest so a context-caused failure is
    diagnosable rather than mysterious.

    Returns (context_path, basis_string).
    """
    df_dir = dockerfile.parent
    if df_dir.resolve() == repo_root.resolve():
        return repo_root, "dockerfile-at-root"

    try:
        text = dockerfile.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return repo_root, "unreadable-default-root"

    candidates = [repo_root, df_dir]
    scores = {id(c): 0 for c in candidates}
    evidence = 0
    for src in _iter_copy_sources(text):
        norm = src.lstrip("./")
        if norm in ("", ".", ".."):
            continue        # exists under every candidate: no evidence
        evidence += 1
        for c in candidates:
            try:
                if list(c.glob(norm)) or (c / norm).exists():
                    scores[id(c)] += 1
            except (OSError, ValueError):
                continue

    root_score, dir_score = scores[id(repo_root)], scores[id(df_dir)]
    if dir_score > root_score:
        return df_dir, f"copy-evidence:dockerfile-dir({dir_score}v{root_score})"
    if root_score > dir_score:
        return repo_root, f"copy-evidence:root({root_score}v{dir_score})"
    if evidence == 0:
        return repo_root, "no-evidence-default-root"
    return repo_root, f"tie-default-root({root_score}v{dir_score})"


def find_dockerfile(repo_dir: Path):
    """Return (dockerfile_path, context_dir) or (None, None).

    Only accepts a genuine build Dockerfile; dev-container, test-fixture,
    docs and arch-specific variants are rejected so we never measure on a
    Dockerfile that is not the project's real image (criterion I1).
    """
    for rel in CANDIDATE_PATHS:
        p = repo_dir / rel
        if p.is_file() and _is_real_build_dockerfile(rel):
            return p, repo_dir
    best = None
    for p in repo_dir.rglob("Dockerfile"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(repo_dir))
        if not _is_real_build_dockerfile(rel):
            continue
        depth = len(Path(rel).parts)
        if best is None or depth < best[1]:
            best = (p, depth)
    if best:
        return best[0], repo_dir
    return None, None


def _resolve_legacy_tag(repo_dir: Path, cutoff: datetime):
    """Newest STABLE release tag older than the cutoff, chosen
    mechanically from git history. Returns (tag, sha, iso_date) or None.

    'Newest tag older than the cutoff' rather than 'oldest tag' is
    deliberate: the oldest tag of a long-lived project may predate
    Docker entirely, while the newest pre-cutoff release is the version
    an organisation that stopped upgrading N years ago would actually
    be running, which is the population the legacy stratum models.
    """
    code, out, _ = sh(["git", "for-each-ref", "--sort=creatordate",
                       "--format=%(refname:short)\t%(creatordate:iso8601-strict)\t%(objectname)",
                       "refs/tags"], cwd=str(repo_dir))
    if code != 0:
        return None
    best = None
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        tag, date_s, sha = parts
        if not _STABLE_TAG_RE.match(tag.strip()):
            continue
        try:
            when = datetime.fromisoformat(date_s.strip())
        except ValueError:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when <= cutoff:
            best = (tag.strip(), sha.strip(), when.isoformat())
        else:
            break  # sorted ascending; everything after is too new
    return best


def _collect_entry(name, url, df, ctx, repo_dir, stratum, ref, ref_sha,
                   ref_date):
    text = df.read_text(encoding="utf-8", errors="replace")
    from_count = sum(1 for ln in text.splitlines()
                     if ln.strip().upper().startswith("FROM "))
    base_images = [ln.split()[1] for ln in text.splitlines()
                   if ln.strip().upper().startswith("FROM ")
                   and len(ln.split()) > 1]
    # The context is inferred per Dockerfile from its COPY/ADD sources,
    # NOT assumed to be the repo root. See infer_build_context: a wrong
    # context makes the baseline build fail spuriously, which silently
    # deletes the image from every downstream statistic.
    context, context_basis = infer_build_context(df, repo_dir)
    return {
        "name": f"{name}@legacy" if stratum == "legacy" else name,
        "project": name,
        "stratum": stratum,
        "repo": url,
        "ref": ref,
        "ref_sha": ref_sha,
        "ref_date": ref_date,
        "dockerfile": str(df),
        "context": str(context),
        "context_basis": context_basis,
        "dockerfile_rel": str(df.relative_to(repo_dir)),
        "from_count": from_count,
        "base_images": base_images,
        "multistage": from_count > 1,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("workdir", nargs="?", default="real_repos")
    ap.add_argument("--legacy-cutoff-years", type=float, default=4.0,
                    help="Legacy stratum: newest stable release tag older "
                         "than this many years (default 4). The tag is "
                         "resolved from git history, never hand-picked.")
    ap.add_argument("--no-legacy", action="store_true",
                    help="Collect only the current stratum.")
    args = ap.parse_args()

    workdir = Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    cutoff = datetime.now(timezone.utc) - timedelta(
        days=365.25 * args.legacy_cutoff_years)

    manifest = []
    cloned, no_df, no_legacy = 0, 0, 0

    for name, url in REPOS.items():
        dest = workdir / name
        if not dest.exists():
            print(f"[clone] {name} <- {url}")
            # blob:none keeps the clone small while retaining full tag
            # history, which the legacy stratum needs; --depth 1 does not.
            code, _, err = sh(["git", "clone", "--filter=blob:none",
                               "--single-branch", url, str(dest)],
                              timeout=900)
            if code != 0:
                print(f"  ! clone failed: {err.strip()[:160]}")
                continue
        cloned += 1

        # ── Current stratum: repository HEAD ────────────────────────
        code, sha_out, _ = sh(["git", "rev-parse", "HEAD"], cwd=str(dest))
        head_sha = sha_out.strip() if code == 0 else ""
        df, ctx = find_dockerfile(dest)
        if df:
            manifest.append(_collect_entry(
                name, url, df, ctx, dest, "current", "HEAD", head_sha, None))
            print(f"  [+] {name}: {df.relative_to(dest)} "
                  f"(FROM x{manifest[-1]['from_count']}"
                  f"{', multistage' if manifest[-1]['multistage'] else ''})")
        else:
            print(f"  ! no Dockerfile found in {name}")
            no_df += 1

        # ── Legacy stratum: newest stable tag older than cutoff ─────
        if args.no_legacy:
            continue
        legacy = _resolve_legacy_tag(dest, cutoff)
        if not legacy:
            print(f"  - {name}: no stable tag older than the cutoff")
            no_legacy += 1
            continue
        tag, tag_sha, tag_date = legacy
        legacy_dir = workdir / f"{name}@legacy"
        if not legacy_dir.exists():
            code, _, err = sh(["git", "worktree", "add", "--detach",
                               str(legacy_dir), tag], cwd=str(dest),
                              timeout=900)
            if code != 0:
                print(f"  ! legacy checkout of {tag} failed: "
                      f"{err.strip()[:160]}")
                no_legacy += 1
                continue
        ldf, lctx = find_dockerfile(legacy_dir)
        if not ldf:
            # A release that predates the project's Docker support is a
            # legitimate mechanical outcome, not an error.
            print(f"  - {name}@{tag}: release has no Dockerfile")
            no_legacy += 1
            continue
        manifest.append(_collect_entry(
            name, url, ldf, lctx, legacy_dir, "legacy", tag, tag_sha,
            tag_date))
        print(f"  [+] {name}@legacy ({tag}, {tag_date[:10]}): "
              f"{ldf.relative_to(legacy_dir)} "
              f"(FROM x{manifest[-1]['from_count']})")

    out = workdir / "manifest.json"
    doc = {
        "criteria_version": CRITERIA_VERSION,
        "collected": datetime.now(timezone.utc).isoformat(),
        "criteria": {
            "I1": "real build Dockerfile; dev/test/docs/arch variants "
                  "excluded mechanically (EXCLUDE_SEGMENTS)",
            "I2": "self-contained build; failures reported, never dropped",
            "I3": "fits 4 vCPU / 6 GB; heavy monorepos excluded (disclosed)",
            "I4": "quota-stratified across Go/Rust/Node/Python/JVM/PHP-Ruby",
            "I5": "established projects with real user bases",
            "legacy_stratum": (
                f"newest stable release tag older than "
                f"{args.legacy_cutoff_years} years, resolved from git "
                f"history; same projects as the current stratum so "
                f"current-vs-legacy comparisons are paired"
            ),
        },
        "known_biases": [
            "public open-source only; private production Dockerfiles are "
            "unobservable",
            "popularity bias: established projects tend to better "
            "Dockerfile hygiene, which makes the corpus HARDER for a "
            "remediation tool, not easier",
            "resource cap excludes the largest builds",
        ],
        "entries": manifest,
    }
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    cur = sum(1 for m in manifest if m["stratum"] == "current")
    leg = sum(1 for m in manifest if m["stratum"] == "legacy")
    ms = sum(1 for m in manifest if m["multistage"])
    print(f"\nRepos cloned: {cloned} | entries: {len(manifest)} "
          f"(current: {cur}, legacy: {leg}) | multi-stage: {ms} | "
          f"no-df: {no_df} | no-legacy-tag: {no_legacy}")
    print(f"Manifest: {out}")


if __name__ == "__main__":
    main()
