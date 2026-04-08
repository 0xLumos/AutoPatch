"""
Automated Pull Request Creator

Creates pull requests with full audit trail for AutoPatch remediation.
Supports GitHub (via gh CLI) and GitLab (via glab CLI).

The PR includes:
- Dockerfile diff (before/after)
- Vulnerability reduction summary
- SBOM diff summary
- Link to full scan reports
- Acceptance criteria result
- Signing verification status
"""

import logging
import os
import tempfile
from typing import Any, Dict, List, Optional

from .utils import run_cmd, generate_diff

logger = logging.getLogger("docker_patch_tool")


class PRCreationError(Exception):
    """Raised when PR creation fails."""
    pass


def is_git_repo(path: str = ".") -> bool:
    """Check if the given path is inside a git repository."""
    code, _ = run_cmd(["git", "-C", path, "rev-parse", "--git-dir"])
    return code == 0


def is_gh_available() -> bool:
    """Check if GitHub CLI (gh) is installed and authenticated."""
    code, _ = run_cmd(["gh", "auth", "status"])
    return code == 0


def create_remediation_branch(
    base_branch: str = "main",
    image_name: str = "",
    work_dir: str = ".",
) -> str:
    """
    Create a new branch for the remediation changes.

    Args:
        base_branch: Branch to base the PR on
        image_name: Image name for branch naming
        work_dir: Git repository working directory

    Returns:
        Name of the created branch

    Raises:
        PRCreationError: If branch creation fails
    """
    # Sanitize image name for branch naming
    safe_name = image_name.replace("/", "-").replace(":", "-").replace(".", "-")
    branch_name = f"autopatch/remediate-{safe_name}"

    # Create and checkout branch
    code, output = run_cmd(
        ["git", "-C", work_dir, "checkout", "-b", branch_name, base_branch]
    )
    if code != 0:
        raise PRCreationError(f"Failed to create branch {branch_name}: {output}")

    logger.info(f"Created remediation branch: {branch_name}")
    return branch_name


def commit_changes(
    files: List[str],
    message: str,
    work_dir: str = ".",
) -> bool:
    """
    Stage and commit the specified files.

    Args:
        files: List of file paths to stage (relative to work_dir)
        message: Commit message
        work_dir: Git repository working directory

    Returns:
        True if commit succeeds
    """
    # Stage files
    for f in files:
        code, output = run_cmd(["git", "-C", work_dir, "add", f])
        if code != 0:
            logger.warning(f"Failed to stage {f}: {output}")

    # Commit
    code, output = run_cmd(
        ["git", "-C", work_dir, "commit", "-m", message]
    )
    if code != 0:
        logger.error(f"Commit failed: {output}")
        return False

    return True


def generate_pr_body(
    original_base: str,
    patched_base: str,
    metrics: Dict[str, Any],
    vuln_diff: Dict[str, List[Dict[str, Any]]],
    dockerfile_diff: str,
    acceptance_result: Optional[tuple] = None,
    signing_status: Optional[str] = None,
) -> str:
    """
    Generate a detailed PR description with full audit trail.

    Args:
        original_base: Original base image
        patched_base: New base image
        metrics: Computed metrics from comparer.compute_metrics()
        vuln_diff: Vulnerability diff from comparer.diff_vulnerabilities()
        dockerfile_diff: Unified diff of Dockerfile changes
        acceptance_result: Tuple of (accepted, reasons) from check_acceptance_criteria
        signing_status: Description of signing verification result

    Returns:
        Markdown-formatted PR body
    """
    resolved_count = len(vuln_diff.get("resolved", []))
    remaining_count = len(vuln_diff.get("remaining", []))
    new_count = len(vuln_diff.get("new", []))
    reduction_pct = metrics.get("vulnerability_reduction_pct", 0)

    body_lines = [
        "## AutoPatch Remediation Summary",
        "",
        f"**Base image change:** `{original_base}` -> `{patched_base}`",
        "",
        "### Vulnerability Impact",
        "",
        f"| Metric | Before | After | Change |",
        f"|--------|--------|-------|--------|",
        f"| Total CVEs | {metrics.get('total_before', '?')} | {metrics.get('total_after', '?')} | {reduction_pct:.1f}% reduction |",
    ]

    # Per-severity breakdown
    before_sev = metrics.get("per_severity_before", {})
    after_sev = metrics.get("per_severity_after", {})
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        b = before_sev.get(sev, 0)
        a = after_sev.get(sev, 0)
        change = b - a
        body_lines.append(f"| {sev} | {b} | {a} | {'+' if change < 0 else '-'}{abs(change)} |")

    body_lines.extend([
        "",
        f"**CVEs resolved:** {resolved_count}",
        f"**CVEs remaining:** {remaining_count}",
        f"**New CVEs introduced:** {new_count}",
        "",
    ])

    # Acceptance criteria
    if acceptance_result:
        accepted, reasons = acceptance_result
        status = "PASSED" if accepted else "FAILED"
        body_lines.extend([
            f"### Acceptance Criteria: {status}",
            "",
        ])
        if reasons:
            for r in reasons:
                body_lines.append(f"- {r}")
            body_lines.append("")

    # Signing status
    if signing_status:
        body_lines.extend([
            f"### Supply Chain Signing: {signing_status}",
            "",
        ])

    # Dockerfile diff
    if dockerfile_diff:
        body_lines.extend([
            "### Dockerfile Changes",
            "",
            "```diff",
            dockerfile_diff[:3000],  # Cap to avoid huge PRs
            "```",
            "",
        ])

    body_lines.extend([
        "---",
        "*Generated by [AutoPatch](https://github.com/0xLumos/AutoPatch)*",
    ])

    return "\n".join(body_lines)


def create_pull_request(
    title: str,
    body: str,
    branch: str,
    base_branch: str = "main",
    work_dir: str = ".",
    labels: Optional[List[str]] = None,
    draft: bool = False,
) -> Optional[str]:
    """
    Create a GitHub Pull Request using gh CLI.

    Args:
        title: PR title
        body: PR body (markdown)
        branch: Source branch name
        base_branch: Target branch name
        work_dir: Git repository working directory
        labels: Optional list of labels to apply
        draft: If True, create as draft PR

    Returns:
        PR URL if created successfully, None otherwise

    Raises:
        PRCreationError: If gh CLI is not available or PR creation fails
    """
    if not is_gh_available():
        raise PRCreationError(
            "GitHub CLI (gh) not found or not authenticated. "
            "Install from https://cli.github.com and run 'gh auth login'."
        )

    # Push branch first
    code, output = run_cmd(
        ["git", "-C", work_dir, "push", "-u", "origin", branch]
    )
    if code != 0:
        raise PRCreationError(f"Failed to push branch {branch}: {output}")

    # Build gh pr create command
    cmd = [
        "gh", "pr", "create",
        "--title", title,
        "--body", body,
        "--base", base_branch,
        "--head", branch,
    ]

    if draft:
        cmd.append("--draft")

    if labels:
        for label in labels:
            cmd.extend(["--label", label])

    code, output = run_cmd(cmd)
    if code != 0:
        raise PRCreationError(f"Failed to create PR: {output}")

    # Extract PR URL from output
    pr_url = output.strip()
    logger.info(f"Pull request created: {pr_url}")
    return pr_url


def create_remediation_pr(
    dockerfile_path: str,
    original_base: str,
    patched_base: str,
    metrics: Dict[str, Any],
    vuln_diff: Dict[str, List[Dict[str, Any]]],
    original_dockerfile: str,
    patched_dockerfile: str,
    acceptance_result: Optional[tuple] = None,
    signing_status: Optional[str] = None,
    base_branch: str = "main",
    draft: bool = False,
) -> Optional[str]:
    """
    High-level function to create a complete remediation PR.

    Handles branch creation, file staging, commit, and PR creation.

    Args:
        dockerfile_path: Path to the Dockerfile being patched
        original_base: Original base image
        patched_base: New base image
        metrics: Computed metrics
        vuln_diff: Vulnerability diff
        original_dockerfile: Original Dockerfile content
        patched_dockerfile: Patched Dockerfile content
        acceptance_result: Acceptance criteria result
        signing_status: Signing verification status
        base_branch: Branch to create PR against
        draft: Create as draft PR

    Returns:
        PR URL if successful, None if PR creation was skipped or failed
    """
    work_dir = os.path.dirname(os.path.abspath(dockerfile_path)) or "."

    if not is_git_repo(work_dir):
        logger.info("Not a git repository; skipping PR creation")
        return None

    try:
        # Generate diff
        dockerfile_diff = generate_diff(original_dockerfile, patched_dockerfile)

        # Create branch
        image_name = patched_base.split(":")[0] if ":" in patched_base else patched_base
        branch = create_remediation_branch(base_branch, image_name, work_dir)

        # Commit the patched Dockerfile
        commit_changes(
            files=[os.path.basename(dockerfile_path)],
            message=(
                f"fix: remediate vulnerabilities in {original_base}\n\n"
                f"Base image: {original_base} -> {patched_base}\n"
                f"Vulnerability reduction: {metrics.get('vulnerability_reduction_pct', 0):.1f}%\n"
                f"Generated by AutoPatch"
            ),
            work_dir=work_dir,
        )

        # Generate PR body
        reduction_pct = metrics.get("vulnerability_reduction_pct", 0)
        title = f"fix: reduce vulnerabilities by {reduction_pct:.0f}% ({original_base})"

        body = generate_pr_body(
            original_base=original_base,
            patched_base=patched_base,
            metrics=metrics,
            vuln_diff=vuln_diff,
            dockerfile_diff=dockerfile_diff,
            acceptance_result=acceptance_result,
            signing_status=signing_status,
        )

        # Create PR
        pr_url = create_pull_request(
            title=title,
            body=body,
            branch=branch,
            base_branch=base_branch,
            work_dir=work_dir,
            labels=["autopatch", "security"],
            draft=draft,
        )

        return pr_url

    except PRCreationError as e:
        logger.error(f"PR creation failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during PR creation: {e}")
        return None
