"""Tests for the automated pull-request path (``src/pr_creator.py``).

This module is the only part of AutoPatch that writes to a repository
the operator owns. Everything else produces artefacts; this produces a
commit and a PR that a human will review and probably merge. That makes
three failure classes far more expensive than a normal bug:

1. **Contaminated commits.** ``git checkout -b <new> <base>`` carries
   uncommitted working-tree changes onto the new branch, so a run on a
   dirty tree can ship unrelated local edits inside a PR titled "fix:
   reduce vulnerabilities". The dirty-tree guard is asserted here in
   both directions, because a guard that never fires and a guard that
   always fires are equally useless.
2. **Misleading PR bodies.** The body is the audit trail a reviewer
   reads before approving a base-image change. A sign flipped in the
   per-severity table turns "8 fewer CRITICALs" into "8 more", and
   nothing downstream would catch it.
3. **Branch-name injection.** The branch name is derived from an image
   reference, which is attacker-influenced in any registry the operator
   does not control. The sanitiser is asserted on the characters that
   actually matter to git ref syntax.

Nothing here may run git, gh, or any subprocess: ``run_cmd`` is stubbed
in every test. ``generate_diff`` is left real because it is pure
difflib with no I/O, and stubbing it would hide diff regressions.
"""
from __future__ import annotations

import os

import pytest

from src import pr_creator
from src.pr_creator import (
    PRCreationError,
    commit_changes,
    create_pull_request,
    create_remediation_branch,
    create_remediation_pr,
    generate_pr_body,
    is_gh_available,
    is_git_repo,
)


class FakeRun:
    """Stub for ``pr_creator.run_cmd``.

    Responses are matched by "every token in the pattern appears in the
    argv", first match wins. That is deliberately loose about the
    ``-C <dir>`` insertion git uses while still distinguishing
    ``git status`` from ``gh auth status``.
    """

    def __init__(self, default=(0, "")):
        self.default = default
        self.responses: list[tuple[list[str], tuple[int, str]]] = []
        self.calls: list[list[str]] = []

    def when(self, tokens, response):
        self.responses.append((list(tokens), response))
        return self

    def __call__(self, cmd, **kwargs):
        argv = list(cmd)
        self.calls.append(argv)
        for tokens, response in self.responses:
            if all(t in argv for t in tokens):
                return response
        return self.default

    def find(self, *tokens):
        """Return the single argv containing all of ``tokens``."""
        hits = [c for c in self.calls if all(t in c for t in tokens)]
        assert len(hits) == 1, f"expected exactly one {tokens} call, got {hits}"
        return hits[0]

    def any_call(self, *tokens) -> bool:
        return any(all(t in c for t in tokens) for c in self.calls)


@pytest.fixture
def run(monkeypatch) -> FakeRun:
    fake = FakeRun()
    monkeypatch.setattr(pr_creator, "run_cmd", fake)
    return fake


def flag_value(cmd: list, flag: str) -> str:
    assert flag in cmd, f"{flag} missing from {cmd}"
    return cmd[cmd.index(flag) + 1]


METRICS = {
    "total_before": 120,
    "total_after": 14,
    "vulnerability_reduction_pct": 88.333,
    "per_severity_before": {"CRITICAL": 10, "HIGH": 30, "MEDIUM": 60,
                            "LOW": 20},
    "per_severity_after": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 10, "LOW": 2},
}

VULN_DIFF = {
    "resolved": [{"id": f"CVE-2024-{n}"} for n in range(106)],
    "remaining": [{"id": "CVE-2023-1"}, {"id": "CVE-2023-2"}],
    "new": [{"id": "CVE-2025-9"}],
}


class TestEnvironmentProbes:
    """These two functions gate everything else. Inverting either one
    would either skip PR creation on every valid repo or attempt a push
    from a directory that is not a repo at all."""

    def test_git_repo_probe_is_scoped_to_the_path(self, run):
        assert is_git_repo("/srv/checkout") is True
        assert run.calls[0] == ["git", "-C", "/srv/checkout", "rev-parse",
                               "--git-dir"]

    def test_git_repo_probe_reports_failure(self, monkeypatch):
        monkeypatch.setattr(pr_creator, "run_cmd", FakeRun(default=(128, "")))
        assert is_git_repo("/tmp") is False

    def test_gh_probe_checks_authentication_not_just_presence(self, run):
        """``gh --version`` succeeds on an unauthenticated install, so
        probing that instead would let PR creation fail at the last
        step after the branch was already pushed."""
        assert is_gh_available() is True
        assert run.calls[0] == ["gh", "auth", "status"]

    def test_gh_probe_reports_unauthenticated(self, monkeypatch):
        monkeypatch.setattr(pr_creator, "run_cmd",
                            FakeRun(default=(1, "not logged in")))
        assert is_gh_available() is False


class TestCreateRemediationBranch:

    def test_dirty_tree_is_refused(self, run):
        run.when(["status", "--porcelain"], (0, " M src/app.py\n?? secret.env\n"))
        with pytest.raises(PRCreationError) as exc:
            create_remediation_branch("main", "debian", "/repo")
        assert "dirty tree" in str(exc.value)
        assert "src/app.py" in str(exc.value), \
            "operator cannot act on the refusal without the file list"

    def test_dirty_tree_check_runs_before_checkout(self, run):
        run.when(["status", "--porcelain"], (0, " M Dockerfile\n"))
        with pytest.raises(PRCreationError):
            create_remediation_branch("main", "debian", "/repo")
        assert not run.any_call("checkout"), \
            "branch was created despite the dirty-tree refusal"

    def test_whitespace_only_status_is_treated_as_clean(self, run):
        """git prints a bare newline in some configurations; treating
        that as dirty would block every legitimate run."""
        run.when(["status", "--porcelain"], (0, "\n  \n"))
        assert create_remediation_branch("main", "debian", "/repo") == \
            "autopatch/remediate-debian"

    def test_unreadable_status_aborts(self, run):
        """A failing status probe means the tree state is unknown. Going
        ahead would be the same as assuming it is clean."""
        run.when(["status", "--porcelain"], (129, "fatal: not a git repo"))
        with pytest.raises(PRCreationError) as exc:
            create_remediation_branch("main", "debian", "/repo")
        assert "fatal: not a git repo" in str(exc.value)
        assert not run.any_call("checkout")

    def test_checkout_argv_bases_the_branch_explicitly(self, run):
        """Omitting the base would branch from whatever HEAD happens to
        be, which on a CI runner is often a detached commit."""
        create_remediation_branch("release/2.1", "nginx", "/repo")
        cmd = run.find("checkout")
        assert cmd == ["git", "-C", "/repo", "checkout", "-b",
                       "autopatch/remediate-nginx", "release/2.1"]

    def test_checkout_failure_raises(self, run):
        run.when(["checkout"], (1, "fatal: a branch named ... already exists"))
        with pytest.raises(PRCreationError) as exc:
            create_remediation_branch("main", "nginx", "/repo")
        assert "already exists" in str(exc.value)

    @pytest.mark.parametrize("image,expected", [
        ("debian", "autopatch/remediate-debian"),
        ("debian:12", "autopatch/remediate-debian-12"),
        ("library/debian:12.5", "autopatch/remediate-library-debian-12-5"),
        ("ghcr.io/acme/app:1.2.3",
         "autopatch/remediate-ghcr-io-acme-app-1-2-3"),
    ])
    def test_branch_name_sanitisation(self, run, image, expected):
        assert create_remediation_branch("main", image, "/repo") == expected

    def test_dot_dot_cannot_survive_into_the_ref(self, run):
        """``..`` is illegal inside a git ref name; a tag such as
        ``app:1..2`` would otherwise produce a branch git refuses to
        create, failing the whole run at the checkout step."""
        name = create_remediation_branch("main", "app:1..2", "/repo")
        assert ".." not in name

    def test_branch_is_namespaced_under_autopatch(self, run):
        """The prefix is what stops a hostile image name from being
        interpreted as a git option, since the ref can never start with
        a dash."""
        name = create_remediation_branch("main", "--upload-pack=evil", "/repo")
        assert name.startswith("autopatch/remediate-")
        assert not name.startswith("-")


class TestCommitChanges:

    def test_each_file_is_staged_individually(self, run):
        assert commit_changes(["Dockerfile", "sbom.json"], "msg", "/repo") is True
        assert run.find("add", "Dockerfile") == \
            ["git", "-C", "/repo", "add", "Dockerfile"]
        assert run.any_call("add", "sbom.json")

    def test_commit_message_is_passed_as_one_argument(self, run):
        """A multi-line message split across argv would silently lose the
        body of the commit."""
        message = "fix: subject\n\nbody line\n"
        commit_changes(["Dockerfile"], message, "/repo")
        assert flag_value(run.find("commit"), "-m") == message

    def test_commit_failure_returns_false(self, run):
        run.when(["commit"], (1, "nothing to commit, working tree clean"))
        assert commit_changes(["Dockerfile"], "msg", "/repo") is False

    def test_staging_failure_aborts_before_committing(self, run):
        """Fixed defect: a failed ``git add`` was only logged at warning
        level and staging continued, so a file that could not be staged
        produced a partial commit that reported success. In practice
        that is the patched Dockerfile going missing from the PR while
        the pipeline says the remediation shipped."""
        run.when(["add", "missing.txt"], (128, "pathspec did not match"))
        assert commit_changes(["missing.txt"], "msg", "/repo") is False
        assert not run.any_call("commit"), \
            "a commit was made after a file failed to stage"

    def test_first_staging_failure_stops_the_remaining_adds(self, run):
        """Continuing after the first failure would stage the files that
        happen to work and hand git a commit nobody asked for."""
        run.when(["add", "Dockerfile"], (128, "pathspec did not match"))
        assert commit_changes(["Dockerfile", "sbom.json"], "msg", "/repo") \
            is False
        assert not run.any_call("add", "sbom.json")

    def test_no_files_still_attempts_a_commit(self, run):
        commit_changes([], "msg", "/repo")
        assert not run.any_call("add")
        assert run.any_call("commit")


class TestGeneratePrBody:
    """The body is the audit trail. Every number in it must be traceable
    to the metrics that produced it."""

    def body(self, **overrides):
        kwargs = dict(
            original_base="debian:10",
            patched_base="debian:12-slim",
            metrics=METRICS,
            vuln_diff=VULN_DIFF,
            dockerfile_diff="--- a\n+++ b\n-FROM debian:10\n+FROM debian:12-slim\n",
        )
        kwargs.update(overrides)
        return generate_pr_body(**kwargs)

    def test_base_image_transition_is_stated(self):
        body = self.body()
        assert "`debian:10` -> `debian:12-slim`" in body

    def test_totals_come_from_metrics(self):
        body = self.body()
        assert "| Total CVEs | 120 | 14 | 88.3% reduction |" in body

    def test_counts_come_from_the_diff_not_the_metrics(self):
        """These two inputs are computed independently; if the body read
        the counts off metrics instead, a diff/metrics disagreement
        would be invisible to the reviewer."""
        body = self.body()
        assert "**CVEs resolved:** 106" in body
        assert "**CVEs remaining:** 2" in body
        assert "**New CVEs introduced:** 1" in body

    def test_severity_reduction_uses_a_minus_sign(self):
        body = self.body()
        assert "| CRITICAL | 10 | 0 | -10 |" in body
        assert "| HIGH | 30 | 2 | -28 |" in body

    def test_severity_regression_uses_a_plus_sign(self):
        """A patched image that adds CRITICALs must not be rendered as a
        reduction; this is the single most consequential sign in the
        table."""
        body = self.body(metrics={
            **METRICS,
            "per_severity_before": {"CRITICAL": 1},
            "per_severity_after": {"CRITICAL": 9},
        })
        assert "| CRITICAL | 1 | 9 | +8 |" in body

    def test_all_four_severities_are_always_rendered(self):
        """Omitting a severity because it is absent from the metrics
        would make a reviewer assume it was not measured."""
        body = self.body(metrics={"vulnerability_reduction_pct": 0.0})
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert f"| {sev} | 0 | 0 |" in body

    def test_missing_totals_render_as_unknown_not_zero(self):
        """Reporting an unmeasured total as 0 would look like a perfect
        result."""
        body = self.body(metrics={"vulnerability_reduction_pct": 0.0})
        assert "| Total CVEs | ? | ? |" in body

    def test_failed_acceptance_is_reported_as_failed(self):
        body = self.body(acceptance_result=(False, ["new CRITICAL introduced"]))
        assert "### Acceptance Criteria: FAILED" in body
        assert "- new CRITICAL introduced" in body
        assert "PASSED" not in body

    def test_passed_acceptance_is_reported_as_passed(self):
        body = self.body(acceptance_result=(True, ["all gates met"]))
        assert "### Acceptance Criteria: PASSED" in body
        assert "- all gates met" in body

    def test_acceptance_section_absent_when_not_evaluated(self):
        """No acceptance result means the gate did not run. Rendering a
        section would imply it did."""
        assert "Acceptance Criteria" not in self.body()

    def test_signing_status_is_surfaced(self):
        body = self.body(signing_status="verified (keyless, GitHub OIDC)")
        assert "### Supply Chain Signing: verified (keyless, GitHub OIDC)" \
            in body

    def test_signing_section_absent_when_unsigned(self):
        assert "Supply Chain Signing" not in self.body()

    def test_dockerfile_diff_is_fenced_as_a_diff(self):
        body = self.body()
        assert "```diff" in body
        assert "+FROM debian:12-slim" in body

    def test_diff_section_absent_when_dockerfile_unchanged(self):
        assert "Dockerfile Changes" not in self.body(dockerfile_diff="")

    def test_oversized_diff_is_truncated(self):
        """GitHub rejects PR bodies over 65536 bytes; an untruncated
        diff of a large Dockerfile would fail the create call after the
        branch had already been pushed."""
        huge = "+" + "x" * 10000
        body = self.body(dockerfile_diff=huge)
        assert "+" + "x" * 2999 in body
        assert "x" * 3000 not in body

    def test_body_is_attributed(self):
        assert "AutoPatch" in self.body().splitlines()[-1]


class TestCreatePullRequest:
    """``create_pull_request`` now insists on seeing a URL in gh's
    stdout, so every test below that is not about the failure path has
    to stub one. Using the real shape of gh output rather than a bare
    ``(0, "")`` keeps these tests exercising the same parse the pipeline
    depends on."""

    PR_CREATED = (0, "https://github.com/acme/x/pull/7\n")

    def test_missing_gh_raises_before_pushing(self, run):
        """Pushing first and failing at ``gh pr create`` would leave an
        orphan branch on the remote."""
        run.when(["gh", "auth", "status"], (1, "not authenticated"))
        with pytest.raises(PRCreationError) as exc:
            create_pull_request("t", "b", "feature", work_dir="/repo")
        assert "gh auth login" in str(exc.value)
        assert not run.any_call("push")

    def test_push_sets_upstream(self, run):
        """Without -u the later ``gh pr create --head`` has no remote
        branch to point at."""
        run.when(["pr", "create"], self.PR_CREATED)
        create_pull_request("t", "b", "feature", work_dir="/repo")
        assert run.find("push") == ["git", "-C", "/repo", "push", "-u",
                                    "origin", "feature"]

    def test_push_failure_raises_before_pr_create(self, run):
        run.when(["push"], (1, "remote rejected: protected branch"))
        with pytest.raises(PRCreationError) as exc:
            create_pull_request("t", "b", "feature", work_dir="/repo")
        assert "protected branch" in str(exc.value)
        assert not run.any_call("pr", "create")

    def test_pr_argv_carries_title_body_base_and_head(self, run):
        run.when(["pr", "create"], (0, "https://github.com/acme/x/pull/7\n"))
        url = create_pull_request("my title", "my body", "feature",
                                  base_branch="develop", work_dir="/repo")
        cmd = run.find("pr", "create")
        assert flag_value(cmd, "--title") == "my title"
        assert flag_value(cmd, "--body") == "my body"
        assert flag_value(cmd, "--base") == "develop"
        assert flag_value(cmd, "--head") == "feature"
        assert url == "https://github.com/acme/x/pull/7"

    def test_draft_flag_is_opt_in(self, run):
        run.when(["pr", "create"], self.PR_CREATED)
        create_pull_request("t", "b", "feature", work_dir="/repo")
        assert "--draft" not in run.find("pr", "create")

    def test_draft_flag_is_added_when_requested(self, run):
        run.when(["pr", "create"], self.PR_CREATED)
        create_pull_request("t", "b", "feature", work_dir="/repo", draft=True)
        assert "--draft" in run.find("pr", "create")

    def test_each_label_gets_its_own_flag(self, run):
        """gh does accept a comma-joined --label, but a label containing
        a comma would then be split into two. One flag per label is the
        only correct encoding."""
        run.when(["pr", "create"], self.PR_CREATED)
        create_pull_request("t", "b", "feature", work_dir="/repo",
                            labels=["autopatch", "security"])
        cmd = run.find("pr", "create")
        assert cmd.count("--label") == 2
        assert "autopatch" in cmd and "security" in cmd

    def test_pr_create_failure_raises(self, run):
        run.when(["pr", "create"], (1, "GraphQL: no commits between branches"))
        with pytest.raises(PRCreationError) as exc:
            create_pull_request("t", "b", "feature", work_dir="/repo")
        assert "no commits between branches" in str(exc.value)

    def test_url_is_extracted_from_noisy_gh_output(self, run):
        """Fixed defect: the whole stripped stdout was returned as the
        "PR URL". gh routinely prints deprecation notices and uncommitted
        change warnings on stdout alongside the link, so the value that
        reached the report, the CI annotation and any caller trying to
        open it was a banner with a URL buried inside it."""
        run.when(["pr", "create"],
                 (0, "Warning: 3 uncommitted changes\n"
                     "https://github.com/acme/x/pull/7\n"))
        url = create_pull_request("t", "b", "feature", work_dir="/repo")
        assert url == "https://github.com/acme/x/pull/7"

    def test_trailing_notice_after_the_url_is_ignored(self, run):
        """gh also prints after the link on some versions. Scanning in
        reverse for the last URL line keeps the created PR winning over
        anything gh advertises around it."""
        run.when(["pr", "create"],
                 (0, "https://github.com/acme/x/pull/7\n"
                     "A new release of gh is available\n"))
        assert create_pull_request("t", "b", "feature", work_dir="/repo") == \
            "https://github.com/acme/x/pull/7"

    def test_output_with_no_url_raises(self, run):
        """A zero exit with no link means gh did something other than
        create the PR the caller asked for. Returning that text as a URL
        made the pipeline report a remediation nobody could open."""
        run.when(["pr", "create"], (0, "Warning: nothing to do\n"))
        with pytest.raises(PRCreationError) as exc:
            create_pull_request("t", "b", "feature", work_dir="/repo")
        assert "no pull-request URL" in str(exc.value)
        assert "Warning: nothing to do" in str(exc.value), \
            "the operator cannot debug this without gh's own output"


class TestCreateRemediationPr:

    @pytest.fixture
    def dockerfile(self, tmp_path):
        path = tmp_path / "Dockerfile"
        path.write_text("FROM debian:10\n")
        return str(path)

    @pytest.fixture
    def gh_ok(self, run):
        """Stub a real ``gh pr create`` result for the tests whose
        subject is the argv rather than the outcome.

        ``create_pull_request`` now refuses output with no URL in it and
        ``create_remediation_pr`` turns that refusal into a None return,
        so without this stub those tests would be asserting on argv from
        a run that quietly failed at the last step.
        """
        run.when(["pr", "create"], (0, "https://github.com/acme/x/pull/7"))
        return run

    def kwargs(self, dockerfile, **overrides):
        base = dict(
            dockerfile_path=dockerfile,
            original_base="debian:10",
            patched_base="debian:12-slim",
            metrics=METRICS,
            vuln_diff=VULN_DIFF,
            original_dockerfile="FROM debian:10\nRUN apt-get update\n",
            patched_dockerfile="FROM debian:12-slim\nRUN apt-get update\n",
        )
        base.update(overrides)
        return base

    def test_non_repo_returns_none_without_touching_git(
            self, dockerfile, monkeypatch):
        """AutoPatch is routinely pointed at a bare Dockerfile outside
        any repository. That must be a clean skip, not an exception."""
        fake = FakeRun()
        fake.when(["rev-parse", "--git-dir"], (128, "not a git repository"))
        monkeypatch.setattr(pr_creator, "run_cmd", fake)
        assert create_remediation_pr(**self.kwargs(dockerfile)) is None
        assert not fake.any_call("checkout")
        assert not fake.any_call("push")

    def test_happy_path_returns_the_pr_url(self, dockerfile, run):
        run.when(["pr", "create"], (0, "https://github.com/acme/x/pull/42"))
        url = create_remediation_pr(**self.kwargs(dockerfile))
        assert url == "https://github.com/acme/x/pull/42"

    def test_work_dir_is_the_dockerfile_directory(self, dockerfile, run, gh_ok):
        """Running git from the process CWD instead would commit into
        whatever repository the operator happened to be standing in."""
        create_remediation_pr(**self.kwargs(dockerfile))
        expected = os.path.dirname(os.path.abspath(dockerfile))
        for cmd in run.calls:
            if cmd and cmd[0] == "git":
                assert cmd[1:3] == ["-C", expected]

    def test_only_the_dockerfile_basename_is_staged(self, dockerfile, run, gh_ok):
        """git is invoked with -C work_dir, so an absolute path would
        still work but a path relative to the wrong root would not.
        Staging the basename keeps the two consistent."""
        create_remediation_pr(**self.kwargs(dockerfile))
        assert run.find("add")[-1] == "Dockerfile"

    def test_branch_name_drops_the_tag_from_the_patched_base(
            self, dockerfile, run, gh_ok):
        create_remediation_pr(**self.kwargs(dockerfile))
        assert run.find("checkout")[-2] == "autopatch/remediate-debian"

    def test_commit_message_records_the_base_transition(self, dockerfile, run, gh_ok):
        create_remediation_pr(**self.kwargs(dockerfile))
        message = flag_value(run.find("commit"), "-m")
        assert "debian:10 -> debian:12-slim" in message
        assert "88.3%" in message

    def test_title_rounds_the_reduction_to_a_whole_percent(
            self, dockerfile, run, gh_ok):
        create_remediation_pr(**self.kwargs(dockerfile))
        title = flag_value(run.find("pr", "create"), "--title")
        assert title == "fix: reduce vulnerabilities by 88% (debian:10)"

    def test_body_contains_the_real_dockerfile_diff(self, dockerfile, run, gh_ok):
        """The diff is computed here rather than passed in, so a
        regression in the call would silently ship an empty diff."""
        create_remediation_pr(**self.kwargs(dockerfile))
        body = flag_value(run.find("pr", "create"), "--body")
        assert "-FROM debian:10" in body
        assert "+FROM debian:12-slim" in body

    def test_labels_are_applied(self, dockerfile, run, gh_ok):
        create_remediation_pr(**self.kwargs(dockerfile))
        cmd = run.find("pr", "create")
        assert "autopatch" in cmd and "security" in cmd

    def test_draft_is_forwarded(self, dockerfile, run, gh_ok):
        create_remediation_pr(**self.kwargs(dockerfile, draft=True))
        assert "--draft" in run.find("pr", "create")

    def test_base_branch_is_forwarded_to_both_checkout_and_pr(
            self, dockerfile, run, gh_ok):
        """A branch cut from main but targeted at develop produces a PR
        full of unrelated commits."""
        create_remediation_pr(**self.kwargs(dockerfile,
                                            base_branch="develop"))
        assert run.find("checkout")[-1] == "develop"
        assert flag_value(run.find("pr", "create"), "--base") == "develop"

    def test_dirty_tree_aborts_and_returns_none(self, dockerfile, run):
        run.when(["status", "--porcelain"], (0, " M unrelated.py\n"))
        assert create_remediation_pr(**self.kwargs(dockerfile)) is None
        assert not run.any_call("push")

    def test_push_failure_returns_none_rather_than_raising(
            self, dockerfile, run):
        """create_remediation_pr is called from the main pipeline after
        the patched image already exists; a PR failure must not discard
        that work."""
        run.when(["push"], (1, "permission denied"))
        assert create_remediation_pr(**self.kwargs(dockerfile)) is None

    def test_unexpected_exception_returns_none(self, dockerfile, monkeypatch):
        fake = FakeRun()
        monkeypatch.setattr(pr_creator, "run_cmd", fake)

        def explode(*a, **k):
            raise MemoryError("diff too large")

        monkeypatch.setattr(pr_creator, "generate_diff", explode)
        assert create_remediation_pr(**self.kwargs(dockerfile)) is None

    def test_failed_commit_aborts_before_push_and_pr(self, dockerfile, run):
        """Fixed defect: the return value of commit_changes was
        discarded, so a failed commit still pushed the branch and opened
        a pull request. The result was an empty PR reported to the
        operator as a success with a URL, meaning the pipeline claimed
        to have delivered a remediation it had never committed. The
        return stays None because create_remediation_pr is called after
        the patched image already exists and a PR failure must not
        discard that work."""
        run.when(["commit"], (1, "nothing to commit, working tree clean"))
        run.when(["pr", "create"], (0, "https://github.com/acme/x/pull/9"))
        assert create_remediation_pr(**self.kwargs(dockerfile)) is None
        assert not run.any_call("push")
        assert not run.any_call("pr", "create")

    def test_failed_staging_aborts_before_push_and_pr(self, dockerfile, run):
        """The same guard has to hold for the other way commit_changes
        reports failure, otherwise an unstageable Dockerfile still opens
        a PR with nothing in it."""
        run.when(["add"], (128, "pathspec 'Dockerfile' did not match"))
        run.when(["pr", "create"], (0, "https://github.com/acme/x/pull/9"))
        assert create_remediation_pr(**self.kwargs(dockerfile)) is None
        assert not run.any_call("push")
        assert not run.any_call("pr", "create")
