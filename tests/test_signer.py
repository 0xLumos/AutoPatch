"""Tests for the cosign signing / verification layer (``src/signer.py``).

This module is the only thing standing between "AutoPatch produced an
image" and "AutoPatch produced an image a downstream verifier should
trust", so a silent regression here does not fail a build, it produces a
false provenance claim. The tests below exist because of four specific
failure classes that this module has already had to defend against:

1. **Silent unsealed keys.** If ``COSIGN_PASSWORD`` is empty, cosign
   writes an unencrypted private key to disk and signs with it without
   prompting. A regression that reintroduces the empty-string default
   would keep every test that only checks "signing succeeded" green
   while turning the signature into theatre.
2. **Unanchored certificate regexes.** Cosign matches
   ``--certificate-*-regexp`` with Go's ``regexp.MatchString``, which is
   a *search*, not a full match. An unanchored issuer pattern accepts an
   attacker-chosen issuer that merely contains the trusted one. The
   anchoring tests assert on real regex semantics, not on string shape.
3. **Mode/log divergence.** The signing log is what the report and the
   reviewer read to decide whether an artefact is signed. Recording a
   successful ``sign`` for a run where cosign was never invoked, or
   recording mode ``keyless`` for a key-mode attestation, is a
   provenance defect. Those two cases are pinned here.
4. **Argv drift.** ``--key`` appearing (or vanishing) from the wrong
   cosign subcommand changes which trust root is used. Every command
   builder is asserted on its actual argv.

No test in this file may touch the network, a real cosign binary, the
real home directory, or a real subprocess. ``run_cmd`` is always stubbed.
"""
from __future__ import annotations

import os
import re
import stat
import threading

import pytest

from src import signer
from src.signer import (
    AttestationError,
    KeyGenerationError,
    KeylessIdentityNotConfigured,
    SBOMError,
    SignatureError,
    SigningError,
    SigningMode,
    UnsealedKeyError,
    VerificationError,
    _anchor,
    _default_key_dir,
    _get_cosign_password,
    _record_signing_log,
    _resolve_keyless_identity,
    _resolve_keyless_issuer,
    attach_sbom,
    clear_signing_logs,
    ensure_cosign_key,
    generate_attestation,
    get_signing_log,
    sign_image,
    verify_attestation,
    verify_image,
)

POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="POSIX file-mode semantics required")

# Every environment variable that changes signer behaviour. Leaking any
# of these in from the developer's shell would make the suite pass or
# fail depending on who runs it, which is exactly the class of bug these
# tests are meant to catch.
SIGNER_ENV_VARS = (
    "COSIGN_PASSWORD",
    "AUTOPATCH_ALLOW_UNSEALED_KEY",
    "COSIGN_CERTIFICATE_IDENTITY_REGEXP",
    "COSIGN_CERTIFICATE_OIDC_ISSUER_REGEXP",
    "AUTOPATCH_ALLOW_ANY_KEYLESS_IDENTITY",
)


@pytest.fixture(autouse=True)
def clean_signer_environment(monkeypatch, tmp_path):
    """Scrub signer env vars and redirect HOME so no test can read or
    write the developer's real ``~/.autopatch/keys``."""
    for var in SIGNER_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    clear_signing_logs()
    yield
    clear_signing_logs()


class RunRecorder:
    """Stub for ``signer.run_cmd`` that captures argv, env and timeout.

    ``result`` may be a ``(code, output)`` tuple or a callable taking the
    argv list, which lets a test make one cosign subcommand fail while
    the rest succeed.
    """

    def __init__(self, result=(0, "ok")):
        self.result = result
        self.calls: list[dict] = []

    def __call__(self, cmd, env_override=None, timeout=None, **kwargs):
        self.calls.append({
            "cmd": list(cmd),
            "env": dict(env_override or {}),
            "timeout": timeout,
        })
        if callable(self.result):
            return self.result(list(cmd))
        return self.result

    @property
    def last(self) -> dict:
        assert self.calls, "run_cmd was never invoked"
        return self.calls[-1]

    @property
    def last_cmd(self) -> list:
        return self.last["cmd"]


def flag_value(cmd: list, flag: str) -> str:
    """Return the argument following ``flag`` in an argv list."""
    assert flag in cmd, f"{flag} missing from {cmd}"
    return cmd[cmd.index(flag) + 1]


def make_keypair(directory) -> str:
    """Materialise a fake cosign key pair so ``ensure_cosign_key`` takes
    its short-circuit path and no generation is attempted."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cosign.key").write_text("PRIVATE")
    (directory / "cosign.pub").write_text("PUBLIC")
    return str(directory)


def cosign_that_writes_its_keys(cmd):
    """``RunRecorder`` result for a cosign that really produces keys.

    ``ensure_cosign_key`` now verifies cosign.key and cosign.pub are on
    disk after a zero exit, so a stub that merely returns ``(0, "")``
    sends every test that walks the generation path into
    ``KeyGenerationError``. Tests whose subject is something else (the
    argv, the log entry, the ensure-before-attest ordering) use this so
    they exercise the success path instead of tripping that guard. The
    files are written at whatever ``--output-key-prefix`` the caller
    passed, so a regression that stops passing the prefix still fails
    those tests rather than being papered over here.
    """
    if "--output-key-prefix" in cmd:
        prefix = cmd[cmd.index("--output-key-prefix") + 1]
        os.makedirs(os.path.dirname(prefix) or ".", exist_ok=True)
        with open(prefix + ".key", "w") as handle:
            handle.write("PRIVATE")
        with open(prefix + ".pub", "w") as handle:
            handle.write("PUBLIC")
    return 0, "ok"


@pytest.fixture
def run(monkeypatch) -> RunRecorder:
    recorder = RunRecorder()
    monkeypatch.setattr(signer, "run_cmd", recorder)
    return recorder


class TestCosignPassword:
    """The unsealed-key opt-in is a security control, not a convenience
    default. If it ever silently returns "" again, every signature this
    tool produces becomes forgeable by anyone with read access to the
    build workspace."""

    def test_password_is_returned_verbatim(self, monkeypatch):
        monkeypatch.setenv("COSIGN_PASSWORD", "s3cr3t passphrase")
        assert _get_cosign_password() == "s3cr3t passphrase"

    def test_unset_password_refuses_by_default(self):
        with pytest.raises(UnsealedKeyError):
            _get_cosign_password()

    def test_empty_password_refuses_by_default(self, monkeypatch):
        """An exported-but-empty COSIGN_PASSWORD is the most likely way
        an operator ends up with an unsealed key, so it must be treated
        identically to unset rather than as "the operator chose ''"."""
        monkeypatch.setenv("COSIGN_PASSWORD", "")
        with pytest.raises(UnsealedKeyError):
            _get_cosign_password()

    def test_explicit_opt_in_allows_empty_password(self, monkeypatch):
        monkeypatch.setenv("AUTOPATCH_ALLOW_UNSEALED_KEY", "1")
        assert _get_cosign_password() == ""

    @pytest.mark.parametrize("value", ["0", "true", "yes", "", "TRUE", "2"])
    def test_opt_in_requires_exactly_one(self, monkeypatch, value):
        """The opt-in is compared against the literal "1". Accepting
        truthy-looking values would let a stray ``=true`` in a CI
        template disable the control without anyone noticing."""
        monkeypatch.setenv("AUTOPATCH_ALLOW_UNSEALED_KEY", value)
        with pytest.raises(UnsealedKeyError):
            _get_cosign_password()

    def test_password_wins_over_opt_in(self, monkeypatch):
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        monkeypatch.setenv("AUTOPATCH_ALLOW_UNSEALED_KEY", "1")
        assert _get_cosign_password() == "pw"

    def test_unsealed_key_error_is_a_runtime_error(self):
        """Callers that catch RuntimeError must keep catching this, and
        it must NOT be a SigningError, because the surrounding handlers
        in sign_image deliberately re-wrap it."""
        assert issubclass(UnsealedKeyError, RuntimeError)
        assert not issubclass(UnsealedKeyError, SigningError)


class TestRegexAnchoring:
    """``_anchor`` guards a trust boundary. These tests assert on regex
    behaviour (does a hostile string match?) rather than on the shape of
    the produced pattern, so a cosmetic rewrite of the helper cannot
    make a real bypass pass."""

    def test_unanchored_pattern_is_wrapped(self):
        assert _anchor("foo") == "^(?:foo)$"

    def test_already_anchored_pattern_is_untouched(self):
        assert _anchor("^foo$") == "^foo$"

    def test_surrounding_whitespace_is_stripped(self):
        """A trailing newline from a here-doc or a CI variable would
        otherwise become part of the pattern and never match."""
        assert _anchor("  foo\n") == "^(?:foo)$"

    def test_wrapped_issuer_rejects_substring_impersonation(self):
        """The concrete bypass this helper exists for: an attacker who
        controls their own OIDC issuer URL can embed the trusted issuer
        in a query string. Go's MatchString is a search, so Python's
        re.search is the faithful model here."""
        pattern = _anchor(r"https://token\.actions\.githubusercontent\.com")
        hostile = ("https://evil.example/?x="
                   "https://token.actions.githubusercontent.com")
        assert re.search(pattern, hostile) is None
        assert re.search(pattern,
                         "https://token.actions.githubusercontent.com")

    def test_wrapped_alternation_anchors_every_branch(self):
        """Wrapping in a non-capturing group is what stops ``^a|b$`` from
        parsing as ``(^a)|(b$)``. Without the group the second branch
        matches any string that merely ends in it."""
        pattern = _anchor("alpha|beta")
        assert re.search(pattern, "alpha")
        assert re.search(pattern, "beta")
        assert re.search(pattern, "xxbeta") is None
        assert re.search(pattern, "alphaxx") is None

    def test_top_level_alternation_is_rewrapped_despite_outer_anchors(self):
        """Fixed defect: the startswith("^")/endswith("$") shortcut used
        to return ``^a|b$`` verbatim, but Go parses that as
        ``(^a)|(b$)``, so the second branch stayed unanchored and
        matched any string merely ENDING in "b". An operator writing a
        perfectly ordinary multi-branch identity regexp with outer
        anchors therefore got exactly the substring bypass _anchor
        exists to prevent. A top-level ``|`` now forces the wrap even
        when the pattern already looks anchored."""
        pattern = _anchor("^alpha|beta$")
        assert re.search(pattern, "alpha")
        assert re.search(pattern, "beta")
        assert re.search(pattern, "attacker-controlled-beta") is None
        assert re.search(pattern, "alpha-controlled-by-attacker") is None

    def test_alternation_inside_a_group_needs_no_rewrap(self):
        """The rewrap must be driven by a real top-level alternation and
        not by the presence of a ``|`` anywhere, otherwise every already
        correct pattern grows a redundant layer on each pass. ``^(?:a|b)$``
        is safe as written because the ``|`` cannot escape the group."""
        assert _anchor("^(?:alpha|beta)$") == "^(?:alpha|beta)$"
        assert _anchor("^[a|b]+$") == "^[a|b]+$"
        assert _anchor(r"^alpha\|beta$") == r"^alpha\|beta$"

    def test_dot_star_wrapping_still_matches_everything(self):
        """Anchoring ``.*`` must not change its meaning; the opt-in path
        relies on it accepting any identity."""
        assert re.search(_anchor(".*"), "anything at all")


class TestKeylessIdentityResolution:
    """Keyless verification with an identity of ``.*`` accepts any
    certificate Fulcio ever issued, which is the same trust level as no
    verification at all."""

    def test_missing_identity_raises(self):
        with pytest.raises(KeylessIdentityNotConfigured):
            _resolve_keyless_identity()

    def test_dot_star_identity_raises_without_opt_in(self, monkeypatch):
        monkeypatch.setenv("COSIGN_CERTIFICATE_IDENTITY_REGEXP", ".*")
        with pytest.raises(KeylessIdentityNotConfigured):
            _resolve_keyless_identity()

    def test_explicit_identity_is_anchored(self, monkeypatch):
        monkeypatch.setenv("COSIGN_CERTIFICATE_IDENTITY_REGEXP",
                           r"https://github\.com/acme/repo@refs/heads/main")
        resolved = _resolve_keyless_identity()
        assert re.search(resolved,
                         "https://github.com/acme/repo@refs/heads/main")
        assert re.search(
            resolved,
            "https://github.com/evil/x?u=https://github.com/acme/repo"
            "@refs/heads/main") is None

    def test_already_anchored_identity_is_preserved(self, monkeypatch):
        monkeypatch.setenv("COSIGN_CERTIFICATE_IDENTITY_REGEXP",
                           "^https://example\\.test/ci$")
        assert _resolve_keyless_identity() == "^https://example\\.test/ci$"

    def test_empty_identity_is_treated_as_unset(self, monkeypatch):
        monkeypatch.setenv("COSIGN_CERTIFICATE_IDENTITY_REGEXP", "")
        with pytest.raises(KeylessIdentityNotConfigured):
            _resolve_keyless_identity()

    def test_opt_in_returns_dot_star(self, monkeypatch):
        monkeypatch.setenv("AUTOPATCH_ALLOW_ANY_KEYLESS_IDENTITY", "1")
        assert _resolve_keyless_identity() == ".*"

    def test_opt_in_requires_exactly_one(self, monkeypatch):
        monkeypatch.setenv("AUTOPATCH_ALLOW_ANY_KEYLESS_IDENTITY", "true")
        with pytest.raises(KeylessIdentityNotConfigured):
            _resolve_keyless_identity()

    def test_error_message_names_the_operation(self):
        """Operators see this string in CI logs; without the operation
        name they cannot tell which cosign call refused."""
        with pytest.raises(KeylessIdentityNotConfigured) as exc:
            _resolve_keyless_identity("verify-attestation")
        assert "verify-attestation" in str(exc.value)

    def test_not_a_signing_error(self):
        """sign/verify wrap this into their own exception type; if it
        became a SigningError subclass the wrapping would change and
        callers would see a different type."""
        assert issubclass(KeylessIdentityNotConfigured, RuntimeError)
        assert not issubclass(KeylessIdentityNotConfigured, SigningError)


class TestKeylessIssuerResolution:

    def test_default_issuers_are_anchored(self):
        issuer = _resolve_keyless_issuer()
        assert re.search(issuer, "https://accounts.google.com")
        assert re.search(issuer,
                         "https://token.actions.githubusercontent.com")
        assert re.search(
            issuer,
            "https://evil.example/?x=https://accounts.google.com") is None

    def test_default_covers_every_documented_issuer(self):
        issuer = _resolve_keyless_issuer()
        for known in ("https://accounts.google.com",
                      "https://github.com/login/oauth",
                      "https://token.actions.githubusercontent.com"):
            assert re.search(issuer, known), known

    def test_override_is_anchored(self, monkeypatch):
        monkeypatch.setenv("COSIGN_CERTIFICATE_OIDC_ISSUER_REGEXP",
                           r"https://oidc\.internal\.test")
        issuer = _resolve_keyless_issuer()
        assert re.search(issuer, "https://oidc.internal.test")
        assert re.search(issuer, "https://oidc.internal.test.evil") is None


@POSIX_ONLY
class TestDefaultKeyDir:
    """Private key material must never land in a world-readable
    directory. The pipeline previously wrote it into the CI workspace."""

    def test_directory_is_created_owner_only(self):
        path = _default_key_dir()
        assert os.path.isdir(path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o700, f"key dir is {oct(mode)}, expected 0o700"

    def test_preexisting_loose_directory_is_retightened(self, monkeypatch):
        """A directory left behind by an earlier run (or by a hostile
        co-tenant on a shared runner) must not keep its permissions."""
        home = os.environ["HOME"]
        loose = os.path.join(home, ".autopatch", "keys")
        os.makedirs(loose, exist_ok=True)
        os.chmod(loose, 0o777)
        path = _default_key_dir()
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700

    def test_path_is_under_home_not_cwd(self):
        assert _default_key_dir().startswith(os.environ["HOME"])
        assert _default_key_dir().endswith(os.path.join(".autopatch", "keys"))


class TestEnsureCosignKey:

    def test_existing_pair_short_circuits(self, tmp_path, run):
        key_dir = make_keypair(tmp_path / "keys")
        assert ensure_cosign_key(key_dir=key_dir) is True
        assert run.calls == [], "cosign was invoked despite an existing pair"

    def test_existing_pair_does_not_require_a_password(self, tmp_path, run):
        """Reusing a key must not demand COSIGN_PASSWORD at the
        ensure step, otherwise every run on a warm cache would fail."""
        key_dir = make_keypair(tmp_path / "keys")
        assert ensure_cosign_key(key_dir=key_dir) is True

    def test_half_a_pair_triggers_regeneration(self, tmp_path, monkeypatch):
        """Only the private key present means the public half was lost;
        verification would then fail with a confusing cosign error."""
        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        (key_dir / "cosign.key").write_text("PRIVATE")
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        recorder = RunRecorder(result=cosign_that_writes_its_keys)
        monkeypatch.setattr(signer, "run_cmd", recorder)
        ensure_cosign_key(key_dir=str(key_dir))
        assert recorder.calls, "missing public key did not trigger generation"
        assert (key_dir / "cosign.pub").exists()

    def test_password_is_resolved_before_cosign_runs(self, tmp_path, run):
        """The whole point of resolving the passphrase first is that an
        unsealed key is never written to disk. If run_cmd is reached,
        cosign has already created the key."""
        with pytest.raises(UnsealedKeyError):
            ensure_cosign_key(key_dir=str(tmp_path / "keys"))
        assert run.calls == []

    def test_generation_passes_password_via_env_not_argv(
            self, tmp_path, monkeypatch):
        """A passphrase on the command line is visible in /proc and in
        any process listing on the build host."""
        monkeypatch.setenv("COSIGN_PASSWORD", "pw-from-env")
        key_dir = tmp_path / "keys"

        def fake(cmd, env_override=None, timeout=None, **kw):
            # Emulate cosign writing the pair so the chmod path runs.
            (key_dir / "cosign.key").write_text("PRIVATE")
            (key_dir / "cosign.pub").write_text("PUBLIC")
            return 0, ""

        recorder = RunRecorder(result=None)
        recorder.result = lambda cmd: fake(cmd)
        monkeypatch.setattr(signer, "run_cmd", recorder)
        assert ensure_cosign_key(key_dir=str(key_dir)) is True
        call = recorder.last
        assert call["cmd"][:2] == ["cosign", "generate-key-pair"]
        assert call["env"] == {"COSIGN_PASSWORD": "pw-from-env"}
        assert "pw-from-env" not in " ".join(call["cmd"])

    def test_output_key_prefix_points_at_key_dir(self, tmp_path, monkeypatch):
        """Without the prefix cosign writes into CWD, which is how key
        material previously leaked into pipeline workspaces."""
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        key_dir = tmp_path / "keys"
        recorder = RunRecorder(result=cosign_that_writes_its_keys)
        monkeypatch.setattr(signer, "run_cmd", recorder)
        ensure_cosign_key(key_dir=str(key_dir))
        prefix = flag_value(recorder.last_cmd, "--output-key-prefix")
        assert prefix == os.path.join(str(key_dir), "cosign")

    def test_nonzero_exit_raises_key_generation_error(
            self, tmp_path, monkeypatch):
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        monkeypatch.setattr(signer, "run_cmd",
                            RunRecorder(result=(1, "boom: no entropy")))
        with pytest.raises(KeyGenerationError) as exc:
            ensure_cosign_key(key_dir=str(tmp_path / "keys"))
        assert "boom: no entropy" in str(exc.value)

    @POSIX_ONLY
    def test_generated_private_key_is_owner_read_write(
            self, tmp_path, monkeypatch):
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        key_dir = tmp_path / "keys"

        def fake(cmd):
            (key_dir / "cosign.key").write_text("PRIVATE")
            os.chmod(key_dir / "cosign.key", 0o644)
            (key_dir / "cosign.pub").write_text("PUBLIC")
            return 0, ""

        monkeypatch.setattr(signer, "run_cmd", RunRecorder(result=fake))
        ensure_cosign_key(key_dir=str(key_dir))
        mode = stat.S_IMODE(os.stat(key_dir / "cosign.key").st_mode)
        assert mode == 0o600, f"private key is {oct(mode)}"

    def test_default_key_dir_is_used_when_none(self, monkeypatch):
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        recorder = RunRecorder(result=cosign_that_writes_its_keys)
        monkeypatch.setattr(signer, "run_cmd", recorder)
        ensure_cosign_key()
        assert os.environ["HOME"] in flag_value(
            recorder.last_cmd, "--output-key-prefix")

    def test_cosign_exiting_zero_without_key_material_raises(
            self, tmp_path, monkeypatch):
        """Fixed defect: a zero exit with no key files on disk used to
        return True, because the only thing that touched the file was a
        chmod whose OSError was swallowed. cosign does exit 0 without
        writing a pair (a read-only mount, an --output-key-prefix
        pointing somewhere unexpected), and the failure then surfaced
        one step later as an opaque cosign "no such file or directory"
        naming a path the operator never typed. The check now happens
        where the cause is still known."""
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        key_dir = tmp_path / "keys"
        monkeypatch.setattr(signer, "run_cmd", RunRecorder(result=(0, "")))
        with pytest.raises(KeyGenerationError) as exc:
            ensure_cosign_key(key_dir=str(key_dir))
        assert str(key_dir) in str(exc.value)
        assert "cosign.key" in str(exc.value)
        assert not (key_dir / "cosign.key").exists()

    def test_only_one_half_written_by_cosign_still_raises(
            self, tmp_path, monkeypatch):
        """A public key with no private half is not a usable pair, and
        the signing step is where that would otherwise be discovered."""
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        key_dir = tmp_path / "keys"

        def half_a_pair(cmd):
            prefix = flag_value(cmd, "--output-key-prefix")
            os.makedirs(os.path.dirname(prefix), exist_ok=True)
            with open(prefix + ".pub", "w") as handle:
                handle.write("PUBLIC")
            return 0, ""

        monkeypatch.setattr(signer, "run_cmd", RunRecorder(result=half_a_pair))
        with pytest.raises(KeyGenerationError):
            ensure_cosign_key(key_dir=str(key_dir))

    @POSIX_ONLY
    def test_explicit_key_dir_is_retightened_to_owner_only(
            self, tmp_path, monkeypatch):
        """Fixed defect: ``os.makedirs(mode=0o700)`` is a no-op on a
        directory that already exists, so an operator pointing --key-dir
        at a world-readable path (a shared CI cache, /tmp) got no
        protection at all while the default path did. Private key
        material must not be readable by a co-tenant on the runner."""
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        key_dir = tmp_path / "loose-keys"
        key_dir.mkdir()
        os.chmod(key_dir, 0o777)
        monkeypatch.setattr(signer, "run_cmd",
                            RunRecorder(result=cosign_that_writes_its_keys))
        assert ensure_cosign_key(key_dir=str(key_dir)) is True
        assert stat.S_IMODE(os.stat(key_dir).st_mode) == 0o700


class TestSignImageNoneMode:
    """``--signing-mode none`` must be unambiguously visible in the log.
    A ``sign``/success=True entry for a run where cosign never executed
    is a false provenance claim, which is worse than no entry at all."""

    def test_returns_true_without_invoking_cosign(self, run):
        assert sign_image("img@sha256:abc", "none") is True
        assert run.calls == []

    def test_records_skip_not_sign(self, run):
        sign_image("img@sha256:abc", "none")
        entries = get_signing_log()
        assert len(entries) == 1
        assert entries[0]["operation"] == "skip"
        assert entries[0]["operation"] != "sign"

    def test_skip_entry_says_the_image_is_unsigned(self, run):
        sign_image("img@sha256:abc", "none")
        entry = get_signing_log()[0]
        assert entry["signing_mode"] == "none"
        assert "UNSIGNED" in (entry["error_message"] or "")

    def test_skip_entry_carries_the_image_reference(self, run):
        sign_image("registry.test/app@sha256:dead", "none")
        assert get_signing_log()[0]["image_ref"] == \
            "registry.test/app@sha256:dead"


class TestSignImageKeyMode:

    def test_argv_and_env(self, tmp_path, monkeypatch, run):
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        key_dir = make_keypair(tmp_path / "keys")
        assert sign_image("img@sha256:abc", "key", key_dir=key_dir) is True
        call = run.last
        assert call["cmd"][:3] == ["cosign", "sign", "--yes"]
        assert flag_value(call["cmd"], "--key") == \
            os.path.join(key_dir, "cosign.key")
        assert call["cmd"][-1] == "img@sha256:abc"
        assert call["env"] == {"COSIGN_PASSWORD": "pw"}

    def test_insecure_registry_flags_are_opt_in(self, tmp_path, monkeypatch, run):
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        key_dir = make_keypair(tmp_path / "keys")
        sign_image("img@sha256:abc", "key", key_dir=key_dir)
        assert "--allow-insecure-registry" not in run.last_cmd
        assert "--allow-http-registry" not in run.last_cmd

    def test_insecure_registry_flags_are_added_when_requested(
            self, tmp_path, monkeypatch, run):
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        key_dir = make_keypair(tmp_path / "keys")
        sign_image("img@sha256:abc", "key", insecure_registry=True,
                   key_dir=key_dir)
        assert "--allow-insecure-registry" in run.last_cmd
        assert "--allow-http-registry" in run.last_cmd

    def test_default_key_dir_matches_generation_dir(self, monkeypatch, run):
        """Regression guard for the defect where the key was generated in
        ~/.autopatch/keys but signing read ./cosign.key, so key mode
        either failed outright or picked up a stale leftover key."""
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        from pathlib import Path
        make_keypair(Path(os.environ["HOME"]) / ".autopatch" / "keys")
        sign_image("img@sha256:abc", "key")
        used = flag_value(run.last_cmd, "--key")
        assert used == os.path.join(
            os.environ["HOME"], ".autopatch", "keys", "cosign.key")

    def test_missing_password_propagates_unsealed_key_error(
            self, tmp_path, run):
        """Fixed defect: the broad ``except Exception`` re-wrapped
        UnsealedKeyError as SignatureError, so callers never saw the
        type ensure_cosign_key documents. "The operator has not
        configured a passphrase" is a setup problem a pipeline should
        fail fast and loudly on; "the registry rejected the signature"
        is a transient one worth retrying. Collapsing them into one type
        made that decision impossible."""
        key_dir = make_keypair(tmp_path / "keys")
        with pytest.raises(UnsealedKeyError) as exc:
            sign_image("img@sha256:abc", "key", key_dir=key_dir)
        assert not isinstance(exc.value, SigningError)
        assert "COSIGN_PASSWORD" in str(exc.value)
        assert run.calls == [], "cosign ran despite the unresolved passphrase"

    def test_key_setup_failure_is_still_recorded_before_it_propagates(
            self, tmp_path, run):
        """Re-raising the original type must not cost the audit trail:
        the run still has to appear in the signing log as a failure, or
        the report would show no sign attempt at all."""
        key_dir = make_keypair(tmp_path / "keys")
        with pytest.raises(UnsealedKeyError):
            sign_image("img@sha256:abc", "key", key_dir=key_dir)
        entry = get_signing_log()[-1]
        assert entry["operation"] == "sign"
        assert entry["success"] is False
        assert entry["signing_mode"] == "key"

    def test_key_generation_failure_propagates_key_generation_error(
            self, tmp_path, monkeypatch):
        """Fixed defect: sign_image documents ``Raises:
        KeyGenerationError`` but the broad handler converted it to
        SignatureError, so a caller branching on the two types silently
        took the wrong branch and the docstring was simply wrong."""
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        monkeypatch.setattr(signer, "run_cmd",
                            RunRecorder(result=(1, "keygen failed")))
        with pytest.raises(KeyGenerationError) as exc:
            sign_image("img@sha256:abc", "key",
                       key_dir=str(tmp_path / "keys"))
        assert not isinstance(exc.value, SignatureError)
        assert "keygen failed" in str(exc.value)


class TestSignImageKeylessMode:

    def test_no_key_flag_and_cosign_yes_env(self, run):
        assert sign_image("img@sha256:abc", "keyless") is True
        call = run.last
        assert "--key" not in call["cmd"]
        assert call["env"] == {"COSIGN_YES": "true"}
        assert call["cmd"][-1] == "img@sha256:abc"

    def test_keyless_signing_needs_no_password(self, run):
        """COSIGN_PASSWORD is deliberately absent in this fixture; if a
        regression made keyless resolve the passphrase, this raises."""
        assert sign_image("img@sha256:abc", "keyless") is True

    def test_timeout_is_bounded(self, run):
        """A hung cosign call must not wedge the pipeline forever."""
        sign_image("img@sha256:abc", "keyless")
        assert run.last["timeout"] == 90

    def test_insecure_flags_precede_the_image_ref(self, run):
        sign_image("img@sha256:abc", "keyless", insecure_registry=True)
        cmd = run.last_cmd
        assert cmd.index("--allow-insecure-registry") < cmd.index(
            "img@sha256:abc")


class TestSignImageErrors:

    def test_unknown_mode_raises_signature_error(self, run):
        with pytest.raises(SignatureError) as exc:
            sign_image("img@sha256:abc", "kelyess")
        assert "kelyess" in str(exc.value)
        assert run.calls == []

    def test_unknown_mode_records_a_failure_entry(self, run):
        """Fixed gap: a rejected mode used to leave no audit trail at
        all, so a pipeline misconfigured with ``--signing-mode keylss``
        produced an empty signing log. An empty log reads exactly like
        "signing was never attempted" rather than "signing was attempted
        and refused", which is the wrong story to tell a reviewer."""
        with pytest.raises(SignatureError):
            sign_image("img@sha256:abc", "bogus")
        entries = get_signing_log()
        assert len(entries) == 1
        assert entries[0]["operation"] == "sign"
        assert entries[0]["success"] is False
        assert entries[0]["signing_mode"] == "bogus"
        assert "bogus" in entries[0]["error_message"]

    def test_nonzero_exit_raises_and_records_failure(self, monkeypatch):
        monkeypatch.setattr(signer, "run_cmd",
                            RunRecorder(result=(1, "denied by registry")))
        with pytest.raises(SignatureError) as exc:
            sign_image("img@sha256:abc", "keyless")
        assert "denied by registry" in str(exc.value)
        entry = get_signing_log()[-1]
        assert entry["operation"] == "sign"
        assert entry["success"] is False
        assert "denied by registry" in entry["error_message"]

    def test_success_records_no_error_message(self, run):
        sign_image("img@sha256:abc", "keyless")
        entry = get_signing_log()[-1]
        assert entry["success"] is True
        assert entry["error_message"] is None

    def test_signature_error_is_a_signing_error(self):
        assert issubclass(SignatureError, SigningError)


class TestVerifyImage:

    def test_key_mode_uses_public_key_from_key_dir(self, tmp_path, run):
        key_dir = make_keypair(tmp_path / "keys")
        assert verify_image("img@sha256:abc", "key", key_dir=key_dir) is True
        cmd = run.last_cmd
        assert cmd[:2] == ["cosign", "verify"]
        assert flag_value(cmd, "--key") == \
            os.path.join(key_dir, "cosign.pub")

    def test_key_mode_never_uses_the_private_key(self, tmp_path, run):
        key_dir = make_keypair(tmp_path / "keys")
        verify_image("img@sha256:abc", "key", key_dir=key_dir)
        assert "cosign.key" not in " ".join(run.last_cmd)

    def test_key_mode_defaults_to_the_per_user_dir(self, run):
        verify_image("img@sha256:abc", "key")
        assert flag_value(run.last_cmd, "--key") == os.path.join(
            os.environ["HOME"], ".autopatch", "keys", "cosign.pub")

    def test_keyless_passes_anchored_matchers(self, monkeypatch, run):
        monkeypatch.setenv("COSIGN_CERTIFICATE_IDENTITY_REGEXP",
                           r"https://github\.com/acme/repo@refs/heads/main")
        assert verify_image("img@sha256:abc", "keyless") is True
        cmd = run.last_cmd
        identity = flag_value(cmd, "--certificate-identity-regexp")
        issuer = flag_value(cmd, "--certificate-oidc-issuer-regexp")
        assert identity.startswith("^") and identity.endswith("$")
        assert re.search(issuer, "https://accounts.google.com")

    def test_keyless_without_identity_propagates_the_config_error(self, run):
        """Fixed defect: the configuration error was re-wrapped as
        VerificationError, making "you have not told me whose signature
        to trust" indistinguishable from "this signature is invalid". A
        misconfigured pipeline then looked exactly like a tampered
        artefact, which is the difference between fixing a CI variable
        and starting an incident."""
        with pytest.raises(KeylessIdentityNotConfigured) as exc:
            verify_image("img@sha256:abc", "keyless")
        assert not isinstance(exc.value, VerificationError)
        assert "COSIGN_CERTIFICATE_IDENTITY_REGEXP" in str(exc.value)
        assert run.calls == [], "cosign ran without a configured identity"

    def test_unconfigured_keyless_still_lands_in_the_log(self, run):
        """Propagating the original type must not silently drop the
        attempt from the audit trail."""
        with pytest.raises(KeylessIdentityNotConfigured):
            verify_image("img@sha256:abc", "keyless")
        entry = get_signing_log()[-1]
        assert entry["operation"] == "verify"
        assert entry["success"] is False

    def test_unknown_mode_raises(self, run):
        with pytest.raises(VerificationError):
            verify_image("img@sha256:abc", "none")

    def test_failure_records_verify_entry(self, monkeypatch, tmp_path):
        monkeypatch.setattr(signer, "run_cmd",
                            RunRecorder(result=(1, "no matching signatures")))
        with pytest.raises(VerificationError):
            verify_image("img@sha256:abc", "key",
                         key_dir=make_keypair(tmp_path / "k"))
        entry = get_signing_log()[-1]
        assert entry["operation"] == "verify"
        assert entry["success"] is False

    def test_success_records_verify_entry(self, tmp_path, run):
        verify_image("img@sha256:abc", "key",
                     key_dir=make_keypair(tmp_path / "k"))
        entry = get_signing_log()[-1]
        assert entry["operation"] == "verify"
        assert entry["success"] is True
        assert entry["signing_mode"] == "key"


class TestGenerateAttestation:
    """The attestation is the artefact a downstream verifier trusts. A
    mode mismatch between the signature actually produced and the mode
    written to the log is a provenance defect."""

    @pytest.fixture
    def predicate(self, tmp_path):
        path = tmp_path / "provenance.json"
        path.write_text('{"buildType": "autopatch"}')
        return str(path)

    def test_none_mode_returns_false_and_skips_cosign(self, predicate, run):
        """An unsigned predicate sitting on disk is not an attestation,
        so returning True here would let the caller report provenance it
        does not have."""
        assert generate_attestation("img@sha256:abc", predicate,
                                    signing_mode="none") is False
        assert run.calls == []

    def test_none_mode_records_a_failed_attestation(self, predicate, run):
        generate_attestation("img@sha256:abc", predicate, signing_mode="none")
        entry = get_signing_log()[-1]
        assert entry["operation"] == "attestation"
        assert entry["success"] is False
        assert entry["signing_mode"] == "none"
        assert "UNSIGNED" in entry["error_message"]

    def test_key_mode_passes_the_key(self, tmp_path, monkeypatch, predicate):
        """Regression guard: this function used to never pass --key, so a
        key-configured pipeline silently produced a keyless attestation
        or failed where no OIDC provider existed."""
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        recorder = RunRecorder()
        monkeypatch.setattr(signer, "run_cmd", recorder)
        key_dir = make_keypair(tmp_path / "keys")
        assert generate_attestation("img@sha256:abc", predicate,
                                    signing_mode="key",
                                    key_dir=key_dir) is True
        call = recorder.last
        assert flag_value(call["cmd"], "--key") == \
            os.path.join(key_dir, "cosign.key")
        assert call["env"] == {"COSIGN_PASSWORD": "pw"}
        assert "COSIGN_YES" not in call["env"]

    def test_key_mode_logs_key_not_keyless(self, tmp_path, monkeypatch,
                                           predicate):
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        monkeypatch.setattr(signer, "run_cmd", RunRecorder())
        generate_attestation("img@sha256:abc", predicate, signing_mode="key",
                             key_dir=make_keypair(tmp_path / "keys"))
        assert get_signing_log()[-1]["signing_mode"] == "key"

    def test_keyless_is_the_default_mode(self, predicate, run):
        assert generate_attestation("img@sha256:abc", predicate) is True
        assert "--key" not in run.last_cmd
        assert run.last["env"] == {"COSIGN_YES": "true"}

    def test_predicate_and_type_are_forwarded(self, predicate, run):
        generate_attestation("img@sha256:abc", predicate,
                             predicate_type="cyclonedx")
        cmd = run.last_cmd
        assert cmd[:3] == ["cosign", "attest", "--yes"]
        assert flag_value(cmd, "--predicate") == predicate
        assert flag_value(cmd, "--type") == "cyclonedx"
        assert cmd[-1] == "img@sha256:abc"

    def test_default_predicate_type_is_slsa(self, predicate, run):
        generate_attestation("img@sha256:abc", predicate)
        assert flag_value(run.last_cmd, "--type") == "slsaprovenance"

    def test_missing_predicate_fails_before_cosign(self, tmp_path, run):
        """Cosign's own error for a missing predicate is opaque; failing
        early keeps the actionable path in the message."""
        missing = str(tmp_path / "does-not-exist.json")
        with pytest.raises(AttestationError) as exc:
            generate_attestation("img@sha256:abc", missing)
        assert missing in str(exc.value)
        assert run.calls == []

    def test_unknown_mode_rejected_before_predicate_check(self, tmp_path, run):
        with pytest.raises(AttestationError) as exc:
            generate_attestation("img@sha256:abc",
                                 str(tmp_path / "nope.json"),
                                 signing_mode="kyeless")
        assert "kyeless" in str(exc.value)

    def test_insecure_flags_are_forwarded(self, predicate, run):
        generate_attestation("img@sha256:abc", predicate,
                             insecure_registry=True)
        assert "--allow-insecure-registry" in run.last_cmd

    def test_nonzero_exit_raises_and_records(self, tmp_path, monkeypatch,
                                             predicate):
        monkeypatch.setattr(signer, "run_cmd",
                            RunRecorder(result=(1, "rekor unreachable")))
        with pytest.raises(AttestationError) as exc:
            generate_attestation("img@sha256:abc", predicate)
        assert "rekor unreachable" in str(exc.value)
        entry = get_signing_log()[-1]
        assert entry["operation"] == "attestation"
        assert entry["success"] is False

    def test_key_mode_ensures_a_key_exists(self, tmp_path, monkeypatch,
                                           predicate):
        """Key mode must not attest with a nonexistent key path; the
        ensure step has to run first."""
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        key_dir = tmp_path / "fresh-keys"
        recorder = RunRecorder(result=cosign_that_writes_its_keys)
        monkeypatch.setattr(signer, "run_cmd", recorder)
        generate_attestation("img@sha256:abc", predicate, signing_mode="key",
                             key_dir=str(key_dir))
        subcommands = [c["cmd"][1] for c in recorder.calls]
        assert subcommands == ["generate-key-pair", "attest"]

    def test_key_setup_failure_propagates_its_own_type(
            self, tmp_path, monkeypatch, predicate):
        """Fixed defect: generate_attestation re-wrapped
        KeyGenerationError and UnsealedKeyError as AttestationError, so
        a broken key setup was reported as a failed attestation. The two
        need different operator responses, and only one of them is worth
        retrying."""
        monkeypatch.setenv("COSIGN_PASSWORD", "pw")
        monkeypatch.setattr(signer, "run_cmd",
                            RunRecorder(result=(1, "keygen failed")))
        with pytest.raises(KeyGenerationError) as exc:
            generate_attestation("img@sha256:abc", predicate,
                                 signing_mode="key",
                                 key_dir=str(tmp_path / "fresh-keys"))
        assert not isinstance(exc.value, AttestationError)
        entry = get_signing_log()[-1]
        assert entry["operation"] == "attestation"
        assert entry["success"] is False


class TestAttachSbom:

    @pytest.fixture
    def sbom(self, tmp_path):
        path = tmp_path / "sbom.spdx.json"
        path.write_text('{"spdxVersion": "SPDX-2.3"}')
        return str(path)

    def test_missing_sbom_fails_before_cosign(self, tmp_path, run):
        missing = str(tmp_path / "absent.json")
        with pytest.raises(SBOMError) as exc:
            attach_sbom("img@sha256:abc", missing, "keyless")
        assert missing in str(exc.value)
        assert run.calls == []

    @pytest.mark.parametrize("mode", ["key", "keyless"])
    def test_attach_never_passes_a_key(self, sbom, run, mode):
        """``cosign attach sbom`` has no --key flag; passing one makes
        cosign reject the invocation outright. Signing the SBOM is a
        separate step."""
        assert attach_sbom("img@sha256:abc", sbom, mode) is True
        cmd = run.last_cmd
        assert cmd[:3] == ["cosign", "attach", "sbom"]
        assert "--key" not in cmd
        assert flag_value(cmd, "--sbom") == sbom
        assert cmd[-1] == "img@sha256:abc"

    def test_none_mode_is_rejected(self, sbom, run):
        """KNOWN INCONSISTENCY, pinned: sign_image treats "none" as a
        clean skip, but attach_sbom raises for the same value, so a
        caller looping over modes has to special-case this function."""
        with pytest.raises(SBOMError) as exc:
            attach_sbom("img@sha256:abc", sbom, "none")
        assert "none" in str(exc.value)
        assert run.calls == []

    def test_insecure_flags_are_forwarded(self, sbom, run):
        attach_sbom("img@sha256:abc", sbom, "key", insecure_registry=True)
        assert "--allow-http-registry" in run.last_cmd

    def test_failure_raises_and_records(self, sbom, monkeypatch):
        monkeypatch.setattr(signer, "run_cmd",
                            RunRecorder(result=(1, "413 payload too large")))
        with pytest.raises(SBOMError):
            attach_sbom("img@sha256:abc", sbom, "keyless")
        entry = get_signing_log()[-1]
        assert entry["operation"] == "sbom"
        assert entry["success"] is False
        assert "413" in entry["error_message"]

    def test_success_records_sbom_entry(self, sbom, run):
        attach_sbom("img@sha256:abc", sbom, "keyless")
        entry = get_signing_log()[-1]
        assert entry["operation"] == "sbom"
        assert entry["success"] is True


class TestVerifyAttestation:

    def test_key_mode_uses_public_key(self, tmp_path, run):
        key_dir = make_keypair(tmp_path / "keys")
        assert verify_attestation("img@sha256:abc", "key",
                                  key_dir=key_dir) is True
        cmd = run.last_cmd
        assert cmd[:2] == ["cosign", "verify-attestation"]
        assert flag_value(cmd, "--key") == os.path.join(key_dir, "cosign.pub")

    def test_keyless_requires_configured_identity(self, run):
        """Fixed defect: same re-wrapping as verify_image. The missing
        identity is a configuration fault and must not reach the caller
        disguised as a failed attestation check, which is what a
        VerificationError means everywhere else in this module."""
        with pytest.raises(KeylessIdentityNotConfigured) as exc:
            verify_attestation("img@sha256:abc", "keyless")
        assert not isinstance(exc.value, VerificationError)
        assert run.calls == []
        entry = get_signing_log()[-1]
        assert entry["operation"] == "verify_attestation"
        assert entry["success"] is False

    def test_keyless_matchers_are_anchored(self, monkeypatch, run):
        monkeypatch.setenv("COSIGN_CERTIFICATE_IDENTITY_REGEXP",
                           "https://ci.example.test/builder")
        verify_attestation("img@sha256:abc", "keyless")
        identity = flag_value(run.last_cmd, "--certificate-identity-regexp")
        assert re.search(identity,
                         "https://evil.test/?u=https://ci.example.test/builder"
                         ) is None

    def test_unknown_mode_raises(self, run):
        with pytest.raises(VerificationError):
            verify_attestation("img@sha256:abc", "none")

    def test_failure_records_distinct_operation(self, tmp_path, monkeypatch):
        """The attestation check must be distinguishable from the plain
        signature check in the log, otherwise a report cannot say which
        one passed."""
        monkeypatch.setattr(signer, "run_cmd",
                            RunRecorder(result=(1, "no attestations")))
        with pytest.raises(VerificationError):
            verify_attestation("img@sha256:abc", "key",
                               key_dir=make_keypair(tmp_path / "k"))
        assert get_signing_log()[-1]["operation"] == "verify_attestation"


class TestSigningLog:

    def test_starts_empty_after_clear(self):
        clear_signing_logs()
        assert get_signing_log() == []

    def test_entries_are_ordered_and_complete(self, run):
        sign_image("a@sha256:1", "none")
        sign_image("b@sha256:2", "keyless")
        entries = get_signing_log()
        assert [e["image_ref"] for e in entries] == ["a@sha256:1", "b@sha256:2"]
        for entry in entries:
            assert set(entry) == {
                "timestamp", "image_ref", "signing_mode", "operation",
                "success", "duration_seconds", "error_message"}
            assert isinstance(entry["duration_seconds"], float)
            assert entry["duration_seconds"] >= 0

    def test_timestamp_is_utc_iso8601(self, run):
        sign_image("a@sha256:1", "none")
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                            get_signing_log()[0]["timestamp"])

    def test_returned_entries_are_snapshots(self, run):
        """Callers serialise this into the report. If it handed back the
        live dataclass instances, a caller mutating the result would
        corrupt the audit trail in place."""
        sign_image("a@sha256:1", "none")
        snapshot = get_signing_log()
        snapshot[0]["success"] = False
        snapshot.append({"image_ref": "forged"})
        fresh = get_signing_log()
        assert len(fresh) == 1
        assert fresh[0]["success"] is True

    def test_clear_is_visible_to_subsequent_records(self, run):
        """clear_signing_logs rebinds the module global. If _record kept
        a stale reference, entries recorded after a clear would vanish."""
        sign_image("a@sha256:1", "none")
        clear_signing_logs()
        sign_image("b@sha256:2", "none")
        assert [e["image_ref"] for e in get_signing_log()] == ["b@sha256:2"]

    def test_concurrent_records_do_not_lose_entries(self):
        """Batch runs record from a worker pool. An unguarded list would
        lose entries under contention and silently understate how many
        images were signed."""
        clear_signing_logs()
        threads = 16
        per_thread = 64

        def worker(idx):
            for i in range(per_thread):
                _record_signing_log(
                    f"img-{idx}-{i}", "keyless", "sign", True, 0.01)

        pool = [threading.Thread(target=worker, args=(n,))
                for n in range(threads)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()

        entries = get_signing_log()
        assert len(entries) == threads * per_thread
        assert len({e["image_ref"] for e in entries}) == threads * per_thread

    def test_reading_while_writing_never_yields_partial_entries(self):
        """A reader that observes the list mid-append must still see
        fully populated dictionaries, not half-built ones."""
        clear_signing_logs()
        stop = threading.Event()
        bad: list = []

        def writer():
            for i in range(500):
                _record_signing_log(f"i{i}", "key", "sign", True, 0.0)
            stop.set()

        def reader():
            while not stop.is_set():
                for entry in get_signing_log():
                    if entry.get("image_ref") is None:
                        bad.append(entry)

        w, r = threading.Thread(target=writer), threading.Thread(target=reader)
        r.start()
        w.start()
        w.join()
        r.join()
        assert bad == []
        assert len(get_signing_log()) == 500


class TestSigningModeEnum:
    """Callers still compare the mode against bare strings, so the enum
    must keep behaving like one."""

    def test_values_are_the_three_supported_modes(self):
        assert set(SigningMode.values()) == {"keyless", "key", "none"}

    def test_members_compare_equal_to_strings(self):
        assert SigningMode.KEY == "key"
        assert SigningMode.NONE == "none"
        assert SigningMode.KEYLESS == "keyless"

    def test_enum_member_drives_the_same_branch_as_the_string(self, run):
        """If SigningMode stopped subclassing str, this would take the
        unknown-mode branch and start raising."""
        assert sign_image("img@sha256:abc", SigningMode.NONE) is True
        assert get_signing_log()[0]["operation"] == "skip"

    def test_exception_hierarchy(self):
        for exc in (SignatureError, VerificationError, AttestationError,
                    SBOMError, KeyGenerationError):
            assert issubclass(exc, SigningError)
        assert issubclass(SigningError, Exception)
