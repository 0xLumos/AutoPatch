"""End-to-end smoke tests over a real Docker daemon and Trivy. These
tests are skipped automatically when the requirements aren't present."""
import os
import pytest


pytestmark = pytest.mark.integration


def test_build_and_scan_original(tiny_dockerfile, tmp_path):
    """Build a tiny image and scan it; assert the scanner returns a
    well-formed CycloneDX SBOM."""
    from src.builder import build_image
    from src.scanner import scan_image, generate_sbom

    image_tag = "limensec-smoke:test"
    success, error_cat, build_time = build_image(image_tag, tiny_dockerfile)
    assert success, f"build failed: {error_cat}"

    scan = scan_image(image_tag, str(tmp_path / "trivy.json"))
    assert "Results" in scan

    sbom = generate_sbom(image_tag, str(tmp_path / "sbom.json"))
    # CycloneDX wrapper fields should be present.
    assert sbom.get("bomFormat") == "CycloneDX"

    # Cleanup
    import subprocess
    subprocess.run(["docker", "rmi", "-f", image_tag], capture_output=True)


def test_inference_picks_alpine(tiny_dockerfile, tmp_path):
    """analyze_sbom on a real Alpine image's SBOM must classify as
    alpine with high confidence."""
    from src.builder import build_image
    from src.scanner import generate_sbom
    from src.patcher import analyze_sbom

    image_tag = "limensec-infer:test"
    build_image(image_tag, tiny_dockerfile)
    sbom = generate_sbom(image_tag, str(tmp_path / "sbom.json"))
    result = analyze_sbom(sbom)
    assert result.os_family == "alpine"
    assert result.confidence > 0.7

    import subprocess
    subprocess.run(["docker", "rmi", "-f", image_tag], capture_output=True)
