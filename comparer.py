import logging

logger = logging.getLogger("docker_patch_tool")

def diff_vulnerabilities(before_scan, after_scan):
    """
    Compare vulnerabilities between before and after scans.
    Returns a dict with lists of 'resolved', 'remaining', and 'new' vulnerabilities.
    Each vulnerability is represented as a dict with keys: id, package, severity, version, fix_version.
    """
    def extract_vulns(scan):
        vulns = []
        for result in scan.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                vulns.append({
                    "id": v.get("VulnerabilityID"),
                    "package": v.get("PkgName"),
                    "version": v.get("InstalledVersion"),
                    "severity": v.get("Severity"),
                    "fix_version": v.get("FixedVersion", "")
                })
        return vulns
    before_list = extract_vulns(before_scan)
    after_list = extract_vulns(after_scan)
    before_keys = {(v['id'], v['package']) for v in before_list}
    after_keys = {(v['id'], v['package']) for v in after_list}
    resolved = [v for v in before_list if (v['id'], v['package']) not in after_keys]
    remaining = [v for v in after_list if (v['id'], v['package']) in before_keys]
    new = [v for v in after_list if (v['id'], v['package']) not in before_keys]
    return {"resolved": resolved, "remaining": remaining, "new": new}

def diff_sbom(before_sbom, after_sbom):
    """
    Compare SBOM components of original and patched images.
    Returns dict with lists of 'added', 'removed', and 'updated' components.
    Each component dict has: name, type, old_version (for removed/updated), new_version (for added/updated).
    """
    before_components = {}
    after_components = {}
    def load_components(sbom, comp_dict):
        comps = sbom.get("components") or sbom.get("Components") or []
        for comp in comps:
            name = comp.get("name") or comp.get("Name")
            comp_type = comp.get("type") or comp.get("Type") or "library"
            version = comp.get("version") or comp.get("Version")
            if name:
                comp_dict[(name, comp_type)] = version
    load_components(before_sbom, before_components)
    load_components(after_sbom, after_components)
    added = []
    removed = []
    updated = []
    for (name, comp_type), old_ver in before_components.items():
        if (name, comp_type) not in after_components:
            removed.append({"name": name, "type": comp_type, "old_version": old_ver})
        else:
            new_ver = after_components[(name, comp_type)]
            if old_ver != new_ver:
                updated.append({"name": name, "type": comp_type, "old_version": old_ver, "new_version": new_ver})
    for (name, comp_type), new_ver in after_components.items():
        if (name, comp_type) not in before_components:
            added.append({"name": name, "type": comp_type, "new_version": new_ver})
    return {"added": added, "removed": removed, "updated": updated}

def compare(before_summary, after_summary):
    """
    Compute simple vulnerability count reduction from before_summary to after_summary.
    Returns a dict with the count difference for each severity.
    """
    diff = {}
    for severity, before_count in before_summary.items():
        after_count = after_summary.get(severity, 0)
        diff[severity] = before_count - after_count
    return diff
