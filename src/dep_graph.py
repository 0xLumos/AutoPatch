"""
AutoPatch Dependency Graph Analysis (B1-B2)

Provides reachability analysis for vulnerabilities by walking the CycloneDX
dependency graph. The goal: a vulnerability in a deeply nested transitive
dependency that no application code can reach is less urgent than one in a
direct dependency.

This module implements:
  B1 - Dependency graph reachability: walk the SBOM dependency tree to
       classify each vulnerable component as DIRECT, TRANSITIVE, or UNREACHABLE.
       Combined with the composite priority formula from scanner_fusion.py to
       weight prioritization by reachability depth.

  B2 - Embedded SBOM vulnerability consumption: when the SBOM itself carries
       a vulnerabilities[] array (CycloneDX 1.5+), consume it directly to
       augment or cross-check scanner findings.

Design notes:
  - CycloneDX represents the dependency graph via the "dependencies" array,
    where each entry has a "ref" (bom-ref of a component) and "dependsOn"
    (list of bom-refs it depends on). We build an adjacency list and BFS
    from the root component.
  - Depth 0 = the root/application itself
  - Depth 1 = direct dependencies
  - Depth 2+ = transitive
  - Components not reachable from the root are classified as UNREACHABLE
    (they may be OS packages or components from other stages).
"""

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple

logger = logging.getLogger("docker_patch_tool")


# ════════════════════════════════════════════════════════════════════
# Data structures
# ════════════════════════════════════════════════════════════════════

@dataclass
class ComponentNode:
    """A node in the dependency graph."""
    bom_ref: str
    name: str
    version: str
    purl: str = ""
    depth: int = -1  # -1 = unreachable
    reachability: str = "UNREACHABLE"  # DIRECT, TRANSITIVE, UNREACHABLE, ROOT

    @property
    def is_reachable(self) -> bool:
        return self.reachability in ("ROOT", "DIRECT", "TRANSITIVE")


@dataclass
class ReachabilityResult:
    """Result of dependency graph reachability analysis."""
    root_ref: Optional[str] = None
    total_components: int = 0
    reachable_count: int = 0
    unreachable_count: int = 0
    max_depth: int = 0
    nodes: Dict[str, ComponentNode] = field(default_factory=dict)
    # Mapping from component name (lowercased) to bom-ref for quick lookup
    name_to_ref: Dict[str, str] = field(default_factory=dict)


@dataclass
class EmbeddedVulnerability:
    """A vulnerability extracted from the SBOM's vulnerabilities[] array."""
    vuln_id: str             # CVE-YYYY-NNNNN or GHSA-xxxx
    source_name: str         # e.g., "NVD", "GitHub Advisory"
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    description: str = ""
    affected_refs: List[str] = field(default_factory=list)  # bom-refs
    affected_versions: List[str] = field(default_factory=list)
    recommendation: str = ""
    cwes: List[str] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════
# B1: Dependency Graph Construction and BFS
# ════════════════════════════════════════════════════════════════════

def build_dependency_graph(sbom_data: Dict[str, Any]) -> ReachabilityResult:
    """
    Build a dependency graph from CycloneDX SBOM and compute reachability.

    The algorithm:
      1. Index all components by bom-ref
      2. Build adjacency list from dependencies[] array
      3. Identify root component from metadata.component.bom-ref
      4. BFS from root, assigning depth to each node
      5. Classify: depth 0 = ROOT, depth 1 = DIRECT, depth 2+ = TRANSITIVE

    Args:
        sbom_data: CycloneDX SBOM as dictionary

    Returns:
        ReachabilityResult with all nodes and their reachability status
    """
    result = ReachabilityResult()

    if not sbom_data:
        return result

    components = sbom_data.get("components", [])
    dependencies = sbom_data.get("dependencies", [])
    metadata = sbom_data.get("metadata", {})

    # Step 1: Index components by bom-ref
    for comp in components:
        bom_ref = comp.get("bom-ref", "")
        if not bom_ref:
            continue
        node = ComponentNode(
            bom_ref=bom_ref,
            name=comp.get("name", ""),
            version=comp.get("version", ""),
            purl=comp.get("purl", ""),
        )
        result.nodes[bom_ref] = node
        # Also index by lowercase name for vulnerability matching
        name_key = comp.get("name", "").lower()
        if name_key:
            result.name_to_ref[name_key] = bom_ref

    result.total_components = len(result.nodes)

    # Step 2: Build adjacency list (parent -> children)
    adjacency: Dict[str, List[str]] = {}
    for dep_entry in dependencies:
        ref = dep_entry.get("ref", "")
        depends_on = dep_entry.get("dependsOn", [])
        if ref:
            adjacency[ref] = depends_on

    # Step 3: Identify root component
    meta_component = metadata.get("component", {})
    root_ref = meta_component.get("bom-ref", "")

    # If no explicit root, try to find one from the dependency graph
    # (a node that appears only as a parent, never as a child)
    if not root_ref:
        all_children: Set[str] = set()
        for children in adjacency.values():
            all_children.update(children)
        potential_roots = [
            ref for ref in adjacency.keys()
            if ref not in all_children and ref in result.nodes
        ]
        if potential_roots:
            root_ref = potential_roots[0]
            logger.debug(
                f"No explicit root in SBOM metadata; inferred root: {root_ref}"
            )

    if not root_ref:
        logger.warning("Cannot determine root component; skipping reachability analysis")
        return result

    result.root_ref = root_ref

    # Step 4: BFS from root
    if root_ref in result.nodes:
        result.nodes[root_ref].depth = 0
        result.nodes[root_ref].reachability = "ROOT"

    queue = deque([root_ref])
    visited: Set[str] = {root_ref}
    max_depth = 0

    while queue:
        current = queue.popleft()
        current_depth = result.nodes[current].depth if current in result.nodes else 0

        for child_ref in adjacency.get(current, []):
            if child_ref in visited:
                continue
            visited.add(child_ref)

            child_depth = current_depth + 1
            max_depth = max(max_depth, child_depth)

            if child_ref in result.nodes:
                result.nodes[child_ref].depth = child_depth
                if child_depth == 1:
                    result.nodes[child_ref].reachability = "DIRECT"
                else:
                    result.nodes[child_ref].reachability = "TRANSITIVE"

            queue.append(child_ref)

    result.max_depth = max_depth
    result.reachable_count = sum(1 for n in result.nodes.values() if n.is_reachable)
    result.unreachable_count = result.total_components - result.reachable_count

    logger.info(
        f"Dependency graph: {result.total_components} components, "
        f"{result.reachable_count} reachable (max depth {max_depth}), "
        f"{result.unreachable_count} unreachable"
    )

    return result


def get_vulnerability_reachability(
    graph: ReachabilityResult,
    package_name: str,
) -> Tuple[str, int]:
    """
    Look up the reachability status of a vulnerable package.

    Args:
        graph: Pre-computed dependency graph
        package_name: Name of the vulnerable package (case-insensitive)

    Returns:
        Tuple of (reachability_label, depth) where:
          reachability_label is ROOT/DIRECT/TRANSITIVE/UNREACHABLE
          depth is the BFS depth (-1 for unreachable)
    """
    name_lower = package_name.lower()
    ref = graph.name_to_ref.get(name_lower)
    if ref and ref in graph.nodes:
        node = graph.nodes[ref]
        return node.reachability, node.depth

    return "UNREACHABLE", -1


def compute_reachability_weight(depth: int) -> float:
    """
    Convert dependency depth to a priority weight factor.

    Deeper dependencies get lower weight because they are harder
    to exploit (attacker must traverse more code paths).

    Args:
        depth: BFS depth from root (-1 for unreachable)

    Returns:
        Weight factor between 0.0 and 1.0
    """
    if depth < 0:
        return 0.1  # Unreachable: lowest priority but not zero
    if depth == 0:
        return 1.0  # Root component
    if depth == 1:
        return 1.0  # Direct dependency: full weight
    if depth == 2:
        return 0.8  # One hop transitive
    if depth <= 4:
        return 0.6  # Two-three hops
    return 0.4  # Deep transitive (4+ hops)


# ════════════════════════════════════════════════════════════════════
# B2: Embedded SBOM Vulnerability Consumption
# ════════════════════════════════════════════════════════════════════

def extract_embedded_vulnerabilities(
    sbom_data: Dict[str, Any],
) -> List[EmbeddedVulnerability]:
    """
    Extract vulnerabilities from the SBOM's own vulnerabilities[] array.

    CycloneDX 1.5+ supports embedding known vulnerabilities directly in the
    SBOM. When the SBOM producer (e.g., Trivy, Grype, Syft) populates this
    field, we can use it as a third signal alongside Trivy and Grype scan
    results.

    Args:
        sbom_data: CycloneDX SBOM dictionary

    Returns:
        List of EmbeddedVulnerability instances
    """
    vulns_array = sbom_data.get("vulnerabilities", [])
    if not vulns_array:
        return []

    results: List[EmbeddedVulnerability] = []

    for vuln_entry in vulns_array:
        vuln_id = vuln_entry.get("id", "")
        if not vuln_id:
            continue

        # Extract source
        source = vuln_entry.get("source", {})
        source_name = source.get("name", "unknown")

        # Extract severity from ratings
        ratings = vuln_entry.get("ratings", [])
        severity = "UNKNOWN"
        for rating in ratings:
            sev = rating.get("severity", "").upper()
            if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                severity = sev
                break

        # Extract affected component refs
        affects = vuln_entry.get("affects", [])
        affected_refs = []
        affected_versions = []
        for affect in affects:
            ref = affect.get("ref", "")
            if ref:
                affected_refs.append(ref)
            for ver_range in affect.get("versions", []):
                ver = ver_range.get("version", "")
                if ver:
                    affected_versions.append(ver)

        # Extract CWEs
        cwes = []
        for cwe in vuln_entry.get("cwes", []):
            cwe_id = cwe if isinstance(cwe, (str, int)) else cwe.get("id", "")
            if cwe_id:
                cwes.append(str(cwe_id))

        # Extract recommendation/analysis
        analysis = vuln_entry.get("analysis", {})
        recommendation = vuln_entry.get("recommendation", "")
        if not recommendation and analysis:
            recommendation = analysis.get("detail", "")

        results.append(EmbeddedVulnerability(
            vuln_id=vuln_id,
            source_name=source_name,
            severity=severity,
            description=vuln_entry.get("description", ""),
            affected_refs=affected_refs,
            affected_versions=affected_versions,
            recommendation=recommendation,
            cwes=cwes,
        ))

    logger.info(f"Extracted {len(results)} embedded vulnerabilities from SBOM")
    return results


def merge_embedded_with_scan(
    scan_cves: Dict[str, Dict[str, Any]],
    embedded: List[EmbeddedVulnerability],
    graph: Optional[ReachabilityResult] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Merge embedded SBOM vulnerabilities with scanner findings.

    For each embedded vulnerability:
      - If already found by scanners: add source confirmation
      - If NOT found by scanners: add as "SBOM-only" finding
      - If reachability graph available: annotate with depth/reachability

    Args:
        scan_cves: Dict of CVE ID -> vulnerability info (from scanner fusion)
        embedded: List of embedded vulnerabilities from SBOM
        graph: Optional dependency graph for reachability annotation

    Returns:
        Augmented scan_cves dict with merged information
    """
    merged = dict(scan_cves)

    for emb_vuln in embedded:
        vuln_id = emb_vuln.vuln_id

        if vuln_id in merged:
            # Already known from scanners; add SBOM as confirming source
            existing = merged[vuln_id]
            sources = existing.get("sources", [])
            if f"sbom:{emb_vuln.source_name}" not in sources:
                sources.append(f"sbom:{emb_vuln.source_name}")
            existing["sources"] = sources
            existing["sbom_confirmed"] = True

            # Add CWE info if scanner didn't have it
            if emb_vuln.cwes and not existing.get("cwes"):
                existing["cwes"] = emb_vuln.cwes

        else:
            # New finding from SBOM only
            entry = {
                "id": vuln_id,
                "severity": emb_vuln.severity,
                "description": emb_vuln.description,
                "sources": [f"sbom:{emb_vuln.source_name}"],
                "sbom_confirmed": True,
                "classification": "SBOM_ONLY",
                "affected_refs": emb_vuln.affected_refs,
                "recommendation": emb_vuln.recommendation,
                "cwes": emb_vuln.cwes,
            }
            merged[vuln_id] = entry

        # Annotate with reachability if graph is available
        if graph and vuln_id in merged:
            for ref in emb_vuln.affected_refs:
                if ref in graph.nodes:
                    node = graph.nodes[ref]
                    merged[vuln_id]["reachability"] = node.reachability
                    merged[vuln_id]["depth"] = node.depth
                    merged[vuln_id]["reachability_weight"] = compute_reachability_weight(node.depth)
                    break

    sbom_only_count = sum(
        1 for v in merged.values()
        if v.get("classification") == "SBOM_ONLY"
    )
    confirmed_count = sum(
        1 for v in merged.values()
        if v.get("sbom_confirmed") and v.get("classification") != "SBOM_ONLY"
    )

    logger.info(
        f"SBOM merge: {confirmed_count} confirmed by SBOM, "
        f"{sbom_only_count} SBOM-only findings added"
    )

    return merged


def summarize_graph(graph: ReachabilityResult) -> Dict[str, Any]:
    """
    Generate a summary dict of the dependency graph for reporting.

    Args:
        graph: Computed reachability result

    Returns:
        Summary dict suitable for JSON export
    """
    depth_distribution: Dict[int, int] = {}
    for node in graph.nodes.values():
        d = node.depth if node.depth >= 0 else -1
        depth_distribution[d] = depth_distribution.get(d, 0) + 1

    return {
        "total_components": graph.total_components,
        "reachable": graph.reachable_count,
        "unreachable": graph.unreachable_count,
        "max_depth": graph.max_depth,
        "depth_distribution": {str(k): v for k, v in sorted(depth_distribution.items())},
        "root_ref": graph.root_ref,
    }
