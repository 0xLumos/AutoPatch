def summarize(report: dict) -> dict:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for res in report.get("Results", []):
        for vuln in res.get("Vulnerabilities", []) or []:
            sev = vuln.get("Severity", "UNKNOWN").upper()
            summary[sev] += 1
    return summary


def top_vulns(report: dict, n: int = 10):
    vulns = []
    for res in report.get("Results", []):
        vulns += res.get("Vulnerabilities", []) or []
    vulns.sort(key=lambda v: v.get("Severity", "UNKNOWN"))
    return vulns[:n]
