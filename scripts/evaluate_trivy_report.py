#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}


def blocking_findings(report_path: Path) -> list[dict[str, str]]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[dict[str, str]] = []
    for result in report.get("Results", []):
        target = str(result.get("Target", "unknown"))
        for vulnerability in result.get("Vulnerabilities") or []:
            severity = str(vulnerability.get("Severity", "UNKNOWN")).upper()
            if severity not in BLOCKING_SEVERITIES:
                continue
            findings.append(
                {
                    "fixed": str(vulnerability.get("FixedVersion") or "none published"),
                    "id": str(vulnerability.get("VulnerabilityID", "unknown")),
                    "installed": str(vulnerability.get("InstalledVersion", "unknown")),
                    "package": str(vulnerability.get("PkgName", "unknown")),
                    "severity": severity,
                    "target": target,
                }
            )
    return sorted(
        findings,
        key=lambda finding: (
            finding["severity"],
            finding["id"],
            finding["target"],
            finding["package"],
        ),
    )


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: evaluate_trivy_report.py REPORT.json")
    report_path = Path(sys.argv[1])
    findings = blocking_findings(report_path)
    if not findings:
        print("Trivy found no HIGH or CRITICAL vulnerabilities.")
        return
    print(f"Trivy found {len(findings)} blocking HIGH/CRITICAL vulnerabilities:")
    for finding in findings:
        print(
            "{severity} {id} target={target} package={package} "
            "installed={installed} fixed={fixed}".format(**finding)
        )
    raise SystemExit(1)


if __name__ == "__main__":
    main()
