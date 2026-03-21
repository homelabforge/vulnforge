"""Parser for Trivy JSON scan output.

Extracted from trivy_scanner.py to separate parsing (pure logic) from
scanning (Docker/process management). Both functions are stateless.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_trivy_output(trivy_data: dict[str, Any], scan_duration: float) -> dict[str, Any]:
    """Parse Trivy JSON output into structured vulnerability + secret data.

    Args:
        trivy_data: Raw Trivy JSON output
        scan_duration: Scan duration in seconds

    Returns:
        Parsed scan data with vulnerabilities, secrets, and counts
    """
    vulnerabilities: list[dict[str, Any]] = []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    fixable_count = 0

    results = trivy_data.get("Results", [])

    for result in results:
        target = result.get("Target", "unknown")
        vulns = result.get("Vulnerabilities", [])

        for vuln in vulns:
            cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
            package_name = vuln.get("PkgName", "unknown")
            severity = vuln.get("Severity", "UNKNOWN")
            installed_version = vuln.get("InstalledVersion", "")
            fixed_version = vuln.get("FixedVersion", "")

            is_fixable = bool(fixed_version and fixed_version != "")

            cvss_score = None
            if "CVSS" in vuln:
                cvss_data = vuln["CVSS"]
                if isinstance(cvss_data, dict):
                    for vendor in ["nvd", "redhat", "ghsa"]:
                        if vendor in cvss_data:
                            v3_score = cvss_data[vendor].get("V3Score")
                            if v3_score:
                                cvss_score = v3_score
                                break

            primary_url = vuln.get("PrimaryURL", "")
            references = vuln.get("References", [])
            references_json = json.dumps(references) if references else None
            title = vuln.get("Title", "")
            description = vuln.get("Description", "")

            vulnerabilities.append(
                {
                    "cve_id": cve_id,
                    "package_name": package_name,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "title": title[:500] if title else None,
                    "description": description[:2000] if description else None,
                    "installed_version": installed_version,
                    "fixed_version": fixed_version if fixed_version else None,
                    "is_fixable": is_fixable,
                    "primary_url": primary_url if primary_url else None,
                    "references": references_json,
                    "target": target,
                }
            )

            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            if is_fixable:
                fixable_count += 1

    secrets = parse_trivy_secrets(trivy_data)
    image_name = trivy_data.get("ArtifactName", "unknown")

    return {
        "image": image_name,
        "vulnerabilities": vulnerabilities,
        "secrets": secrets,
        "total_count": len(vulnerabilities),
        "fixable_count": fixable_count,
        "critical_count": severity_counts["CRITICAL"],
        "high_count": severity_counts["HIGH"],
        "medium_count": severity_counts["MEDIUM"],
        "low_count": severity_counts["LOW"],
        "scan_duration_seconds": scan_duration,
        "secret_count": len(secrets),
    }


def parse_trivy_secrets(trivy_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse Trivy secret scan results from JSON output.

    All secret content is redacted for security. Only rule IDs, categories,
    severity, and line numbers are preserved.

    Args:
        trivy_data: Raw Trivy JSON output

    Returns:
        List of parsed (redacted) secrets
    """
    secrets: list[dict[str, Any]] = []

    results = trivy_data.get("Results", [])

    for result in results:
        target = result.get("Target", "unknown")
        secret_findings = result.get("Secrets", [])

        for secret in secret_findings:
            code_lines = secret.get("Code", {}).get("Lines", [])

            redacted_lines = []
            if code_lines:
                for line in code_lines:
                    redacted_lines.append(
                        {
                            "Number": line.get("Number"),
                            "Content": "***REDACTED***",
                            "IsCause": line.get("IsCause", False),
                        }
                    )

                code_snippet = "\n".join(
                    [f"Line {line['Number']}: ***REDACTED***" for line in redacted_lines]
                )
            else:
                code_snippet = None

            layer_info = secret.get("Layer", {})
            layer_digest = layer_info.get("Digest") if layer_info else None

            match_value = secret.get("Match", "")
            redacted_match = "***REDACTED***" if match_value else ""

            secrets.append(
                {
                    "rule_id": secret.get("RuleID", "unknown"),
                    "category": secret.get("Category", "Generic"),
                    "title": secret.get("Title", "Unknown Secret"),
                    "severity": secret.get("Severity", "UNKNOWN"),
                    "match": redacted_match,
                    "start_line": secret.get("StartLine"),
                    "end_line": secret.get("EndLine"),
                    "code_snippet": code_snippet,
                    "layer_digest": layer_digest,
                    "file_path": target,
                }
            )

    if secrets:
        logger.info("Found %d secrets during scan", len(secrets))

    return secrets
