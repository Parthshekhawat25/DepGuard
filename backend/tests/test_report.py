from app.services.report import generate_csv_report, generate_html_report


def sample_scan():
    return {
        "scan_id": "scan-123",
        "scan_timestamp": "2026-11-18T12:00:00Z",
        "filename": "requirements.txt",
        "summary": {
            "total": 3,
            "vulnerable": 1,
            "no_known_match": 0,
            "unresolved": 1,
            "scan_error": 1,
            "total_unique_vulnerability_ids": 1,
        },
        "dependencies": [
            {
                "package_name": "requests",
                "requested_version": "2.31.0",
                "installed_version": "2.31.0",
                "scan_status": "vulnerable",
                "vulnerabilities": [
                    {
                        "vulnerability_id": "PYSEC-REPORT-1",
                        "summary": "Report summary",
                        "details": "Report details",
                        "published": "2026-01-01T00:00:00Z",
                        "modified": "2026-01-02T00:00:00Z",
                        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                        "affected_versions": ["2.31.0"],
                        "fixed_versions": ["2.32.0"],
                        "references": [
                            {
                                "type": "ADVISORY",
                                "url": "https://example.com/advisory",
                            }
                        ],
                    }
                ],
            },
            {
                "package_name": "flask",
                "requested_version": ">=2.0",
                "installed_version": None,
                "scan_status": "unresolved",
                "error": "An exact pinned version is required",
                "vulnerabilities": [],
            },
            {
                "package_name": "urllib3",
                "requested_version": "2.0.0",
                "installed_version": "2.0.0",
                "scan_status": "scan_error",
                "error": "OSV request timed out",
                "vulnerabilities": [],
            },
        ],
        "invalid_lines": [],
        "unsupported_lines": [],
        "limitations": ["No known match is not a guarantee of safety."],
    }


def test_reports_include_scan_metadata_findings_and_failures():
    scan = sample_scan()

    csv_report = generate_csv_report(scan)
    assert "record_type" in csv_report
    assert "summary" in csv_report
    assert "PYSEC-REPORT-1" in csv_report
    assert "Report details" in csv_report
    assert "https://example.com/advisory" in csv_report
    assert "flask" in csv_report
    assert "OSV request timed out" in csv_report

    html_report = generate_html_report(scan)
    assert "scan-123" in html_report
    assert "Report details" in html_report
    assert "Affected versions" in html_report
    assert "Unresolved packages" in html_report
    assert "flask" in html_report
    assert "Scan errors" in html_report
    assert "OSV request timed out" in html_report
