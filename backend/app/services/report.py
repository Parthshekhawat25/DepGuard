"""CSV and HTML report generation for completed scans."""

import csv
from html import escape
from io import StringIO
from typing import Any, Iterable


CSV_COLUMNS = [
    "record_type",
    "scan_id",
    "scan_timestamp",
    "filename",
    "package_name",
    "requested_version",
    "installed_version",
    "scan_status",
    "vulnerability_id",
    "summary",
    "details",
    "published",
    "modified",
    "severity",
    "affected_versions",
    "fixed_versions",
    "references",
    "error",
]


def generate_csv_report(scan: dict[str, Any]) -> str:
    """Generate a CSV report from the serialized API scan record."""

    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS)
    writer.writeheader()

    base = {
        "scan_id": scan["scan_id"],
        "scan_timestamp": scan["scan_timestamp"],
        "filename": scan["filename"],
    }

    writer.writerow(
        {
            **base,
            "record_type": "summary",
            "summary": _summary_text(scan.get("summary", {})),
        }
    )

    for dependency in scan["dependencies"]:
        vulnerabilities = dependency.get("vulnerabilities", [])
        rows: Iterable[dict[str, Any]]
        if vulnerabilities:
            rows = (
                _vulnerability_row(base, dependency, vulnerability)
                for vulnerability in vulnerabilities
            )
        else:
            rows = [_dependency_row(base, dependency)]

        for row in rows:
            writer.writerow(row)

    for issue_type in ("invalid_lines", "unsupported_lines"):
        for issue in scan.get(issue_type, []):
            writer.writerow(
                {
                    **base,
                    "record_type": issue_type.removesuffix("_lines"),
                    "scan_status": "unresolved",
                    "error": (
                        f"line {issue.get('line_number')}: "
                        f"{issue.get('reason', '')}"
                    ),
                }
            )

    return output.getvalue()


def generate_html_report(scan: dict[str, Any]) -> str:
    """Generate a self-contained HTML report from a scan record."""

    summary = scan["summary"]
    dependency_rows = []
    vulnerability_rows = []
    unresolved_items = []
    scan_error_items = []

    for dependency in scan["dependencies"]:
        dependency_rows.append(
            "<tr>"
            f"<td>{_html(dependency.get('package_name'))}</td>"
            f"<td>{_html(dependency.get('requested_version'))}</td>"
            f"<td>{_html(dependency.get('installed_version'))}</td>"
            f"<td>{_html(dependency.get('scan_status'))}</td>"
            f"<td>{len(dependency.get('vulnerabilities', []))}</td>"
            "</tr>"
        )
        if dependency.get("scan_status") == "unresolved":
            unresolved_items.append(_dependency_issue_item(dependency))
        if dependency.get("scan_status") == "scan_error":
            scan_error_items.append(_dependency_issue_item(dependency))

        for vulnerability in dependency.get("vulnerabilities", []):
            references = "<br>".join(
                _reference_link(reference)
                for reference in vulnerability.get("references", [])
            )
            severity = ", ".join(
                filter(
                    None,
                    (
                        severity_item.get("score")
                        for severity_item in vulnerability.get(
                            "severity", []
                        )
                    ),
                )
            )
            vulnerability_rows.append(
                "<tr>"
                f"<td>{_html(dependency.get('package_name'))}</td>"
                f"<td>{_html(vulnerability.get('vulnerability_id'))}</td>"
                f"<td>{_html(vulnerability.get('summary'))}</td>"
                f"<td>{_html(vulnerability.get('details'))}</td>"
                f"<td>{_html(severity)}</td>"
                f"<td>{_html(', '.join(vulnerability.get('affected_versions', [])))}</td>"
                f"<td>{_html(', '.join(vulnerability.get('fixed_versions', [])))}</td>"
                f"<td>{_html(vulnerability.get('published'))}</td>"
                f"<td>{_html(vulnerability.get('modified'))}</td>"
                f"<td>{references}</td>"
                "</tr>"
            )

    issue_items = []
    for issue_type in ("invalid_lines", "unsupported_lines"):
        for issue in scan.get(issue_type, []):
            issue_items.append(
                "<li>"
                f"{_html(issue_type.removesuffix('_lines'))}: "
                f"line {_html(issue.get('line_number'))} — "
                f"{_html(issue.get('reason'))}"
                "</li>"
            )

    limitation_items = "".join(
        f"<li>{_html(limitation)}</li>"
        for limitation in scan.get("limitations", [])
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DepGuard scan report</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ background:#0b1220; color:#e5edf8; font:15px/1.5 Arial,sans-serif; margin:0; padding:32px; }}
    main {{ max-width:1180px; margin:auto; }}
    .card {{ background:#111c2f; border:1px solid #263853; border-radius:12px; padding:20px; margin:16px 0; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }}
    .metric strong {{ display:block; font-size:26px; color:#67e8f9; }}
    table {{ border-collapse:collapse; width:100%; }}
    th,td {{ border-bottom:1px solid #263853; padding:10px; text-align:left; vertical-align:top; }}
    th {{ color:#9eb0c9; font-size:12px; text-transform:uppercase; }}
    a {{ color:#67e8f9; }}
  </style>
</head>
<body>
<main>
  <h1>DepGuard scan report</h1>
  <p><strong>File:</strong> {_html(scan.get('filename'))}<br>
     <strong>Scan ID:</strong> {_html(scan.get('scan_id'))}<br>
     <strong>Timestamp:</strong> {_html(scan.get('scan_timestamp'))}</p>
  <section class="card grid">
    {_metric("Dependencies", summary.get("total", 0))}
    {_metric("Vulnerable", summary.get("vulnerable", 0))}
    {_metric("No known match", summary.get("no_known_match", 0))}
    {_metric("Unresolved", summary.get("unresolved", 0))}
    {_metric("Scan errors", summary.get("scan_error", 0))}
    {_metric("Unique IDs", summary.get("total_unique_vulnerability_ids", 0))}
  </section>
  <section class="card">
    <h2>Dependency inventory</h2>
    <table>
      <thead><tr><th>Package</th><th>Requested</th><th>Queried version</th><th>Status</th><th>Findings</th></tr></thead>
      <tbody>{''.join(dependency_rows) or '<tr><td colspan="5">No dependencies</td></tr>'}</tbody>
    </table>
  </section>
  <section class="card">
    <h2>Vulnerability findings</h2>
    <table>
      <thead><tr><th>Package</th><th>ID</th><th>Summary</th><th>Details</th><th>Severity</th><th>Affected versions</th><th>Fixed versions</th><th>Published</th><th>Modified</th><th>References</th></tr></thead>
      <tbody>{''.join(vulnerability_rows) or '<tr><td colspan="10">No vulnerability findings</td></tr>'}</tbody>
    </table>
  </section>
  <section class="card">
    <h2>Unresolved packages</h2>
    <ul>{''.join(unresolved_items) or '<li>None</li>'}</ul>
  </section>
  <section class="card">
    <h2>Scan errors</h2>
    <ul>{''.join(scan_error_items) or '<li>None</li>'}</ul>
  </section>
  <section class="card">
    <h2>Invalid and unsupported lines</h2>
    <ul>{''.join(issue_items) or '<li>None</li>'}</ul>
  </section>
  <section class="card">
    <h2>Limitations</h2>
    <ul>{limitation_items}</ul>
  </section>
</main>
</body>
</html>
"""


def _dependency_row(
    base: dict[str, Any],
    dependency: dict[str, Any],
) -> dict[str, Any]:
    return {
        **base,
        "record_type": "dependency",
        "package_name": dependency.get("package_name", ""),
        "requested_version": dependency.get("requested_version", ""),
        "installed_version": dependency.get("installed_version", ""),
        "scan_status": dependency.get("scan_status", ""),
        "error": dependency.get("error", ""),
    }


def _vulnerability_row(
    base: dict[str, Any],
    dependency: dict[str, Any],
    vulnerability: dict[str, Any],
) -> dict[str, Any]:
    severity = ", ".join(
        filter(
            None,
            (
                item.get("score")
                for item in vulnerability.get("severity", [])
            ),
        )
    )
    references = "; ".join(
        reference.get("url", "")
        for reference in vulnerability.get("references", [])
        if reference.get("url")
    )
    return {
        **base,
        "record_type": "vulnerability",
        "package_name": dependency.get("package_name", ""),
        "requested_version": dependency.get("requested_version", ""),
        "installed_version": dependency.get("installed_version", ""),
        "scan_status": dependency.get("scan_status", ""),
        "vulnerability_id": vulnerability.get("vulnerability_id", ""),
        "summary": vulnerability.get("summary", ""),
        "details": vulnerability.get("details", ""),
        "published": vulnerability.get("published", ""),
        "modified": vulnerability.get("modified", ""),
        "severity": severity,
        "affected_versions": ", ".join(
            vulnerability.get("affected_versions", [])
        ),
        "fixed_versions": ", ".join(
            vulnerability.get("fixed_versions", [])
        ),
        "references": references,
        "error": dependency.get("error", ""),
    }


def _summary_text(summary: dict[str, Any]) -> str:
    fields = (
        ("total_dependencies", summary.get("total", 0)),
        ("vulnerable_dependencies", summary.get("vulnerable", 0)),
        ("no_known_match_dependencies", summary.get("no_known_match", 0)),
        ("unresolved_dependencies", summary.get("unresolved", 0)),
        ("scan_error_dependencies", summary.get("scan_error", 0)),
        (
            "unique_vulnerability_ids",
            summary.get("total_unique_vulnerability_ids", 0),
        ),
    )
    return "; ".join(f"{name}={value}" for name, value in fields)


def _dependency_issue_item(dependency: dict[str, Any]) -> str:
    requested = dependency.get("requested_version") or "version not resolved"
    error = dependency.get("error")
    suffix = f" - {_html(error)}" if error else ""
    return (
        "<li>"
        f"<strong>{_html(dependency.get('package_name'))}</strong> "
        f"({_html(requested)}){suffix}"
        "</li>"
    )


def _metric(label: str, value: Any) -> str:
    return (
        '<div class="metric">'
        f"<span>{_html(label)}</span>"
        f"<strong>{_html(value)}</strong>"
        "</div>"
    )


def _reference_link(reference: dict[str, Any]) -> str:
    url = reference.get("url")
    if not url:
        return ""
    safe_url = escape(str(url), quote=True)
    return f'<a href="{safe_url}" rel="noreferrer">{safe_url}</a>'


def _html(value: Any) -> str:
    return escape("" if value is None else str(value))
