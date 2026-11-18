"""Scan and report API endpoints."""

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Callable
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from fastapi.responses import Response

from app.services import analyzer
from app.services.analyzer import AnalysisResult
from app.services.osv_client import OSVClient
from app.services.parser import parse_requirements
from app.services.report import generate_csv_report, generate_html_report


MAX_FILE_SIZE = 1024 * 1024
SUPPORTED_EXTENSION = ".txt"
LIMITATIONS = [
    (
        "No known match means OSV returned no matching advisory for the "
        "exact queried version; it is not a guarantee that the package is safe."
    ),
    (
        "Unpinned and ranged dependencies are unresolved because DepGuard "
        "does not guess installed versions."
    ),
    (
        "Results depend on OSV availability and the advisory coverage of the "
        "queried ecosystem."
    ),
]

router = APIRouter(prefix="/scans", tags=["scans"])
scan_store: dict[str, dict[str, Any]] = {}
osv_client_factory: Callable[[], OSVClient] = OSVClient


@router.post("", status_code=status.HTTP_200_OK)
async def create_scan(file: UploadFile = File(...)) -> dict[str, Any]:
    filename = Path(file.filename or "").name
    if not filename or Path(filename).suffix.lower() != SUPPORTED_EXTENSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only requirements.txt-style .txt files are supported",
        )

    content = await file.read(MAX_FILE_SIZE + 1)
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded requirements file is empty",
        )
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="The uploaded file exceeds the 1 MB limit",
        )

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file must be valid UTF-8 text",
        )

    if not text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded requirements file is empty",
        )

    try:
        parsed = parse_requirements(text)
        analysis = await analyzer.analyze_dependencies(
            parsed,
            osv_client=osv_client_factory(),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {exc}",
        )

    scan_id = uuid4().hex
    scan_timestamp = datetime.now(timezone.utc).isoformat().replace(
        "+00:00",
        "Z",
    )
    scan = _serialize_scan(
        scan_id=scan_id,
        scan_timestamp=scan_timestamp,
        filename=filename,
        analysis=analysis,
        invalid_lines=parsed.invalid_lines,
        unsupported_lines=parsed.unsupported_lines,
    )
    scan_store[scan_id] = scan
    return scan


@router.get("/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    scan = scan_store.get(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return scan


@router.get("/{scan_id}/report.csv")
async def download_csv_report(scan_id: str) -> Response:
    scan = _get_scan_or_404(scan_id)
    content = generate_csv_report(scan)
    report_name = _safe_report_name(scan["filename"], "csv")
    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{report_name}"'
            )
        },
    )


@router.get("/{scan_id}/report.html")
async def download_html_report(scan_id: str) -> Response:
    scan = _get_scan_or_404(scan_id)
    content = generate_html_report(scan)
    report_name = _safe_report_name(scan["filename"], "html")
    return Response(
        content=content,
        media_type="text/html",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{report_name}"'
            )
        },
    )


def _get_scan_or_404(scan_id: str) -> dict[str, Any]:
    scan = scan_store.get(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return scan


def _serialize_scan(
    scan_id: str,
    scan_timestamp: str,
    filename: str,
    analysis: AnalysisResult,
    invalid_lines: list[Any],
    unsupported_lines: list[Any],
) -> dict[str, Any]:
    summary = {
        "total": analysis.summary.total_dependencies,
        "vulnerable": analysis.summary.vulnerable_dependencies,
        "no_known_match": analysis.summary.no_known_match_dependencies,
        "unresolved": analysis.summary.unresolved_dependencies,
        "scan_error": analysis.summary.scan_error_dependencies,
        "total_unique_vulnerability_ids": (
            analysis.summary.total_unique_vulnerability_ids
        ),
    }

    dependencies = []
    for dependency in analysis.dependencies:
        dependencies.append(
            {
                "package_name": dependency.package_name,
                "requested_version": dependency.requested_version,
                "installed_version": dependency.installed_version,
                "scan_status": dependency.scan_status,
                "status": dependency.scan_status,
                "error": dependency.error,
                "source_information": dependency.source_information,
                "vulnerability_ids": dependency.vulnerability_ids,
                "vulnerabilities": [
                    {
                        "vulnerability_id": finding.vulnerability_id,
                        "summary": finding.summary,
                        "details": finding.details,
                        "published": finding.published,
                        "modified": finding.modified,
                        "severity": [
                            {
                                "type": severity.type,
                                "score": severity.score,
                            }
                            for severity in finding.severity
                        ],
                        "affected_versions": finding.affected_versions,
                        "fixed_versions": finding.fixed_versions,
                        "references": [
                            {
                                "type": reference.type,
                                "url": reference.url,
                            }
                            for reference in finding.references
                        ],
                    }
                    for finding in dependency.vulnerabilities
                ],
            }
        )

    return {
        "scan_id": scan_id,
        "scan_timestamp": scan_timestamp,
        "filename": filename,
        "summary": summary,
        "dependencies": dependencies,
        "results": dependencies,
        "invalid_lines": [_serialize_issue(issue) for issue in invalid_lines],
        "unsupported_lines": [
            _serialize_issue(issue) for issue in unsupported_lines
        ],
        "limitations": LIMITATIONS,
        "reports": {
            "csv": f"/api/v1/scans/{scan_id}/report.csv",
            "html": f"/api/v1/scans/{scan_id}/report.html",
        },
    }


def _serialize_issue(issue: Any) -> dict[str, Any]:
    return {
        "line_number": issue.line_number,
        "raw_line": issue.raw_line,
        "reason": issue.reason,
        "issue_type": issue.issue_type,
    }


def _safe_report_name(filename: str, extension: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(filename).stem).strip("-")
    return f"{stem or 'depguard-scan'}.{extension}"
