"""Deterministic vulnerability analysis over parsed dependencies."""

from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional, Union

from app.services.osv_client import (
    OSVAffectedPackage,
    OSVClient,
    OSVQueryResult,
    OSVRangeEvent,
    OSVReference,
    OSVSeverity,
    OSVVulnerability,
)
from app.services.parser import ParseResult, ParsedDependency


SCAN_STATUSES = {
    "vulnerable",
    "no_known_match",
    "unresolved",
    "scan_error",
}


@dataclass
class VulnerabilityFinding:
    """A vulnerability finding attached to one analyzed dependency."""

    vulnerability_id: Optional[str]
    summary: Optional[str]
    details: Optional[str]
    published: Optional[str]
    modified: Optional[str]
    severity: List[OSVSeverity] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    references: List[OSVReference] = field(default_factory=list)
    affected_packages: List[OSVAffectedPackage] = field(default_factory=list)

    @property
    def fixed_version(self) -> Optional[str]:
        """Return the first explicitly supplied fixed version, if any."""

        return self.fixed_versions[0] if self.fixed_versions else None


@dataclass
class DependencyAnalysis:
    """The one final status and findings for a logical dependency entry."""

    package_name: str
    requested_version: Optional[str]
    installed_version: Optional[str]
    scan_status: str
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    error: Optional[str] = None
    source_information: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        """Short alias for consumers that call the field ``status``."""

        return self.scan_status

    @property
    def vulnerability_ids(self) -> List[str]:
        """Return only non-empty IDs explicitly supplied by OSV."""

        return [
            finding.vulnerability_id
            for finding in self.vulnerabilities
            if finding.vulnerability_id
        ]


@dataclass
class AnalysisSummary:
    total_dependencies: int
    vulnerable_dependencies: int
    no_known_match_dependencies: int
    unresolved_dependencies: int
    scan_error_dependencies: int
    total_unique_vulnerability_ids: int

    @property
    def total(self) -> int:
        return self.total_dependencies

    @property
    def vulnerable(self) -> int:
        return self.vulnerable_dependencies

    @property
    def no_known_match(self) -> int:
        return self.no_known_match_dependencies

    @property
    def unresolved(self) -> int:
        return self.unresolved_dependencies

    @property
    def scan_error(self) -> int:
        return self.scan_error_dependencies


@dataclass
class AnalysisResult:
    dependencies: List[DependencyAnalysis]
    summary: AnalysisSummary

    @property
    def results(self) -> List[DependencyAnalysis]:
        return self.dependencies


ParsedDependenciesInput = Union[
    ParseResult,
    Iterable[ParsedDependency],
]


async def analyze_dependencies(
    parsed_dependencies: ParsedDependenciesInput,
    osv_client: Optional[OSVClient] = None,
) -> AnalysisResult:
    """Analyze parsed dependencies and return one status per dependency.

    Only exact pins produced by the parser are sent to OSV. Ranges and
    unpinned entries are unresolved because this function never guesses an
    installed version.
    """

    dependencies = _extract_dependencies(parsed_dependencies)
    unique_dependencies = _deduplicate_dependencies(dependencies)
    client = osv_client or OSVClient()
    analyses: List[DependencyAnalysis] = []

    for dependency in unique_dependencies:
        if not _is_exact_pin(dependency):
            analyses.append(_unresolved_result(dependency))
            continue

        try:
            osv_result = await client.query_dependency(dependency)
        except Exception as exc:
            analyses.append(
                _scan_error_result(
                    dependency,
                    f"OSV query failed: {exc}",
                )
            )
            continue

        analyses.append(_analyze_osv_result(dependency, osv_result))

    return AnalysisResult(
        dependencies=analyses,
        summary=_build_summary(analyses),
    )


def _extract_dependencies(
    parsed_dependencies: ParsedDependenciesInput,
) -> List[ParsedDependency]:
    if isinstance(parsed_dependencies, ParseResult):
        dependencies = parsed_dependencies.dependencies
    else:
        dependencies = list(parsed_dependencies)

    for dependency in dependencies:
        if not isinstance(dependency, ParsedDependency):
            raise TypeError(
                "analyze_dependencies expects ParsedDependency objects"
            )
    return dependencies


def _deduplicate_dependencies(
    dependencies: Iterable[ParsedDependency],
) -> List[ParsedDependency]:
    unique: List[ParsedDependency] = []
    seen: set[tuple[str, Optional[str], str]] = set()

    for dependency in dependencies:
        key = (
            dependency.package_name,
            dependency.requested_version,
            dependency.version_specifier,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(dependency)
    return unique


def _is_exact_pin(dependency: ParsedDependency) -> bool:
    return (
        dependency.is_pinned
        and dependency.requested_version is not None
        and "*" not in dependency.requested_version
        and dependency.version_specifier
        == f"=={dependency.requested_version}"
    )


def _unresolved_result(
    dependency: ParsedDependency,
) -> DependencyAnalysis:
    return DependencyAnalysis(
        package_name=dependency.package_name,
        requested_version=dependency.requested_version,
        installed_version=None,
        scan_status="unresolved",
        error="An exact pinned version is required for OSV lookup",
        source_information={
            "source": "requirements.txt",
            "version_specifier": dependency.version_specifier,
        },
    )


def _scan_error_result(
    dependency: ParsedDependency,
    error: str,
    http_status: Optional[int] = None,
) -> DependencyAnalysis:
    source_information: dict[str, Any] = {"source": "OSV"}
    if http_status is not None:
        source_information["http_status"] = http_status

    return DependencyAnalysis(
        package_name=dependency.package_name,
        requested_version=dependency.requested_version,
        installed_version=dependency.requested_version,
        scan_status="scan_error",
        error=error,
        source_information=source_information,
    )


def _analyze_osv_result(
    dependency: ParsedDependency,
    osv_result: OSVQueryResult,
) -> DependencyAnalysis:
    source_information: dict[str, Any] = {
        "source": "OSV",
        "status": osv_result.status,
    }
    if osv_result.http_status is not None:
        source_information["http_status"] = osv_result.http_status

    if osv_result.status == "scan_error":
        return _scan_error_result(
            dependency,
            osv_result.error or "OSV lookup failed",
            http_status=osv_result.http_status,
        )

    if osv_result.status == "unresolved":
        return DependencyAnalysis(
            package_name=dependency.package_name,
            requested_version=dependency.requested_version,
            installed_version=None,
            scan_status="unresolved",
            error=osv_result.error,
            source_information=source_information,
        )

    if osv_result.vulnerabilities:
        return DependencyAnalysis(
            package_name=dependency.package_name,
            requested_version=dependency.requested_version,
            installed_version=dependency.requested_version,
            scan_status="vulnerable",
            vulnerabilities=_deduplicate_findings(osv_result.vulnerabilities),
            error=osv_result.error,
            source_information=source_information,
        )

    if osv_result.status == "no_known_match":
        return DependencyAnalysis(
            package_name=dependency.package_name,
            requested_version=dependency.requested_version,
            installed_version=dependency.requested_version,
            scan_status="no_known_match",
            source_information=source_information,
        )

    return _scan_error_result(
        dependency,
        f"Unexpected OSV result status: {osv_result.status}",
    )


def _deduplicate_findings(
    vulnerabilities: Iterable[OSVVulnerability],
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    seen_ids: set[str] = set()

    for vulnerability in vulnerabilities:
        vulnerability_id = vulnerability.osv_id
        if vulnerability_id and vulnerability_id in seen_ids:
            continue
        if vulnerability_id:
            seen_ids.add(vulnerability_id)
        findings.append(_to_finding(vulnerability))

    return findings


def _to_finding(
    vulnerability: OSVVulnerability,
) -> VulnerabilityFinding:
    affected_versions: List[str] = []
    fixed_versions: List[str] = []

    for affected_package in vulnerability.affected:
        for version in affected_package.versions:
            if version not in affected_versions:
                affected_versions.append(version)
        for fixed_version in affected_package.fixed_versions:
            if fixed_version not in fixed_versions:
                fixed_versions.append(fixed_version)

    return VulnerabilityFinding(
        vulnerability_id=vulnerability.osv_id,
        summary=vulnerability.summary,
        details=vulnerability.details,
        published=vulnerability.published,
        modified=vulnerability.modified,
        severity=list(vulnerability.severity),
        affected_versions=affected_versions,
        fixed_versions=fixed_versions,
        references=list(vulnerability.references),
        affected_packages=list(vulnerability.affected),
    )


def _build_summary(
    analyses: Iterable[DependencyAnalysis],
) -> AnalysisSummary:
    analysis_list = list(analyses)
    unique_vulnerability_ids = {
        vulnerability_id
        for analysis in analysis_list
        for vulnerability_id in analysis.vulnerability_ids
    }

    return AnalysisSummary(
        total_dependencies=len(analysis_list),
        vulnerable_dependencies=_count_status(
            analysis_list,
            "vulnerable",
        ),
        no_known_match_dependencies=_count_status(
            analysis_list,
            "no_known_match",
        ),
        unresolved_dependencies=_count_status(
            analysis_list,
            "unresolved",
        ),
        scan_error_dependencies=_count_status(
            analysis_list,
            "scan_error",
        ),
        total_unique_vulnerability_ids=len(unique_vulnerability_ids),
    )


def _count_status(
    analyses: Iterable[DependencyAnalysis],
    status: str,
) -> int:
    return sum(analysis.scan_status == status for analysis in analyses)
