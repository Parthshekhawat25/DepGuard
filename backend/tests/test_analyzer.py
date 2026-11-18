import asyncio

from app.services.analyzer import analyze_dependencies
from app.services.osv_client import (
    OSVAffectedPackage,
    OSVQueryResult,
    OSVReference,
    OSVSeverity,
    OSVVulnerability,
)
from app.services.parser import parse_requirements


def run(coroutine):
    return asyncio.run(coroutine)


class FakeOSVClient:
    def __init__(self, responses=None, error=None):
        self.responses = responses or {}
        self.error = error
        self.calls = []

    async def query_dependency(self, dependency):
        self.calls.append(dependency)
        if self.error is not None:
            raise self.error
        return self.responses[dependency.package_name]


def vulnerability(
    vulnerability_id,
    summary="Test vulnerability",
    fixed_versions=None,
):
    return OSVVulnerability(
        osv_id=vulnerability_id,
        summary=summary,
        details="Test details",
        published="2024-01-01T00:00:00Z",
        modified="2024-01-02T00:00:00Z",
        affected=[
            OSVAffectedPackage(
                ecosystem="PyPI",
                name="requests",
                purl=None,
                versions=["2.31.0"],
                fixed_versions=fixed_versions or [],
            )
        ],
        severity=[OSVSeverity(type="CVSS_V3", score="7.5")],
        references=[
            OSVReference(
                type="ADVISORY",
                url="https://example.com/advisory",
            )
        ],
    )


def query_result(status, vulnerabilities=None, error=None):
    return OSVQueryResult(
        package_name="requests",
        version="2.31.0",
        ecosystem="PyPI",
        status=status,
        vulnerabilities=vulnerabilities or [],
        error=error,
    )


def test_vulnerable_package_includes_normalized_finding_data():
    parsed = parse_requirements("requests==2.31.0")
    client = FakeOSVClient(
        {
            "requests": query_result(
                "vulnerable",
                [
                    vulnerability(
                        "PYSEC-1",
                        fixed_versions=["2.32.0"],
                    )
                ],
            )
        }
    )

    result = run(analyze_dependencies(parsed, client))

    dependency = result.dependencies[0]
    finding = dependency.vulnerabilities[0]
    assert dependency.scan_status == "vulnerable"
    assert dependency.package_name == "requests"
    assert dependency.installed_version == "2.31.0"
    assert dependency.vulnerability_ids == ["PYSEC-1"]
    assert finding.summary == "Test vulnerability"
    assert finding.severity[0].score == "7.5"
    assert finding.fixed_versions == ["2.32.0"]
    assert finding.references[0].url == "https://example.com/advisory"


def test_package_with_no_known_match():
    parsed = parse_requirements("requests==2.31.0")
    client = FakeOSVClient({"requests": query_result("no_known_match")})

    result = run(analyze_dependencies(parsed, client))

    assert result.dependencies[0].scan_status == "no_known_match"
    assert result.dependencies[0].vulnerabilities == []
    assert result.summary.no_known_match_dependencies == 1


def test_unpinned_package_is_unresolved_and_not_queried():
    parsed = parse_requirements("requests")
    client = FakeOSVClient()

    result = run(analyze_dependencies(parsed, client))

    assert result.dependencies[0].scan_status == "unresolved"
    assert result.dependencies[0].installed_version is None
    assert client.calls == []


def test_ranged_package_is_unresolved_and_not_queried():
    parsed = parse_requirements("requests>=2.0,<3.0")
    client = FakeOSVClient()

    result = run(analyze_dependencies(parsed, client))

    assert result.dependencies[0].scan_status == "unresolved"
    assert result.dependencies[0].requested_version is None
    assert client.calls == []


def test_osv_failure_becomes_scan_error():
    parsed = parse_requirements("requests==2.31.0")
    client = FakeOSVClient(error=TimeoutError("timed out"))

    result = run(analyze_dependencies(parsed, client))

    dependency = result.dependencies[0]
    assert dependency.scan_status == "scan_error"
    assert dependency.installed_version == "2.31.0"
    assert "timed out" in dependency.error
    assert result.summary.scan_error_dependencies == 1


def test_multiple_vulnerabilities_for_one_package():
    parsed = parse_requirements("requests==2.31.0")
    client = FakeOSVClient(
        {
            "requests": query_result(
                "vulnerable",
                [vulnerability("PYSEC-1"), vulnerability("GHSA-2")],
            )
        }
    )

    result = run(analyze_dependencies(parsed, client))

    assert len(result.dependencies[0].vulnerabilities) == 2
    assert result.summary.total_unique_vulnerability_ids == 2


def test_duplicate_vulnerability_ids_are_counted_once():
    parsed = parse_requirements("requests==2.31.0")
    client = FakeOSVClient(
        {
            "requests": query_result(
                "vulnerable",
                [vulnerability("PYSEC-1"), vulnerability("PYSEC-1")],
            )
        }
    )

    result = run(analyze_dependencies(parsed, client))

    assert len(result.dependencies[0].vulnerabilities) == 1
    assert result.summary.total_unique_vulnerability_ids == 1


def test_empty_dependency_list():
    client = FakeOSVClient()

    result = run(analyze_dependencies([], client))

    assert result.dependencies == []
    assert result.summary.total_dependencies == 0
    assert result.summary.total_unique_vulnerability_ids == 0
    assert client.calls == []


def test_mixed_scan_results_and_duplicate_dependency_are_counted_once():
    parsed = parse_requirements(
        """
        requests==2.31.0
        requests==2.31.0
        flask==3.0.0
        django
        urllib3>=2.0
        """
    )
    client = FakeOSVClient(
        {
            "requests": query_result(
                "vulnerable",
                [vulnerability("SHARED-ID")],
            ),
            "flask": query_result("no_known_match"),
        }
    )

    result = run(analyze_dependencies(parsed, client))

    assert result.summary.total_dependencies == 4
    assert result.summary.vulnerable_dependencies == 1
    assert result.summary.no_known_match_dependencies == 1
    assert result.summary.unresolved_dependencies == 2
    assert result.summary.scan_error_dependencies == 0
    assert result.summary.total_unique_vulnerability_ids == 1
    assert [dependency.package_name for dependency in client.calls] == [
        "requests",
        "flask",
    ]
