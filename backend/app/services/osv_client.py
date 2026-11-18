"""Client and response models for the OSV vulnerability query API."""

import asyncio
from dataclasses import dataclass, field
from typing import Any, List, Literal, Optional

import httpx
from packaging.version import InvalidVersion, Version

from app.services.parser import ParsedDependency


DEFAULT_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_ECOSYSTEM = "PyPI"
QueryStatus = Literal[
    "vulnerable",
    "no_known_match",
    "unresolved",
    "scan_error",
]


@dataclass
class OSVSeverity:
    type: Optional[str]
    score: Optional[str]


@dataclass
class OSVReference:
    type: Optional[str]
    url: Optional[str]


@dataclass
class OSVRangeEvent:
    introduced: Optional[str] = None
    fixed: Optional[str] = None
    last_affected: Optional[str] = None
    limit: Optional[str] = None


@dataclass
class OSVAffectedRange:
    range_type: Optional[str]
    events: List[OSVRangeEvent] = field(default_factory=list)


@dataclass
class OSVAffectedPackage:
    ecosystem: Optional[str]
    name: Optional[str]
    purl: Optional[str]
    versions: List[str] = field(default_factory=list)
    ranges: List[OSVAffectedRange] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)


@dataclass
class OSVVulnerability:
    osv_id: Optional[str]
    summary: Optional[str]
    details: Optional[str]
    published: Optional[str]
    modified: Optional[str]
    affected: List[OSVAffectedPackage] = field(default_factory=list)
    severity: List[OSVSeverity] = field(default_factory=list)
    references: List[OSVReference] = field(default_factory=list)


@dataclass
class OSVQueryResult:
    package_name: str
    version: Optional[str]
    ecosystem: str
    status: QueryStatus
    vulnerabilities: List[OSVVulnerability] = field(default_factory=list)
    error: Optional[str] = None
    http_status: Optional[int] = None


class OSVClient:
    """Query OSV using only exact pinned dependencies from the parser."""

    def __init__(
        self,
        query_url: str = DEFAULT_OSV_QUERY_URL,
        ecosystem: str = DEFAULT_ECOSYSTEM,
        timeout: float = 10.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        max_retries: int = 2,
        retry_backoff: float = 0.25,
        max_retry_delay: float = 2.0,
    ) -> None:
        self.query_url = query_url
        self.ecosystem = ecosystem
        self.timeout = timeout
        self.transport = transport
        self.max_retries = max(0, max_retries)
        self.retry_backoff = max(0.0, retry_backoff)
        self.max_retry_delay = max(0.0, max_retry_delay)

    async def query_dependency(
        self,
        dependency: ParsedDependency,
    ) -> OSVQueryResult:
        """Query OSV for a parser dependency only when it is exactly pinned."""

        if not _is_safe_exact_pin(dependency):
            return OSVQueryResult(
                package_name=dependency.package_name,
                version=dependency.requested_version,
                ecosystem=self.ecosystem,
                status="unresolved",
                error="OSV queries require an exact pinned package version",
            )

        return await self._query_exact_version(
            package_name=dependency.package_name,
            version=dependency.requested_version,
        )

    async def _query_exact_version(
        self,
        package_name: str,
        version: str,
    ) -> OSVQueryResult:
        vulnerabilities: List[OSVVulnerability] = []
        page_token: Optional[str] = None
        seen_page_tokens: set[str] = set()

        while True:
            payload = {
                "package": {
                    "ecosystem": self.ecosystem,
                    "name": package_name,
                },
                "version": version,
            }
            if page_token is not None:
                payload["page_token"] = page_token

            response_data, error_result = await self._request_page(
                package_name=package_name,
                version=version,
                payload=payload,
            )
            if error_result is not None:
                return error_result

            if response_data is None:
                return _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    "OSV API returned an empty response",
                )

            raw_vulnerabilities = response_data.get("vulns", [])
            if raw_vulnerabilities is None:
                return _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    "OSV response contains an invalid vulnerabilities field",
                )
            if not isinstance(raw_vulnerabilities, list):
                return _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    "OSV response contains an invalid vulnerabilities field",
                )
            if any(
                not isinstance(record, dict)
                for record in raw_vulnerabilities
            ):
                return _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    "OSV response contains a malformed vulnerability record",
                )

            vulnerabilities.extend(
                normalize_vulnerability(record)
                for record in raw_vulnerabilities
            )

            next_page_token = response_data.get("next_page_token")
            if next_page_token in (None, ""):
                break
            if not isinstance(next_page_token, str):
                return _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    "OSV response contains an invalid page token",
                )
            if next_page_token in seen_page_tokens:
                return _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    "OSV response repeated a page token",
                )

            seen_page_tokens.add(next_page_token)
            page_token = next_page_token

        status: QueryStatus = (
            "vulnerable" if vulnerabilities else "no_known_match"
        )
        return OSVQueryResult(
            package_name=package_name,
            version=version,
            ecosystem=self.ecosystem,
            status=status,
            vulnerabilities=vulnerabilities,
        )

    async def _request_page(
        self,
        package_name: str,
        version: str,
        payload: dict[str, Any],
    ) -> tuple[Optional[dict[str, Any]], Optional[OSVQueryResult]]:
        client_kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.transport is not None:
            client_kwargs["transport"] = self.transport

        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(**client_kwargs) as client:
                    response = await client.post(
                        self.query_url,
                        json=payload,
                    )
                    response.raise_for_status()
            except httpx.TimeoutException:
                return None, _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    "OSV request timed out",
                )
            except httpx.ConnectError:
                return None, _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    "Could not connect to the OSV API",
                )
            except httpx.HTTPStatusError as exc:
                if (
                    exc.response.status_code == 429
                    and attempt < self.max_retries
                ):
                    delay = self._retry_delay(exc.response, attempt)
                    if delay > 0:
                        await asyncio.sleep(delay)
                    continue
                return None, _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    f"OSV API returned HTTP {exc.response.status_code}",
                    http_status=exc.response.status_code,
                )
            except httpx.RequestError as exc:
                return None, _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    f"OSV request failed: {exc}",
                )

            try:
                response_data = response.json()
            except ValueError:
                return None, _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    "OSV API returned invalid JSON",
                )

            if not isinstance(response_data, dict):
                return None, _error_result(
                    package_name,
                    version,
                    self.ecosystem,
                    "OSV API returned a malformed response",
                )
            return response_data, None

        return None, _error_result(
            package_name,
            version,
            self.ecosystem,
            "OSV request failed after retries",
        )

    def _retry_delay(
        self,
        response: httpx.Response,
        attempt: int,
    ) -> float:
        retry_after = response.headers.get("retry-after")
        if retry_after is not None:
            try:
                return min(
                    max(0.0, float(retry_after)),
                    self.max_retry_delay,
                )
            except ValueError:
                pass
        return min(
            self.retry_backoff * (2**attempt),
            self.max_retry_delay,
        )


def normalize_vulnerability(record: dict[str, Any]) -> OSVVulnerability:
    """Normalize one OSV record without filling missing source data."""

    return OSVVulnerability(
        osv_id=_optional_text(record.get("id")),
        summary=_optional_text(record.get("summary")),
        details=_optional_text(record.get("details")),
        published=_optional_text(record.get("published")),
        modified=_optional_text(record.get("modified")),
        affected=_normalize_affected(record.get("affected")),
        severity=_normalize_severity(record.get("severity")),
        references=_normalize_references(record.get("references")),
    )


def _normalize_affected(value: Any) -> List[OSVAffectedPackage]:
    if not isinstance(value, list):
        return []

    affected: List[OSVAffectedPackage] = []
    for item in value:
        if not isinstance(item, dict):
            continue

        package = item.get("package")
        package = package if isinstance(package, dict) else {}
        ranges = _normalize_ranges(item.get("ranges"))
        fixed_versions = _fixed_versions_from_ranges(ranges)

        affected.append(
            OSVAffectedPackage(
                ecosystem=_optional_text(package.get("ecosystem")),
                name=_optional_text(package.get("name")),
                purl=_optional_text(package.get("purl")),
                versions=_string_list(item.get("versions")),
                ranges=ranges,
                fixed_versions=fixed_versions,
            )
        )
    return affected


def _normalize_ranges(value: Any) -> List[OSVAffectedRange]:
    if not isinstance(value, list):
        return []

    ranges: List[OSVAffectedRange] = []
    for item in value:
        if not isinstance(item, dict):
            continue

        events: List[OSVRangeEvent] = []
        raw_events = item.get("events")
        if isinstance(raw_events, list):
            for raw_event in raw_events:
                if not isinstance(raw_event, dict):
                    continue
                events.append(
                    OSVRangeEvent(
                        introduced=_optional_text(raw_event.get("introduced")),
                        fixed=_optional_text(raw_event.get("fixed")),
                        last_affected=_optional_text(
                            raw_event.get("last_affected")
                        ),
                        limit=_optional_text(raw_event.get("limit")),
                    )
                )

        ranges.append(
            OSVAffectedRange(
                range_type=_optional_text(item.get("type")),
                events=events,
            )
        )
    return ranges


def _fixed_versions_from_ranges(
    ranges: List[OSVAffectedRange],
) -> List[str]:
    fixed_versions: List[str] = []
    for affected_range in ranges:
        for event in affected_range.events:
            if event.fixed and event.fixed not in fixed_versions:
                fixed_versions.append(event.fixed)
    return fixed_versions


def _normalize_severity(value: Any) -> List[OSVSeverity]:
    if not isinstance(value, list):
        return []

    severity: List[OSVSeverity] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        severity_type = _optional_text(item.get("type"))
        score = _optional_text(item.get("score"))
        if severity_type is not None or score is not None:
            severity.append(OSVSeverity(type=severity_type, score=score))
    return severity


def _normalize_references(value: Any) -> List[OSVReference]:
    if not isinstance(value, list):
        return []

    references: List[OSVReference] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        reference_type = _optional_text(item.get("type"))
        url = _optional_text(item.get("url"))
        if reference_type is not None or url is not None:
            references.append(OSVReference(type=reference_type, url=url))
    return references


def _string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _optional_text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _is_safe_exact_pin(dependency: ParsedDependency) -> bool:
    if not dependency.is_pinned or not dependency.requested_version:
        return False
    if "*" in dependency.requested_version:
        return False
    if dependency.version_specifier != f"=={dependency.requested_version}":
        return False
    try:
        Version(dependency.requested_version)
    except InvalidVersion:
        return False
    return True


def _error_result(
    package_name: str,
    version: str,
    ecosystem: str,
    error: str,
    http_status: Optional[int] = None,
) -> OSVQueryResult:
    return OSVQueryResult(
        package_name=package_name,
        version=version,
        ecosystem=ecosystem,
        status="scan_error",
        error=error,
        http_status=http_status,
    )
