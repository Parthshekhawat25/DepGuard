import asyncio
import json

import httpx

from app.services.osv_client import (
    DEFAULT_OSV_QUERY_URL,
    OSVClient,
)
from app.services.parser import parse_requirements


def run(coroutine):
    return asyncio.run(coroutine)


def pinned_dependency():
    return parse_requirements("requests==2.31.0").pinned_dependencies[0]


def test_successful_response_with_vulnerabilities():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == DEFAULT_OSV_QUERY_URL
        assert json.loads(request.content) == {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "version": "2.31.0",
        }
        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "PYSEC-2024-1",
                        "summary": "Example summary",
                        "details": "Example details",
                        "published": "2024-01-01T00:00:00Z",
                        "modified": "2024-01-02T00:00:00Z",
                        "affected": [
                            {
                                "package": {
                                    "ecosystem": "PyPI",
                                    "name": "requests",
                                },
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "2.32.0"},
                                        ],
                                    }
                                ],
                                "versions": ["2.31.0"],
                            }
                        ],
                        "severity": [
                            {"type": "CVSS_V3", "score": "7.5"}
                        ],
                        "references": [
                            {
                                "type": "ADVISORY",
                                "url": "https://example.com/advisory",
                            }
                        ],
                    }
                ]
            },
        )

    result = run(OSVClient(transport=httpx.MockTransport(handler)).query_dependency(
        pinned_dependency()
    ))

    assert result.status == "vulnerable"
    assert result.error is None
    assert len(result.vulnerabilities) == 1
    vulnerability = result.vulnerabilities[0]
    assert vulnerability.osv_id == "PYSEC-2024-1"
    assert vulnerability.summary == "Example summary"
    assert vulnerability.details == "Example details"
    assert vulnerability.affected[0].versions == ["2.31.0"]
    assert vulnerability.affected[0].fixed_versions == ["2.32.0"]
    assert vulnerability.severity[0].score == "7.5"
    assert vulnerability.references[0].url == "https://example.com/advisory"


def test_successful_response_with_no_vulnerabilities():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    result = run(OSVClient(transport=httpx.MockTransport(handler)).query_dependency(
        pinned_dependency()
    ))

    assert result.status == "no_known_match"
    assert result.vulnerabilities == []
    assert result.error is None


def test_http_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "unavailable"})

    result = run(OSVClient(transport=httpx.MockTransport(handler)).query_dependency(
        pinned_dependency()
    ))

    assert result.status == "scan_error"
    assert result.http_status == 503
    assert result.error == "OSV API returned HTTP 503"


def test_connection_timeout():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    result = run(OSVClient(transport=httpx.MockTransport(handler)).query_dependency(
        pinned_dependency()
    ))

    assert result.status == "scan_error"
    assert result.error == "OSV request timed out"


def test_connection_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection failed", request=request)

    result = run(OSVClient(transport=httpx.MockTransport(handler)).query_dependency(
        pinned_dependency()
    ))

    assert result.status == "scan_error"
    assert result.error == "Could not connect to the OSV API"


def test_invalid_json_response():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json")

    result = run(OSVClient(transport=httpx.MockTransport(handler)).query_dependency(
        pinned_dependency()
    ))

    assert result.status == "scan_error"
    assert result.error == "OSV API returned invalid JSON"


def test_incomplete_vulnerability_data_preserves_missing_fields():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "OSV-INCOMPLETE",
                        "affected": [
                            {
                                "package": {"name": "requests"},
                                "ranges": [
                                    {
                                        "events": [
                                            {"introduced": "0"},
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
        )

    result = run(OSVClient(transport=httpx.MockTransport(handler)).query_dependency(
        pinned_dependency()
    ))

    assert result.status == "vulnerable"
    vulnerability = result.vulnerabilities[0]
    assert vulnerability.osv_id == "OSV-INCOMPLETE"
    assert vulnerability.summary is None
    assert vulnerability.severity == []
    assert vulnerability.affected[0].fixed_versions == []
    assert vulnerability.references == []


def test_malformed_vulnerability_record_returns_scan_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": ["not-an-object"]})

    result = run(OSVClient(transport=httpx.MockTransport(handler)).query_dependency(
        pinned_dependency()
    ))

    assert result.status == "scan_error"
    assert result.error == "OSV response contains a malformed vulnerability record"


def test_unpinned_dependency_is_not_sent_to_osv():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("OSV must not be queried for an unpinned dependency")

    dependency = parse_requirements("requests>=2.0").unpinned_dependencies[0]
    result = run(OSVClient(transport=httpx.MockTransport(handler)).query_dependency(
        dependency
    ))

    assert result.status == "unresolved"
    assert result.error == "OSV queries require an exact pinned package version"


def test_paginated_response_combines_vulnerabilities():
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "vulns": [{"id": "OSV-PAGE-1"}],
                    "next_page_token": "page-2",
                },
            )
        return httpx.Response(
            200,
            json={"vulns": [{"id": "OSV-PAGE-2"}]},
        )

    client = OSVClient(
        transport=httpx.MockTransport(handler),
        retry_backoff=0,
    )
    result = run(client.query_dependency(pinned_dependency()))

    assert result.status == "vulnerable"
    assert [vulnerability.osv_id for vulnerability in result.vulnerabilities] == [
        "OSV-PAGE-1",
        "OSV-PAGE-2",
    ]
    assert requests[1]["page_token"] == "page-2"


def test_rate_limit_is_retried():
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                429,
                headers={"Retry-After": "0"},
            )
        return httpx.Response(200, json={})

    client = OSVClient(
        transport=httpx.MockTransport(handler),
        retry_backoff=0,
    )
    result = run(client.query_dependency(pinned_dependency()))

    assert calls == 2
    assert result.status == "no_known_match"
