from fastapi.testclient import TestClient

from app.main import app
from app.routes import scans
from app.services.osv_client import (
    OSVAffectedPackage,
    OSVQueryResult,
    OSVReference,
    OSVSeverity,
    OSVVulnerability,
)


class FakeOSVClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def query_dependency(self, dependency):
        self.calls.append(dependency.package_name)
        return self.responses[dependency.package_name]


def make_vulnerability():
    return OSVVulnerability(
        osv_id="PYSEC-API-1",
        summary="API test vulnerability",
        details="API test details",
        published="2024-01-01T00:00:00Z",
        modified="2024-01-02T00:00:00Z",
        affected=[
            OSVAffectedPackage(
                ecosystem="PyPI",
                name="requests",
                purl=None,
                versions=["2.31.0"],
                fixed_versions=["2.32.0"],
            )
        ],
        severity=[OSVSeverity(type="CVSS_V3", score="7.5")],
        references=[
            OSVReference(
                type="ADVISORY",
                url="https://example.com/api-advisory",
            )
        ],
    )


def make_result(status, vulnerabilities=None, error=None):
    return OSVQueryResult(
        package_name="requests",
        version="2.31.0",
        ecosystem="PyPI",
        status=status,
        vulnerabilities=vulnerabilities or [],
        error=error,
    )


def configure_client(monkeypatch, fake_client):
    scans.scan_store.clear()
    monkeypatch.setattr(
        scans,
        "osv_client_factory",
        lambda: fake_client,
    )


def test_scan_upload_and_report_downloads(monkeypatch):
    fake_client = FakeOSVClient(
        {
            "requests": make_result(
                "vulnerable",
                [make_vulnerability()],
            )
        }
    )
    configure_client(monkeypatch, fake_client)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            files={
                "file": (
                    "requirements.txt",
                    b"requests==2.31.0\nflask>=2.0\n-r base.txt\n",
                    "text/plain",
                )
            },
        )

        assert response.status_code == 200
        scan = response.json()
        assert scan["scan_id"]
        assert scan["filename"] == "requirements.txt"
        assert scan["summary"]["total"] == 2
        assert scan["summary"]["vulnerable"] == 1
        assert scan["summary"]["unresolved"] == 1
        assert len(scan["unsupported_lines"]) == 1
        assert fake_client.calls == ["requests"]

        csv_response = client.get(scan["reports"]["csv"])
        assert csv_response.status_code == 200
        assert "text/csv" in csv_response.headers["content-type"]
        assert "PYSEC-API-1" in csv_response.text
        assert "requests" in csv_response.text

        html_response = client.get(scan["reports"]["html"])
        assert html_response.status_code == 200
        assert "text/html" in html_response.headers["content-type"]
        assert "DepGuard scan report" in html_response.text
        assert "PYSEC-API-1" in html_response.text
        assert "Limitations" in html_response.text


def test_scan_error_is_not_reported_as_safe(monkeypatch):
    fake_client = FakeOSVClient(
        {
            "requests": make_result(
                "scan_error",
                error="OSV API returned HTTP 503",
            )
        }
    )
    configure_client(monkeypatch, fake_client)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            files={"file": ("requirements.txt", b"requests==2.31.0")},
        )

    assert response.status_code == 200
    scan = response.json()
    assert scan["summary"]["scan_error"] == 1
    assert scan["summary"]["no_known_match"] == 0
    assert scan["dependencies"][0]["scan_status"] == "scan_error"


def test_empty_file_is_rejected(monkeypatch):
    configure_client(monkeypatch, FakeOSVClient({}))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            files={"file": ("requirements.txt", b"")},
        )

    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_invalid_utf8_is_rejected(monkeypatch):
    configure_client(monkeypatch, FakeOSVClient({}))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            files={"file": ("requirements.txt", b"\xff\xfe\xfa")},
        )

    assert response.status_code == 400
    assert "utf-8" in response.json()["detail"].lower()


def test_large_file_is_rejected(monkeypatch):
    configure_client(monkeypatch, FakeOSVClient({}))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            files={
                "file": (
                    "requirements.txt",
                    b"r" * (1024 * 1024 + 1),
                )
            },
        )

    assert response.status_code == 413
    assert "1 mb" in response.json()["detail"].lower()


def test_unsupported_file_extension_is_rejected(monkeypatch):
    configure_client(monkeypatch, FakeOSVClient({}))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            files={"file": ("requirements.csv", b"requests==2.31.0")},
        )

    assert response.status_code == 400
    assert ".txt" in response.json()["detail"]


def test_health_endpoint_is_preserved():
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
