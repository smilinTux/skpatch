"""skpatch.dtrack must look up or create a project, upload a BOM by project
uuid, poll processing status to completion, fetch metrics/findings, and map
a raw finding into skpatch.policy.Finding kwargs - all without ever
touching a real network (every HTTP call goes through an injected fake
session)."""

import pytest

from skpatch.dtrack import (
    DtrackError,
    ensure_project,
    finding_to_policy_kwargs,
    findings,
    is_processed,
    project_metrics,
    project_name_version,
    upload_bom,
    wait_processed,
)


class FakeResp:
    def __init__(self, status_code=200, json_body=None):
        self.status_code = status_code
        self._json = json_body if json_body is not None else {}

    def json(self):
        return self._json


class FakeSession:
    def __init__(self, *, lookup_status=404, lookup_body=None, put_project_body=None, poll_sequence=None):
        self.calls = []
        self._lookup_status = lookup_status
        self._lookup_body = lookup_body or {}
        self._put_project_body = (
            put_project_body if put_project_body is not None else {"uuid": "new-project-uuid"}
        )
        self._poll_sequence = list(poll_sequence or [])

    def get(self, url, **kwargs):
        self.calls.append(("get", url, kwargs))
        if "/bom/token/" in url:
            body = self._poll_sequence.pop(0) if self._poll_sequence else {"processing": False}
            return FakeResp(200, body)
        if "/project/lookup" in url:
            return FakeResp(self._lookup_status, self._lookup_body)
        return FakeResp(200, {})

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        return FakeResp(200, {})

    def put(self, url, **kwargs):
        self.calls.append(("put", url, kwargs))
        if url.endswith("/api/v1/project"):
            return FakeResp(200, self._put_project_body)
        if url.endswith("/api/v1/bom"):
            return FakeResp(200, {"token": "a-token"})
        return FakeResp(200, {})


def test_ensure_project_returns_existing_uuid_on_a_200_lookup():
    session = FakeSession(lookup_status=200, lookup_body={"uuid": "existing-uuid"})
    project = ensure_project(
        session,
        base_url="https://skbom.example.org",
        api_key="k",
        name="estate-a/svc/redis",
        version="abc123def456",
    )
    assert project.uuid == "existing-uuid"
    assert all(call[0] != "put" for call in session.calls)  # never creates when the lookup found one


def test_ensure_project_creates_on_a_404_lookup():
    session = FakeSession(lookup_status=404, put_project_body={"uuid": "created-uuid"})
    project = ensure_project(
        session,
        base_url="https://skbom.example.org",
        api_key="k",
        name="estate-a/svc/redis",
        version="abc123def456",
        tags=["estate-a", "svc"],
    )
    assert project.uuid == "created-uuid"
    put_call = next(c for c in session.calls if c[0] == "put")
    assert put_call[2]["json"]["tags"] == [{"name": "estate-a"}, {"name": "svc"}]
    assert put_call[2]["headers"]["X-Api-Key"] == "k"


def test_ensure_project_raises_on_an_unexpected_lookup_status():
    session = FakeSession(lookup_status=500)
    with pytest.raises(DtrackError):
        ensure_project(session, base_url="https://skbom.example.org", api_key="k", name="n", version="v")


def test_ensure_project_raises_when_create_returns_no_uuid():
    session = FakeSession(lookup_status=404, put_project_body={})
    with pytest.raises(DtrackError):
        ensure_project(session, base_url="https://skbom.example.org", api_key="k", name="n", version="v")


def test_upload_bom_returns_the_processing_token():
    session = FakeSession()
    token = upload_bom(
        session,
        base_url="https://skbom.example.org",
        api_key="k",
        project_uuid="proj-uuid",
        cyclonedx_json_bytes=b'{"bomFormat": "CycloneDX"}',
    )
    assert token == "a-token"
    put_call = next(c for c in session.calls if c[0] == "put" and c[1].endswith("/api/v1/bom"))
    assert put_call[2]["json"]["project"] == "proj-uuid"


def test_upload_bom_raises_without_a_token():
    class NoTokenSession(FakeSession):
        def put(self, url, **kwargs):
            self.calls.append(("put", url, kwargs))
            return FakeResp(200, {})

    with pytest.raises(DtrackError):
        upload_bom(
            NoTokenSession(),
            base_url="https://skbom.example.org",
            api_key="k",
            project_uuid="proj-uuid",
            cyclonedx_json_bytes=b"{}",
        )


def test_upload_bom_raises_on_a_rejected_upload():
    class RejectSession(FakeSession):
        def put(self, url, **kwargs):
            self.calls.append(("put", url, kwargs))
            return FakeResp(400, {})

    with pytest.raises(DtrackError):
        upload_bom(
            RejectSession(),
            base_url="https://skbom.example.org",
            api_key="k",
            project_uuid="p",
            cyclonedx_json_bytes=b"{}",
        )


def test_is_processed_reflects_the_processing_flag():
    done = FakeSession(poll_sequence=[{"processing": False}])
    assert is_processed(done, base_url="https://skbom.example.org", api_key="k", token="t") is True

    busy = FakeSession(poll_sequence=[{"processing": True}])
    assert is_processed(busy, base_url="https://skbom.example.org", api_key="k", token="t") is False


def test_wait_processed_polls_until_done():
    session = FakeSession(poll_sequence=[{"processing": True}, {"processing": True}, {"processing": False}])
    sleeps = []
    result = wait_processed(
        session,
        base_url="https://skbom.example.org",
        api_key="k",
        token="t",
        poll_interval=0.0,
        max_wait=10.0,
        sleep=sleeps.append,
    )
    assert result is True
    assert len(sleeps) == 2  # slept between the two "still processing" polls


def test_wait_processed_returns_false_on_timeout_without_raising():
    session = FakeSession(poll_sequence=[{"processing": True}] * 10)
    clock = iter([0.0, 0.0, 1.0, 5.0])  # deadline is 0 + max_wait(0) = 0; second check is already past it

    def fake_clock():
        try:
            return next(clock)
        except StopIteration:
            return 999.0

    result = wait_processed(
        session,
        base_url="https://skbom.example.org",
        api_key="k",
        token="t",
        poll_interval=0.0,
        max_wait=0.0,
        sleep=lambda s: None,
        clock=fake_clock,
    )
    assert result is False


def test_project_metrics_returns_the_parsed_body():
    class MetricsSession(FakeSession):
        def get(self, url, **kwargs):
            self.calls.append(("get", url, kwargs))
            return FakeResp(200, {"critical": 1, "high": 2})

    metrics = project_metrics(
        MetricsSession(), base_url="https://skbom.example.org", api_key="k", project_uuid="p"
    )
    assert metrics == {"critical": 1, "high": 2}


def test_project_metrics_raises_on_a_non_2xx_status():
    class FailMetricsSession(FakeSession):
        def get(self, url, **kwargs):
            self.calls.append(("get", url, kwargs))
            return FakeResp(503, {})

    with pytest.raises(DtrackError):
        project_metrics(
            FailMetricsSession(), base_url="https://skbom.example.org", api_key="k", project_uuid="p"
        )


def test_findings_returns_the_list_body():
    class FindingsSession(FakeSession):
        def get(self, url, **kwargs):
            self.calls.append(("get", url, kwargs))
            return FakeResp(200, [{"vulnerability": {"vulnId": "CVE-2026-1"}}])

    rows = findings(FindingsSession(), base_url="https://skbom.example.org", api_key="k", project_uuid="p")
    assert rows[0]["vulnerability"]["vulnId"] == "CVE-2026-1"


def test_findings_tolerates_a_non_list_body():
    class WeirdSession(FakeSession):
        def get(self, url, **kwargs):
            self.calls.append(("get", url, kwargs))
            return FakeResp(200, {"not": "a list"})

    rows = findings(WeirdSession(), base_url="https://skbom.example.org", api_key="k", project_uuid="p")
    assert rows == []


def test_finding_to_policy_kwargs_treats_a_version_diff_as_fix_available():
    raw = {
        "vulnerability": {"vulnId": "CVE-2026-9999", "severity": "CRITICAL"},
        "component": {"version": "1.0.0", "latestVersion": "1.0.1"},
    }
    kwargs = finding_to_policy_kwargs(raw, exposure="public")
    assert kwargs == {
        "cve_id": "CVE-2026-9999",
        "severity": "critical",
        "fix_available": True,
        "exposure": "public",
        "rebuild_available": False,
    }


def test_finding_to_policy_kwargs_defaults_fix_available_false_without_a_version_diff():
    raw = {"vulnerability": {"vulnId": "CVE-2026-1", "severity": "high"}, "component": {"version": "1.0.0"}}
    kwargs = finding_to_policy_kwargs(raw)
    assert kwargs["fix_available"] is False
    assert kwargs["exposure"] == "internal"


def test_project_name_version_uses_the_short_digest():
    name, version = project_name_version(
        estate="estate-a", service="skhub-prod_nextcloud", repo="nextcloud", digest="sha256:" + "b" * 64
    )
    assert name == "estate-a/skhub-prod_nextcloud/nextcloud"
    assert version == "b" * 12


def test_project_name_version_falls_back_to_untagged_without_a_digest():
    _, version = project_name_version(estate="e", service="s", repo="r", digest=None)
    assert version == "untagged"
