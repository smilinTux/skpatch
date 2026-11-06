"""sbom.sync_image_sbom must scan with trivy, upload to Dependency-Track
under the <estate>/<service> project name and <tag>@<digest> version, and
deactivate every other version of that project - all without ever touching
a real network (every HTTP call goes through an injected fake session) or a
real trivy binary (every subprocess call goes through an injected fake
runner)."""

import json

import pytest

from skpatch.config import DependencyTrackConfig
from skpatch.imageref import parse_image_ref
from skpatch.sbom import (
    TRIVY_IMAGE,
    SbomError,
    default_trivy_cache_dir,
    project_name_for,
    project_version_for,
    run_trivy_sbom,
    sync_image_sbom,
)


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeResp:
    def __init__(self, status_code=200, json_body=None):
        self.status_code = status_code
        self._json = json_body if json_body is not None else {}

    def json(self):
        return self._json


class FakeSession:
    def __init__(self, project_versions=None):
        self.calls = []
        self._project_versions = project_versions or []

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        return FakeResp(200)

    def get(self, url, **kwargs):
        self.calls.append(("get", url, kwargs))
        return FakeResp(200, self._project_versions)

    def patch(self, url, **kwargs):
        self.calls.append(("patch", url, kwargs))
        return FakeResp(200)


CYCLONEDX_BOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}


def test_project_naming_matches_estate_service_tag_digest_convention():
    ref = parse_image_ref("nextcloud:34.0.4@sha256:" + "b" * 64)
    assert project_name_for("estate-a", "skhub-prod_nextcloud") == "estate-a/skhub-prod_nextcloud"
    assert project_version_for(ref) == "34.0.4@sha256:" + "b" * 64


def test_run_trivy_sbom_parses_the_cyclonedx_json():
    def fake_runner(argv, capture_output, text, timeout):
        assert argv[:3] == ["trivy", "image", "--quiet"]
        return FakeCompleted(0, stdout=json.dumps(CYCLONEDX_BOM))

    bom = run_trivy_sbom("nextcloud:34.0.4@sha256:" + "b" * 64, runner=fake_runner)
    assert bom["bomFormat"] == "CycloneDX"


def test_run_trivy_sbom_raises_sbomerror_on_nonzero_exit():
    def fake_runner(argv, capture_output, text, timeout):
        return FakeCompleted(1, stderr="FATAL unable to pull image")

    with pytest.raises(SbomError):
        run_trivy_sbom("bad-image:latest", runner=fake_runner)


def test_run_trivy_sbom_raises_sbomerror_on_unparsable_output():
    def fake_runner(argv, capture_output, text, timeout):
        return FakeCompleted(0, stdout="not json")

    with pytest.raises(SbomError):
        run_trivy_sbom("redis:7-alpine", runner=fake_runner)


def test_run_trivy_sbom_uses_the_pinned_container_when_requested():
    captured = {}

    def fake_runner(argv, capture_output, text, timeout):
        captured["argv"] = argv
        return FakeCompleted(0, stdout=json.dumps(CYCLONEDX_BOM))

    bom = run_trivy_sbom(
        "nextcloud:34.0.4@sha256:" + "b" * 64,
        use_container=True,
        cache_dir="/tmp/skpatch-trivy-cache",
        runner=fake_runner,
    )
    assert bom["bomFormat"] == "CycloneDX"
    argv = captured["argv"]
    assert argv[0] == "docker"
    assert argv[:3] == ["docker", "run", "--rm"]
    assert "-v" in argv
    assert argv[argv.index("-v") + 1] == "/tmp/skpatch-trivy-cache:/root/.cache/trivy"
    assert TRIVY_IMAGE in argv
    assert argv[-1] == "nextcloud:34.0.4@sha256:" + "b" * 64


def test_run_trivy_sbom_container_mode_defaults_the_cache_dir():
    captured = {}

    def fake_runner(argv, capture_output, text, timeout):
        captured["argv"] = argv
        return FakeCompleted(0, stdout=json.dumps(CYCLONEDX_BOM))

    run_trivy_sbom("redis:7-alpine", use_container=True, runner=fake_runner)
    mount = captured["argv"][captured["argv"].index("-v") + 1]
    assert mount == f"{default_trivy_cache_dir()}:/root/.cache/trivy"


def test_run_trivy_sbom_local_binary_is_still_the_default():
    def fake_runner(argv, capture_output, text, timeout):
        assert argv[0] == "trivy"
        assert "docker" not in argv
        return FakeCompleted(0, stdout=json.dumps(CYCLONEDX_BOM))

    run_trivy_sbom("redis:7-alpine", runner=fake_runner)


def test_sync_image_sbom_uploads_and_deactivates_old_versions(tmp_path):
    key_file = tmp_path / "dt-api-key"
    key_file.write_text("super-secret-key\n")
    dt_config = DependencyTrackConfig(base_url="https://skbom.example.org", api_key_file=str(key_file))
    ref = parse_image_ref("nextcloud:34.0.4@sha256:" + "b" * 64)
    session = FakeSession(
        project_versions=[
            {"uuid": "old-1", "version": "34.0.3@sha256:" + "c" * 64, "active": True},
            {"uuid": "new-1", "version": "34.0.4@sha256:" + "b" * 64, "active": True},
        ]
    )

    def fake_runner(argv, capture_output, text, timeout):
        return FakeCompleted(0, stdout=json.dumps(CYCLONEDX_BOM))

    result = sync_image_sbom(
        estate="estate-a",
        service="skhub-prod_nextcloud",
        ref=ref,
        raw_image="nextcloud:34.0.4@sha256:" + "b" * 64,
        dt_config=dt_config,
        session=session,
        subprocess_runner=fake_runner,
    )
    assert result.uploaded is True
    assert result.deactivated_versions == ["34.0.3@sha256:" + "c" * 64]
    post_call = next(c for c in session.calls if c[0] == "post")
    assert post_call[2]["headers"]["X-Api-Key"] == "super-secret-key"


def test_sync_image_sbom_reports_a_trivy_failure_without_raising(tmp_path):
    key_file = tmp_path / "dt-api-key"
    key_file.write_text("key\n")
    dt_config = DependencyTrackConfig(base_url="https://skbom.example.org", api_key_file=str(key_file))
    ref = parse_image_ref("redis:7-alpine@sha256:" + "a" * 64)
    session = FakeSession()

    def failing_runner(argv, capture_output, text, timeout):
        return FakeCompleted(1, stderr="scan failed")

    result = sync_image_sbom(
        estate="estate-a",
        service="redis",
        ref=ref,
        raw_image="redis:7-alpine@sha256:" + "a" * 64,
        dt_config=dt_config,
        session=session,
        subprocess_runner=failing_runner,
    )
    assert result.uploaded is False
    assert result.error
    assert session.calls == []


def test_sync_image_sbom_forwards_container_knobs_to_trivy(tmp_path):
    key_file = tmp_path / "dt-api-key"
    key_file.write_text("super-secret-key\n")
    dt_config = DependencyTrackConfig(base_url="https://skbom.example.org", api_key_file=str(key_file))
    ref = parse_image_ref("nextcloud:34.0.4@sha256:" + "b" * 64)
    captured = {}

    def fake_runner(argv, capture_output, text, timeout):
        captured["argv"] = argv
        return FakeCompleted(0, stdout=json.dumps(CYCLONEDX_BOM))

    result = sync_image_sbom(
        estate="estate-a",
        service="skhub-prod_nextcloud",
        ref=ref,
        raw_image="nextcloud:34.0.4@sha256:" + "b" * 64,
        dt_config=dt_config,
        session=FakeSession(),
        subprocess_runner=fake_runner,
        use_container=True,
        cache_dir="/tmp/skpatch-trivy-cache",
    )
    assert result.uploaded is True
    assert captured["argv"][0] == "docker"


def test_sync_image_sbom_reports_a_missing_api_key_file_without_raising():
    dt_config = DependencyTrackConfig(base_url="https://skbom.example.org", api_key_file="/does/not/exist")
    ref = parse_image_ref("redis:7-alpine@sha256:" + "a" * 64)
    result = sync_image_sbom(
        estate="estate-a",
        service="redis",
        ref=ref,
        raw_image="redis:7-alpine@sha256:" + "a" * 64,
        dt_config=dt_config,
        session=FakeSession(),
    )
    assert result.uploaded is False
    assert "does not exist" in result.error
