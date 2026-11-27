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
    dedupe_bom,
    default_trivy_cache_dir,
    project_name_for,
    project_version_for,
    run_trivy_sbom,
    sync_image_sbom,
    upload_bom,
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
        # Dependency-Track answers 415 to a JSON POST on /api/v1/bom: POST
        # there is multipart only. JSON uploads must be a PUT.
        self.calls.append(("post", url, kwargs))
        return FakeResp(415)

    def put(self, url, **kwargs):
        self.calls.append(("put", url, kwargs))
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
    put_call = next(c for c in session.calls if c[0] == "put")
    assert put_call[1].endswith("/api/v1/bom")
    assert put_call[2]["headers"]["X-Api-Key"] == "super-secret-key"
    assert not any(c[0] == "post" for c in session.calls)


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


def test_dedupe_bom_drops_exact_duplicate_components_and_dependencies():
    crate = {"bom-ref": "pkg:cargo/aho-corasick@1.1.4", "name": "aho-corasick", "version": "1.1.4"}
    other = {"bom-ref": "pkg:cargo/aho-corasick@1.1.4", "name": "aho-corasick", "version": "1.1.4", "x": 1}
    nested = {"bom-ref": "app", "name": "app", "components": [crate, dict(crate)]}
    dep = {"ref": "app", "dependsOn": ["pkg:cargo/aho-corasick@1.1.4"]}
    bom = {
        "bomFormat": "CycloneDX",
        "components": [crate, dict(crate), other, nested],
        "dependencies": [dep, dict(dep)],
    }
    out = dedupe_bom(bom)
    # byte-identical entries go, a near duplicate stays (nothing is merged)
    assert out["components"] == [crate, other, {"bom-ref": "app", "name": "app", "components": [crate]}]
    assert out["dependencies"] == [dep]
    assert len(bom["components"]) == 4  # input left alone


def test_upload_bom_sends_a_deduplicated_bom():
    import base64

    crate = {"bom-ref": "c", "name": "c"}
    session = FakeSession()
    upload_bom(
        session,
        base_url="https://dt.example",
        api_key="k",
        project_name="nor/x",
        project_version="1@sha256:0",
        bom={"bomFormat": "CycloneDX", "components": [crate, dict(crate)]},
    )
    ((method, _url, kwargs),) = session.calls
    assert method == "put"
    sent = json.loads(base64.b64decode(kwargs["json"]["bom"]))
    assert sent["components"] == [crate]


def test_run_trivy_sbom_container_mounts_the_docker_config_read_only(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}")
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    captured = {}

    def fake_runner(argv, capture_output, text, timeout):
        captured["argv"] = argv
        return FakeCompleted(0, stdout=json.dumps(CYCLONEDX_BOM))

    run_trivy_sbom("skgit.example/x/y:1", use_container=True, cache_dir="/c", runner=fake_runner)
    argv = captured["argv"]
    assert f"{cfg}:/root/.docker/config.json:ro" in argv
    assert argv.index(f"{cfg}:/root/.docker/config.json:ro") < argv.index(TRIVY_IMAGE)

    run_trivy_sbom("x:1", use_container=True, cache_dir="/c", docker_config=None, runner=fake_runner)
    assert not any("/root/.docker/config.json" in a for a in captured["argv"])


def test_run_trivy_sbom_container_skips_a_missing_docker_config(tmp_path, monkeypatch):
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "nope"))
    captured = {}

    def fake_runner(argv, capture_output, text, timeout):
        captured["argv"] = argv
        return FakeCompleted(0, stdout=json.dumps(CYCLONEDX_BOM))

    run_trivy_sbom("x:1", use_container=True, cache_dir="/c", runner=fake_runner)
    assert not any("/root/.docker/config.json" in a for a in captured["argv"])
