"""Smoke tests for every `skpatch` subcommand: each one must load config,
call into the right library function, print JSON, and exit non-zero on a
failure result - without ever touching a real network, subprocess, or ssh
session (every library call is monkeypatched)."""

import json

from click.testing import CliRunner

from skpatch import cli
from skpatch.inventory import InventoryResult
from skpatch.renovate import RenovateResult
from skpatch.sbom import SyncResult


def write_config(tmp_path, body):
    path = tmp_path / "config.yaml"
    path.write_text(body)
    return path


def test_inventory_command_prints_json_for_every_configured_estate(tmp_path, monkeypatch):
    config_path = write_config(
        tmp_path,
        """
clusters:
  estate-a:
    manager_hosts: ["mgr-a1.example"]
""",
    )

    def fake_collect(estate, hosts, **kwargs):
        return InventoryResult(estate=estate, manager_used=hosts[0], services=[], unreachable=False)

    monkeypatch.setattr(cli.inventory_mod, "collect_estate_inventory", fake_collect)
    result = CliRunner().invoke(cli.main, ["inventory", "--config", str(config_path)])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["estate"] == "estate-a"


def test_inventory_command_with_no_estates_configured_exits_nonzero(tmp_path):
    config_path = write_config(tmp_path, "clusters: {}\n")
    result = CliRunner().invoke(cli.main, ["inventory", "--config", str(config_path)])
    assert result.exit_code != 0


def test_policy_command_classifies_findings_from_a_json_file(tmp_path):
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps(
            [
                {"cve_id": "CVE-2026-1", "severity": "critical", "fix_available": True, "exposure": "public"},
                {"cve_id": "CVE-2026-2", "severity": "low", "fix_available": True},
            ]
        )
    )
    result = CliRunner().invoke(cli.main, ["policy", "--findings-file", str(findings_path)])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["same_day"][0]["cve_id"] == "CVE-2026-1"
    assert payload["monthly"][0]["cve_id"] == "CVE-2026-2"


def test_sbom_command_without_dependency_track_block_exits_nonzero(tmp_path):
    config_path = write_config(tmp_path, "clusters: {}\n")
    result = CliRunner().invoke(
        cli.main,
        [
            "sbom",
            "--config",
            str(config_path),
            "--estate",
            "estate-a",
            "--service",
            "svc",
            "--image",
            "redis:7-alpine",
        ],
    )
    assert result.exit_code != 0


def test_sbom_command_reports_a_failed_upload_as_nonzero_exit(tmp_path, monkeypatch):
    key_file = tmp_path / "key"
    key_file.write_text("k")
    config_path = write_config(
        tmp_path,
        f"""
clusters: {{}}
dependency_track:
  base_url: "https://skbom.example.org"
  api_key_file: "{key_file}"
""",
    )

    def fake_sync(**kwargs):
        return SyncResult(
            estate=kwargs["estate"],
            service=kwargs["service"],
            project_name="estate-a/svc",
            project_version="v1@sha256:" + "a" * 64,
            uploaded=False,
            deactivated_versions=[],
            error="trivy failed",
        )

    monkeypatch.setattr(cli.sbom_mod, "sync_image_sbom", fake_sync)
    result = CliRunner().invoke(
        cli.main,
        [
            "sbom",
            "--config",
            str(config_path),
            "--estate",
            "estate-a",
            "--service",
            "svc",
            "--image",
            "redis:7-alpine@sha256:" + "a" * 64,
        ],
    )
    assert result.exit_code != 0


def test_renovate_command_without_renovate_block_exits_nonzero(tmp_path):
    config_path = write_config(tmp_path, "clusters: {}\n")
    result = CliRunner().invoke(cli.main, ["renovate", "--config", str(config_path)])
    assert result.exit_code != 0


def test_renovate_command_prints_the_result_and_succeeds(tmp_path, monkeypatch):
    config_path = write_config(
        tmp_path,
        """
clusters: {}
renovate:
  endpoint: "https://skgit.example.org/api/v1"
  token_file: "/does/not/matter"
  repositories: ["estate-a/skstacks"]
""",
    )
    monkeypatch.setattr(
        cli.renovate_mod, "run_renovate", lambda cfg: RenovateResult(ok=True, returncode=0, stdout="clean")
    )
    result = CliRunner().invoke(cli.main, ["renovate", "--config", str(config_path)])
    assert result.exit_code == 0
    assert json.loads(result.output)["ok"] is True


def test_probe_command_with_no_matching_runtime_reports_empty_runtimes(tmp_path, monkeypatch):
    config_path = write_config(tmp_path, "clusters: {}\n")
    monkeypatch.setattr(
        cli.probe_mod,
        "load_floors",
        lambda path: {"php": {"images": ["nextcloud"], "probe": ["php"], "min_versions": {}}},
    )
    result = CliRunner().invoke(
        cli.main,
        [
            "probe",
            "--config",
            str(config_path),
            "--estate",
            "estate-a",
            "--service",
            "svc",
            "--image-repo",
            "redis",
            "--manager",
            "mgr1",
        ],
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["runtimes"] == []


def test_probe_command_evaluates_a_matching_runtime(tmp_path, monkeypatch):
    config_path = write_config(tmp_path, "clusters: {}\n")
    floors = {
        "php": {
            "images": ["nextcloud"],
            "probe": ["php", "-r", "echo PHP_VERSION;"],
            "parse": r"(\d+\.\d+\.\d+)",
            "min_versions": {"8.5": 12},
        }
    }
    monkeypatch.setattr(cli.probe_mod, "load_floors", lambda path: floors)
    monkeypatch.setattr(
        cli.probe_mod, "probe_runtime", lambda *a, **k: type("R", (), {"output": "8.5.10", "error": None})()
    )
    result = CliRunner().invoke(
        cli.main,
        [
            "probe",
            "--config",
            str(config_path),
            "--estate",
            "estate-a",
            "--service",
            "svc",
            "--image-repo",
            "nextcloud",
            "--manager",
            "mgr1",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["below_floor"] is True
