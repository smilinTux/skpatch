"""updates: running images in, Renovate lookup out, ranked rows and a report.

Renovate itself is never run here: the runner is a fake that returns a
synthetic Renovate JSON log in the exact shape a ``--dry-run=lookup`` run
logs its extraction (one line with ``config.<manager>[].deps[].updates[]``).
"""

import json
from pathlib import Path

from skpatch.inventory import InventoryResult, ServiceImage
from skpatch.updates import (
    build_manifests,
    lookup_argv,
    lookup_env,
    parse_lookup_log,
    render_markdown,
    run_lookup,
    summary_line,
)

IMMICH = "ghcr.io/immich-app/immich-server:v3.3.5@sha256:" + "a" * 64
PG = "postgres:16.15@sha256:" + "b" * 64
REDIS = "redis:8.10.3-alpine@sha256:" + "c" * 64


def inv(estate="estate-a", unreachable=False):
    return InventoryResult(
        estate=estate,
        manager_used=None if unreachable else "mgr1",
        unreachable=unreachable,
        services=(
            []
            if unreachable
            else [
                ServiceImage(estate, "skgallery-prod_immich-server", IMMICH),
                ServiceImage(estate, "skhub-prod_db", PG),
                ServiceImage(estate, "skorch-prod_db", PG),
                ServiceImage(estate, "skhub-prod_redis", REDIS),
            ]
        ),
    )


def lookup_log(estate="estate-a"):
    deps = [
        {
            "depName": "ghcr.io/immich-app/immich-server",
            "currentValue": "v3.3.5",
            "replaceString": IMMICH,
            "updates": [
                {"updateType": "patch", "newValue": "v3.3.6"},
                {"updateType": "minor", "newValue": "v3.4.2"},
            ],
        },
        {
            "depName": "postgres",
            "currentValue": "16.15",
            "replaceString": PG,
            "updates": [
                {"updateType": "minor", "newValue": "16.16"},
                {"updateType": "major", "newValue": "19.0"},
            ],
        },
        {
            "depName": "redis",
            "currentValue": "8.10.3-alpine",
            "replaceString": REDIS,
            "updates": [
                {"updateType": "digest", "newValue": "8.10.3-alpine", "newDigest": "sha256:" + "d" * 64},
                {"updateType": "pinDigest", "newValue": "8.10.3-alpine"},
            ],
        },
        {"depName": "busybox", "currentValue": "1.36", "updates": [{"updateType": "pinDigest"}]},
    ]
    extraction = {
        "msg": "packageFiles with updates",
        "config": {"docker-compose": [{"packageFile": f"{estate}/docker-compose.yml", "deps": deps}]},
    }
    return "\n".join([json.dumps({"msg": "noise"}), json.dumps(extraction), "not json"])


def test_build_manifests_writes_one_compose_per_reachable_estate(tmp_path):
    out = build_manifests([inv(), inv("estate-b", unreachable=True)], tmp_path)
    assert list(out) == ["estate-a"]
    assert out["estate-a"] == sorted({IMMICH, PG, REDIS})  # PG listed once though two services run it
    text = (tmp_path / "estate-a" / "docker-compose.yml").read_text()
    assert text.count("image:") == 3 and IMMICH in text
    assert not (tmp_path / "estate-b").exists()
    assert json.loads((tmp_path / "renovate.json").read_text())["docker-compose"]["enabled"] is True


def test_parse_ranks_majors_first_and_drops_pin_noise():
    services = {
        ("estate-a", PG): ["skhub-prod_db", "skorch-prod_db"],
        ("estate-a", IMMICH): ["skgallery-prod_immich-server"],
    }
    rows = parse_lookup_log(lookup_log(), services)
    assert [r.image for r in rows] == ["postgres", "ghcr.io/immich-app/immich-server", "redis"]
    pg, immich, redis = rows
    assert (pg.minor, pg.major, pg.services) == ("16.16", "19.0", ["skhub-prod_db", "skorch-prod_db"])
    assert (immich.patch, immich.minor, immich.major) == ("v3.3.6", "v3.4.2", None)
    assert redis.digest is True and redis.patch is None  # a rebuild of the same tag
    assert all(r.image != "busybox" for r in rows)  # pinDigest only: not an update


def test_report_and_summary():
    rows = parse_lookup_log(lookup_log())
    md = render_markdown(rows)
    assert "## estate-a (3 images: 1 patch, 2 minor, 1 major)" in md
    assert "| redis | 8.10.3-alpine | rebuild |" in md
    assert summary_line(rows) == "estate-a: 3 images (1 with a major)"
    assert summary_line([]) == "no updates"


def test_lookup_env_is_dry_run_only_and_token_optional():
    env = lookup_env(None)
    assert env["RENOVATE_PLATFORM"] == "local" and env["RENOVATE_DRY_RUN"] == "lookup"
    assert "RENOVATE_GITHUB_COM_TOKEN" not in env
    assert lookup_env("t")["RENOVATE_GITHUB_COM_TOKEN"] == "t"


def test_lookup_argv_container_passes_env_by_name_never_value():
    argv = lookup_argv(None, "renovate/renovate:41", "/w")
    assert argv[:3] == ["docker", "run", "--rm"] and argv[-1] == "renovate/renovate:41"
    assert "RENOVATE_GITHUB_COM_TOKEN" in argv and not any("=" in a for a in argv if a.startswith("RENOVATE"))
    assert lookup_argv(["npx", "-y", "renovate@41"], "ignored", "/w") == ["npx", "-y", "renovate@41"]


class Done:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_run_lookup_end_to_end_with_a_fake_runner(tmp_path):
    calls = []

    def runner(argv, **kw):
        calls.append((argv, kw.get("cwd")))
        if argv[0] == "git":
            return Done()
        assert kw["env"]["RENOVATE_DRY_RUN"] == "lookup"
        assert (Path(kw["cwd"]) / "estate-a" / "docker-compose.yml").is_file()
        return Done(0, stdout=lookup_log())

    rows, err = run_lookup([inv()], command=["renovate"], runner=runner, workdir=str(tmp_path))
    assert err == "" and len(rows) == 3
    assert [c[0][0] for c in calls] == ["git", "git", "git", "renovate"]


def test_run_lookup_reports_a_renovate_failure_instead_of_raising(tmp_path):
    def runner(argv, **kw):
        return Done() if argv[0] == "git" else Done(1, stdout="", stderr="boom")

    rows, err = run_lookup([inv()], command=["renovate"], runner=runner, workdir=str(tmp_path))
    assert rows == [] and "exited 1" in err and "boom" in err
