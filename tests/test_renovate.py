"""renovate.run_renovate must build a docker-run invocation that never
shell-interpolates config content, read the bot token from its own file
(never a value baked into this repo), and report a container failure in the
result rather than raising - so a scheduled weekly run can log it and keep
going."""

import pytest

from skpatch.config import RenovateConfig
from skpatch.renovate import RenovateError, build_docker_run_argv, build_renovate_env, run_renovate


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def make_config(**overrides):
    defaults = dict(
        endpoint="https://skgit.example.org/api/v1",
        token_file="/does/not/matter",
        repositories=["smilintux-estate/skstacks"],
    )
    defaults.update(overrides)
    return RenovateConfig(**defaults)


def test_build_renovate_env_carries_platform_endpoint_and_repositories():
    cfg = make_config()
    env = build_renovate_env(cfg, "tok-123")
    assert env["RENOVATE_PLATFORM"] == "gitea"
    assert env["RENOVATE_ENDPOINT"] == cfg.endpoint
    assert env["RENOVATE_TOKEN"] == "tok-123"
    assert "smilintux-estate/skstacks" in env["RENOVATE_REPOSITORIES"]


def test_build_docker_run_argv_never_interpolates_values_into_a_shell_string():
    cfg = make_config()
    env = build_renovate_env(cfg, "tok-123")
    argv = build_docker_run_argv(cfg, env)
    assert argv[:3] == ["docker", "run", "--rm"]
    assert argv[-1] == cfg.image
    # every env var is its own -e NAME=value pair, not a single joined string
    assert argv.count("-e") == len(env)


def test_run_renovate_reads_the_token_from_its_own_file(tmp_path):
    token_file = tmp_path / "renovate-token"
    token_file.write_text("real-token\n")
    cfg = make_config(token_file=str(token_file))
    seen = {}

    def fake_runner(argv, capture_output, text, timeout):
        seen["argv"] = argv
        return FakeCompleted(0, stdout="renovate ran clean")

    result = run_renovate(cfg, runner=fake_runner)
    assert result.ok is True
    assert "real-token" in " ".join(seen["argv"])


def test_run_renovate_raises_renovate_error_on_missing_token_file(tmp_path):
    cfg = make_config(token_file=str(tmp_path / "missing"))
    with pytest.raises(RenovateError):
        run_renovate(cfg, runner=lambda *a, **k: FakeCompleted(0))


def test_run_renovate_reports_a_nonzero_container_exit_without_raising():
    cfg = make_config()

    def failing_runner(argv, capture_output, text, timeout):
        return FakeCompleted(1, stderr="renovate config error")

    result = run_renovate(cfg, token="tok", runner=failing_runner)
    assert result.ok is False
    assert result.returncode == 1
