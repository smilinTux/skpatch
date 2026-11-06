"""Run Renovate against a Forgejo/Gitea endpoint, as a Windmill flow step.

skpatch does not reimplement dependency-update detection: it shells out to
the official ``renovate/renovate`` container with the operator's own
endpoint, token and repository list, matching the design decision in
``docs/skpatch-program.md`` ("Renovate is a Windmill flow running the
``renovate/renovate`` container ..., not a standalone service"). This module
only builds the correct ``docker run`` invocation and environment, and runs
it through an injectable runner so tests never touch Docker or the network.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from skpatch.config import RenovateConfig


class RenovateError(Exception):
    """Raised when the token file is missing, or the renovate container itself fails."""


@dataclass
class RenovateResult:
    ok: bool
    returncode: int
    stdout: str = ""
    stderr: str = ""


def _read_token(path: str) -> str:
    p = Path(path).expanduser()
    if not p.is_file():
        raise RenovateError(f"{p} does not exist; provision the Renovate bot token there first")
    token = p.read_text().strip()
    if not token:
        raise RenovateError(f"{p} is empty")
    return token


def build_renovate_env(config: RenovateConfig, token: str) -> dict[str, str]:
    """The environment variables that configure Renovate's self-hosted run.

    ``RENOVATE_REPOSITORIES`` takes a JSON array when more than one repo is
    given; a single repo can be passed as a plain string, but a JSON array
    is accepted for either case and is simpler to build deterministically.
    """
    import json

    env = {
        "RENOVATE_PLATFORM": config.platform,
        "RENOVATE_ENDPOINT": config.endpoint,
        "RENOVATE_TOKEN": token,
        "RENOVATE_REPOSITORIES": json.dumps(config.repositories),
    }
    return env


def build_docker_run_argv(config: RenovateConfig, env: dict[str, str]) -> list[str]:
    """The ``docker run`` argv for one Renovate pass. Env values are passed
    with ``-e NAME=value`` rather than interpolated into a shell string, so
    nothing here is vulnerable to shell injection from config content."""
    argv = ["docker", "run", "--rm"]
    for key, value in env.items():
        argv += ["-e", f"{key}={value}"]
    argv.append(config.image)
    return argv


def run_renovate(
    config: RenovateConfig, *, token: str | None = None, timeout: float = 1800, runner=None
) -> RenovateResult:
    """Run one Renovate pass against ``config.endpoint``.

    ``token`` is injectable for tests; in production it is read from
    ``config.token_file``. Raises ``RenovateError`` only for a
    configuration problem (missing/empty token file); a non-zero container
    exit is reported in the returned ``RenovateResult``, not raised, so a
    caller can log it and keep the scheduled run going.
    """
    runner = runner or subprocess.run
    resolved_token = token if token is not None else _read_token(config.token_file)
    env = build_renovate_env(config, resolved_token)
    argv = build_docker_run_argv(config, env)

    try:
        proc = runner(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return RenovateResult(ok=False, returncode=-1, stderr=f"renovate run timed out: {exc}")

    return RenovateResult(
        ok=proc.returncode == 0, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr
    )
