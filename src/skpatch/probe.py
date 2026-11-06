"""Probe an in-image runtime version and compare it against a security floor.

Used for runtimes where the image tag says nothing about the embedded
interpreter version (e.g. a Nextcloud image tag names the app version, not
the PHP version baked inside it). Two read-only steps:

1. Find which node a service's task is currently running on
   (``docker service ps``), then on that node find the container
   (``docker ps``) and ``docker exec`` the runtime's probe command inside it
   (e.g. ``php -r 'echo PHP_VERSION;'``). This is ``probe_runtime``, adapted
   from skstacks PR #223's ``php_probe.py``.
2. Compare the probed version string against ``floors.yaml``'s configured
   minimum-safe patch level. This is ``evaluate``/``runtimes_for_image``,
   folded in from the sibling module PR #223 called ``php_floor.py`` -
   skpatch keeps the floor table and its evaluator in one module since
   nothing else in this package consumes the floor logic on its own.

Despite the PHP-shaped example, both halves are runtime-name agnostic:
adding OpenSSL/Node/Python floors needs a ``floors.yaml`` edit, no code
change.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from skpatch._remote import run_remote

_PS_NODE_CMD_TMPL = "sudo docker service ps {svc} --filter desired-state=running --format '{{{{.Node}}}}'"
_PS_CONTAINER_CMD_TMPL = "sudo docker ps --filter name={svc} --format '{{{{.ID}}}}'"


@dataclass
class ProbeResult:
    output: str | None = None  # combined stdout from the probe command, or None on failure
    error: str | None = None


def probe_runtime(
    service: str,
    probe_argv: list[str],
    *,
    manager: str,
    jump: str | None,
    user: str | None,
    identity: str | None,
    runner=None,
) -> ProbeResult:
    """Find the node running ``service`` and exec ``probe_argv`` inside its container.

    Never raises: an unreachable node or a container missing the probed
    runtime (e.g. a non-matching image) comes back as ``ProbeResult.error``,
    not an exception, so one bad probe does not take down the whole run.
    """
    runner = runner or subprocess.run

    node_result = run_remote(
        manager, _PS_NODE_CMD_TMPL.format(svc=service), jump=jump, user=user, identity=identity, runner=runner
    )
    if not node_result.ok:
        return ProbeResult(error=f"could not find running task for {service}: {node_result.stderr.strip()}")
    nodes = [n.strip() for n in node_result.stdout.splitlines() if n.strip()]
    if not nodes:
        return ProbeResult(error=f"{service} has no running task")
    node = nodes[0]

    ps_result = run_remote(
        node,
        _PS_CONTAINER_CMD_TMPL.format(svc=service),
        jump=jump,
        user=user,
        identity=identity,
        runner=runner,
    )
    if not ps_result.ok:
        return ProbeResult(error=f"could not reach node {node} for {service}: {ps_result.stderr.strip()}")
    container_ids = [c.strip() for c in ps_result.stdout.splitlines() if c.strip()]
    if not container_ids:
        return ProbeResult(error=f"no container found for {service} on {node}")
    container_id = container_ids[0]

    exec_cmd = "sudo docker exec " + container_id + " " + " ".join(shlex.quote(a) for a in probe_argv)
    exec_result = run_remote(node, exec_cmd, jump=jump, user=user, identity=identity, runner=runner)
    if not exec_result.ok:
        return ProbeResult(error=(exec_result.stderr or "probe command failed").strip())
    return ProbeResult(output=exec_result.stdout.strip())


@dataclass
class FloorCheck:
    runtime: str
    version: str | None  # probed version string, e.g. "8.5.10"; None if unparsable/unavailable
    floor: int | None  # the configured minimum patch for this version's major.minor
    below_floor: bool
    note: str = ""  # e.g. "no floor configured for 8.6", "probe failed: ..."


def default_floors_path() -> Path:
    """The floors.yaml shipped with the package. ``--floors`` overrides it."""
    return Path(resources.files("skpatch.data").joinpath("floors.yaml"))


def load_floors(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).expanduser().read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping of runtime -> config")
    return data


def runtimes_for_image(floors: dict[str, Any], image_repo: str) -> list[str]:
    """Which runtime names (keys of floors.yaml) apply to this image repo.

    Match is a case-insensitive substring check against each runtime's
    "images" list, mirroring how an operator would eyeball it ("this image
    is nextcloud, so check php").
    """
    repo_lower = image_repo.lower()
    out = []
    for name, cfg in floors.items():
        for pattern in cfg.get("images", []):
            if pattern.lower() in repo_lower:
                out.append(name)
                break
    return out


def _parse_major_minor(version: str) -> tuple[str, int] | None:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return None
    major, minor, patch = m.groups()
    return f"{major}.{minor}", int(patch)


def evaluate(
    runtime: str, floors: dict[str, Any], probed_version: str | None, probe_error: str | None = None
) -> FloorCheck:
    """Compare a probed version string against this runtime's floor table."""
    if probe_error:
        return FloorCheck(
            runtime=runtime, version=None, floor=None, below_floor=False, note=f"probe failed: {probe_error}"
        )

    cfg = floors.get(runtime, {})
    parse_re = cfg.get("parse")
    version = probed_version
    if version and parse_re:
        m = re.search(parse_re, version)
        version = m.group(1) if m else None

    if not version:
        return FloorCheck(
            runtime=runtime,
            version=probed_version,
            floor=None,
            below_floor=False,
            note="could not parse a version from the probe output",
        )

    parsed = _parse_major_minor(version)
    if not parsed:
        return FloorCheck(
            runtime=runtime,
            version=version,
            floor=None,
            below_floor=False,
            note="version string not in major.minor.patch form",
        )
    line, patch = parsed
    min_versions = cfg.get("min_versions", {})
    floor = min_versions.get(line)
    if floor is None:
        return FloorCheck(
            runtime=runtime,
            version=version,
            floor=None,
            below_floor=False,
            note=f"no floor configured for {line}.x",
        )
    return FloorCheck(runtime=runtime, version=version, floor=floor, below_floor=patch < floor)
