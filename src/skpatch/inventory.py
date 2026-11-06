"""Inventory every running Swarm service's image on an estate.

``docker service inspect --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}'``
returns the image in ``repo:tag@sha256:digest`` form (Swarm pins the digest
at deploy time), which is exactly what a registry/digest comparison needs. A
manager can answer for the whole cluster, so only one manager host needs to
be reachable; the others in ``manager_hosts`` are tried in order as a
fallback. Read-only throughout. Adapted from skstacks PR #223
(``v1/scripts/image_monitor/inventory.py``).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from skpatch._remote import RemoteResult, run_remote

_LS_CMD = "sudo docker service ls --format '{{.Name}}'"
_INSPECT_CMD_TMPL = (
    "sudo docker service inspect {svc} --format '{{{{.Spec.TaskTemplate.ContainerSpec.Image}}}}'"
)


@dataclass
class ServiceImage:
    estate: str
    service: str
    image: str  # raw "repo:tag@sha256:digest" as reported by Swarm


@dataclass
class InventoryResult:
    estate: str
    manager_used: str | None
    services: list[ServiceImage]
    unreachable: bool
    error: str = ""


def _first_reachable_manager(
    estate: str, manager_hosts: list[str], jump: str | None, user: str | None, identity: str | None, runner
) -> tuple[str | None, RemoteResult | None]:
    last = None
    for host in manager_hosts:
        result = run_remote(host, "true", jump=jump, user=user, identity=identity, runner=runner)
        last = result
        if not result.unreachable:
            return host, result
    return None, last


def collect_estate_inventory(
    estate: str,
    manager_hosts: list[str],
    *,
    jump: str | None = None,
    user: str | None = None,
    identity: str | None = None,
    runner=None,
) -> InventoryResult:
    """List every running service's pinned image on one estate.

    One service failing to inspect (e.g. removed mid-run) does not drop the
    rest of the inventory. Every manager host being unreachable reports
    ``unreachable=True``, it never raises.
    """
    runner = runner or subprocess.run

    manager, probe = _first_reachable_manager(estate, manager_hosts, jump, user, identity, runner)
    if manager is None:
        return InventoryResult(
            estate=estate,
            manager_used=None,
            services=[],
            unreachable=True,
            error=(probe.stderr if probe else "no manager hosts configured"),
        )

    ls_result = run_remote(manager, _LS_CMD, jump=jump, user=user, identity=identity, runner=runner)
    if not ls_result.ok:
        return InventoryResult(
            estate=estate,
            manager_used=manager,
            services=[],
            unreachable=ls_result.unreachable,
            error=ls_result.stderr or "docker service ls failed",
        )

    names = [line.strip() for line in ls_result.stdout.splitlines() if line.strip()]
    services: list[ServiceImage] = []
    for name in names:
        cmd = _INSPECT_CMD_TMPL.format(svc=name)
        inspect = run_remote(manager, cmd, jump=jump, user=user, identity=identity, runner=runner)
        if not inspect.ok:
            continue
        image = inspect.stdout.strip()
        if image:
            services.append(ServiceImage(estate=estate, service=name, image=image))

    return InventoryResult(estate=estate, manager_used=manager, services=services, unreachable=False)
