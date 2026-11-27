"""Scan an image on the swarm node that runs it.

Some images can't be pulled from the operator host: they were built on an
estate node and never pushed (``skgentis/skgentis:<sha>`` on a single-node
estate, ``skfence-prod-error-pages:latest``), or they name an estate-local
registry such as ``127.0.0.1:5000/...``. For those, ``skpatch sbom --on-node``
finds the node running the service's task and runs the same pinned Trivy
container there, against that node's Docker daemon (Trivy only reads
images through the socket). The BOM comes back over ssh
and is uploaded from the operator host exactly like a local scan.

This is the one place skpatch starts a container on an estate node (the
throwaway ``--rm`` Trivy scanner). It never changes a service, an image tag
or a host package.
"""

from __future__ import annotations

import dataclasses
import shlex
import subprocess

from skpatch._remote import SSH_TIMEOUT_SECONDS, run_remote
from skpatch.config import ClusterConfig
from skpatch.imageref import ImageRef
from skpatch.inventory import _first_reachable_manager

NODE_CACHE_DIR = "/var/cache/skpatch-trivy"
# Estate nodes are often busy, and some local images are large (a 4.2 GB ML
# worker took over Trivy's default 5 minutes on a loaded nam node).
NODE_SCAN_TIMEOUT_SECONDS = 1200


def _ssh_kw(cluster: ClusterConfig) -> dict:
    return {"jump": cluster.jump, "user": cluster.ssh_user, "identity": cluster.ssh_identity}


def locate_node(cluster: ClusterConfig, service: str, *, runner=subprocess.run) -> str | None:
    """Hostname of the swarm node running ``service``'s task, or None."""
    manager, _ = _first_reachable_manager(
        "", cluster.manager_hosts, cluster.jump, cluster.ssh_user, cluster.ssh_identity, runner
    )
    if manager is None:
        return None
    cmd = (
        f"sudo docker service ps {shlex.quote(service)} --filter desired-state=running "
        "--format '{{.Node}}'"
    )
    res = run_remote(manager, cmd, runner=runner, **_ssh_kw(cluster))
    nodes = [line.strip() for line in res.stdout.splitlines() if line.strip()] if res.ok else []
    return nodes[0] if nodes else None


def node_host(cluster: ClusterConfig, node: str) -> str:
    """The ssh host for a swarm node hostname (``node_hosts`` alias, else the name itself)."""
    return cluster.node_hosts.get(node, node)


def running_image_id(host: str, cluster: ClusterConfig, service: str, *, runner=subprocess.run) -> str | None:
    """Image id of ``service``'s running container on ``host``. Scanning by id
    finds the image even when its tag has since been removed or moved on the
    node (a rebuilt local tag, a pruned estate-local registry name)."""
    svc = shlex.quote(service)
    cmd = (
        f"C=$(sudo docker ps -q --filter label=com.docker.swarm.service.name={svc} | head -n1); "
        '[ -n "$C" ] && sudo docker inspect --format \'{{.Image}}\' "$C"'
    )
    res = run_remote(host, cmd, runner=runner, **_ssh_kw(cluster))
    image_id = res.stdout.strip() if res.ok else ""
    return image_id if image_id.startswith("sha256:") else None


def pin_ref(ref: ImageRef, image_id: str | None) -> ImageRef:
    """Give a tag-only ref the running image id as its digest, so the
    Dependency-Track version changes when a mutable tag (``latest``) is rebuilt."""
    return dataclasses.replace(ref, digest=image_id) if image_id and not ref.digest else ref


def trivy_runner(
    host: str,
    cluster: ClusterConfig,
    *,
    container_image: str,
    cache_dir: str = NODE_CACHE_DIR,
    runner=subprocess.run,
):
    """A ``subprocess.run`` stand-in for ``sbom.run_trivy_sbom`` that runs the
    trivy arguments inside ``container_image`` on ``host``."""

    def run(argv, *, capture_output=True, text=True, timeout=300, **_ignored):
        timeout = max(timeout, NODE_SCAN_TIMEOUT_SECONDS)
        args = list(argv[1:])
        if args[:1] == ["image"]:
            args[1:1] = ["--timeout", f"{timeout - 60}s"]
        trivy_args = " ".join(shlex.quote(a) for a in args)
        cmd = (
            "sudo docker run --rm --network host "
            "-v /var/run/docker.sock:/var/run/docker.sock "
            f"-v {shlex.quote(cache_dir)}:/root/.cache/trivy "
            f"{shlex.quote(container_image)} {trivy_args}"
        )
        res = run_remote(host, cmd, runner=runner, timeout=timeout + SSH_TIMEOUT_SECONDS, **_ssh_kw(cluster))
        if res.unreachable and not res.stderr:
            res.stderr = f"could not reach {host}"
        return subprocess.CompletedProcess(argv, 0 if res.ok else 1, res.stdout, res.stderr)

    return run
