"""`skpatch` command-line entry point.

Thin wiring over the library modules: every subcommand loads the operator's
external config (``--config``, never a value baked into this repo), calls
into ``skpatch.inventory`` / ``skpatch.sbom`` / ``skpatch.policy`` /
``skpatch.renovate`` / ``skpatch.probe``, and prints JSON to stdout so the
Windmill wrappers under ``windmill/f/skpatch/`` can parse the result. These
are also the entry points Windmill's scripts call directly in-process
(see ``windmill/f/skpatch/README.md``); the CLI exists for running by hand
and from a systemd timer.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from typing import Any

import click

from skpatch import dtrack as dtrack_mod
from skpatch import exposure as exposure_mod
from skpatch import inventory as inventory_mod
from skpatch import policy as policy_mod
from skpatch import probe as probe_mod
from skpatch import renovate as renovate_mod
from skpatch import sbom as sbom_mod
from skpatch.config import load_config
from skpatch.imageref import parse_image_ref


def _dump(obj: Any) -> str:
    def default(o: Any) -> Any:
        if hasattr(o, "__dict__"):
            return asdict(o) if hasattr(o, "__dataclass_fields__") else o.__dict__
        return str(o)

    return json.dumps(obj, indent=2, default=default)


@click.group()
@click.version_option(package_name="skpatch")
def main() -> None:
    """skpatch: pin, inventory, scan and patch every image on a schedule."""


@main.command()
@click.option("--config", "config_path", required=True, help="Path to the operator's estate config YAML.")
@click.option(
    "--estate", "estate_name", default=None, help="Only inventory this estate (default: all configured)."
)
def inventory(config_path: str, estate_name: str | None) -> None:
    """List every running service's pinned image, per estate."""
    cfg = load_config(config_path)
    estates = {estate_name: cfg.clusters[estate_name]} if estate_name else cfg.clusters
    if not estates:
        click.echo("no estates configured", err=True)
        raise SystemExit(1)

    results = []
    for name, cluster in estates.items():
        result = inventory_mod.collect_estate_inventory(
            name,
            cluster.manager_hosts,
            jump=cluster.jump,
            user=cluster.ssh_user,
            identity=cluster.ssh_identity,
        )
        results.append(result)
    click.echo(_dump(results))


@main.command()
@click.option("--config", "config_path", required=True, help="Path to the operator's estate config YAML.")
@click.option("--estate", "estate_name", required=True)
@click.option("--service", "service_name", required=True)
@click.option("--image", "raw_image", required=True, help="repo:tag@sha256:digest as reported by Swarm.")
def sbom(config_path: str, estate_name: str, service_name: str, raw_image: str) -> None:
    """Scan one image digest with Trivy and upload the SBOM to Dependency-Track."""
    import requests

    cfg = load_config(config_path)
    if cfg.dependency_track is None:
        click.echo("no dependency_track block configured", err=True)
        raise SystemExit(1)

    ref = parse_image_ref(raw_image)
    result = sbom_mod.sync_image_sbom(
        estate=estate_name,
        service=service_name,
        ref=ref,
        raw_image=raw_image,
        dt_config=cfg.dependency_track,
        session=requests.Session(),
        use_container=cfg.trivy.use_container,
        container_image=cfg.trivy.container_image or sbom_mod.TRIVY_IMAGE,
        docker_cmd=cfg.trivy.docker_cmd,
        cache_dir=cfg.trivy.cache_dir,
    )
    click.echo(_dump(result))
    if not result.uploaded:
        raise SystemExit(1)


@main.group()
def dtrack() -> None:
    """Low-level Dependency-Track operations (skpatch.dtrack): project
    lookup/create, BOM upload by project uuid, and findings/metrics."""


@dtrack.command("upload")
@click.argument("project_name")
@click.argument("project_version")
@click.argument("bom_path", type=click.File("rb"))
@click.option("--base-url", "base_url", required=True, help="Dependency-Track base URL.")
@click.option(
    "--api-key-file",
    "api_key_file",
    required=True,
    help="Path to a file whose only content is the Dependency-Track API key.",
)
@click.option("--tag", "tags", multiple=True, help="Project tag; repeatable.")
@click.option(
    "--wait/--no-wait", default=True, help="Wait for Dependency-Track to finish processing the BOM."
)
def dtrack_upload(
    project_name: str,
    project_version: str,
    bom_path,
    base_url: str,
    api_key_file: str,
    tags: tuple,
    wait: bool,
) -> None:
    """Ensure PROJECT_NAME/PROJECT_VERSION exists in Dependency-Track and upload BOM_PATH to it."""
    import requests

    from skpatch.sbom import _read_api_key

    api_key = _read_api_key(api_key_file)
    session = requests.Session()
    project = dtrack_mod.ensure_project(
        session,
        base_url=base_url,
        api_key=api_key,
        name=project_name,
        version=project_version,
        tags=list(tags),
    )
    token = dtrack_mod.upload_bom(
        session,
        base_url=base_url,
        api_key=api_key,
        project_uuid=project.uuid,
        cyclonedx_json_bytes=bom_path.read(),
    )
    processed = (
        dtrack_mod.wait_processed(session, base_url=base_url, api_key=api_key, token=token) if wait else None
    )
    click.echo(_dump({"project_uuid": project.uuid, "token": token, "processed": processed}))


@main.command()
@click.option("--findings-file", "findings_path", required=True, type=click.File("r"))
def policy(findings_path) -> None:
    """Classify a JSON list of Dependency-Track findings into release lanes."""
    raw = json.load(findings_path)
    findings = [policy_mod.Finding(**row) for row in raw]
    buckets = policy_mod.classify_findings(findings)
    out = {lane.value: [asdict(f) for f in items] for lane, items in buckets.items()}
    click.echo(_dump(out))


@main.command()
@click.option("--config", "config_path", required=True, help="Path to the operator's estate config YAML.")
def renovate(config_path: str) -> None:
    """Run Renovate against the configured Forgejo/Gitea endpoint."""
    cfg = load_config(config_path)
    if cfg.renovate is None:
        click.echo("no renovate block configured", err=True)
        raise SystemExit(1)
    result = renovate_mod.run_renovate(cfg.renovate)
    click.echo(_dump(result))
    if not result.ok:
        raise SystemExit(1)


@main.command()
@click.option("--config", "config_path", required=True, help="Path to the operator's estate config YAML.")
@click.option("--estate", "estate_name", required=True)
@click.option("--service", "service_name", required=True)
@click.option(
    "--image-repo", "image_repo", required=True, help="Image repository, used to match floors.yaml."
)
@click.option("--manager", "manager_host", required=True)
@click.option("--floors", "floors_path", default=None, help="Override the bundled floors.yaml.")
def probe(
    config_path: str,
    estate_name: str,
    service_name: str,
    image_repo: str,
    manager_host: str,
    floors_path: str | None,
) -> None:
    """Probe an in-image runtime version and compare it against its security floor."""
    cfg = load_config(config_path)
    cluster = cfg.clusters.get(estate_name)
    path = floors_path or cfg.floors_file or probe_mod.default_floors_path()
    floors = probe_mod.load_floors(path)
    runtimes = probe_mod.runtimes_for_image(floors, image_repo)
    if not runtimes:
        click.echo(
            _dump({"service": service_name, "runtimes": [], "note": "no runtime floor matches this image"})
        )
        return

    checks = []
    for runtime in runtimes:
        probe_argv = floors[runtime]["probe"]
        jump = cluster.jump if cluster else None
        user = cluster.ssh_user if cluster else None
        identity = cluster.ssh_identity if cluster else None
        result = probe_mod.probe_runtime(
            service_name, probe_argv, manager=manager_host, jump=jump, user=user, identity=identity
        )
        checks.append(probe_mod.evaluate(runtime, floors, result.output, probe_error=result.error))
    click.echo(_dump(checks))


if __name__ == "__main__":
    sys.exit(main())
