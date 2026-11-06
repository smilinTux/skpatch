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
    )
    click.echo(_dump(result))
    if not result.uploaded:
        raise SystemExit(1)


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
