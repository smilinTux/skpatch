#requirements:
#skpatch
"""Windmill wrapper: run skpatch inventory for every configured estate.

Thin wiring only. All logic lives in skpatch.inventory; this script exists
so Windmill's scheduler (f/skpatch's daily flow) has something to call with
a typed argument list. config_path points at the operator's own estate
config, read from the Windmill worker's filesystem (or a Windmill resource
path mounted there) - never a value committed to this repo.
"""
from dataclasses import asdict

from skpatch.config import load_config
from skpatch.inventory import collect_estate_inventory


def main(config_path: str, estate: str | None = None) -> list[dict]:
    cfg = load_config(config_path)
    estates = {estate: cfg.clusters[estate]} if estate else cfg.clusters
    results = []
    for name, cluster in estates.items():
        result = collect_estate_inventory(
            name,
            cluster.manager_hosts,
            jump=cluster.jump,
            user=cluster.ssh_user,
            identity=cluster.ssh_identity,
        )
        results.append(asdict(result))
    return results
