#requirements:
#skpatch
#requests
"""Windmill wrapper: scan one image digest and sync its SBOM to Dependency-Track.

Called once per distinct, not-yet-known image digest. The caller (the daily
flow, see daily.flow/flow.yaml) is expected to loop over the rows returned
by inventory.py and only call this for digests Dependency-Track hasn't seen
yet - this script does not do that de-duplication itself, so a rerun on an
already-synced digest is harmless but wasted work, not an error.
"""
from dataclasses import asdict

import requests

from skpatch.config import load_config
from skpatch.imageref import parse_image_ref
from skpatch.sbom import sync_image_sbom


def main(config_path: str, estate: str, service: str, raw_image: str) -> dict:
    cfg = load_config(config_path)
    if cfg.dependency_track is None:
        raise ValueError("no dependency_track block in config_path")
    ref = parse_image_ref(raw_image)
    result = sync_image_sbom(
        estate=estate,
        service=service,
        ref=ref,
        raw_image=raw_image,
        dt_config=cfg.dependency_track,
        session=requests.Session(),
    )
    return asdict(result)
