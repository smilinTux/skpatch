#requirements:
#skpatch
#requests
"""Windmill wrapper: Trivy-scan one inventoried image, upload the SBOM to
Dependency-Track by project uuid (skpatch.dtrack), wait for it to finish
processing, classify the resulting findings into policy lanes, and fire an
immediate notice for any same_day/watch finding.

Called once per inventoried service by the forloop step of f/skpatch's
sbom_daily flow (see sbom_daily.flow/flow.yaml and docs/skpatch-program.md's
"Pipeline" step 2). Exposure is looked up here (skpatch.exposure, read-only
`docker service inspect` over ssh against `manager`) rather than passed in,
so this script's findings already carry a real exposure class into
skpatch.policy instead of defaulting to "internal".

Project naming here differs from skpatch.sbom.sync_image_sbom's
``<estate>/<service>`` convention used by the existing f/skpatch/sbom
script: this flow names the project ``<estate>/<service>/<repo>``, version
= the short (12-char) sha256 digest (skpatch.dtrack.project_name_version),
so a repository name shared by two services never collides on one
Dependency-Track project.

``skbom`` is the Windmill resource f/skpatch/skbom: {"base_url": str,
"api_key": str}. See docs/skpatch-program.md's "Dependency-Track Windmill
resource" section for the full shape and provisioning note.
"""

import json
from dataclasses import asdict

import requests

from skpatch import exposure as exposure_mod
from skpatch.config import load_config
from skpatch.dtrack import ensure_project, finding_to_policy_kwargs, project_name_version
from skpatch.dtrack import findings as dt_findings
from skpatch.dtrack import upload_bom as dt_upload_bom
from skpatch.dtrack import wait_processed
from skpatch.imageref import parse_image_ref
from skpatch.notify import notify_all
from skpatch.policy import Finding, Lane, classify_findings
from skpatch.sbom import TRIVY_IMAGE, run_trivy_sbom

_ACTIONABLE = {Lane.SAME_DAY, Lane.WATCH}


def main(
    config_path: str,
    estate: str,
    service: str,
    raw_image: str,
    manager: str | None,
    skbom: dict,
) -> dict:
    cfg = load_config(config_path)
    cluster = cfg.clusters.get(estate)
    ref = parse_image_ref(raw_image)
    trivy_cfg = cfg.trivy

    exposure = "internal"
    if manager and cluster:
        labels = exposure_mod.fetch_service_labels(
            service,
            manager=manager,
            jump=cluster.jump,
            user=cluster.ssh_user,
            identity=cluster.ssh_identity,
        )
        exposure = exposure_mod.classify_exposure(labels).exposure

    bom = run_trivy_sbom(
        raw_image,
        use_container=trivy_cfg.use_container,
        container_image=trivy_cfg.container_image or TRIVY_IMAGE,
        docker_cmd=trivy_cfg.docker_cmd,
        cache_dir=trivy_cfg.cache_dir,
    )

    session = requests.Session()
    base_url = skbom["base_url"]
    api_key = skbom["api_key"]
    project_name, project_version = project_name_version(
        estate=estate, service=service, repo=ref.repo, digest=ref.digest
    )

    project = ensure_project(
        session,
        base_url=base_url,
        api_key=api_key,
        name=project_name,
        version=project_version,
        tags=[estate, service],
    )
    token = dt_upload_bom(
        session,
        base_url=base_url,
        api_key=api_key,
        project_uuid=project.uuid,
        cyclonedx_json_bytes=json.dumps(bom).encode(),
    )
    processed = wait_processed(session, base_url=base_url, api_key=api_key, token=token)

    raw_findings = (
        dt_findings(session, base_url=base_url, api_key=api_key, project_uuid=project.uuid)
        if processed
        else []
    )
    parsed = [Finding(**finding_to_policy_kwargs(row, exposure=exposure)) for row in raw_findings]
    buckets = classify_findings(parsed)

    notified = []
    for lane in _ACTIONABLE:
        for finding in buckets.get(lane, []):
            room = cfg.notify.talk_urgent_room if lane == Lane.SAME_DAY else cfg.notify.talk_digest_room
            severity = "error" if lane == Lane.SAME_DAY else "warning"
            outcomes = notify_all(
                title=f"{finding.cve_id} on {estate}/{service}",
                summary=(
                    f"severity={finding.severity} fix_available={finding.fix_available} "
                    f"exposure={finding.exposure} lane={lane.value}"
                ),
                severity=severity,
                room=room,
                talk_credentials_file=cfg.notify.talk_credentials_file,
                skalert_credentials_file=cfg.notify.skalert_credentials_file,
                ref_id=f"skpatch-sbom-{finding.cve_id}-{estate}-{service}",
            )
            notified.append(
                {"cve_id": finding.cve_id, "lane": lane.value, "outcomes": [asdict(o) for o in outcomes]}
            )

    return {
        "estate": estate,
        "service": service,
        "exposure": exposure,
        "project_uuid": project.uuid,
        "project_name": project_name,
        "project_version": project_version,
        "processed": processed,
        "lanes": {lane.value: len(items) for lane, items in buckets.items()},
        "notified_same_day": notified,
    }
