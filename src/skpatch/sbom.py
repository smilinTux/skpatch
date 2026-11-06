"""Generate a CycloneDX SBOM for an image digest and upload it to Dependency-Track.

Pipeline (see docs/skpatch-program.md "Pipeline" step 2):

1. ``trivy image --format cyclonedx`` on the pinned ``repo:tag@sha256:digest``
   reference, run via the injectable ``runner`` (never a bare ``os.system``,
   so tests never touch a real shell or the network).
2. Upload the resulting BOM to Dependency-Track as project
   ``<estate>/<service>``, version ``<tag>@<digest>``. Dependency-Track then
   re-matches the SBOM against NVD/GHSA/OSV on its own schedule; this module
   never queries vulnerability data itself.
3. Mark every other version of that same project inactive, so the
   dashboard and the policy module only ever see the currently-deployed
   digest as "active".

All HTTP goes through an injectable ``requests.Session``-shaped object, so
tests supply a fake with no network access.
"""

from __future__ import annotations

import base64
import json
import subprocess
from dataclasses import dataclass
from typing import Any, Protocol

from skpatch.config import DependencyTrackConfig
from skpatch.imageref import ImageRef


class SbomError(Exception):
    """Raised when trivy fails to produce a BOM, or Dependency-Track rejects an upload."""


class _HttpSession(Protocol):
    def get(self, url: str, **kwargs: Any) -> Any: ...
    def post(self, url: str, **kwargs: Any) -> Any: ...
    def patch(self, url: str, **kwargs: Any) -> Any: ...


@dataclass
class SyncResult:
    estate: str
    service: str
    project_name: str
    project_version: str
    uploaded: bool
    deactivated_versions: list[str]
    error: str = ""


def project_name_for(estate: str, service: str) -> str:
    return f"{estate}/{service}"


def project_version_for(ref: ImageRef) -> str:
    """ "<tag>@<digest>", falling back to the bare digest if the image was pinned
    by digest only (no tag)."""
    if ref.tag and ref.digest:
        return f"{ref.tag}@{ref.digest}"
    return ref.tag or ref.digest or "unknown"


def run_trivy_sbom(
    image: str, *, trivy_cmd: str = "trivy", timeout: float = 300, runner=None
) -> dict[str, Any]:
    """Run ``trivy image --format cyclonedx`` against a fully-qualified image
    reference (tag and/or digest included) and return the parsed BOM.

    Raises SbomError on a non-zero exit or unparsable output; never raises a
    raw subprocess exception so a scheduled run can log and skip one bad
    image instead of crashing the whole sync.
    """
    runner = runner or subprocess.run
    argv = [trivy_cmd, "image", "--quiet", "--format", "cyclonedx", image]
    try:
        proc = runner(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SbomError(f"trivy timed out scanning {image}") from exc
    if proc.returncode != 0:
        raise SbomError(f"trivy exited {proc.returncode} scanning {image}: {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        raise SbomError(f"trivy produced unparsable CycloneDX JSON for {image}") from exc


def _read_api_key(path: str) -> str:
    from pathlib import Path

    p = Path(path).expanduser()
    if not p.is_file():
        raise SbomError(f"{p} does not exist; provision the Dependency-Track API key there first")
    key = p.read_text().strip()
    if not key:
        raise SbomError(f"{p} is empty")
    return key


def upload_bom(
    session: _HttpSession,
    *,
    base_url: str,
    api_key: str,
    project_name: str,
    project_version: str,
    bom: dict[str, Any],
    timeout: float = 60,
) -> None:
    """PUT the BOM to Dependency-Track's ``/api/v1/bom`` endpoint.

    Dependency-Track's upload API takes the BOM base64-encoded inside a JSON
    body, with ``autoCreate`` so a never-seen-before project is created on
    first upload.
    """
    body = {
        "projectName": project_name,
        "projectVersion": project_version,
        "autoCreate": True,
        "bom": base64.b64encode(json.dumps(bom).encode()).decode(),
    }
    resp = session.post(
        f"{base_url.rstrip('/')}/api/v1/bom",
        json=body,
        headers={"X-Api-Key": api_key, "Content-Type": "application/json"},
        timeout=timeout,
    )
    status = getattr(resp, "status_code", 200)
    if status >= 300:
        raise SbomError(
            f"Dependency-Track rejected the BOM upload for {project_name}/{project_version}: {status}"
        )


def list_project_versions(
    session: _HttpSession, *, base_url: str, api_key: str, project_name: str, timeout: float = 30
) -> list[dict[str, Any]]:
    resp = session.get(
        f"{base_url.rstrip('/')}/api/v1/project",
        params={"name": project_name},
        headers={"X-Api-Key": api_key},
        timeout=timeout,
    )
    data = resp.json() if hasattr(resp, "json") else []
    return data if isinstance(data, list) else []


def deactivate_other_versions(
    session: _HttpSession,
    *,
    base_url: str,
    api_key: str,
    project_name: str,
    keep_version: str,
    timeout: float = 30,
) -> list[str]:
    """Mark every version of ``project_name`` other than ``keep_version`` inactive.

    Returns the list of versions that were deactivated.
    """
    versions = list_project_versions(
        session, base_url=base_url, api_key=api_key, project_name=project_name, timeout=timeout
    )
    deactivated: list[str] = []
    for proj in versions:
        version = proj.get("version")
        if version == keep_version or not proj.get("active", True):
            continue
        uuid = proj.get("uuid")
        if not uuid:
            continue
        session.patch(
            f"{base_url.rstrip('/')}/api/v1/project/{uuid}",
            json={"active": False},
            headers={"X-Api-Key": api_key, "Content-Type": "application/json"},
            timeout=timeout,
        )
        deactivated.append(version)
    return deactivated


def sync_image_sbom(
    *,
    estate: str,
    service: str,
    ref: ImageRef,
    raw_image: str,
    dt_config: DependencyTrackConfig,
    session: _HttpSession,
    trivy_cmd: str = "trivy",
    subprocess_runner=None,
    api_key: str | None = None,
) -> SyncResult:
    """End to end: scan ``raw_image`` with trivy, upload to Dependency-Track,
    deactivate the project's other versions.

    ``api_key`` is injectable for tests; in production it is read from
    ``dt_config.api_key_file``.
    """
    project_name = project_name_for(estate, service)
    project_version = project_version_for(ref)
    try:
        key = api_key if api_key is not None else _read_api_key(dt_config.api_key_file)
        bom = run_trivy_sbom(raw_image, trivy_cmd=trivy_cmd, runner=subprocess_runner)
        upload_bom(
            session,
            base_url=dt_config.base_url,
            api_key=key,
            project_name=project_name,
            project_version=project_version,
            bom=bom,
        )
        deactivated = deactivate_other_versions(
            session,
            base_url=dt_config.base_url,
            api_key=key,
            project_name=project_name,
            keep_version=project_version,
        )
        return SyncResult(
            estate=estate,
            service=service,
            project_name=project_name,
            project_version=project_version,
            uploaded=True,
            deactivated_versions=deactivated,
        )
    except SbomError as exc:
        return SyncResult(
            estate=estate,
            service=service,
            project_name=project_name,
            project_version=project_version,
            uploaded=False,
            deactivated_versions=[],
            error=str(exc),
        )
