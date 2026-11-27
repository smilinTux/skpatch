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
from pathlib import Path
from typing import Any, Protocol

from skpatch.config import DependencyTrackConfig
from skpatch.imageref import ImageRef

# Pinned aquasec/trivy container, exact tag + digest (never a floating tag;
# see CONTRIBUTING.md's "bumping a pinned container digest" row for how to
# re-pin this). Verified against Docker Hub's repository API 2026-11-06;
# this is the "0.x" release the task that added container-mode scanning
# asked to pin, not "latest", so a re-pin is a deliberate, reviewable diff.
TRIVY_IMAGE = "aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"


def default_docker_config() -> str | None:
    """The host's docker client config (``$DOCKER_CONFIG/config.json`` or
    ``~/.docker/config.json``) if it exists, else None. A container-mode
    trivy run mounts it read-only so it can pull private registry images
    (for example skgit's) with the same logins the host already has."""
    import os

    base = os.environ.get("DOCKER_CONFIG") or str(Path("~/.docker").expanduser())
    path = Path(base) / "config.json"
    return str(path) if path.is_file() else None


def default_trivy_cache_dir() -> str:
    """Where a container-mode trivy run persists its vulnerability DB cache
    between runs (bind-mounted at /root/.cache/trivy in the container), so a
    scheduled run does not re-download the DB on every invocation."""
    return str(Path("~/.cache/skpatch/trivy").expanduser())


class SbomError(Exception):
    """Raised when trivy fails to produce a BOM, or Dependency-Track rejects an upload."""


class _HttpSession(Protocol):
    def get(self, url: str, **kwargs: Any) -> Any: ...
    def post(self, url: str, **kwargs: Any) -> Any: ...
    def put(self, url: str, **kwargs: Any) -> Any: ...
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
    # Set when the estate/stack parents or the project's place under them
    # could not be ensured. The BOM upload does not depend on it.
    hierarchy_error: str = ""


def project_name_for(estate: str, service: str) -> str:
    return f"{estate}/{service}"


def project_version_for(ref: ImageRef) -> str:
    """ "<tag>@<digest>", falling back to the bare digest if the image was pinned
    by digest only (no tag)."""
    if ref.tag and ref.digest:
        return f"{ref.tag}@{ref.digest}"
    return ref.tag or ref.digest or "unknown"


def stack_for(service: str) -> str | None:
    """The swarm stack of a ``<stack>_<service>`` name (``skhub-prod_nextcloud``
    is in ``skhub-prod``); ``None`` for a name with no stack part."""
    stack, sep, rest = service.partition("_")
    return stack if sep and stack and rest else None


def hierarchy_tags(estate: str, service: str) -> list[str]:
    stack = stack_for(service)
    return [f"estate-{estate}"] + ([f"stack-{stack}"] if stack else [])


# Collection projects (no BOM of their own) that roll their children up in
# Dependency-Track 4.13+: the estate sums its stacks, a stack sums the latest
# version of each of its services (older versions are deactivated anyway).
ESTATE_LOGIC = "AGGREGATE_DIRECT_CHILDREN"
STACK_LOGIC = "AGGREGATE_LATEST_VERSION_CHILDREN"


def _lookup_project(
    session: _HttpSession, *, base_url: str, api_key: str, name: str, version: str | None, timeout: float = 30
) -> dict[str, Any] | None:
    params = {"name": name}
    if version is not None:
        params["version"] = version
    resp = session.get(
        f"{base_url.rstrip('/')}/api/v1/project/lookup",
        params=params,
        headers={"X-Api-Key": api_key},
        timeout=timeout,
    )
    status = getattr(resp, "status_code", 200)
    if status == 404:
        return None
    if status >= 300:
        raise SbomError(f"Dependency-Track project lookup for {name} failed: HTTP {status}")
    data = resp.json() if hasattr(resp, "json") else None
    return data if isinstance(data, dict) and data.get("uuid") else None


def ensure_collection(
    session: _HttpSession,
    *,
    base_url: str,
    api_key: str,
    name: str,
    logic: str,
    classifier: str,
    tags: list[str],
    parent_uuid: str | None = None,
    timeout: float = 30,
) -> str:
    """Find or create the versionless collection project ``name`` and keep its
    collection logic and parent as given. Returns its uuid."""
    base = base_url.rstrip("/")
    headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}
    current = _lookup_project(session, base_url=base, api_key=api_key, name=name, version=None, timeout=timeout)
    if current is None:
        body: dict[str, Any] = {
            "name": name,
            "classifier": classifier,
            "collectionLogic": logic,
            "active": True,
            "tags": [{"name": t} for t in tags],
        }
        if parent_uuid:
            body["parent"] = {"uuid": parent_uuid}
        resp = session.put(f"{base}/api/v1/project", json=body, headers=headers, timeout=timeout)
        status = getattr(resp, "status_code", 200)
        data = resp.json() if hasattr(resp, "json") else None
        if status >= 300 or not isinstance(data, dict) or not data.get("uuid"):
            raise SbomError(f"Dependency-Track did not create the collection project {name}: HTTP {status}")
        return data["uuid"]
    patch: dict[str, Any] = {}
    if current.get("collectionLogic") != logic:
        patch["collectionLogic"] = logic
    if parent_uuid and (current.get("parent") or {}).get("uuid") != parent_uuid:
        patch["parent"] = {"uuid": parent_uuid}
    if patch:
        resp = session.patch(f"{base}/api/v1/project/{current['uuid']}", json=patch, headers=headers, timeout=timeout)
        status = getattr(resp, "status_code", 200)
        if status >= 300:
            raise SbomError(f"Dependency-Track refused to update the collection project {name}: HTTP {status}")
    return current["uuid"]


def ensure_hierarchy(
    session: _HttpSession, *, base_url: str, api_key: str, estate: str, service: str, timeout: float = 30
) -> str:
    """Ensure ``<estate>`` and ``<estate>/<stack>`` collection projects exist
    and return the uuid a service project belongs under (the stack, or the
    estate for a service name with no stack part)."""
    estate_uuid = ensure_collection(
        session,
        base_url=base_url,
        api_key=api_key,
        name=estate,
        logic=ESTATE_LOGIC,
        classifier="PLATFORM",
        tags=[f"estate-{estate}"],
        timeout=timeout,
    )
    stack = stack_for(service)
    if stack is None:
        return estate_uuid
    return ensure_collection(
        session,
        base_url=base_url,
        api_key=api_key,
        name=f"{estate}/{stack}",
        logic=STACK_LOGIC,
        classifier="APPLICATION",
        tags=hierarchy_tags(estate, service),
        parent_uuid=estate_uuid,
        timeout=timeout,
    )


def place_project(
    session: _HttpSession,
    *,
    base_url: str,
    api_key: str,
    project_name: str,
    project_version: str,
    parent_uuid: str,
    timeout: float = 30,
) -> None:
    """Move an existing service project under ``parent_uuid`` and mark it the
    latest version. The upload's ``parentUUID`` only applies when it creates
    the project, so projects made before the hierarchy need this."""
    current = _lookup_project(
        session, base_url=base_url, api_key=api_key, name=project_name, version=project_version, timeout=timeout
    )
    if current is None:
        return
    patch: dict[str, Any] = {}
    if (current.get("parent") or {}).get("uuid") != parent_uuid:
        patch["parent"] = {"uuid": parent_uuid}
    if current.get("isLatest") is not True:
        patch["isLatest"] = True
    if not patch:
        return
    resp = session.patch(
        f"{base_url.rstrip('/')}/api/v1/project/{current['uuid']}",
        json=patch,
        headers={"X-Api-Key": api_key, "Content-Type": "application/json"},
        timeout=timeout,
    )
    status = getattr(resp, "status_code", 200)
    if status >= 300:
        raise SbomError(f"Dependency-Track refused to move {project_name} under its stack: HTTP {status}")


def run_trivy_sbom(
    image: str,
    *,
    trivy_cmd: str = "trivy",
    use_container: bool = False,
    container_image: str = TRIVY_IMAGE,
    docker_cmd: str = "docker",
    cache_dir: str | None = None,
    docker_config: str | None = "auto",
    timeout: float = 300,
    runner=None,
) -> dict[str, Any]:
    """Run ``trivy image --format cyclonedx`` against a fully-qualified image
    reference (tag and/or digest included) and return the parsed BOM.

    Two ways to run trivy, both producing the identical CycloneDX output:

    - **local binary** (default, ``use_container=False``): ``trivy_cmd`` on
      the worker's PATH. Exactly the pre-existing behavior; nothing above
      this function needs to change to keep using it.
    - **pinned container** (``use_container=True``): the exact
      ``container_image`` (default ``TRIVY_IMAGE``, a tag+digest pin, never
      a floating tag) via ``docker_cmd run --rm``, bind-mounting
      ``cache_dir`` (default ``default_trivy_cache_dir()``) at
      ``/root/.cache/trivy`` so the vulnerability DB persists between runs.
      ``docker_config`` (default ``"auto"``: ``default_docker_config()``;
      None disables it) is mounted read-only at ``/root/.docker/config.json``
      so private registries the host is logged in to can be pulled. Only
      inline ``auth`` entries work this way, not a credential helper.

    Raises SbomError on a non-zero exit or unparsable output; never raises a
    raw subprocess exception so a scheduled run can log and skip one bad
    image instead of crashing the whole sync.
    """
    runner = runner or subprocess.run
    if use_container:
        resolved_cache_dir = cache_dir or default_trivy_cache_dir()
        argv = [
            docker_cmd,
            "run",
            "--rm",
            "-v",
            f"{resolved_cache_dir}:/root/.cache/trivy",
        ]
        resolved_docker_config = default_docker_config() if docker_config == "auto" else docker_config
        if resolved_docker_config:
            argv += ["-v", f"{resolved_docker_config}:/root/.docker/config.json:ro"]
        argv += [
            container_image,
            "image",
            "--quiet",
            "--format",
            "cyclonedx",
            image,
        ]
    else:
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


def _dedupe_items(items: list[Any]) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    for item in items:
        key = json.dumps(item, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def dedupe_bom(bom: dict[str, Any]) -> dict[str, Any]:
    """Drop exact duplicate entries from ``components`` (at every nesting
    level) and ``dependencies``.

    trivy can list the same component twice (seen with cargo crates in
    n8n and Windmill images). CycloneDX requires unique array items, so
    Dependency-Track's schema validation answers 400 to the whole BOM.
    Only byte-identical entries are dropped; nothing is merged.
    """

    def _walk(components: list[Any]) -> list[Any]:
        unique = _dedupe_items(components)
        for comp in unique:
            if isinstance(comp, dict) and isinstance(comp.get("components"), list):
                comp["components"] = _walk(comp["components"])
        return unique

    out = dict(bom)
    if isinstance(out.get("components"), list):
        out["components"] = _walk(out["components"])
    if isinstance(out.get("dependencies"), list):
        out["dependencies"] = _dedupe_items(out["dependencies"])
    return out


def upload_bom(
    session: _HttpSession,
    *,
    base_url: str,
    api_key: str,
    project_name: str,
    project_version: str,
    bom: dict[str, Any],
    timeout: float = 60,
    parent_uuid: str | None = None,
    tags: list[str] | None = None,
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
        "bom": base64.b64encode(json.dumps(dedupe_bom(bom)).encode()).decode(),
    }
    if parent_uuid:
        body["parentUUID"] = parent_uuid
    if tags:
        # Bound to the project on every upload, created or not.
        body["projectTags"] = [{"name": t} for t in tags]
        body["isLatest"] = True
    # PUT, not POST: Dependency-Track takes a JSON (base64 BOM) upload only on
    # PUT /api/v1/bom; POST there is multipart and answers 415 to JSON.
    resp = session.put(
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
    use_container: bool = False,
    container_image: str = TRIVY_IMAGE,
    docker_cmd: str = "docker",
    cache_dir: str | None = None,
    subprocess_runner=None,
    api_key: str | None = None,
    hierarchy: bool = True,
) -> SyncResult:
    """End to end: scan ``raw_image`` with trivy, upload to Dependency-Track,
    deactivate the project's other versions.

    ``api_key`` is injectable for tests; in production it is read from
    ``dt_config.api_key_file``. ``use_container``/``container_image``/
    ``docker_cmd``/``cache_dir`` pass straight through to
    ``run_trivy_sbom``; their defaults reproduce the pre-existing
    local-binary behavior exactly.

    With ``hierarchy`` (the default) the project goes under collection
    projects ``<estate>`` and ``<estate>/<stack>`` and carries the tags
    ``estate-<estate>`` and ``stack-<stack>``. A hierarchy failure is reported
    in ``hierarchy_error`` and never stops the upload.
    """
    project_name = project_name_for(estate, service)
    project_version = project_version_for(ref)
    try:
        key = api_key if api_key is not None else _read_api_key(dt_config.api_key_file)
        bom = run_trivy_sbom(
            raw_image,
            trivy_cmd=trivy_cmd,
            use_container=use_container,
            container_image=container_image,
            docker_cmd=docker_cmd,
            cache_dir=cache_dir,
            runner=subprocess_runner,
        )
        parent_uuid = None
        hierarchy_error = ""
        if hierarchy:
            try:
                parent_uuid = ensure_hierarchy(
                    session, base_url=dt_config.base_url, api_key=key, estate=estate, service=service
                )
            except SbomError as exc:
                hierarchy_error = str(exc)
        upload_bom(
            session,
            base_url=dt_config.base_url,
            api_key=key,
            project_name=project_name,
            project_version=project_version,
            bom=bom,
            parent_uuid=parent_uuid,
            tags=hierarchy_tags(estate, service) if hierarchy else None,
        )
        if parent_uuid:
            try:
                place_project(
                    session,
                    base_url=dt_config.base_url,
                    api_key=key,
                    project_name=project_name,
                    project_version=project_version,
                    parent_uuid=parent_uuid,
                )
            except SbomError as exc:
                hierarchy_error = str(exc)
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
            hierarchy_error=hierarchy_error,
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
