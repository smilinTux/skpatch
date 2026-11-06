"""A small Dependency-Track API client: project lookup/create, BOM upload by
project uuid, wait-for-processing, project metrics, and findings.

``skpatch.sbom.sync_image_sbom`` predates this module and drives
Dependency-Track's name+version ``autoCreate`` upload path directly (no
uuid lookup, no processing wait, no findings query); that path still works
and its tests are untouched. This module is for callers that need the
project uuid up front, such as reading metrics/findings right after an
upload, or explicit project tagging - the ``f/skpatch/sbom_dtrack_sync``
Windmill script (see windmill/f/skpatch/sbom_daily.flow) and the
``skpatch dtrack`` CLI subcommand both use it.

All HTTP goes through an injectable session (``requests.Session``-shaped:
``get``/``post``/``put``), so tests supply a fake with no network access -
see tests/test_dtrack.py.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


class DtrackError(Exception):
    """Raised when Dependency-Track rejects a request or returns something
    this client cannot use (a non-2xx status, or a 200 with no uuid/token)."""


class _HttpSession(Protocol):
    def get(self, url: str, **kwargs: Any) -> Any: ...
    def post(self, url: str, **kwargs: Any) -> Any: ...
    def put(self, url: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True)
class Project:
    uuid: str
    name: str
    version: str
    tags: list[str] = field(default_factory=list)


def _headers(api_key: str, *, json_body: bool = True) -> dict[str, str]:
    headers = {"X-Api-Key": api_key}
    if json_body:
        headers["Content-Type"] = "application/json"
    return headers


def _status(resp: Any) -> int:
    return getattr(resp, "status_code", 200)


def _json(resp: Any) -> Any:
    return resp.json() if hasattr(resp, "json") else None


def _require(resp: Any, action: str) -> Any:
    status = _status(resp)
    if status >= 300:
        raise DtrackError(f"Dependency-Track {action} failed: HTTP {status}")
    return _json(resp)


def ensure_project(
    session: _HttpSession,
    *,
    base_url: str,
    api_key: str,
    name: str,
    version: str,
    tags: list[str] | None = None,
    classifier: str = "APPLICATION",
    timeout: float = 30,
) -> Project:
    """Look up a project by name+version (``GET /api/v1/project/lookup``);
    create it (``PUT /api/v1/project``) if it does not exist yet.

    Dependency-Track has no single get-or-create endpoint. A 404 from the
    lookup means "create it"; any other non-2xx status raises.
    """
    base = base_url.rstrip("/")
    resp = session.get(
        f"{base}/api/v1/project/lookup",
        params={"name": name, "version": version},
        headers=_headers(api_key, json_body=False),
        timeout=timeout,
    )
    status = _status(resp)
    if status == 200:
        data = _json(resp) or {}
        if isinstance(data, dict) and data.get("uuid"):
            return Project(uuid=data["uuid"], name=name, version=version, tags=list(tags or []))
    elif status != 404:
        raise DtrackError(f"Dependency-Track project lookup failed: HTTP {status}")

    body: dict[str, Any] = {"name": name, "version": version, "classifier": classifier, "active": True}
    if tags:
        body["tags"] = [{"name": t} for t in tags]
    resp = session.put(f"{base}/api/v1/project", json=body, headers=_headers(api_key), timeout=timeout)
    data = _require(resp, "project create") or {}
    uuid = data.get("uuid") if isinstance(data, dict) else None
    if not uuid:
        raise DtrackError(f"Dependency-Track did not return a uuid creating project {name}/{version}")
    return Project(uuid=uuid, name=name, version=version, tags=list(tags or []))


def upload_bom(
    session: _HttpSession,
    *,
    base_url: str,
    api_key: str,
    project_uuid: str,
    cyclonedx_json_bytes: bytes,
    timeout: float = 60,
) -> str:
    """``PUT /api/v1/bom`` for an existing project (by uuid). Returns the
    processing token Dependency-Track hands back, for ``wait_processed()``.
    Raises DtrackError if the upload is rejected or no token comes back."""
    body = {"project": project_uuid, "bom": base64.b64encode(cyclonedx_json_bytes).decode()}
    resp = session.put(f"{base_url.rstrip('/')}/api/v1/bom", json=body, headers=_headers(api_key), timeout=timeout)
    data = _require(resp, "BOM upload") or {}
    token = data.get("token") if isinstance(data, dict) else None
    if not token:
        raise DtrackError(f"Dependency-Track did not return a processing token for project {project_uuid}")
    return token


def is_processed(session: _HttpSession, *, base_url: str, api_key: str, token: str, timeout: float = 30) -> bool:
    """``GET /api/v1/bom/token/{token}``: True once Dependency-Track is done
    matching this BOM against its vulnerability sources."""
    resp = session.get(
        f"{base_url.rstrip('/')}/api/v1/bom/token/{token}", headers=_headers(api_key, json_body=False), timeout=timeout
    )
    data = _require(resp, "BOM token poll") or {}
    return not bool(data.get("processing", True)) if isinstance(data, dict) else False


def wait_processed(
    session: _HttpSession,
    *,
    base_url: str,
    api_key: str,
    token: str,
    timeout: float = 30,
    poll_interval: float = 2.0,
    max_wait: float = 300.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    """Poll ``is_processed`` until it reports done, or ``max_wait`` seconds
    elapse. Returns True once processing finished, False on a timeout - a
    stuck BOM never raises here, so a scheduled run can log it and move on
    rather than fail the whole flow over one slow scan."""
    deadline = clock() + max_wait
    while True:
        if is_processed(session, base_url=base_url, api_key=api_key, token=token, timeout=timeout):
            return True
        if clock() >= deadline:
            return False
        sleep(poll_interval)


def project_metrics(
    session: _HttpSession, *, base_url: str, api_key: str, project_uuid: str, timeout: float = 30
) -> dict[str, Any]:
    """``GET /api/v1/metrics/project/{uuid}/current``."""
    resp = session.get(
        f"{base_url.rstrip('/')}/api/v1/metrics/project/{project_uuid}/current",
        headers=_headers(api_key, json_body=False),
        timeout=timeout,
    )
    return _require(resp, "project metrics fetch") or {}


def findings(
    session: _HttpSession,
    *,
    base_url: str,
    api_key: str,
    project_uuid: str,
    suppressed: bool = False,
    timeout: float = 30,
) -> list[dict[str, Any]]:
    """``GET /api/v1/finding/project/{uuid}``. Returns the raw finding
    objects Dependency-Track reports; see ``finding_to_policy_kwargs`` to
    turn one into ``skpatch.policy.Finding`` keyword arguments."""
    resp = session.get(
        f"{base_url.rstrip('/')}/api/v1/finding/project/{project_uuid}",
        params={"suppressed": "true" if suppressed else "false"},
        headers=_headers(api_key, json_body=False),
        timeout=timeout,
    )
    data = _require(resp, "findings fetch")
    return data if isinstance(data, list) else []


def finding_to_policy_kwargs(raw: dict[str, Any], *, exposure: str = "internal") -> dict[str, Any]:
    """Map one Dependency-Track finding (as returned by ``findings()``) to
    the keyword arguments ``skpatch.policy.Finding`` expects.

    Honest limit: Dependency-Track's finding schema has no first-class "fix
    available" flag. This uses the one signal it does expose, the
    component's own upgrade path (``component.latestVersion`` vs
    ``component.version``), as a conservative proxy: a missing or equal
    ``latestVersion`` is treated as "no known fix yet" (``fix_available``
    False) rather than guessed true, so an ambiguous finding lands in the
    slower ``watch``/``monthly`` lanes instead of falsely triggering a
    ``same_day`` release. See docs/skpatch-program.md's "Dependency-Track
    findings to policy.Finding mapping" for the operator-facing version of
    this caveat, and skpatch.policy for the lane table itself.
    """
    vulnerability = raw.get("vulnerability") or {}
    component = raw.get("component") or {}
    latest = component.get("latestVersion")
    current = component.get("version")
    fix_available = bool(latest) and bool(current) and latest != current
    return {
        "cve_id": vulnerability.get("vulnId") or "UNKNOWN",
        "severity": str(vulnerability.get("severity") or "unknown").lower(),
        "fix_available": fix_available,
        "exposure": exposure,
        "rebuild_available": False,
    }


def project_name_version(*, estate: str, service: str, repo: str, digest: str | None) -> tuple[str, str]:
    """``<estate>/<service>/<repo>`` project name, short (12-char) sha256
    digest as the version - the naming convention the sbom_daily flow uses
    (see windmill/f/skpatch/sbom_dtrack_sync.py), distinct from
    ``skpatch.sbom.project_name_for``'s ``<estate>/<service>`` convention
    used by the older, still-supported ``f/skpatch/sbom`` script."""
    short = digest.split(":", 1)[-1][:12] if digest else "untagged"
    return f"{estate}/{service}/{repo}", short
