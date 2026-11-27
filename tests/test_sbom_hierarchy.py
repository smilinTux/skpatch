"""Estate and stack collection projects in Dependency-Track (sbom.ensure_hierarchy)."""

from __future__ import annotations

import base64
import json
import uuid as uuidlib

from skpatch.config import DependencyTrackConfig
from skpatch.imageref import parse_image_ref
from skpatch.sbom import (
    ESTATE_LOGIC,
    STACK_LOGIC,
    hierarchy_tags,
    stack_for,
    sync_image_sbom,
)

CYCLONEDX_BOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
IMAGE = "nextcloud:34.0.4@sha256:" + "b" * 64
VERSION = "34.0.4@sha256:" + "b" * 64


class Resp:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class FakeDtrack:
    """Projects keyed by (name, version); lookup, create, patch and BOM upload."""

    def __init__(self, projects=None, fail_create=False):
        self.projects = {}
        self.calls = []
        self.fail_create = fail_create
        for p in projects or []:
            self._add(p)

    def _add(self, p):
        p = {"uuid": str(uuidlib.uuid4()), "version": None, "active": True, "isLatest": False} | p
        self.projects[(p["name"], p["version"])] = p
        return p

    def _by_uuid(self, u):
        return next(p for p in self.projects.values() if p["uuid"] == u)

    def get(self, url, params=None, **kw):
        self.calls.append(("get", url, params))
        if url.endswith("/api/v1/project/lookup"):
            p = self.projects.get((params["name"], params.get("version")))
            return Resp(200, p) if p else Resp(404)
        if url.endswith("/api/v1/project"):
            return Resp(200, [p for (n, _), p in self.projects.items() if n == params["name"]])
        return Resp(404)

    def put(self, url, json=None, **kw):
        self.calls.append(("put", url, json))
        if url.endswith("/api/v1/project"):
            if self.fail_create:
                return Resp(500)
            p = self._add({k: v for k, v in json.items() if k != "tags"} | {"tags": json.get("tags", [])})
            return Resp(201, p)
        if url.endswith("/api/v1/bom"):
            key = (json["projectName"], json["projectVersion"])
            if key not in self.projects:
                new = {"name": key[0], "version": key[1], "isLatest": bool(json.get("isLatest"))}
                if json.get("parentUUID"):
                    new["parent"] = {"uuid": json["parentUUID"]}
                self._add(new)
            self.projects[key]["tags"] = json.get("projectTags", [])
            return Resp(200, {"token": "t"})
        return Resp(404)

    def post(self, url, **kw):
        self.calls.append(("post", url, kw))
        return Resp(415)

    def patch(self, url, json=None, **kw):
        self.calls.append(("patch", url, json))
        self._by_uuid(url.rsplit("/", 1)[1]).update(json)
        return Resp(200, {})


def _sync(dt, service="skhub-prod_nextcloud", **kw):
    cfg = DependencyTrackConfig(base_url="https://skbom.example.org", api_key_file="/nonexistent")
    return sync_image_sbom(
        estate="estate-a",
        service=service,
        ref=parse_image_ref(IMAGE),
        raw_image=IMAGE,
        dt_config=cfg,
        session=dt,
        api_key="k",
        subprocess_runner=lambda *a, **k: type(
            "C", (), {"returncode": 0, "stdout": json.dumps(CYCLONEDX_BOM), "stderr": ""}
        )(),
        **kw,
    )


def test_stack_comes_from_the_swarm_service_name():
    assert stack_for("skhub-prod_nextcloud") == "skhub-prod"
    assert stack_for("chefboyrdavescafe-dbbackup_db-backup") == "chefboyrdavescafe-dbbackup"
    assert stack_for("standalone") is None
    assert stack_for("_x") is None and stack_for("x_") is None
    assert hierarchy_tags("estate-a", "skhub-prod_nextcloud") == ["estate-estate-a", "stack-skhub-prod"]
    assert hierarchy_tags("nor", "standalone") == ["estate-nor"]


def test_first_upload_builds_estate_and_stack_collections():
    dt = FakeDtrack()
    result = _sync(dt)
    assert result.uploaded and result.hierarchy_error == ""
    estate = dt.projects[("estate-a", None)]
    stack = dt.projects[("estate-a/skhub-prod", None)]
    svc = dt.projects[("estate-a/skhub-prod_nextcloud", VERSION)]
    assert estate["collectionLogic"] == ESTATE_LOGIC and "parent" not in estate
    assert stack["collectionLogic"] == STACK_LOGIC and stack["parent"] == {"uuid": estate["uuid"]}
    assert svc["parent"] == {"uuid": stack["uuid"]} and svc["isLatest"] is True
    assert svc["tags"] == [{"name": "estate-estate-a"}, {"name": "stack-skhub-prod"}]


def test_second_run_changes_nothing():
    dt = FakeDtrack()
    _sync(dt)
    dt.calls.clear()
    _sync(dt)
    assert not [c for c in dt.calls if c[0] == "patch"]
    assert [c[1] for c in dt.calls if c[0] == "put"] == ["https://skbom.example.org/api/v1/bom"]


def test_existing_flat_project_is_moved_under_its_stack():
    dt = FakeDtrack(projects=[{"name": "estate-a/skhub-prod_nextcloud", "version": VERSION}])
    result = _sync(dt)
    assert result.hierarchy_error == ""
    svc = dt.projects[("estate-a/skhub-prod_nextcloud", VERSION)]
    assert svc["parent"] == {"uuid": dt.projects[("estate-a/skhub-prod", None)]["uuid"]}
    assert svc["isLatest"] is True


def test_drifted_collection_logic_is_restored():
    dt = FakeDtrack(projects=[{"name": "estate-a", "collectionLogic": "NONE"}])
    _sync(dt)
    assert dt.projects[("estate-a", None)]["collectionLogic"] == ESTATE_LOGIC


def test_service_without_stack_sits_under_the_estate():
    dt = FakeDtrack()
    _sync(dt, service="standalone")
    svc = dt.projects[("estate-a/standalone", VERSION)]
    assert svc["parent"] == {"uuid": dt.projects[("estate-a", None)]["uuid"]}
    assert ("estate-a/standalone", None) not in dt.projects


def test_hierarchy_failure_never_stops_the_upload():
    dt = FakeDtrack(fail_create=True)
    result = _sync(dt)
    assert result.uploaded is True
    assert "collection project estate-a" in result.hierarchy_error
    assert ("estate-a/skhub-prod_nextcloud", VERSION) in dt.projects
    bom_put = next(c for c in dt.calls if c[0] == "put" and c[1].endswith("/api/v1/bom"))
    assert "parentUUID" not in bom_put[2]


def test_hierarchy_can_be_turned_off():
    dt = FakeDtrack()
    result = _sync(dt, hierarchy=False)
    assert result.uploaded and ("estate-a", None) not in dt.projects
    bom_put = next(c for c in dt.calls if c[0] == "put")
    assert "projectTags" not in bom_put[2] and "parentUUID" not in bom_put[2]
    assert json.loads(base64.b64decode(bom_put[2]["bom"])) == CYCLONEDX_BOM
