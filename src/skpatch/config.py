"""Load the operator's estate configuration.

skpatch is public framework code; the concrete hostnames, estate layout and
credentials it runs against are operational data and never live in this
repo. An operator keeps one YAML file outside the repo (e.g.
``~/.skcapstone/skpatch/config.yaml``) and passes its path with
``--config``; see ``examples/estate.example.yaml`` for the template this
module validates against.

Every field with a real-world value (hostnames, tokens, room names) lives in
that external file. Nothing here hardcodes a host, an IP or a client name.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class ClusterConfig(BaseModel):
    """One estate's reachable Swarm manager(s)."""

    manager_hosts: list[str] = Field(min_length=1)
    jump: str | None = None
    ssh_user: str | None = None
    ssh_identity: str | None = None
    docker_cmd: str = "sudo docker"


class RegistryConfig(BaseModel):
    """Upstream registry lookup / pull behavior."""

    max_retries: int = 4
    backoff_base_seconds: float = 5.0
    request_timeout_seconds: float = 15.0
    mirror: str | None = None


class DependencyTrackConfig(BaseModel):
    """Where skbom (Dependency-Track) lives and how to authenticate to it."""

    base_url: str
    api_key_file: str
    project_classifier: str = "APPLICATION"


class NotifyConfig(BaseModel):
    """Optional, config-driven notification adapters.

    Every adapter is optional: a missing credentials file disables that
    adapter for the run and logs a warning, it never raises out of a
    scheduled job. See notify.py.
    """

    skalert_credentials_file: str | None = None
    talk_credentials_file: str | None = None
    talk_digest_room: str = "Ops Admin"
    talk_urgent_room: str = "Ops Urgent"
    gtd_context: str = "@fleet"
    gtd_enabled: bool = True


class RenovateConfig(BaseModel):
    """Renovate-as-a-Windmill-flow configuration."""

    platform: str = "gitea"
    endpoint: str
    token_file: str
    repositories: list[str] = Field(default_factory=list)
    image: str = "renovate/renovate:latest"


class EstateConfig(BaseModel):
    """The full, validated operator configuration."""

    clusters: dict[str, ClusterConfig] = Field(default_factory=dict)
    floors_file: str | None = None
    state_file: str = "~/.skcapstone/skpatch/state.json"
    cache_file: str = "~/.skcapstone/skpatch/registry_cache.json"
    cache_ttl_hours: float = 20.0
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    dependency_track: DependencyTrackConfig | None = None
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    renovate: RenovateConfig | None = None

    @field_validator("clusters")
    @classmethod
    def _at_least_one_cluster_for_a_real_run(cls, v: dict[str, ClusterConfig]) -> dict[str, ClusterConfig]:
        # Empty is allowed (e.g. a config built only for `skpatch renovate`),
        # callers that need inventory/exposure/probe check this themselves.
        return v


def load_config(path: str | Path) -> EstateConfig:
    """Read and validate an estate config file.

    Raises FileNotFoundError if the path does not exist, and
    pydantic.ValidationError if the YAML does not match the schema.
    """
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"{p} does not exist; see examples/estate.example.yaml")
    raw: Any = yaml.safe_load(p.read_text()) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{p}: expected a YAML mapping at the top level")
    return EstateConfig.model_validate(raw)
