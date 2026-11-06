"""config.load_config must validate the operator's estate YAML against the
pydantic schema, reject a missing file loudly, and reject a malformed
top-level shape - never silently fall back to an empty config an unattended
run would then mis-report as "no estates configured" versus "the config is
broken"."""

import pytest

from skpatch.config import load_config


def test_missing_config_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "does-not-exist.yaml")


def test_minimal_valid_config_loads_with_defaults(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("""
clusters:
  estate-a:
    manager_hosts: ["mgr-a1.example", "mgr-a2.example"]
""")
    cfg = load_config(path)
    assert "estate-a" in cfg.clusters
    assert cfg.clusters["estate-a"].manager_hosts == ["mgr-a1.example", "mgr-a2.example"]
    assert cfg.notify.talk_digest_room == "Ops Admin"
    assert cfg.dependency_track is None
    assert cfg.trivy.use_container is False
    assert cfg.trivy.container_image is None


def test_full_config_with_dependency_track_and_renovate_blocks(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("""
clusters:
  estate-a:
    manager_hosts: ["mgr-a1.example"]
    jump: "jump.example"
dependency_track:
  base_url: "https://skbom.example.org"
  api_key_file: "~/.skcapstone/secrets/skbom-api-key"
renovate:
  endpoint: "https://skgit.example.org/api/v1"
  token_file: "~/.skcapstone/secrets/renovate-token"
  repositories: ["smilintux-estate/skstacks"]
""")
    cfg = load_config(path)
    assert cfg.dependency_track.base_url == "https://skbom.example.org"
    assert cfg.renovate.repositories == ["smilintux-estate/skstacks"]
    assert cfg.renovate.platform == "gitea"


def test_trivy_block_overrides_the_container_defaults(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        """
clusters: {}
trivy:
  use_container: true
  container_image: "aquasec/trivy:0.76.2@sha256:"""
        + "a" * 64
        + """"
  docker_cmd: "podman"
  cache_dir: "/var/cache/skpatch-trivy"
"""
    )
    cfg = load_config(path)
    assert cfg.trivy.use_container is True
    assert cfg.trivy.docker_cmd == "podman"
    assert cfg.trivy.cache_dir == "/var/cache/skpatch-trivy"


def test_top_level_list_instead_of_mapping_is_rejected(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("- not\n- a\n- mapping\n")
    with pytest.raises(ValueError):
        load_config(path)


def test_cluster_with_no_manager_hosts_is_rejected(tmp_path):
    import pydantic

    path = tmp_path / "config.yaml"
    path.write_text("""
clusters:
  estate-a:
    manager_hosts: []
""")
    with pytest.raises(pydantic.ValidationError):
        load_config(path)
