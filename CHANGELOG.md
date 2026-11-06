# Changelog

All notable changes to `skpatch` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added

- `src/skpatch/` Python package: `config` (pydantic estate-config schema),
  `inventory` (read-only Swarm inventory over ssh), `exposure` (Traefik
  label classification into `public`/`sso`/`internal`), `probe` (in-image
  runtime version probe plus security-floor evaluation, e.g. PHP), `sbom`
  (Trivy CycloneDX scan + Dependency-Track upload with inactive-version
  cleanup), `policy` (pure release-lane classification over
  Dependency-Track findings), `notify` (optional SKAlert/Telegram, Nextcloud
  Talk, and GTD-upsert adapters, config-driven, fail-closed on missing
  credentials), and `renovate` (runs the `renovate/renovate` container
  against a Forgejo/Gitea endpoint).
- `skpatch` CLI (`inventory`, `sbom`, `policy`, `renovate`, `probe`
  subcommands).
- `windmill/f/skpatch/` Windmill scripts and flows (`inventory`, `sbom`,
  `renovate`, `policy_alerts`, plus a daily and a weekly flow) wrapping the
  CLI entry points, in the `wmill sync` layout.
- `inventory.py`, `exposure.py`, `probe.py` (folding in the former
  `php_floor.py` logic), and `imageref.py` salvaged and adapted from
  `smilinTux/skstacks` PR #223 (`v1/scripts/image_monitor/`), with the
  hand-rolled vulnerability register (`vulns.yml`, `vuln_register.py`,
  `versions.py`, `registry.py`, `render_register.py`,
  `check_fleet_vulns.py`) deliberately left behind: Dependency-Track is now
  the register, and Renovate detects upstream versions and rebuilds.
- Docs per the SK repo doc standard: `README.md`, `SOP.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `docs/skpatch-program.md`.
- CI: `tests.yml` (pytest), `skred-scan.yml` (gitleaks + Trivy + Semgrep +
  estate denylist, mirroring `smilinTux/skstacks`), `validate-docs.yml`
  (mermaid fences parse, no em/en dashes).
- 76 pytest tests across 10 modules plus the CLI, all mocking
  subprocess/HTTP - no network, no live host, no real Docker or ssh.
- **Phase 4:** `skpatch.dtrack`, a Dependency-Track API client
  (`ensure_project`, `upload_bom` by project uuid, `wait_processed`,
  `project_metrics`, `findings`, plus a `finding_to_policy_kwargs` mapper
  into `skpatch.policy.Finding`), with its own test suite. `skpatch.sbom`
  gains an opt-in pinned-container Trivy mode (`TRIVY_IMAGE`,
  `use_container`, `cache_dir`) alongside the existing local-binary path;
  defaults are unchanged. `EstateConfig` gains a `trivy` block wiring those
  knobs through an operator's config file. `skpatch` CLI gains a `dtrack`
  group (`dtrack upload`). New Windmill flow `f/skpatch/sbom_daily`
  (03:30 UTC): inventory -> per-service `sbom_dtrack_sync` (Trivy scan,
  real-time exposure lookup, Dependency-Track upload by project uuid,
  policy classify, immediate same_day/watch notice) -> `sbom_daily_summary`
  (one end-of-run digest). Documents the new `f/skpatch/skbom` Windmill
  resource shape. This flow runs alongside the pre-existing `f/skpatch/daily`
  (02:00 UTC, name+version autoCreate), which is unchanged.

[0.1.0]: https://github.com/smilinTux/skpatch/releases/tag/v0.1.0
