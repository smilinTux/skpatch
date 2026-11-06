# Security Policy - skpatch

`skpatch` is the public code home of a patch-management program: it inventories
running images over read-only ssh, generates SBOMs and uploads them to
Dependency-Track, classifies Dependency-Track findings into release lanes, and
drives Renovate and notification adapters. It is **not** a crypto component
(it generates no key material and performs no cryptographic operations of its
own); it declares no maturity tier under the SK cryptography standard.

It still has a real attack surface, because it runs with credentials that can
reach production inventory and because its output (a release lane, an alert)
drives operator action.

## Threat model

### In scope

| Surface | Why it matters |
|---|---|
| `src/skpatch/inventory.py`, `exposure.py`, `probe.py` | Run `sudo docker service ls/inspect/ps`, `docker ps`, `docker exec` over ssh. **Read-only by construction** - no call site in this package issues a write, a deploy, a restart, or a credential rotation. A change here that adds a write call is a design violation, not a feature. |
| `src/skpatch/sbom.py` | Shells out to `trivy` and uploads the resulting SBOM (plus, implicitly, your running inventory - which images, which versions) to your Dependency-Track instance over the configured `base_url`. An operator pointing this at a public, unauthenticated Dependency-Track instance leaks their inventory. |
| `src/skpatch/notify.py` | Holds Talk/SKAlert bearer tokens and a GTD upsert path in memory for the duration of one call. Every adapter reads its credentials from an operator-owned file (`--config`'s paths), never from a value in this repo, and fails closed (skips, logs, never raises) when that file is absent. |
| `src/skpatch/renovate.py` | Builds a `docker run renovate/renovate` invocation carrying a Forgejo/Gitea bot token. Env values are passed as discrete `-e NAME=value` argv entries, never interpolated into a shell string, so repository names or endpoints from config cannot inject a second command. |
| `.github/workflows/*.yml` | CI has no deploy credentials and no access to any estate. `skred-scan.yml`'s denylist gate reads `secrets.ESTATE_DENYLIST` to catch an accidentally-committed hostname/estate/client string; a fork PR cannot read that secret and still gets the gitleaks + Trivy + Semgrep gate. |

### Out of scope / explicitly not here

- **Any write path to a running service.** `skpatch` inventories and probes;
  it never issues `docker service update`, a restart, or a config change. The
  deploy roles (image pins, the actual update) live in `smilinTux/skstacks`.
- **Hostnames, IPs, estate layout, and client names.** These are operational
  data and never belong in this repo. See "Never commit real infrastructure
  data" below.
- **Dependency-Track and Windmill's own security posture.** This repo is a
  client of both; their own threat models are out of scope here.

## Never commit real infrastructure data

This is a **public** repo. Hostnames, IP addresses, estate names, and client
names never appear in code, tests, docs, or example configs - only
placeholders (`mgr-a1.example`, `estate-a`, `skflow.example.org`). Every
example YAML in `examples/` is a template an operator copies **outside** the
repo and fills in privately. `.github/workflows/skred-scan.yml` runs
gitleaks, Trivy, and Semgrep on every push and PR, plus an estate-denylist
gate seeded from a repo secret, following the pattern in
`smilinTux/skstacks`'s `skred-scan.yml`.

## Secret handling

- Every credential (Dependency-Track API key, Talk/SKAlert tokens, the
  Renovate bot token) is read from a file path supplied in the operator's
  own config, never from a value baked into this repo or logged by it.
- A missing or incomplete credentials file raises `NotConfigured` (notify)
  or a clear `SbomError`/`RenovateError` (sbom/renovate) - the run logs a
  warning and continues, it never crashes the whole scheduled job over one
  missing adapter.
- No module in this package ever prints a secret value, even at debug
  verbosity.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting
(Security tab -> "Report a vulnerability") on this repo rather than opening a
public issue. We aim to acknowledge within 72 hours and to agree a disclosure
timeline with the reporter before any public write-up.

## Dependency posture

Direct runtime dependencies are `pydantic`, `PyYAML`, `click`, and `requests`
(see `pyproject.toml`). `.github/workflows/skred-scan.yml` runs Trivy and
Semgrep against this repo's source and dependency manifest on every push, PR,
and nightly schedule; `tests.yml` runs the full pytest suite on every push and
PR.
