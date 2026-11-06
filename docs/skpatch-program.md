# The skpatch program

This is the canonical, generic description of the skpatch program: what it
is, the tools involved, the schedule, the policy table, and how a finding
turns into a shipped fix. It carries no estate-specific data (no hostnames,
IPs, or client names) - that detail lives in each operator's own deploy-side
documentation (for example, `smilinTux/skstacks`'s own
`docs/skpatch-program.md`, which links back here as the canonical program
doc and adds estate-specific deployment detail).

## Goal

Every container image an estate runs is pinned (no floating `:latest`),
inventoried, scanned, and patched on a fixed cadence: a same-day fix for a
critical, publicly-reachable finding; a weekly batch for everything else
with a fix available; a monthly review for the rest. No hand-rolled
vulnerability register: Dependency-Track is the register, Renovate detects
upstream version/rebuild availability, and this package's `policy` module is
the only place a finding becomes a release-lane decision.

## Tools

| Tool | Role | Where it lives |
|---|---|---|
| **skpatch** | The Python package + CLI + Windmill flows in this repo: inventory, exposure classification, SBOM generation, policy classification, notification fan-out, Renovate invocation, runtime-floor probing. | `smilinTux/skpatch` (this repo) |
| **skbom** | The operator's packaging of Dependency-Track (API + UI + Postgres) plus the daily Trivy SBOM job, behind SSO with a dashboard tile. Receives SBOMs from `skpatch sbom`; does the actual CVE matching against NVD/GHSA/OSV on its own schedule. | A deploy role in `smilinTux/skstacks` (e.g. `v1/ansible/optional/skbom`); the Dependency-Track project itself is upstream OSS. |
| **skflow** | Windmill: the scheduler that runs this program's flows. One workspace (conventionally named `skops`), folders per project: `f/skpatch` (this program), `f/skrelease` (release-gate dispatch, tag, forward-merge, deploy), `f/ops` (shared notify adapters: Talk, Telegram/SKAlert, GTD upsert, ITIL change). | A deploy role in `smilinTux/skstacks` (e.g. `v1/ansible/optional/skflow`). |
| **Renovate** | Dependency-update detection and PR creation. Run as the official `renovate/renovate` container, driven by `skpatch renovate` / `windmill/f/skpatch/renovate.py`, against the operator's own git host (Forgejo/Gitea, or GitHub). Not a standalone service. | Upstream OSS (`renovate/renovate`), invoked by this repo. |
| **Trivy** | SBOM generation (CycloneDX) and the image-scanning engine behind `skpatch sbom`. | Upstream OSS. |

## Windmill layout

One workspace, conventionally `skops`. Folders under it:

- **`f/skpatch`** - this program: `inventory`, `sbom`, `renovate`,
  `policy_alerts`, plus a daily flow (inventory + SBOM sync) and a weekly
  flow (Renovate + policy digest). See `windmill/f/skpatch/README.md` for
  the exact script/flow layout this repo ships.
- **`f/skrelease`** - release-gate dispatch, tagging the exact tested
  commit, forward-merging, and deploying (first to the primary estate, then
  any secondary estate in the next deploy window, or same-day for a
  critical). Owned by the deploy-side repo (`skstacks`), not this one.
- **`f/ops`** - shared notification adapters this program's `notify` module
  calls into for Talk (`f/ops/notify`) and reuses the conventions of for GTD
  upsert and ITIL change records. Owned by the deploy-side repo.

## Pipeline

1. **Daily, inventory** (`f/skpatch/inventory` -> `skpatch inventory`): for
   each configured estate, `docker service ls` + `inspect` over ssh from a
   worker with read access (read-only), one row per service: image, tag,
   digest, and exposure class (`public`, `sso`, `internal`) from the Traefik
   labels (`skpatch.exposure`).
2. **Daily, SBOM sync** (`f/skpatch/sbom` -> `skpatch sbom`): for each
   distinct image digest not yet known to Dependency-Track,
   `trivy image --format cyclonedx`, uploaded as project
   `<estate>/<service>` version `<tag>@<digest>`. Old versions of the same
   project are marked inactive, so the dashboard only ever shows the
   currently-deployed digest as active.
3. **Continuous**: Dependency-Track re-matches every stored SBOM against
   NVD, GHSA, and OSV on its own schedule. `skpatch policy` (and
   `f/skpatch/policy_alerts`) classifies the resulting findings into lanes
   (see the table below) and `skpatch.notify` fans an actionable finding out
   to whichever adapters are configured.
4. **Weekly, Renovate** (`f/skpatch/renovate` -> `skpatch renovate`):
   Renovate against the operator's git host, across the framework repo and
   every instance repo it is configured for. Grouped minor/patch/digest
   PRs per service, majors handled separately. Renovate's own
   `osvVulnerabilityAlerts` opens an immediate security PR for any pin with
   a known vulnerability, outside the weekly schedule.
5. **Gate and release**: every PR runs the operator's own release gate
   (`f/skrelease` in the deploy-side repo); a green gate tags the exact
   tested commit, forward-merges, bumps the instance repo's pin, and
   deploys. This program never bypasses the gate except for the documented
   same-day critical lane, which still runs the gate, just on an expedited
   timeline.

### Policy

| Finding | Lane | Notes |
|---|---|---|
| Critical, fix available, exposure public or sso | **same_day** | Security PR, gate, deploy, same calendar day. An image-only tactical update ahead of a full gate pass is acceptable for this lane alone. |
| Critical, no fix available | **watch** | Alert, GTD waiting-for, re-checked daily until a fix lands or a mitigation decision is made. |
| High, fix available | **weekly** | Batched into the weekly Renovate/gate/deploy cycle. |
| Rebuild available on the same tag (new digest, no CVE delta) | **weekly** | Digest bumps grouped per service. |
| Everything else | **monthly** | Reviewed from the Dependency-Track/skbom dashboard. |
| Host packages (not image CVEs) | N/A - see the host-patching role | Unattended security upgrades plus a host-update dashboard, a separate deploy role from this program (`skpatch` the Ansible role in `skstacks`, distinct from `skpatch` this package - see "Naming" below). |

This table is implemented, verbatim, by `src/skpatch/policy.py`; the module
docstring and this table are kept in sync by convention (see
`CONTRIBUTING.md`'s "new policy lane or rule" row).

**Honest limits:** a full release-gate run can take hours depending on the
estate's test suite and hardware. "Same day" means same calendar day, not
same hour - shortening it is an infrastructure decision for the operator
running the gate, not something this package controls.

## Naming

Two things share the name "skpatch" by design, at two different layers:

- **This repo / Python package** - the program's code: inventory, SBOM,
  policy, notify, Renovate, probe.
- **A deploy role of the same name in `skstacks`**
  (`v1/ansible/optional/skpatch`) - the host-level linux-update-dashboard
  role (OS package patching, unattended upgrades), which predates this
  repo and covers a different layer (the host, not the container image).

Both are part of "the skpatch program" in the broadest sense: pin,
inventory, scan, and patch *everything*, image and host alike, on a
schedule.

## Out of scope

A SIEM, a registry replacement, host-level CVE scanning beyond the
unattended-upgrades role above, and scanning anything outside the
operator's own estate.
