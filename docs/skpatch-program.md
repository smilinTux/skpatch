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
| **skpatch** | The Python package + CLI + Windmill flows in this repo: inventory, exposure classification, SBOM generation (`sbom`), a Dependency-Track API client (`dtrack`: project lookup/create, BOM upload by project uuid, processing wait, metrics, findings), policy classification, notification fan-out, Renovate invocation, runtime-floor probing. | `smilinTux/skpatch` (this repo) |
| **skbom** | The operator's packaging of Dependency-Track (API + UI + Postgres) plus the daily Trivy SBOM job, behind SSO with a dashboard tile. Receives SBOMs from `skpatch sbom`; does the actual CVE matching against NVD/GHSA/OSV on its own schedule. | A deploy role in `smilinTux/skstacks` (e.g. `v1/ansible/optional/skbom`); the Dependency-Track project itself is upstream OSS. |
| **skflow** | Windmill: the scheduler that runs this program's flows. One workspace (conventionally named `skops`), folders per project: `f/skpatch` (this program), `f/skrelease` (release-gate dispatch, tag, forward-merge, deploy), `f/ops` (shared notify adapters: Talk, Telegram/SKAlert, GTD upsert, ITIL change). | A deploy role in `smilinTux/skstacks` (e.g. `v1/ansible/optional/skflow`). |
| **Renovate** | Dependency-update detection and PR creation. Run as the official `renovate/renovate` container, driven by `skpatch renovate` / `windmill/f/skpatch/renovate.py`, against the operator's own git host (Forgejo/Gitea, or GitHub). Not a standalone service. | Upstream OSS (`renovate/renovate`), invoked by this repo. |
| **Trivy** | SBOM generation (CycloneDX) and the image-scanning engine behind `skpatch sbom`. | Upstream OSS. |

## Windmill layout

One workspace, conventionally `skops`. Folders under it:

- **`f/skpatch`** - this program: `inventory`, `sbom`, `renovate`,
  `policy_alerts`, `sbom_dtrack_sync`, `sbom_daily_summary`, plus a daily
  flow (inventory + SBOM sync, name+version autoCreate), a `sbom_daily` flow
  (inventory + per-service Trivy-to-Dependency-Track sync by project uuid,
  policy classify, notify) and a weekly flow (Renovate + policy digest). See
  `windmill/f/skpatch/README.md` for the exact script/flow layout this repo
  ships, including the `f/skpatch/skbom` resource `sbom_dtrack_sync` reads.
- **`f/skrelease`** - release-gate dispatch, tagging the exact tested
  commit, forward-merging, and deploying (first to the primary estate, then
  any secondary estate in the next deploy window, or same-day for a
  critical). Owned by the deploy-side repo (`skstacks`), not this one.
- **`f/ops`** - shared notification adapters this program's `notify` module
  calls into for Talk (`f/ops/notify`) and reuses the conventions of for GTD
  upsert and ITIL change records. Owned by the deploy-side repo.

### The `f/skpatch/skbom` Windmill resource

`sbom_dtrack_sync` (the `sbom_daily` flow's per-service step) reads
Dependency-Track's base URL and API key from a Windmill resource at
`f/skpatch/skbom`, not from a file path on the worker. Shape:

```json
{
  "base_url": "https://skbom.example.org",
  "api_key": "<Dependency-Track API key>"
}
```

The operator provisions this once, in the `skops` workspace. Windmill's own
resource store holds the `api_key` value encrypted at rest; it is never
committed, logged, or printed by anything in this repo. This is a different
credential path from `skpatch.config.DependencyTrackConfig.api_key_file`
(used by the older `skpatch sbom` CLI command and the pre-existing
`f/skpatch/daily` flow), which reads the key from a file on the worker's
filesystem instead - both paths authenticate against the same
Dependency-Track instance, an operator just picks whichever one fits a
given script's runtime.

## Pipeline

1. **Daily, inventory** (`f/skpatch/inventory` -> `skpatch inventory`): for
   each configured estate, `docker service ls` + `inspect` over ssh from a
   worker with read access (read-only), one row per service: image, tag,
   digest, and exposure class (`public`, `sso`, `internal`) from the Traefik
   labels (`skpatch.exposure`).
2. **Daily, SBOM sync**: two Windmill flows cover this step, both producing
   a CycloneDX SBOM with Trivy (`skpatch.sbom.run_trivy_sbom`, either the
   `trivy` binary on the worker's PATH or the pinned `aquasec/trivy`
   container, see `skpatch.sbom.TRIVY_IMAGE`):
   - `f/skpatch/daily` (02:00 UTC, pre-existing) -> `skpatch sbom` / the
     library's `sync_image_sbom`: name+version `autoCreate` upload, project
     `<estate>/<service>` version `<tag>@<digest>`. Old versions of the
     same project are marked inactive, so the dashboard only ever shows the
     currently-deployed digest as active.
   - `f/skpatch/sbom_daily` (03:30 UTC) -> `f/skpatch/sbom_dtrack_sync` per
     inventoried service: `skpatch.dtrack.ensure_project` resolves the
     project uuid up front (project `<estate>/<service>/<repo>`, version =
     the short sha256 digest), `upload_bom` + `wait_processed` wait for
     Dependency-Track to finish matching the BOM, then `findings` is
     queried immediately and classified (step 3 below) in the same run,
     instead of waiting for a separate scheduled pass.
3. **Continuous / same-run**: Dependency-Track re-matches every stored SBOM
   against NVD, GHSA, and OSV on its own schedule; `sbom_daily` additionally
   pulls findings right after its own upload finishes processing.
   `skpatch policy` (via `f/skpatch/policy_alerts` for the weekly batch, or
   inline inside `f/skpatch/sbom_dtrack_sync` for the daily pass) classifies
   the resulting findings into lanes (see the table below) and
   `skpatch.notify` fans an actionable finding out to whichever adapters
   are configured: `sbom_dtrack_sync` fires an immediate notice per
   same_day/watch finding, and `f/skpatch/sbom_daily_summary` posts one
   end-of-run digest aggregating every service's lane counts.

   **Dependency-Track findings -> `policy.Finding` mapping (honest
   limit):** Dependency-Track's finding schema has no first-class "fix
   available" flag. `skpatch.dtrack.finding_to_policy_kwargs` uses the one
   signal it does expose, the affected component's own upgrade path
   (`component.latestVersion` vs `component.version`), as a conservative
   proxy: a missing or unchanged `latestVersion` is treated as "no known
   fix yet" rather than guessed true, so an ambiguous finding lands in the
   slower `watch`/`monthly` lanes instead of falsely triggering a
   `same_day` release. `exposure` comes from a real-time
   `skpatch.exposure` lookup inside `sbom_dtrack_sync`, not a stored value.
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
