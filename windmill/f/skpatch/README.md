# windmill/f/skpatch

Windmill scripts and flows for the skpatch program, in `wmill sync` layout:
a `*.py` file paired with a `*.script.yaml` of the same name is a script; a
`<name>.flow/flow.yaml` is a flow; a `<name>.schedule.yaml` attaches a cron
schedule to a flow or script of the same name.

## Workspace and folder convention

One Windmill workspace, conventionally named **`skops`**. Folders under it,
per `docs/skpatch-program.md`'s "Windmill layout":

- **`f/skpatch`** (this folder) - the scripts and flows this repo ships.
- **`f/skrelease`** - release-gate dispatch, tag, forward-merge, deploy.
  Owned by the deploy-side repo (`smilinTux/skstacks`), not this one.
- **`f/ops`** - shared notification adapters (`f/ops/notify`, the Talk bot
  target this folder's `notify.py` wraps). Owned by the deploy-side repo.

## What is here

| File | Kind | Wraps |
|---|---|---|
| `inventory.py` / `.script.yaml` | script | `skpatch.inventory.collect_estate_inventory` |
| `sbom.py` / `.script.yaml` | script | `skpatch.sbom.sync_image_sbom` |
| `renovate.py` / `.script.yaml` | script | `skpatch.renovate.run_renovate` |
| `policy_alerts.py` / `.script.yaml` | script | `skpatch.policy.classify_findings` + `skpatch.notify` |
| `sbom_dtrack_sync.py` / `.script.yaml` | script | `skpatch.dtrack` (ensure_project/upload_bom/wait_processed/findings) + `skpatch.sbom.run_trivy_sbom` + `skpatch.exposure` + `skpatch.notify`, per service |
| `sbom_daily_summary.py` / `.script.yaml` | script | `skpatch.notify.notify_all`, aggregates the sbom_dtrack_sync forloop into one digest |
| `daily.flow/flow.yaml` + `daily.schedule.yaml` | flow + schedule | inventory -> SBOM sync (name+version autoCreate path), daily at 02:00 |
| `sbom_daily.flow/flow.yaml` + `sbom_daily.schedule.yaml` | flow + schedule | inventory -> per-service Trivy scan + Dependency-Track upload (project uuid) + policy classify + same-day notice -> end-of-run digest, daily at 03:30 UTC |
| `weekly.flow/flow.yaml` + `weekly.schedule.yaml` | flow + schedule | Renovate -> policy digest, Monday 06:00 |

`sbom_daily` is the fuller Dependency-Track pipeline (explicit project
uuids, a processing wait, a findings pull, policy lanes, notify); the
pre-existing `daily` flow (autoCreate by name+version, no wait, no findings
pull) is unchanged and can run alongside it or be retired by the operator
once `sbom_daily` is adopted - see sbom_daily.flow/flow.yaml's description.

### The `f/skpatch/skbom` resource

`sbom_dtrack_sync.py` takes Dependency-Track's base URL and API key as a
Windmill resource, not a file path, because this is the Windmill-native
path (contrast with `skpatch.config.DependencyTrackConfig.api_key_file`,
which the older CLI/`sbom.py` path reads from the worker's filesystem). The
operator creates it once in the `skops` workspace, under `f/skpatch`:

```json
{
  "base_url": "https://skbom.example.org",
  "api_key": "<Dependency-Track API key>"
}
```

Never commit a filled-in copy of this resource; Windmill's own resource
store holds the secret, encrypted at rest, same as every other `$res:`
reference in this folder.

Every script's `#requirements:` header names `skpatch` (this package,
installed from this repo so Windmill's Python runtime can import it) plus
any extra dependency the script itself needs (e.g. `requests` for
`sbom.py`). None of them import `skos` or any other framework-internal
package directly - `skpatch.notify.gtd_upsert_finding`'s lazy import of
`skos.gtd_ingest` is the one exception, and it is only reached if the
operator's deploy-side Windmill environment has `skos` installed; this repo
and its tests never require it.

## Deploying these to a workspace

From a machine with `wmill` installed and authenticated against the
operator's Windmill instance:

```bash
wmill workspace add skops <your-workspace-id> <your-windmill-base-url>
wmill workspace switch skops
cd windmill
wmill sync push
```

`estate_config_path` in each `*.schedule.yaml` (`$res:f/skpatch/estate_config_path`)
is a Windmill resource the operator creates once, pointing at wherever the
worker reads its estate config from - never a value committed here.

## Local testing without Windmill

Every script's `main()` is a thin wrapper around a `skpatch` library call,
so it can be exercised directly:

```bash
python -c "import windmill.f.skpatch.inventory as m; print(m.main('/path/to/config.yaml'))"
```

(This requires `skpatch` installed and the `windmill/` directory on
`PYTHONPATH`; it is not part of the pytest suite under `tests/`, which
tests the library modules these scripts call into.)
