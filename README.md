# skpatch

**Pin, inventory, scan and patch every container image on a schedule: same-day
for critical, weekly for the rest.** Used by operators running a container
estate who want "a CVE lands, we know within a day and we're patched within
the week" instead of a hand-kept spreadsheet.
**Maturity tier:** T0 - N/A (no key material; see [SECURITY.md](SECURITY.md)) ·
**Version phase:** Incubating v1.

## Start here

- `src/skpatch/cli.py` - the CLI entry point; the fastest way to see how the
  pieces compose.
- `src/skpatch/policy.py` - where a Dependency-Track finding becomes a
  same-day/weekly/monthly decision.
- `docs/skpatch-program.md` - the program in full: tools, cadence, the
  policy table, release path.
- `examples/estate.example.yaml` - the config template; copy it outside
  this repo and fill in your own hosts.

## Quickstart

```bash
git clone https://github.com/smilinTux/skpatch
cd skpatch
pip install -e ".[dev]"
cp examples/estate.example.yaml ~/.skcapstone/skpatch/config.yaml  # then edit it
skpatch inventory --config ~/.skcapstone/skpatch/config.yaml
```

## What this is

`skpatch` inventories every running container image on an estate (read-only,
over ssh), classifies its exposure from Traefik labels, scans it with Trivy
and uploads the SBOM to Dependency-Track, classifies the resulting findings
into release lanes, fans alerts out to whichever notification adapters are
configured, and drives Renovate against the operator's own git host. It
ships as a Python package, a `skpatch` CLI, and a set of Windmill flows
(`windmill/f/skpatch/`) that schedule the daily inventory/SBOM pass and the
weekly Renovate/policy pass.

It is deliberately **not** the thing that applies a pin to a running
service, nor the release gate, nor the deploy. Those live in
`smilinTux/skstacks`, which this repo never writes to.

## Honest claims (read this)

- This package performs no cryptographic operations of its own and carries
  no key material; it relies entirely on the transport security (ssh, TLS)
  of the systems it talks to, which it does not alter or harden. See
  [SOP.md section 9](SOP.md#9-maturity-tier--version-reference).
- Every notify/sbom/renovate credential is read from an operator-owned file
  path outside this repo; a missing one disables that one adapter for the
  run and logs a warning, it never crashes the whole job and it is never
  logged or printed.
- "Same day" for a critical, fixed, publicly-exposed finding means same
  calendar day, not same hour; see `docs/skpatch-program.md`'s "Honest
  limits" note.

## Docs

- [SOP.md](./SOP.md) - architecture (mermaid), build, test, release,
  configuration, API reference, troubleshooting.
- [SECURITY.md](./SECURITY.md) · [CONTRIBUTING.md](./CONTRIBUTING.md) ·
  [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) ·
  [CHANGELOG.md](./CHANGELOG.md)
- [docs/skpatch-program.md](./docs/skpatch-program.md) - the patch-management
  program this package implements, in generic terms (no estate-specific
  data).

## Related projects / See also

- ⬆️ **Depends on:** [Trivy](https://github.com/aquasecurity/trivy) for SBOM
  generation, [Dependency-Track](https://github.com/DependencyTrack/dependency-track)
  as the vulnerability register, and [Renovate](https://github.com/renovatebot/renovate)
  for dependency-update detection - `skpatch` orchestrates all three, it
  reimplements none of them.
- ⬇️ **Used by:** [skstacks](https://github.com/smilinTux/skstacks) -
  `v1/ansible/optional/skpatch` (the linux-update-dashboard deploy role) and
  the forthcoming `skbom` role consume this program's conventions
  (project naming, policy lanes) without this repo ever deploying anything
  itself.
- ↔️ **Sibling:** [skstacks](https://github.com/smilinTux/skstacks) also owns
  **skflow** (Windmill, `v1/ansible/optional/skflow`) - the scheduler this
  repo's flows (`windmill/f/skpatch/`) run inside - and **sksec-web**
  ([smilinTux/sksec-skworld-io](https://github.com/smilinTux/sksec-skworld-io)),
  the edge security layer that fronts a `skbom`/Dependency-Track dashboard
  once deployed.
- ↔️ **Sibling:** [skpatch.skworld.io](https://github.com/smilinTux/skpatch-skworld-io) -
  the public-facing landing page for this program.
- 📐 **Standards:** [sk-standards](https://github.com/smilinTux/sk-standards) -
  the doc, architecture, and cryptography standards this repo follows.

*License: AGPL-3.0-or-later (matching `smilinTux/skstacks`; see [LICENSE](LICENSE)).*
