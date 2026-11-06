# Contributing to skpatch

Thanks for helping with `skpatch`. This repo is the public code home of the
patch-management program: image inventory, exposure classification, SBOM
generation, Dependency-Track upload, policy-lane classification, Renovate
automation, and the Windmill flows that schedule all of it. The deploy-side
roles (actually applying a pin on an estate) live in `smilinTux/skstacks`;
this repo never writes to a running service.

By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md). All contributions are licensed under
this repo's recorded license, **AGPL-3.0-or-later** (matching
`smilinTux/skstacks`; see [LICENSE](LICENSE)).

Start with [SOP.md](SOP.md) if you have not read it: sections 2-4 cover
architecture, build, and test.

## Ground rules

1. **Never commit a real hostname, IP, estate name, or client name.** This
   is a public repo; every example config under `examples/` is a template
   with placeholder hosts. See [SECURITY.md](SECURITY.md).
2. **Read-only stays read-only.** `inventory.py`, `exposure.py`, and
   `probe.py` only ever run inspection commands over ssh. A PR that adds a
   write/mutate call to one of these modules is out of scope here; that
   belongs in `skstacks`.
3. **No claim without evidence.** If a PR description says a change fixes
   something or makes a lane classification more correct, link the test
   that proves it.
4. **Credentials are config, not code.** Every notify/sbom/renovate
   credential is read from an operator-supplied file path; never add a
   default that points at a real URL or bakes in a token.
5. **Shell-safe by construction.** Config-derived values passed to
   `subprocess`/`docker run` go in as discrete argv entries, never
   interpolated into a joined shell string. `renovate.py`'s
   `build_docker_run_argv` is the pattern to follow.

## What kind of change is this?

| Change | Extra requirements |
|---|---|
| Docs/typo | Nothing beyond CI green. |
| New policy lane or rule | Update the table in `docs/skpatch-program.md` *and* `src/skpatch/policy.py`'s docstring in the same PR; add a happy-path + edge-case test. |
| New notify adapter | Must be optional and config-driven; a missing credentials file must raise `NotConfigured` and be caught by `notify_all`, never crash the run. Add tests mirroring `test_notify.py`'s "missing credentials" and "well-formed credentials" pairs. |
| New Windmill script under `windmill/f/skpatch/` | Follow the `wmill sync` layout (`*.py` + `*.script.yaml`); wire it through the existing CLI entry points rather than duplicating logic. |
| Touching `_remote.py` (the ssh helper) | Highest blast radius in the repo - every inventory/exposure/probe call goes through it. Add a test for any new failure mode (timeout, exit 255, non-zero exit) mirroring the existing three-way split. |

## Workflow

1. Branch from `main`: `fix/...`, `feat/...`, `docs/...`, `ci/...`.
2. Make your change with tests (see "Test gate" below).
3. Run the full suite locally (see [SOP.md section 4](SOP.md#4-test)).
4. Open a PR against `main`. CI runs `tests.yml`, `skred-scan.yml`, and
   `validate-docs.yml`.
5. Squash-merge once green and reviewed.

There is no release branch; a merge to `main` plus a version bump in
`pyproject.toml` and an entry in `CHANGELOG.md` is a release (see
[SOP.md section 5](SOP.md#5-release--deploy)).

## Test gate

Every module needs at least 3 tests: a happy path, an edge case, and a
failure case, mirroring the shape in `tests/`. No test may touch the
network, a real ssh session, or a real Docker daemon - `subprocess.run` and
any HTTP session are always passed in as an injectable `runner`/`session`
argument so a fake can stand in.

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -v
black --check --line-length 110 src/ tests/
```

## Commits

- Conventional, imperative subject lines: `feat(sbom): ...`,
  `fix(policy): ...`, `docs: ...`, `ci: ...`.
- No em dashes or en dashes anywhere, including commit messages - use a
  comma, a period, or a hyphen instead.
- When a contribution is co-authored by an AI agent, end the commit with a
  `Co-Authored-By:` trailer naming the agent that actually did the work.
  Never add a footer you cannot evidence.

## Reporting security issues

**Do not** open a public issue for a vulnerability. Follow
[SECURITY.md](SECURITY.md): GitHub private vulnerability reporting, 72 hour
acknowledgement, coordinated disclosure.
