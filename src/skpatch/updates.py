"""Which newer releases exist for the images an estate is actually running.

Renovate on the framework repo only sees framework defaults. The versions an
estate really runs often come from instance-side pins (an encrypted vault, an
override file) that no repo scanner can read. This module closes that gap
without reimplementing version logic:

1. take the inventory (``inventory.collect_estate_inventory``: every running
   service's ``repo:tag@sha256:digest`` as Swarm reports it),
2. write one throwaway ``docker-compose.yml`` per estate that lists exactly
   those image references,
3. run Renovate in ``--platform=local --dry-run=lookup`` mode over that
   directory (nothing is pushed, no PR is opened, no token is written),
4. read Renovate's JSON log and turn it into per-image update rows
   (patch / minor / major / digest), ranked for a human.

Renovate does the hard part (semver lines, suffixes like ``-alpine``, digest
rebuilds of the same tag, registry auth), so the answer matches what Renovate
would propose on a repo. Everything is injectable for tests; nothing here
touches a node except through the inventory module's read-only ssh.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from skpatch.inventory import InventoryResult

# Update types Renovate reports that are not "a newer release": pinning a
# digest or a range is bookkeeping, not an update to roll out.
_IGNORED_UPDATE_TYPES = {"pin", "pinDigest", "lockFileMaintenance", "rollback", "bump"}
_RANK = {"major": 3, "minor": 2, "patch": 1, "digest": 0}

LOOKUP_RENOVATE_CONFIG = {
    "extends": ["config:recommended"],
    "separateMinorPatch": True,
    "separateMultipleMajor": False,
    "docker-compose": {"enabled": True},
    "dependencyDashboard": False,
    "prHourlyLimit": 0,
    "prConcurrentLimit": 0,
}


@dataclass
class ImageUpdate:
    estate: str
    image: str  # repository, e.g. "ghcr.io/immich-app/immich-server"
    current: str  # running tag, e.g. "v3.3.5"
    patch: str | None = None
    minor: str | None = None
    major: str | None = None
    digest: bool = False  # a rebuild of the same tag exists
    services: list[str] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return max(
            (_RANK[k] for k in ("major", "minor", "patch") if getattr(self, k)),
            default=_RANK["digest"],
        )


def _split_image(raw: str) -> tuple[str, str | None]:
    """``repo:tag@sha256:x`` -> (``repo``, ``tag``). The registry port colon is kept."""
    ref = raw.split("@", 1)[0]
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > slash:
        return ref[:colon], ref[colon + 1 :]
    return ref, None


def build_manifests(inventories: list[InventoryResult], workdir: str | Path) -> dict[str, list[str]]:
    """Write ``<workdir>/<estate>/docker-compose.yml`` listing every unique running image.

    Returns ``{estate: [raw image refs]}``. Unreachable estates are skipped
    (the caller reports them); a service with an image Renovate cannot read
    (digest only, no tag) is still listed, Renovate just reports no update.
    """
    out: dict[str, list[str]] = {}
    root = Path(workdir)
    for inv in inventories:
        if inv.unreachable:
            continue
        images = sorted({s.image for s in inv.services if s.image})
        out[inv.estate] = images
        d = root / inv.estate
        d.mkdir(parents=True, exist_ok=True)
        lines = ["services:"]
        for i, img in enumerate(images, 1):
            lines += [f"  s{i}:", f"    image: {json.dumps(img)}"]
        (d / "docker-compose.yml").write_text("\n".join(lines) + "\n")
    (root / "renovate.json").write_text(json.dumps(LOOKUP_RENOVATE_CONFIG, indent=2) + "\n")
    return out


def lookup_argv(command: list[str] | None, image: str, workdir: str) -> list[str]:
    """The command that runs Renovate over ``workdir``.

    ``command`` (e.g. ``["npx", "-y", "renovate@41"]``) runs Renovate directly
    in ``workdir``; without it the pinned container is used with ``workdir``
    mounted. Values never go through a shell.
    """
    if command:
        return list(command)
    return ["docker", "run", "--rm", "-v", f"{workdir}:/usr/src/app", "-w", "/usr/src/app",
            "-e", "RENOVATE_PLATFORM", "-e", "RENOVATE_DRY_RUN", "-e", "RENOVATE_REQUIRE_CONFIG",
            "-e", "LOG_LEVEL", "-e", "LOG_FORMAT", "-e", "RENOVATE_GITHUB_COM_TOKEN", image]


def lookup_env(github_token: str | None) -> dict[str, str]:
    env = {
        "RENOVATE_PLATFORM": "local",
        "RENOVATE_DRY_RUN": "lookup",
        "RENOVATE_REQUIRE_CONFIG": "ignored",
        "LOG_LEVEL": "debug",
        "LOG_FORMAT": "json",
    }
    if github_token:
        # only for github.com changelog/tag lookups and rate limits; never logged
        env["RENOVATE_GITHUB_COM_TOKEN"] = github_token
    return env


def _git_init(workdir: str, runner) -> None:
    # Renovate's local platform reads the working tree of a git repository.
    for argv in (
        ["git", "init", "-q"],
        ["git", "add", "-A"],
        ["git", "-c", "user.email=skpatch@localhost", "-c", "user.name=skpatch", "commit", "-qm", "inventory"],
    ):
        runner(argv, cwd=workdir, capture_output=True, text=True, check=True)


def parse_lookup_log(log_text: str, services: dict[tuple[str, str], list[str]] | None = None) -> list[ImageUpdate]:
    """Turn Renovate's JSON log into update rows.

    Renovate logs the full extraction (``config`` keyed by manager, each with
    ``packageFile`` and ``deps[].updates[]``) once per run. ``services`` maps
    ``(estate, raw image)`` to service names for the report.
    """
    services = services or {}
    rows: dict[tuple[str, str, str], ImageUpdate] = {}
    for line in log_text.splitlines():
        if '"packageFile"' not in line or '"config"' not in line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        cfg = entry.get("config")
        if not isinstance(cfg, dict):
            continue
        for pf in cfg.get("docker-compose", []) or []:
            estate = Path(pf.get("packageFile", "")).parts[0] if pf.get("packageFile") else "?"
            for dep in pf.get("deps", []):
                ups = [u for u in dep.get("updates", []) if u.get("updateType") not in _IGNORED_UPDATE_TYPES]
                if not ups:
                    continue
                repo = dep.get("depName") or dep.get("packageName") or "?"
                cur = str(dep.get("currentValue") or "")
                key = (estate, repo, cur)
                row = rows.setdefault(key, ImageUpdate(estate=estate, image=repo, current=cur))
                for u in ups:
                    t = u.get("updateType")
                    if t == "digest":
                        row.digest = True
                    elif t in ("patch", "minor", "major"):
                        setattr(row, t, str(u.get("newValue") or u.get("newVersion") or ""))
                raw = dep.get("replaceString") or ""
                names = services.get((estate, raw)) or [
                    n for (e, img), ns in services.items() if e == estate and _split_image(img) == (repo, cur) for n in ns
                ]
                row.services = sorted(set(row.services) | set(names))
        break  # the extraction is logged once
    return sorted(rows.values(), key=lambda r: (r.estate, -r.rank, r.image))


def run_lookup(
    inventories: list[InventoryResult],
    *,
    command: list[str] | None = None,
    image: str = "renovate/renovate:41",
    github_token: str | None = None,
    timeout: float = 1800,
    runner=None,
    workdir: str | None = None,
) -> tuple[list[ImageUpdate], str]:
    """Inventory in, update rows out. Returns ``(rows, error)``; never raises for a Renovate failure."""
    runner = runner or subprocess.run
    tmp = None
    if workdir is None:
        tmp = tempfile.TemporaryDirectory(prefix="skpatch-updates-")
        workdir = tmp.name
    try:
        build_manifests(inventories, workdir)
        services: dict[tuple[str, str], list[str]] = defaultdict(list)
        for inv in inventories:
            for s in inv.services:
                services[(inv.estate, s.image)].append(s.service)
        _git_init(workdir, runner)
        env = {**os.environ, **lookup_env(github_token)}
        try:
            proc = runner(lookup_argv(command, image, workdir), cwd=workdir, env=env,
                          capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return [], "renovate lookup timed out"
        rows = parse_lookup_log(proc.stdout, services)
        err = "" if proc.returncode == 0 else f"renovate exited {proc.returncode}: {proc.stderr[-500:]}"
        return rows, err
    finally:
        if tmp is not None:
            tmp.cleanup()


def render_markdown(rows: list[ImageUpdate], *, title: str = "Running-image updates") -> str:
    """One table per estate, majors first. Majors of data stores need a migration plan."""
    out = [f"# {title}", ""]
    by: dict[str, list[ImageUpdate]] = defaultdict(list)
    for r in rows:
        by[r.estate].append(r)
    for estate in sorted(by):
        rs = by[estate]
        counts = {k: sum(1 for r in rs if getattr(r, k)) for k in ("patch", "minor", "major")}
        out += [f"## {estate} ({len(rs)} images: {counts['patch']} patch, {counts['minor']} minor, "
                f"{counts['major']} major)", "",
                "| Image | Running | Patch | Minor | Major | Services |", "|---|---|---|---|---|---|"]
        for r in rs:
            patch = r.patch or ("rebuild" if r.digest else "")
            svcs = ", ".join(s.rsplit("_", 1)[-1] for s in r.services)[:80]
            out.append(f"| {r.image} | {r.current} | {patch} | {r.minor or ''} | {r.major or ''} | {svcs} |")
        out.append("")
    return "\n".join(out)


def summary_line(rows: list[ImageUpdate]) -> str:
    est = sorted({r.estate for r in rows})
    parts = []
    for e in est:
        rs = [r for r in rows if r.estate == e]
        parts.append(f"{e}: {len(rs)} images ({sum(1 for r in rs if r.major)} with a major)")
    return "; ".join(parts) or "no updates"
