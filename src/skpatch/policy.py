"""Policy lanes: which release cadence a Dependency-Track finding falls into.

Pure functions over Dependency-Track finding data; no network, no
subprocess, no filesystem access. This is the module unit tests should be
able to exercise exhaustively, since it is the one place "same day" vs
"weekly" vs "monthly" actually gets decided.

Lane table (see docs/skpatch-program.md for the operator-facing version):

| Finding                                                     | Lane        |
|--------------------------------------------------------------|-------------|
| critical, fix available, exposure public or sso              | same_day    |
| critical, no fix available                                   | watch       |
| high, fix available                                          | weekly      |
| rebuild-on-same-tag (new digest, same tag, no CVE change)     | weekly      |
| everything else                                               | monthly     |
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Lane(str, Enum):
    SAME_DAY = "same_day"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    WATCH = "watch"  # critical, no fix yet: alert + GTD waiting-for, re-check daily


_CRITICAL = "critical"
_HIGH = "high"
_PUBLIC_EXPOSURES = {"public", "sso"}


@dataclass(frozen=True)
class Finding:
    """One Dependency-Track vulnerability match, trimmed to what policy needs.

    ``severity`` is Dependency-Track's own string, lower-cased on compare so
    callers can pass it through unmodified from the API response.
    """

    cve_id: str
    severity: str
    fix_available: bool
    exposure: str = "internal"  # "public" | "sso" | "internal", from exposure.classify_exposure
    rebuild_available: bool = False  # a newer digest exists for the same tag, no CVE delta


def classify_finding(finding: Finding) -> Lane:
    """Return the release lane a single finding belongs to."""
    severity = finding.severity.lower()

    if severity == _CRITICAL:
        if not finding.fix_available:
            return Lane.WATCH
        if finding.exposure in _PUBLIC_EXPOSURES:
            return Lane.SAME_DAY
        # Critical, fixed, but internal-only: still urgent but not a same-day
        # trigger on its own; it rides the weekly batch unless something else
        # escalates it.
        return Lane.WEEKLY

    if severity == _HIGH and finding.fix_available:
        return Lane.WEEKLY

    if finding.rebuild_available:
        return Lane.WEEKLY

    return Lane.MONTHLY


def classify_findings(findings: list[Finding]) -> dict[Lane, list[Finding]]:
    """Bucket a list of findings by lane, preserving input order within each bucket."""
    buckets: dict[Lane, list[Finding]] = {lane: [] for lane in Lane}
    for finding in findings:
        buckets[classify_finding(finding)].append(finding)
    return buckets


def worst_lane(findings: list[Finding]) -> Lane | None:
    """The most urgent lane among a set of findings (e.g. for one service),
    or None if there are no findings at all. Urgency order: same_day > watch
    > weekly > monthly."""
    if not findings:
        return None
    priority = {Lane.SAME_DAY: 0, Lane.WATCH: 1, Lane.WEEKLY: 2, Lane.MONTHLY: 3}
    lanes = {classify_finding(f) for f in findings}
    return min(lanes, key=lambda lane: priority[lane])
