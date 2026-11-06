#requirements:
#skpatch
"""Windmill wrapper: classify a batch of Dependency-Track findings and notify.

Takes a list of findings (as plain dicts matching skpatch.policy.Finding's
fields - this script does not itself query Dependency-Track's API; the
caller, typically a flow step upstream, is responsible for that query) and:

1. classifies every finding into a lane (skpatch.policy),
2. fans same_day and watch findings out to whichever notify adapters are
   configured (skpatch.notify.notify_all), and
3. upserts each actionable finding into the unified GTD.

Returns the full lane breakdown so the flow's next step (or its own log)
can show the weekly digest counts.
"""
from dataclasses import asdict

from skpatch.config import load_config
from skpatch.notify import gtd_upsert_finding, notify_all
from skpatch.policy import Finding, Lane, classify_findings

_ACTIONABLE = {Lane.SAME_DAY, Lane.WATCH}


def main(config_path: str, estate: str, service: str, image: str, findings: list[dict]) -> dict:
    cfg = load_config(config_path)
    parsed = [Finding(**row) for row in findings]
    buckets = classify_findings(parsed)

    notified = []
    for lane in _ACTIONABLE:
        for finding in buckets.get(lane, []):
            room = cfg.notify.talk_urgent_room if lane == Lane.SAME_DAY else cfg.notify.talk_digest_room
            severity = "error" if lane == Lane.SAME_DAY else "warning"
            outcomes = notify_all(
                title=f"{finding.cve_id} on {estate}/{service}",
                summary=f"severity={finding.severity} fix_available={finding.fix_available} exposure={finding.exposure}",
                severity=severity,
                room=room,
                talk_credentials_file=cfg.notify.talk_credentials_file,
                skalert_credentials_file=cfg.notify.skalert_credentials_file,
                ref_id=f"skpatch-{finding.cve_id}-{estate}-{service}",
            )
            notified.append({"cve_id": finding.cve_id, "outcomes": [asdict(o) for o in outcomes]})
            if cfg.notify.gtd_enabled:
                gtd_upsert_finding(
                    estate=estate,
                    service=service,
                    image=image,
                    text=f"{finding.cve_id}: {finding.severity}, fix_available={finding.fix_available}",
                    context=cfg.notify.gtd_context,
                    source="skpatch",
                    source_ref=f"{finding.cve_id}/{estate}/{service}",
                )

    return {
        "lanes": {lane.value: len(items) for lane, items in buckets.items()},
        "notified": notified,
    }
