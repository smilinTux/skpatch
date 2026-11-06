#requirements:
#skpatch
"""Windmill wrapper: aggregate the per-image lane counts from f/skpatch's
sbom_daily forloop (f/skpatch/sbom_dtrack_sync, one result per inventoried
service) into one end-of-run digest notice.

Called once per flow run, after the forloop (see sbom_daily.flow/flow.yaml
step order). This is the "one summary per run" notice; any same_day/watch
finding already got its own immediate notice from sbom_dtrack_sync.py - this
script never re-notifies those, it only totals the lane counts.
"""

from skpatch.config import load_config
from skpatch.notify import notify_all


def main(config_path: str, results: list[dict]) -> dict:
    cfg = load_config(config_path)
    totals: dict[str, int] = {}
    scanned = 0
    for row in results:
        if not isinstance(row, dict):
            continue
        scanned += 1
        for lane, count in (row.get("lanes") or {}).items():
            totals[lane] = totals.get(lane, 0) + count

    lane_summary = ", ".join(f"{lane}={count}" for lane, count in sorted(totals.items())) or "no findings"
    outcomes = notify_all(
        title="skpatch daily SBOM-to-Dependency-Track digest",
        summary=f"{scanned} image(s) scanned: {lane_summary}",
        severity="info",
        room=cfg.notify.talk_digest_room,
        talk_credentials_file=cfg.notify.talk_credentials_file,
        skalert_credentials_file=cfg.notify.skalert_credentials_file,
        ref_id="skpatch-sbom-daily-summary",
    )
    return {"totals": totals, "images_scanned": scanned, "outcomes": [o.__dict__ for o in outcomes]}
