#requirements:
#skpatch
"""Windmill wrapper: newer releases for every image the estates are running.

Thin wiring only. All logic lives in skpatch.updates (inventory -> Renovate
--dry-run=lookup -> ranked rows); this script runs it on a schedule, writes
the markdown report under updates.report_dir, and posts one summary line to
the Talk digest room when notify credentials are configured.
"""
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from skpatch import notify, updates
from skpatch.config import load_config
from skpatch.inventory import collect_estate_inventory


def main(config_path: str, estate: str | None = None, post: bool = True) -> dict:
    cfg = load_config(config_path)
    estates = {estate: cfg.clusters[estate]} if estate else cfg.clusters
    inventories = [
        collect_estate_inventory(n, c.manager_hosts, jump=c.jump, user=c.ssh_user, identity=c.ssh_identity)
        for n, c in estates.items()
    ]
    token = None
    if cfg.updates.github_token_file:
        p = Path(cfg.updates.github_token_file).expanduser()
        token = p.read_text().strip() if p.is_file() else None
    rows, error = updates.run_lookup(
        inventories, command=cfg.updates.command, image=cfg.updates.image,
        github_token=token, timeout=cfg.updates.timeout_seconds,
    )
    out_dir = Path(cfg.updates.report_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    report = out_dir / f"running-image-updates-{stamp}.md"
    report.write_text(updates.render_markdown(rows, title=f"Running-image updates {stamp}"))
    posted = False
    if post and cfg.notify.talk_credentials_file:
        try:
            creds = notify.load_talk_credentials(cfg.notify.talk_credentials_file)
            posted = notify.post_talk(creds, title="skpatch: running-image updates",
                                      summary=updates.summary_line(rows), severity="info",
                                      room=cfg.notify.talk_digest_room, ref_id=f"skpatch-updates-{stamp}")
        except notify.NotConfigured:
            posted = False
    return {
        "unreachable": [i.estate for i in inventories if i.unreachable],
        "error": error,
        "report": str(report),
        "posted": posted,
        "summary": updates.summary_line(rows),
        "updates": [asdict(r) for r in rows],
    }
