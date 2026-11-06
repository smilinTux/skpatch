"""policy.classify_finding is the one place "same day" vs "weekly" vs
"monthly" gets decided, so every row of docs/skpatch-program.md's policy
table needs its own test, plus the edge cases (no fix yet, internal-only
critical) that the table's prose carries but the table itself doesn't
spell out."""

from skpatch.policy import Finding, Lane, classify_finding, classify_findings, worst_lane


def test_critical_with_fix_and_public_exposure_is_same_day():
    f = Finding(cve_id="CVE-2026-1", severity="critical", fix_available=True, exposure="public")
    assert classify_finding(f) == Lane.SAME_DAY


def test_critical_with_fix_and_sso_exposure_is_also_same_day():
    f = Finding(cve_id="CVE-2026-2", severity="CRITICAL", fix_available=True, exposure="sso")
    assert classify_finding(f) == Lane.SAME_DAY


def test_critical_with_no_fix_is_watch_not_same_day():
    f = Finding(cve_id="CVE-2026-3", severity="critical", fix_available=False, exposure="public")
    assert classify_finding(f) == Lane.WATCH


def test_critical_with_fix_but_internal_only_rides_the_weekly_batch():
    f = Finding(cve_id="CVE-2026-4", severity="critical", fix_available=True, exposure="internal")
    assert classify_finding(f) == Lane.WEEKLY


def test_high_with_fix_is_weekly():
    f = Finding(cve_id="CVE-2026-5", severity="high", fix_available=True, exposure="internal")
    assert classify_finding(f) == Lane.WEEKLY


def test_high_with_no_fix_falls_to_monthly():
    f = Finding(cve_id="CVE-2026-6", severity="high", fix_available=False)
    assert classify_finding(f) == Lane.MONTHLY


def test_rebuild_on_same_tag_is_weekly_even_with_low_severity():
    f = Finding(cve_id="n/a", severity="low", fix_available=False, rebuild_available=True)
    assert classify_finding(f) == Lane.WEEKLY


def test_everything_else_is_monthly():
    f = Finding(cve_id="CVE-2026-7", severity="medium", fix_available=True)
    assert classify_finding(f) == Lane.MONTHLY


def test_classify_findings_buckets_every_finding_exactly_once():
    findings = [
        Finding(cve_id="a", severity="critical", fix_available=True, exposure="public"),
        Finding(cve_id="b", severity="high", fix_available=True),
        Finding(cve_id="c", severity="low", fix_available=True),
    ]
    buckets = classify_findings(findings)
    total = sum(len(v) for v in buckets.values())
    assert total == len(findings)
    assert buckets[Lane.SAME_DAY] == [findings[0]]
    assert buckets[Lane.WEEKLY] == [findings[1]]
    assert buckets[Lane.MONTHLY] == [findings[2]]


def test_worst_lane_picks_the_most_urgent_of_several_findings():
    findings = [
        Finding(cve_id="a", severity="medium", fix_available=True),
        Finding(cve_id="b", severity="critical", fix_available=True, exposure="public"),
    ]
    assert worst_lane(findings) == Lane.SAME_DAY


def test_worst_lane_of_no_findings_is_none():
    assert worst_lane([]) is None
