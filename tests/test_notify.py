"""Every notify adapter must fail closed (skip, log, never crash the run)
when its credentials are not provisioned yet, build the right request when
they are, and GTD capture must key on (source, source_ref) so a rerun's
upsert is idempotent rather than a duplicate. notify_all must dispatch to
whichever adapters are configured and swallow a configured-but-missing
credentials file without raising."""

import json

import pytest

from skpatch import notify


def test_missing_talk_credentials_file_raises_not_configured(tmp_path):
    with pytest.raises(notify.NotConfigured):
        notify.load_talk_credentials(tmp_path / "does-not-exist.env")


def test_incomplete_talk_credentials_file_raises_not_configured(tmp_path):
    path = tmp_path / "creds.env"
    path.write_text("WM_NOTIFY_BASE_URL=https://skflow.example.org\n")  # missing workspace/token
    with pytest.raises(notify.NotConfigured):
        notify.load_talk_credentials(path)


def test_well_formed_talk_credentials_file_loads(tmp_path):
    path = tmp_path / "creds.env"
    path.write_text(
        "WM_NOTIFY_BASE_URL=https://skflow.example.org/\n"
        "WM_NOTIFY_WORKSPACE=skops\n"
        "WM_NOTIFY_TOKEN=abc123\n"
    )
    creds = notify.load_talk_credentials(path)
    assert creds.base_url == "https://skflow.example.org"  # trailing slash stripped
    assert creds.workspace == "skops"
    assert creds.token == "abc123"


class FakeResponse:
    def __init__(self, body):
        self._body = json.dumps(body).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_post_talk_calls_run_wait_result_with_the_right_room_and_token():
    creds = notify.TalkCredentials(
        base_url="https://skflow.example.org", workspace="skops", token="secret-tok"
    )
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["auth"] = req.get_header("Authorization")
        seen["body"] = json.loads(req.data)
        return FakeResponse({"posted": True})

    ok = notify.post_talk(
        creds,
        title="t",
        summary="s",
        severity="error",
        room="Ops Urgent",
        ref_id="skpatch-urgent",
        urlopen=fake_urlopen,
    )
    assert ok is True
    assert seen["url"] == "https://skflow.example.org/api/w/skops/jobs/run_wait_result/p/f/ops/notify"
    assert seen["auth"] == "Bearer secret-tok"
    assert seen["body"]["room"] == "Ops Urgent"
    assert seen["body"]["severity"] == "error"


def test_missing_skalert_credentials_file_raises_not_configured(tmp_path):
    with pytest.raises(notify.NotConfigured):
        notify.load_skalert_credentials(tmp_path / "does-not-exist.env")


def test_post_skalert_calls_the_alert_endpoint():
    creds = notify.SkalertCredentials(base_url="https://skalert.example.org", token="tok", chat_id="123")
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data)
        return FakeResponse({"ok": True})

    ok = notify.post_skalert(creds, title="t", summary="s", severity="warning", urlopen=fake_urlopen)
    assert ok is True
    assert seen["url"] == "https://skalert.example.org/api/alert"
    assert seen["body"]["chat_id"] == "123"


def test_gtd_upsert_uses_skpatch_source_and_estate_service_image_ref():
    calls = []

    def fake_upsert(**kwargs):
        calls.append(kwargs)
        return ("item-123", "created")

    item_id, action = notify.gtd_upsert_finding(
        estate="estate-b",
        service="skflow-prod_worker",
        image="windmill-labs/windmill:1.837.0@sha256:" + "a" * 64,
        text="PHP 8.3.33 is below the floor",
        upsert_fn=fake_upsert,
    )
    assert item_id == "item-123" and action == "created"
    assert calls[0]["source"] == "skpatch"
    assert (
        calls[0]["source_ref"]
        == "estate-b/skflow-prod_worker/windmill-labs/windmill:1.837.0@sha256:" + "a" * 64
    )


def test_gtd_upsert_is_idempotent_on_rerun_with_the_same_source_ref():
    seen_refs = []

    def fake_upsert(**kwargs):
        seen_refs.append(kwargs["source_ref"])
        return ("item-1", "unchanged" if len(seen_refs) > 1 else "created")

    for _ in range(2):
        notify.gtd_upsert_finding(
            estate="estate-a",
            service="skbook-prod_bookstack",
            image="lscr.io/linuxserver/bookstack:v26.09-ls285@sha256:" + "b" * 64,
            text="PHP 8.5.10 is below the floor",
            upsert_fn=fake_upsert,
        )
    assert len(set(seen_refs)) == 1


def test_notify_all_skips_unconfigured_adapters_without_raising():
    outcomes = notify.notify_all(
        title="t",
        summary="s",
        severity="warning",
        room="Ops Admin",
        talk_credentials_file=None,
        skalert_credentials_file=None,
    )
    assert outcomes == []


def test_notify_all_reports_a_missing_credentials_file_as_skipped_not_raised(tmp_path):
    outcomes = notify.notify_all(
        title="t",
        summary="s",
        severity="warning",
        room="Ops Admin",
        talk_credentials_file=str(tmp_path / "missing.env"),
        skalert_credentials_file=None,
    )
    assert len(outcomes) == 1
    assert outcomes[0].adapter == "talk"
    assert outcomes[0].sent is False
    assert outcomes[0].skipped_reason
