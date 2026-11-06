"""Notification adapters: SKAlert/Telegram, Nextcloud Talk bot, and GTD upsert.

Every adapter is optional and config-driven. A missing credentials file (the
normal state until an operator provisions one) raises ``NotConfigured``,
which every call site in this module and in the CLI treats as "log a
warning and skip this adapter" - never as a reason to fail the whole run.
Adapted from skstacks PR #223 (``v1/scripts/image_monitor/notify.py``), with
the Talk/GTD paths kept as-is and an SKAlert/Telegram adapter added
alongside them so skpatch does not depend on any one notification channel
being wired up.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("skpatch.notify")


class NotConfigured(Exception):
    """Raised when an adapter's credentials file is missing or incomplete.

    Callers treat this as "skip this adapter, log a warning, keep going" -
    never as a reason to fail the whole run.
    """


def _load_env_file(path: str | Path, required_keys: tuple[str, ...]) -> dict[str, str]:
    p = Path(path).expanduser()
    if not p.is_file():
        raise NotConfigured(f"{p} does not exist yet; see docs/skpatch-program.md 'Notify'")
    values: dict[str, str] = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    missing = [k for k in required_keys if not values.get(k)]
    if missing:
        raise NotConfigured(f"{p} is missing: {', '.join(missing)}")
    return values


# --- Nextcloud Talk (via the existing f/ops/notify Windmill script) --------


@dataclass
class TalkCredentials:
    base_url: str
    workspace: str
    token: str


def load_talk_credentials(path: str | Path) -> TalkCredentials:
    """Read WM_NOTIFY_BASE_URL / WM_NOTIFY_WORKSPACE / WM_NOTIFY_TOKEN from a
    KEY=VALUE env file. Never logs the token value."""
    values = _load_env_file(path, ("WM_NOTIFY_BASE_URL", "WM_NOTIFY_WORKSPACE", "WM_NOTIFY_TOKEN"))
    return TalkCredentials(
        base_url=values["WM_NOTIFY_BASE_URL"].rstrip("/"),
        workspace=values["WM_NOTIFY_WORKSPACE"],
        token=values["WM_NOTIFY_TOKEN"],
    )


def post_talk(
    creds: TalkCredentials,
    *,
    title: str,
    summary: str,
    severity: str,
    room: str,
    ref_id: str = "",
    timeout: float = 30,
    urlopen: Callable = urllib.request.urlopen,
) -> bool:
    """Call the ``f/ops/notify`` Windmill flow via ``run_wait_result``.

    Returns whether the flow reported ``posted: true``. Raises on a
    transport/HTTP error; the caller decides whether that should fail the
    run (it should not, by default - see ``notify_all``).
    """
    url = f"{creds.base_url}/api/w/{creds.workspace}/jobs/run_wait_result/p/f/ops/notify"
    body = json.dumps(
        {"title": title, "summary": summary, "severity": severity, "room": room, "ref_id": ref_id}
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {creds.token}", "Content-Type": "application/json"},
    )
    with urlopen(req, timeout=timeout) as resp:
        result = json.loads(resp.read() or b"{}")
    return bool(result.get("posted"))


# --- SKAlert / Telegram -----------------------------------------------------


@dataclass
class SkalertCredentials:
    base_url: str
    token: str
    chat_id: str


def load_skalert_credentials(path: str | Path) -> SkalertCredentials:
    """Read SKALERT_BASE_URL / SKALERT_TOKEN / SKALERT_CHAT_ID from a
    KEY=VALUE env file. Never logs the token value."""
    values = _load_env_file(path, ("SKALERT_BASE_URL", "SKALERT_TOKEN", "SKALERT_CHAT_ID"))
    return SkalertCredentials(
        base_url=values["SKALERT_BASE_URL"].rstrip("/"),
        token=values["SKALERT_TOKEN"],
        chat_id=values["SKALERT_CHAT_ID"],
    )


def post_skalert(
    creds: SkalertCredentials,
    *,
    title: str,
    summary: str,
    severity: str,
    timeout: float = 30,
    urlopen: Callable = urllib.request.urlopen,
) -> bool:
    """Send a Telegram alert through SKAlert's webhook. Returns whether the
    call reported success. Raises on a transport/HTTP error."""
    url = f"{creds.base_url}/api/alert"
    body = json.dumps(
        {"chat_id": creds.chat_id, "title": title, "summary": summary, "severity": severity}
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {creds.token}", "Content-Type": "application/json"},
    )
    with urlopen(req, timeout=timeout) as resp:
        result = json.loads(resp.read() or b"{}")
    return bool(result.get("ok", result.get("success", False)))


# --- GTD upsert --------------------------------------------------------------


def gtd_upsert_finding(
    *,
    estate: str,
    service: str,
    image: str,
    text: str,
    status: str = "next",
    context: str = "@fleet",
    meta: dict[str, Any] | None = None,
    source: str = "skpatch",
    source_ref: str | None = None,
    upsert_fn: Callable | None = None,
) -> tuple[str, str]:
    """Upsert one finding into the unified GTD, keyed by
    ``(source, source_ref)`` so a rerun with nothing new patches the
    existing item instead of duplicating it.

    ``source_ref`` defaults to ``"<estate>/<service>/<image>"``. A caller
    tracking a specific CVE should pass its own
    ``source_ref="<cve-id>/<estate>/<service>"`` so the two conventions never
    collide on the same GTD key.

    ``upsert_fn`` is injectable for tests; in production it is
    ``skos.gtd_ingest.upsert`` with a ``GtdCapture``, imported lazily so this
    module (and its tests) don't need ``skos`` installed to exercise the
    rest of the package.
    """
    source_ref = source_ref or f"{estate}/{service}/{image}"
    if upsert_fn is None:
        from skos.gtd_ingest import GtdCapture, upsert as _upsert

        def upsert_fn(**kwargs):
            return _upsert(GtdCapture(**kwargs))

    return upsert_fn(
        text=text, source=source, source_ref=source_ref, context=context, status=status, meta=meta or {}
    )


# --- Dispatcher --------------------------------------------------------------


@dataclass
class NotifyOutcome:
    adapter: str
    sent: bool
    skipped_reason: str = ""


def notify_all(
    *,
    title: str,
    summary: str,
    severity: str,
    room: str,
    talk_credentials_file: str | None,
    skalert_credentials_file: str | None,
    ref_id: str = "",
) -> list[NotifyOutcome]:
    """Fan a single finding out to every configured adapter.

    A ``None`` credentials path means that adapter is disabled by config,
    not misconfigured - it is skipped silently. A configured-but-missing
    file raises ``NotConfigured`` internally, which is caught here and
    turned into a skipped outcome with a warning logged; this function
    itself never raises.
    """
    outcomes: list[NotifyOutcome] = []

    if talk_credentials_file:
        try:
            creds = load_talk_credentials(talk_credentials_file)
            sent = post_talk(creds, title=title, summary=summary, severity=severity, room=room, ref_id=ref_id)
            outcomes.append(NotifyOutcome(adapter="talk", sent=sent))
        except NotConfigured as exc:
            logger.warning("talk notify adapter not configured: %s", exc)
            outcomes.append(NotifyOutcome(adapter="talk", sent=False, skipped_reason=str(exc)))
        except Exception as exc:  # noqa: BLE001 - a notify failure must never fail the run
            logger.warning("talk notify adapter failed: %s", exc)
            outcomes.append(NotifyOutcome(adapter="talk", sent=False, skipped_reason=str(exc)))

    if skalert_credentials_file:
        try:
            creds = load_skalert_credentials(skalert_credentials_file)
            sent = post_skalert(creds, title=title, summary=summary, severity=severity)
            outcomes.append(NotifyOutcome(adapter="skalert", sent=sent))
        except NotConfigured as exc:
            logger.warning("skalert notify adapter not configured: %s", exc)
            outcomes.append(NotifyOutcome(adapter="skalert", sent=False, skipped_reason=str(exc)))
        except Exception as exc:  # noqa: BLE001
            logger.warning("skalert notify adapter failed: %s", exc)
            outcomes.append(NotifyOutcome(adapter="skalert", sent=False, skipped_reason=str(exc)))

    return outcomes
