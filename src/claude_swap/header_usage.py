"""Usage read from inference replies' rate-limit headers.

WHY THIS EXISTS. ``/api/oauth/usage`` needs the ``user:profile`` scope and
has its own ~30 requests/hour budget per account. A setup-token account
(``claude setup-token`` → ``cswap add-token``, scope ``user:inference`` only)
can never read it, and a full login that exhausts the budget goes blind. But
every ``/v1/messages`` reply carries the same numbers in
``anthropic-ratelimit-unified-{5h,7d}-{utilization,reset}`` (measured
2026-10-04: 0.23 / 0.77 against the usage endpoint's 23% / 77%).

Two sources, cheapest first:

- **Passive**: the cswap-pin proxy files the headers of every inference reply
  it relays under a sha256 prefix of the bearer, in
  ``<backup>/pin-proxy/ratelimits.json``. Free, and fresh whenever the
  account is in use. A slot is matched by fingerprinting its access token.
- **Probe**: a one-token Haiku request, made only for an inference-only
  credential whose passive reading is older than ``PASSIVE_MAX_AGE_S``. It
  costs a few input tokens of that account's quota.

Header usage carries no per-model ``scoped`` windows and no ``spend``; the
5h/7d windows are what autoswitch decides on.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

_logger = logging.getLogger(__name__)

RATELIMIT_FILE = "ratelimits.json"
_PREFIX = "anthropic-ratelimit-unified-"
# A passive reading at most this old is served as-is for an inference-only
# credential; older, it is re-measured with a probe. Usage only RISES through
# inference, and inference through this machine refreshes the reading, so an
# older reading is an upper bound except for use elsewhere (other machines,
# claude.ai) — this bound caps that blind spot.
PASSIVE_MAX_AGE_S = 15 * 60
# What autoswitch accepts as a stand-in for an unreadable active account.
FALLBACK_MAX_AGE_S = 30 * 60
PROBE_MODEL = "claude-haiku-4-5-20251001"
_PROBE_URL = "https://api.anthropic.com/v1/messages"
_PROFILE_SCOPE = "user:profile"


def bearer_fingerprint(token: str) -> str:
    """The key the pin proxy files a bearer's readings under."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


def ledger_path() -> Path:
    from claude_swap.paths import get_backup_root

    return get_backup_root() / "pin-proxy" / RATELIMIT_FILE


def is_inference_only(oauth_data: dict | None) -> bool:
    """Whether this credential cannot read ``/api/oauth/usage``.

    True for a setup token (``scopes == ["user:inference"]``, no refresh
    token). A credential that lists no scopes at all is assumed to be a full
    login, which is what every pre-scopes cswap backup is.
    """
    if not oauth_data:
        return False
    scopes = oauth_data.get("scopes")
    if not isinstance(scopes, list) or not scopes:
        return False
    return _PROFILE_SCOPE not in scopes


def usage_from_headers(headers: dict, now: float | None = None) -> dict | None:
    """Normalize header values (keys without the prefix) into cswap's shape.

    A window whose reset has already passed reads 0%: the reading predates
    the reset, and nothing has been spent since or a newer reply would say so.
    """
    from claude_swap.oauth import build_usage_result

    now = time.time() if now is None else now
    data: dict = {}
    for window, key in (("five_hour", "5h"), ("seven_day", "7d")):
        raw = headers.get(f"{key}-utilization")
        if raw is None:
            continue
        try:
            pct = float(raw) * 100.0
        except (TypeError, ValueError):
            continue
        entry: dict = {"utilization": round(pct, 2)}
        reset = headers.get(f"{key}-reset")
        try:
            reset_at = float(reset) if reset is not None else None
        except (TypeError, ValueError):
            reset_at = None
        if reset_at is not None:
            if reset_at <= now:
                entry["utilization"] = 0.0
            else:
                entry["resets_at"] = datetime.fromtimestamp(
                    reset_at, tz=timezone.utc
                ).isoformat()
        data[window] = entry
    if not data:
        return None
    result = build_usage_result(data)
    if result is not None:
        # SAY WHAT IS MISSING. Headers carry no per-model percentages, so a
        # row built from them must not look complete next to one from the
        # usage endpoint. What they DO name is the limit currently binding
        # (`representative-claim`) and whether it is refusing (`status`).
        result["partial"] = {
            "source": "headers",
            "binding": headers.get("representative-claim"),
            "status": headers.get("status"),
        }
    return result


def claim_label(claim: str | None) -> str:
    """``seven_day_opus`` -> ``Opus 7d``; ``five_hour`` -> ``5h``."""
    if not claim:
        return "unknown"
    if claim == "five_hour":
        return "5h"
    if claim == "seven_day":
        return "7d"
    if claim.startswith("seven_day_"):
        return f"{claim[len('seven_day_'):].replace('_', ' ').title()} 7d"
    return claim


def partial_note(usage: dict | None) -> str | None:
    """One line saying a header-built reading is partial, or None.

    ``binding: 7d · per-model % not reported``, or ``AT LIMIT: Opus 7d · …``
    when the binding limit is refusing requests. "Binding" is Anthropic's
    own ``representative-claim``, NOT the highest percentage shown: measured
    2026-10-04 it named 5h at 2% while 7d stood at 37%.
    """
    info = usage.get("partial") if isinstance(usage, dict) else None
    if not isinstance(info, dict):
        return None
    label = claim_label(info.get("binding") or info.get("tightest"))
    lead = (f"AT LIMIT: {label}" if info.get("status") == "rejected"
            else f"binding: {label}")
    return f"{lead} · per-model % not reported"


def passive_reading(access_token: str | None) -> dict | None:
    """The pin proxy's latest reading for this bearer, or None."""
    if not access_token:
        return None
    try:
        data = json.loads(ledger_path().read_text())
        reading = data["tokens"][bearer_fingerprint(access_token)]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return reading if isinstance(reading, dict) else None


def passive_usage(access_token: str | None, max_age_s: float) -> dict | None:
    """Usage from the pin proxy's ledger if its reading is recent enough."""
    reading = passive_reading(access_token)
    if not reading:
        return None
    at = reading.get("at")
    if not isinstance(at, (int, float)) or time.time() - at > max_age_s:
        return None
    headers = reading.get("headers")
    return usage_from_headers(headers) if isinstance(headers, dict) else None


def probe_usage(access_token: str) -> dict | None:
    """Measure usage with a one-token inference request.

    Raises ``urllib.error.HTTPError``/``URLError`` like ``request_usage_data``
    so the caller classifies failures the same way — except a 429 that
    carries rate-limit headers, which IS a reading (the account is at a
    limit) and is returned as one.
    """
    from claude_swap.oauth import OAUTH_BETA_HEADER, _pin_aware_ssl_context

    body = json.dumps({
        "model": PROBE_MODEL,
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "."}],
    }).encode()
    req = urllib.request.Request(
        _PROBE_URL,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {access_token}",
            "anthropic-version": "2023-06-01",
            "anthropic-beta": OAUTH_BETA_HEADER,
            "content-type": "application/json",
            "User-Agent": "claude-swap/1.0 (usage-probe)",
        },
    )
    try:
        with urllib.request.urlopen(
            req, timeout=15, context=_pin_aware_ssl_context()
        ) as resp:
            hdrs = resp.headers
    except urllib.error.HTTPError as e:
        if e.code != 429 or not _pick(e.headers):
            raise
        hdrs = e.headers
    return usage_from_headers(_pick(hdrs))


def _pick(headers) -> dict:
    out: dict = {}
    if headers is None:
        return out
    for k, v in headers.items():
        kl = k.lower()
        if kl.startswith(_PREFIX):
            out[kl[len(_PREFIX):]] = v
    return out


def fetch_inference_only(access_token: str, context: str):
    """A ``UsageOutcome`` for an inference-only credential: passive, else probe."""
    from claude_swap.oauth import (
        UsageOutcome,
        _classify_usage_error,
        _log_usage_failure,
    )

    usage = passive_usage(access_token, PASSIVE_MAX_AGE_S)
    if usage is not None:
        return UsageOutcome(usage)
    try:
        return UsageOutcome(probe_usage(access_token))
    except Exception as e:  # noqa: BLE001 — classified like any usage failure
        kind, retry_after = _classify_usage_error(e)
        _log_usage_failure(f"{context} (header probe)", e, kind, retry_after)
        return UsageOutcome(None, error=kind, retry_after_s=retry_after)
