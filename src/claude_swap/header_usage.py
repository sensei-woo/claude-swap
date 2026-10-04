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
from pathlib import Path

_logger = logging.getLogger(__name__)

RATELIMIT_FILE = "ratelimits.json"
_PREFIX = "anthropic-ratelimit-unified-"
# A passive reading at most this old is served as-is for a setup-token slot.
# Usage only RISES through inference, and inference through this machine
# refreshes the reading, so an older reading is an upper bound except for use
# elsewhere (other machines, claude.ai) -- this bound caps that blind spot.
PASSIVE_MAX_AGE_S = 15 * 60
# What autoswitch accepts as a stand-in for an unreadable active account.
FALLBACK_MAX_AGE_S = 30 * 60


def bearer_fingerprint(token: str) -> str:
    """The key the pin proxy files a bearer's readings under."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


def ledger_path() -> Path:
    from claude_swap.paths import get_backup_root

    return get_backup_root() / "pin-proxy" / RATELIMIT_FILE


def usage_from_headers(headers: dict, now: float | None = None) -> dict | None:
    """Normalize ledger headers (keys without the prefix) into cswap's shape.

    A window whose reset has already passed reads 0%: the reading predates
    the reset, and nothing has been spent since or a newer reply would say so.
    """
    from claude_swap import oauth

    now = time.time() if now is None else now
    full = {f"{_PREFIX}{k}": v for k, v in headers.items()}
    for window in ("5h", "7d", "7d_oi"):
        try:
            reset_at = float(full.get(f"{_PREFIX}{window}-reset"))
        except (TypeError, ValueError):
            continue
        if reset_at <= now:
            full[f"{_PREFIX}{window}-utilization"] = "0"
            full.pop(f"{_PREFIX}{window}-reset", None)
    data = oauth.parse_unified_ratelimit_headers(full)
    if not any(k in data for k in ("five_hour", "seven_day", "limits", "rejected")):
        return None
    try:
        usage = oauth.build_usage_result(data)
    except Exception:  # noqa: BLE001 - an unusable reading is no reading
        _logger.debug("unusable ledger headers", exc_info=True)
        return None
    if usage is None:
        return None
    usage["source"] = oauth.USAGE_SOURCE_HEADERS
    return usage


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
