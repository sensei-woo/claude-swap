"""A slot's setup token as the fallback for its full OAuth login.

WHY. A full login (`claude auth login`) gives everything — per-model usage,
profile, connectors, session routes — but its refresh token is one-time-use
and dies the moment a superseded copy is POSTed (`invalid_grant`). A setup
token (`claude setup-token`) can do inference only, and lives a year with no
refresh token, so it cannot die that way. Owner ruling 2026-10-04: the full
login is the default while it lives; when it dies the slot keeps working on
its setup token instead of stopping at "re-login needed".

STORAGE. The setup token is kept beside the slot's backup under the
pseudo-slot ``<num>-setup-token`` (same backend: Keychain or ``.enc``), with
its ``setupToken`` dates riding inside the blob under ``cswapSetupToken`` —
the roster entry is rebuilt by `cswap add`, so the dates cannot live only
there. A pseudo-slot is not in ``sequence.json``, so removing the real slot
does not delete it; ``forget()`` does.
"""

from __future__ import annotations

import json
import logging

_logger = logging.getLogger(__name__)

SUFFIX = "-setup-token"
MODE_KEY = "credentialMode"
MODE_FALLBACK = "setup-token-fallback"


def _key(num: str) -> str:
    return f"{num}{SUFFIX}"


def save(switcher, num: str, email: str, credentials: str,
         dates: dict | None) -> None:
    """Keep ``credentials`` (a setup-token blob) as slot ``num``'s fallback."""
    blob = json.loads(credentials)
    blob.pop("cswapSetupToken", None)
    if dates:
        blob["cswapSetupToken"] = dates
    switcher._store._write_account_credentials(_key(num), email, json.dumps(blob))


def read(switcher, num: str, email: str) -> "tuple[str, dict | None] | None":
    """(credential blob without our dates, dates) or None."""
    try:
        raw = switcher._store._read_account_credentials(_key(num), email)
    except Exception:  # noqa: BLE001 — absent or unreadable both mean "none"
        return None
    if not raw:
        return None
    try:
        blob = json.loads(raw)
    except ValueError:
        return None
    dates = blob.pop("cswapSetupToken", None)
    if not (blob.get("claudeAiOauth") or {}).get("accessToken"):
        return None
    return json.dumps(blob), dates if isinstance(dates, dict) else None


def forget(switcher, num: str, email: str) -> None:
    switcher._store._delete_account_credentials(_key(num), email)


def activate(switcher, num: str, email: str, active: bool) -> bool:
    """Put slot ``num``'s setup token in place of its dead full login.

    Writes the slot backup (the dead login is retained one generation as the
    backup's ``.prev``), and the LIVE credential too when the slot is active,
    keeping the machine-shared keys (the design grant, MCP OAuth) from live.
    Marks the roster entry so every surface can say what happened. Never
    raises: a failed fallback must leave the slot exactly as it was.
    """
    got = read(switcher, num, email)
    if got is None:
        return False
    creds, dates = got
    try:
        switcher._write_account_credentials(num, email, creds)
        if active:
            live = switcher._read_credentials()
            switcher._write_credentials(
                switcher._prepare_credentials_for_activation(creds, live))
        data = switcher._get_sequence_data()
        rec = data["accounts"].get(num)
        if rec is not None:
            rec[MODE_KEY] = MODE_FALLBACK
            if dates:
                rec["setupToken"] = dates
            switcher._write_json(switcher.sequence_file, data)
        switcher._usage_store.clear_dead_token(
            [num], {num: (email, (rec or {}).get("organizationUuid", "") or "")})
    except Exception:  # noqa: BLE001
        _logger.warning("setup-token fallback for account %s failed", num,
                        exc_info=True)
        return False
    _logger.warning(
        "Account %s: full login dead (invalid_grant) — now running on its "
        "setup token. Re-login only restores per-model usage.", num)
    return True


def preserve_before_oauth_add(switcher, num: str, email: str) -> bool:
    """Before a full login overwrites slot ``num``, keep its setup token.

    Called by `cswap add` on the slot it is about to write. A slot whose
    stored credential is a setup token (scopes lack ``user:profile``) has it
    copied to the fallback store with the roster's dates.
    """
    from claude_swap import header_usage, oauth

    try:
        current = switcher._read_account_credentials(num, email)
    except Exception:  # noqa: BLE001
        return False
    if not current or not header_usage.is_inference_only(
            oauth.extract_oauth_data(current)):
        return False
    rec = (switcher._get_sequence_data().get("accounts") or {}).get(num) or {}
    save(switcher, num, email, current, rec.get("setupToken"))
    _logger.info("Account %s: kept its setup token as the fallback for the "
                 "new full login", num)
    return True


def add_from_token(switcher, token: str, slot) -> None:
    """`cswap add-token --fallback --slot N`: (re)store slot N's setup token.

    The slot's full login is untouched; only its fallback and the roster's
    expiry dates change. ``token`` is the raw token, ``-`` for one stdin
    line, or empty to prompt without echo.
    """
    import getpass
    import sys

    from claude_swap.doctor import setup_token_record
    from claude_swap.exceptions import ValidationError

    if slot is None:
        raise ValidationError("--fallback needs --slot N")
    if token == "-":
        token = sys.stdin.readline().rstrip("\n")
    elif not token:
        token = getpass.getpass("Token: ")
    token = token.strip()
    if not token.startswith("sk-ant-oat"):
        raise ValidationError("--fallback takes a `claude setup-token` token (sk-ant-oat…)")
    num = str(slot)
    data = switcher._get_sequence_data()
    rec = (data.get("accounts") or {}).get(num)
    if rec is None:
        raise ValidationError(f"No account in slot {num}")
    email = rec.get("email", "")
    dates = setup_token_record()
    creds = json.dumps({"claudeAiOauth": {"accessToken": token,
                                          "scopes": ["user:inference"]}})
    save(switcher, num, email, creds, dates)
    rec["setupToken"] = dates
    switcher._write_json(switcher.sequence_file, data)
    _logger.info("Account %s: stored a new setup-token fallback", num)
    print(f"Stored setup-token fallback for account {num} ({email}); "
          f"expires {dates['expiresAt'][:10]}.")
