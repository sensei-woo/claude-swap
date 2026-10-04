"""`cswap doctor`: one screen of what needs doing, or "nothing to do".

Everything here reads files cswap already keeps (the roster, the usage
cache, settings, the pin's wiring). It never calls the usage endpoint, so it
is free to run as often as wanted — by the owner or by an agent.

Also home of setup-token expiry. `claude setup-token` mints a token valid for
one year and carries no expiry cswap can read, so `add-token` records when
the token was added (``setupToken.addedAt`` / ``expiresAt`` on the roster
entry) and every surface warns ``WARN_DAYS`` ahead.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

SETUP_TOKEN_LIFETIME = timedelta(days=365)
WARN_DAYS = 30


@dataclass(frozen=True)
class Finding:
    level: str  # "action" (something to do) or "note" (worth knowing)
    what: str
    fix: str | None = None
    slot: str | None = None


# ---------------------------------------------------------------------------
# Setup-token expiry
# ---------------------------------------------------------------------------


def setup_token_record(now: datetime | None = None) -> dict:
    """The ``setupToken`` block ``add-token`` stores on a roster entry."""
    now = now or datetime.now(timezone.utc)
    return {
        "addedAt": now.isoformat(),
        "expiresAt": (now + SETUP_TOKEN_LIFETIME).isoformat(),
    }


def setup_token_expiry(record: dict | None) -> float | None:
    """Epoch seconds a slot's setup token expires, or None if not one."""
    st = record.get("setupToken") if isinstance(record, dict) else None
    if not isinstance(st, dict) or not st.get("expiresAt"):
        return None
    try:
        return datetime.fromisoformat(st["expiresAt"]).timestamp()
    except (TypeError, ValueError):
        return None


def _renew_fix(num: str, email: str) -> str:
    return (f"run `claude setup-token` and approve it as {email}, then "
            f"`cswap add-token --slot {num} --email {email}`")


def expiry_finding(num: str, record: dict, now: float | None = None):
    """An action when a slot's setup token is within WARN_DAYS of expiry."""
    ts = setup_token_expiry(record)
    if ts is None:
        return None
    now = time.time() if now is None else now
    days = (ts - now) / 86400
    email = record.get("email", "?")
    date = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
    if days <= 0:
        what = f"setup token EXPIRED on {date}"
    elif days <= WARN_DAYS:
        what = f"setup token expires in {int(days)}d ({date})"
    else:
        return None
    return Finding("action", what, _renew_fix(num, email), num)


def expiry_short(num: str, record: dict | None, now: float | None = None):
    """The menu-bar suffix for a slot whose token needs renewing, or None."""
    f = expiry_finding(num, record or {}, now)
    if f is None:
        return None
    return f"⚠ {f.what} — renew: claude setup-token as {record.get('email')}"


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def _engine_running() -> bool:
    try:
        out = subprocess.run(
            ["pgrep", "-f", r"cswap (menubar|auto)"],
            capture_output=True, text=True, timeout=5,
        )
        return out.returncode == 0 and bool(out.stdout.strip())
    except Exception:  # noqa: BLE001
        return False


def _menubar_autoswitch(switcher) -> bool | None:
    try:
        data = json.loads(
            (switcher.backup_dir / "menubar_settings.json").read_text())
        return bool(data.get("auto_switch_enabled"))
    except (OSError, ValueError):
        return None


def run_checks(switcher, now: float | None = None) -> list[Finding]:
    from claude_swap import oauth
    from claude_swap.settings import load_settings

    now = time.time() if now is None else now
    findings: list[Finding] = []
    seq = switcher._get_sequence_data()
    accounts = seq.get("accounts") or {}
    active = seq.get("activeAccountNumber")
    active = str(active) if active is not None else None
    try:
        settings = load_settings(switcher.backup_dir)
        threshold = settings.threshold
    except Exception:  # noqa: BLE001
        settings, threshold = None, 90.0

    try:
        entries = switcher._usage_store.entries(
            {n: (r.get("email", ""), r.get("organizationUuid", "") or "")
             for n, r in accounts.items()})
    except Exception:  # noqa: BLE001
        entries = {}

    for num, rec in sorted(accounts.items(), key=lambda kv: int(kv[0])):
        email = rec.get("email", "?")
        who = f"slot {num} ({rec.get('alias') or email})"
        exp = expiry_finding(num, rec, now)
        if exp is not None:
            findings.append(Finding(exp.level, f"{who}: {exp.what}", exp.fix, num))
        entry = entries.get(num)
        if entry is None:
            continue
        try:
            fp = oauth.credential_fingerprint(
                switcher._read_account_credentials(num, email) or "")
        except Exception:  # noqa: BLE001
            fp = None
        if entry.token_dead(stored_fp=fp):
            when = (datetime.fromtimestamp(entry.last_attempt_at)
                    .strftime("%Y-%m-%d %H:%M") if entry.last_attempt_at else "?")
            findings.append(Finding(
                "action",
                f"{who}: login is dead (refresh token rejected, {when})",
                "first rule out a false alarm (concierge accounts.md → "
                "'re-login needed is often false'); then "
                f"`cswap switch {num}`, `claude auth login --claudeai --email "
                f"{email}`, `cswap add`, and switch back",
                num,
            ))
        elif (entry.consecutive_failures >= 5 and entry.last_error
              and num == active):
            findings.append(Finding(
                "note",
                f"{who}: usage unreadable for {entry.consecutive_failures} "
                f"polls ({entry.last_error})",
                None, num,
            ))

    # The active account against the switch threshold, from cached numbers.
    if active and active in entries:
        value = entries[active].decision_value()
        headroom = oauth.account_headroom(value if isinstance(value, dict) else None)
        if headroom is not None:
            used = 100.0 - headroom
            name = accounts.get(active, {}).get("alias") or accounts.get(
                active, {}).get("email", active)
            if headroom <= 0:
                findings.append(Finding(
                    "action", f"active account {name} is AT ITS LIMIT ({used:.0f}%)",
                    "`cswap auto --once` switches if another account has room; "
                    "`cswap list` shows which", active))
            elif used >= threshold:
                findings.append(Finding(
                    "note",
                    f"active account {name} is at {used:.0f}% (switch point "
                    f"{threshold:.0f}%) — autoswitch should move it",
                    None, active))

    # Autoswitch engine.
    engine = _engine_running()
    enabled = _menubar_autoswitch(switcher)
    if not engine:
        findings.append(Finding(
            "note", "no autoswitch engine is running (no `cswap menubar`/`auto`)",
            "start the menu bar: `cswap menubar` (see concierge accounts.md "
            "→ 'Upgrading' for the clean-environment launch)"))
    elif enabled is False:
        findings.append(Finding(
            "note", "autoswitch is OFF in the menu bar",
            "tick 'Auto-switch accounts' in the cswap menu"))
    if settings is not None and settings.failover_on_unknown_usage is False:
        pass  # deliberate here; not a finding

    # The pin.
    try:
        from claude_swap import pin

        recorded = pin.pinned_email_recorded(switcher)
        if recorded:
            if pin.pinned_slot(switcher) is None:
                findings.append(Finding(
                    "action",
                    f"the pin names {recorded}, which no cswap slot holds",
                    "`cswap add` that account, or `cswap pin <slot>`"))
            elif pin._wiring_present(switcher) and not pin._wired_port_is_serving(
                    switcher):
                findings.append(Finding(
                    "action", "the pin proxy is not answering (Remote Control "
                    "and Desktop re-billing are off)", "`cswap pin --heal`"))
    except Exception:  # noqa: BLE001 — the pin is optional
        pass

    order = {"action": 0, "note": 1}
    return sorted(findings, key=lambda f: order.get(f.level, 2))


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


def doctor_command(argv: list[str]) -> None:
    import argparse

    from claude_swap.switcher import ClaudeAccountSwitcher

    parser = argparse.ArgumentParser(
        prog="cswap doctor",
        description="Show only what needs doing: dead or expiring tokens, an "
        "active account at its limit, a stopped autoswitch, a broken pin. "
        "Reads local state only (no usage-endpoint calls). Exit 1 when "
        "something needs action.",
    )
    parser.add_argument("--json", action="store_true",
                        help="machine-readable findings")
    args = parser.parse_args(argv)

    findings = run_checks(ClaudeAccountSwitcher())
    actions = [f for f in findings if f.level == "action"]
    if args.json:
        print(json.dumps({
            "ok": not actions,
            "findings": [asdict(f) for f in findings],
        }, indent=2))
    elif not findings:
        print("✓ nothing to do — all accounts, tokens and the pin look healthy")
    else:
        if not actions:
            print("✓ nothing to do")
        for i, f in enumerate(findings, 1):
            mark = "✗" if f.level == "action" else "·"
            print(f"{mark} {f.what}")
            if f.fix:
                print(f"    → {f.fix}")
    sys.exit(1 if actions else 0)
