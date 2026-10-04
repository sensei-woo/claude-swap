"""Usage from inference replies' rate-limit headers, and the hold policy.

See ``claude_swap.header_usage`` for why: a setup-token slot cannot read
``/api/oauth/usage``, and unreadable usage must not be read as exhausted.
"""

from __future__ import annotations

import json
import time
from unittest.mock import patch

from claude_swap import header_usage, oauth
from claude_swap.autoswitch import AutoSwitchEngine, SwitchEvent, TickOutcome
from claude_swap.json_output import USAGE_FOREIGN_CREDENTIAL

from tests.test_autoswitch import EngineHarness, _usage

_SETUP = {"accessToken": "sk-ant-oat01-x", "scopes": ["user:inference"]}
_FULL = {
    "accessToken": "at", "refreshToken": "rt",
    "scopes": ["user:inference", "user:profile"],
}


class TestHeaderParsing:
    def test_fractions_become_percent_with_resets(self):
        future = time.time() + 3600
        u = header_usage.usage_from_headers({
            "5h-utilization": "0.23", "5h-reset": str(int(future)),
            "7d-utilization": "0.77", "7d-reset": str(int(future + 86400)),
            "status": "allowed_warning",
        })
        assert u["five_hour"]["pct"] == 23.0
        assert u["seven_day"]["pct"] == 77.0
        assert u["five_hour"]["resets_at"]
        assert oauth.account_headroom(u) == 23.0

    def test_a_window_past_its_reset_reads_zero(self):
        past = time.time() - 60
        u = header_usage.usage_from_headers({
            "5h-utilization": "0.9", "5h-reset": str(int(past)),
            "7d-utilization": "0.4",
        })
        assert u["five_hour"]["pct"] == 0.0
        assert u["seven_day"]["pct"] == 40.0

    def test_no_utilization_headers_is_no_reading(self):
        assert header_usage.usage_from_headers({"status": "allowed"}) is None

    def test_inference_only_needs_an_explicit_scope_list(self):
        assert header_usage.is_inference_only(_SETUP)
        assert not header_usage.is_inference_only(_FULL)
        assert not header_usage.is_inference_only({"accessToken": "at"})
        assert not header_usage.is_inference_only(None)


def _write_ledger(path, token: str, at: float, headers: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "tokens": {
        header_usage.bearer_fingerprint(token): {
            "at": at, "status": 200, "headers": headers,
        },
    }}))


class TestPassiveAndProbe:
    def test_passive_reading_respects_max_age(self, tmp_path):
        ledger = tmp_path / "ratelimits.json"
        _write_ledger(ledger, "TOK", time.time() - 120,
                      {"5h-utilization": "0.5", "7d-utilization": "0.1"})
        with patch.object(header_usage, "ledger_path", return_value=ledger):
            assert header_usage.passive_usage("TOK", 300)["five_hour"]["pct"] == 50.0
            assert header_usage.passive_usage("TOK", 60) is None
            assert header_usage.passive_usage("OTHER", 300) is None

    def test_setup_token_never_calls_the_usage_endpoint(self, tmp_path):
        ledger = tmp_path / "ratelimits.json"
        _write_ledger(ledger, _SETUP["accessToken"], time.time(),
                      {"5h-utilization": "0.3", "7d-utilization": "0.6"})
        creds = json.dumps({"claudeAiOauth": _SETUP})
        with (
            patch.object(header_usage, "ledger_path", return_value=ledger),
            patch.object(oauth, "request_usage_data",
                         side_effect=AssertionError("usage endpoint called")),
            patch.object(header_usage, "probe_usage",
                         side_effect=AssertionError("probed despite a reading")),
        ):
            out = oauth.try_fetch_usage_for_account("2", "b@x", creds, True)
        assert out.error is None
        assert out.usage["seven_day"]["pct"] == 60.0

    def test_setup_token_probes_without_a_fresh_reading(self, tmp_path):
        creds = json.dumps({"claudeAiOauth": _SETUP})
        probed = header_usage.usage_from_headers(
            {"5h-utilization": "0.1", "7d-utilization": "0.2"})
        with (
            patch.object(header_usage, "ledger_path",
                         return_value=tmp_path / "missing.json"),
            patch.object(oauth, "request_usage_data",
                         side_effect=AssertionError("usage endpoint called")),
            patch.object(header_usage, "probe_usage", return_value=probed) as p,
        ):
            out = oauth.try_fetch_usage_for_account("2", "b@x", creds, False)
        p.assert_called_once_with(_SETUP["accessToken"])
        assert out.usage["seven_day"]["pct"] == 20.0

    def test_full_login_still_uses_the_usage_endpoint(self):
        creds = json.dumps({"claudeAiOauth": {**_FULL, "expiresAt": int(
            (time.time() + 3600) * 1000)}})
        with (
            patch.object(oauth, "request_usage_data",
                         return_value={"five_hour": {"utilization": 5.0}}) as r,
            patch.object(header_usage, "probe_usage",
                         side_effect=AssertionError("probed a full login")),
        ):
            out = oauth.try_fetch_usage_for_account("1", "a@x", creds, True)
        r.assert_called_once()
        assert out.usage["five_hour"]["pct"] == 5.0


def _harness(temp_home, **kw) -> EngineHarness:
    h = EngineHarness(temp_home, **kw)
    h.seed(1, "a@example.com")
    h.seed(2, "b@example.com")
    h.make_live("a@example.com", 1)
    return h


class TestUnreadableIsNotExhausted:
    def test_hold_instead_of_failover_when_switched_off(self, temp_home):
        h = _harness(temp_home, failover_on_unknown_usage=False)
        unknown = {"1": None, "2": _usage(10)}
        with patch.object(AutoSwitchEngine, "_header_usage_for_active",
                          return_value=None):
            for _ in range(8):  # far past unhealthy_ticks (3)
                assert h.tick_with_usage(unknown) is TickOutcome.NO_ACTION
        assert h.active_number() == 1
        assert h.engine._unhealthy_ticks == 0

    def test_a_broken_credential_still_fails_over(self, temp_home):
        h = _harness(temp_home, failover_on_unknown_usage=False)
        foreign = {"1": USAGE_FOREIGN_CREDENTIAL, "2": _usage(10)}
        with patch.object(AutoSwitchEngine, "_header_usage_for_active",
                          return_value=None):
            outcomes = [h.tick_with_usage(foreign) for _ in range(3)]
        assert outcomes[-1] is TickOutcome.SWITCHED

    def test_default_keeps_upstream_failover(self, temp_home):
        h = _harness(temp_home)
        unknown = {"1": None, "2": _usage(10)}
        with patch.object(AutoSwitchEngine, "_header_usage_for_active",
                          return_value=None):
            outcomes = [h.tick_with_usage(unknown) for _ in range(3)]
        assert outcomes[-1] is TickOutcome.SWITCHED

    def test_header_ledger_reports_a_real_limit(self, temp_home):
        h = _harness(temp_home, failover_on_unknown_usage=False)
        unknown = {"1": None, "2": _usage(10)}
        with patch.object(AutoSwitchEngine, "_header_usage_for_active",
                          return_value=_usage(100)):
            assert h.tick_with_usage(unknown) is TickOutcome.SWITCHED
        switch = next(e for e in h.events if isinstance(e, SwitchEvent))
        assert switch.trigger == "at-limit"
        assert h.active_number() == 2


class TestPartialLabel:
    """A header-built reading must say it is partial and name the binding limit."""

    def _usage(self, claim="seven_day", status="allowed"):
        return header_usage.usage_from_headers({
            "5h-utilization": "0.0", "7d-utilization": "0.36",
            "representative-claim": claim, "status": status,
        })

    def test_claim_labels(self):
        assert header_usage.claim_label("seven_day") == "7d"
        assert header_usage.claim_label("five_hour") == "5h"
        assert header_usage.claim_label("seven_day_opus") == "Opus 7d"
        assert header_usage.claim_label(None) == "unknown"

    def test_menubar_row_says_partial(self):
        from claude_swap.menubar import usage_summary

        row = usage_summary(self._usage())
        assert row.endswith("binding: 7d · per-model % not reported")
        assert "7d 36%" in row
        # A full reading (usage endpoint) carries no such note.
        assert "not reported" not in usage_summary(_usage(10))

    def test_at_limit_is_loud(self):
        note = header_usage.partial_note(self._usage("seven_day_opus", "rejected"))
        assert note == "AT LIMIT: Opus 7d · per-model % not reported"

    def test_cli_and_json_carry_it(self):
        from claude_swap.json_output import usage_to_json
        from claude_swap.switcher import _format_usage_lines

        u = self._usage()
        assert any(l.startswith("note:") and "not reported" in l
                   for l in _format_usage_lines(u))
        j = usage_to_json(u)["partial"]
        assert j == {"source": "headers", "perModel": "not reported",
                     "binding": "seven_day", "status": "allowed"}
