"""`cswap doctor` and setup-token expiry warnings."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from claude_swap import doctor
from claude_swap.usage_store import UsageEntry

from tests.test_autoswitch import EngineHarness


def _rec(days_left: float, email: str = "b@example.com") -> dict:
    exp = datetime.now(timezone.utc) + timedelta(days=days_left)
    return {"email": email, "setupToken": {
        "addedAt": (exp - doctor.SETUP_TOKEN_LIFETIME).isoformat(),
        "expiresAt": exp.isoformat()}}


class TestExpiry:
    def test_quiet_until_the_warning_window(self):
        assert doctor.expiry_finding("2", _rec(200)) is None
        assert doctor.expiry_short("2", _rec(200)) is None

    def test_warns_inside_thirty_days_with_the_fix(self):
        f = doctor.expiry_finding("2", _rec(21.5))
        assert f.level == "action"
        assert f.what.startswith("setup token expires in 21d")
        assert "claude setup-token" in f.fix
        assert "cswap add-token --slot 2 --email b@example.com" in f.fix
        assert doctor.expiry_short("2", _rec(21.5)).startswith("⚠ setup token expires in 21d")

    def test_expired_is_loud(self):
        assert "EXPIRED" in doctor.expiry_finding("2", _rec(-1)).what

    def test_not_a_setup_token(self):
        assert doctor.expiry_finding("1", {"email": "a@x"}) is None
        assert doctor.setup_token_expiry(None) is None

    def test_record_is_one_year(self):
        now = datetime(2026, 10, 4, tzinfo=timezone.utc)
        r = doctor.setup_token_record(now)
        assert r["expiresAt"].startswith("2027-10-04")


def _harness(temp_home):
    h = EngineHarness(temp_home)
    h.seed(1, "a@example.com")
    h.seed(2, "b@example.com")
    h.make_live("a@example.com", 1)
    return h


class TestAddTokenRecordsTheDate:
    def test_add_token_stamps_setup_token(self, temp_home):
        h = _harness(temp_home)
        h.switcher.add_account_from_token("sk-ant-oat01-abc", email="c@example.com", slot=3)
        rec = h.switcher._get_sequence_data()["accounts"]["3"]
        ts = doctor.setup_token_expiry(rec)
        assert ts is not None
        assert 364 < (ts - time.time()) / 86400 <= 365

    def test_api_key_gets_no_expiry(self, temp_home):
        h = _harness(temp_home)
        h.switcher.add_account_from_token("sk-ant-api03-abc", email="k@example.com", slot=3)
        rec = h.switcher._get_sequence_data()["accounts"]["3"]
        assert "setupToken" not in rec


class TestDoctor:
    def _run(self, h, entries=None, engine=True, autoswitch=True):
        entries = entries or {}
        with (
            patch.object(h.switcher._usage_store, "entries",
                         return_value=entries),
            patch.object(doctor, "_engine_running", return_value=engine),
            patch.object(doctor, "_menubar_autoswitch", return_value=autoswitch),
            patch.object(doctor, "_design_grant_finding", return_value=None),
        ):
            return doctor.run_checks(h.switcher)

    def test_healthy_is_nothing_to_do(self, temp_home):
        assert self._run(_harness(temp_home)) == []

    def test_expiring_token_is_an_action(self, temp_home):
        h = _harness(temp_home)
        data = h.switcher._get_sequence_data()
        data["accounts"]["2"].update(_rec(10))
        h.switcher._write_json(h.switcher.sequence_file, data)
        [f] = self._run(h)
        assert f.level == "action" and f.slot == "2"
        assert "expires in" in f.what

    def test_dead_login_is_an_action(self, temp_home):
        h = _harness(temp_home)
        dead = UsageEntry(auth_dead_strikes=1, last_error="invalid_grant",
                          last_attempt_at=time.time())
        [f] = self._run(h, {"2": dead})
        assert f.level == "action" and "login is dead" in f.what
        assert "claude auth login --claudeai --email b@example.com" in f.fix

    def test_active_at_limit(self, temp_home):
        h = _harness(temp_home)
        full = UsageEntry(last_good={"five_hour": {"pct": 100.0}},
                          fetched_at=time.time(), age_s=0.0)
        findings = self._run(h, {"1": full})
        assert any("AT ITS LIMIT" in f.what for f in findings)

    def test_stopped_engine_is_a_note(self, temp_home):
        [f] = self._run(_harness(temp_home), engine=False)
        assert f.level == "note" and "no autoswitch engine" in f.what

    def test_command_exit_codes(self, temp_home, capsys):
        h = _harness(temp_home)
        with (
            patch("claude_swap.switcher.ClaudeAccountSwitcher",
                  return_value=h.switcher),
            patch.object(doctor, "run_checks", return_value=[]),
        ):
            with pytest.raises(SystemExit) as e:
                doctor.doctor_command([])
        assert e.value.code == 0
        assert "nothing to do" in capsys.readouterr().out
        bad = [doctor.Finding("action", "x broke", "fix it")]
        with (
            patch("claude_swap.switcher.ClaudeAccountSwitcher",
                  return_value=h.switcher),
            patch.object(doctor, "run_checks", return_value=bad),
        ):
            with pytest.raises(SystemExit) as e:
                doctor.doctor_command(["--json"])
        assert e.value.code == 1
        out = json.loads(capsys.readouterr().out)
        assert out["ok"] is False and out["findings"][0]["fix"] == "fix it"


def test_menubar_row_carries_the_warning():
    from claude_swap.menubar import format_account_label

    row = format_account_label("2", "b@x", None, warning="⚠ setup token expires in 9d")
    assert row.endswith("⚠ setup token expires in 9d")


class TestDesignGrant:
    def _live(self, h, extra):
        live = json.loads(h.switcher._read_credentials())
        live.pop("designOauth", None)
        live.update(extra)
        h.switcher._write_credentials(json.dumps(live))

    def test_missing_grant_is_an_action_with_the_fix(self, temp_home):
        h = _harness(temp_home)
        self._live(h, {})
        f = doctor._design_grant_finding(h.switcher)
        assert f.level == "action" and "no Claude Design grant" in f.what
        assert "/design" in f.fix

    def test_present_grant_is_quiet(self, temp_home):
        h = _harness(temp_home)
        self._live(h, {"designOauth": {"accessToken": "d", "refreshToken": "r",
                                       "expiresAt": 1}})
        assert doctor._design_grant_finding(h.switcher) is None

    def test_unreadable_live_store_is_not_a_finding(self, temp_home):
        h = _harness(temp_home)
        with patch.object(h.switcher, "_read_credentials", side_effect=OSError):
            assert doctor._design_grant_finding(h.switcher) is None
