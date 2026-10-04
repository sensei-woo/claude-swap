"""A slot's setup token as the fallback for its dead full login."""

from __future__ import annotations

import json
import time

from claude_swap import doctor, fallback, oauth
from claude_swap.usage_store import FetchRecord

from tests.test_autoswitch import EngineHarness

_SETUP = json.dumps({"claudeAiOauth": {"accessToken": "sk-ant-oat01-T",
                                       "scopes": ["user:inference"]}})
_DATES = {"addedAt": "2026-10-04T04:44:37+00:00",
          "expiresAt": "2027-10-04T04:44:37+00:00"}


def _harness(temp_home):
    h = EngineHarness(temp_home)
    h.seed(1, "a@example.com")
    h.seed(2, "b@example.com")
    h.make_live("a@example.com", 1)
    return h


def test_save_read_roundtrip_keeps_dates_out_of_the_credential(temp_home):
    h = _harness(temp_home)
    fallback.save(h.switcher, "2", "b@example.com", _SETUP, _DATES)
    creds, dates = fallback.read(h.switcher, "2", "b@example.com")
    assert json.loads(creds) == json.loads(_SETUP)
    assert dates == _DATES
    # The real slot is untouched.
    assert "sk-2" in h.switcher._read_account_credentials("2", "b@example.com")


def test_no_fallback_reads_none(temp_home):
    assert fallback.read(_harness(temp_home).switcher, "2", "b@example.com") is None


def test_activate_swaps_backup_marks_mode_and_heals_strike(temp_home):
    h = _harness(temp_home)
    fallback.save(h.switcher, "2", "b@example.com", _SETUP, _DATES)
    ident = {"2": ("b@example.com", "")}
    h.switcher._usage_store.record(
        {"2": FetchRecord(error="invalid_grant", struck_fp="x")}, ident)
    assert fallback.activate(h.switcher, "2", "b@example.com", active=False)
    stored = h.switcher._read_account_credentials("2", "b@example.com")
    assert oauth.extract_access_token(stored) == "sk-ant-oat01-T"
    rec = h.switcher._get_sequence_data()["accounts"]["2"]
    assert rec[fallback.MODE_KEY] == fallback.MODE_FALLBACK
    assert rec["setupToken"] == _DATES
    entry = h.switcher._usage_store.entries(ident)["2"]
    assert not entry.token_dead()
    notes = [f for f in doctor.run_checks(h.switcher) if "running on its setup token" in f.what]
    assert notes and notes[0].level == "note"


def test_activate_on_the_active_slot_writes_live_and_keeps_shared_keys(temp_home):
    h = _harness(temp_home)
    live = json.loads(h.switcher._read_credentials())
    live["designOauth"] = {"accessToken": "design"}
    h.switcher._write_credentials(json.dumps(live))
    fallback.save(h.switcher, "1", "a@example.com", _SETUP, _DATES)
    assert fallback.activate(h.switcher, "1", "a@example.com", active=True)
    now_live = json.loads(h.switcher._read_credentials())
    assert now_live["claudeAiOauth"]["accessToken"] == "sk-ant-oat01-T"
    assert now_live["designOauth"] == {"accessToken": "design"}


def test_preserve_copies_only_a_setup_token(temp_home):
    h = _harness(temp_home)
    # Slot 2 holds a full login: nothing to preserve.
    assert not fallback.preserve_before_oauth_add(h.switcher, "2", "b@example.com")
    h.switcher._write_account_credentials("2", "b@example.com", _SETUP,
                                          attributed=True)
    data = h.switcher._get_sequence_data()
    data["accounts"]["2"]["setupToken"] = _DATES
    h.switcher._write_json(h.switcher.sequence_file, data)
    assert fallback.preserve_before_oauth_add(h.switcher, "2", "b@example.com")
    assert fallback.read(h.switcher, "2", "b@example.com")[1] == _DATES


def test_activate_without_fallback_changes_nothing(temp_home):
    h = _harness(temp_home)
    before = h.switcher._read_account_credentials("2", "b@example.com")
    assert not fallback.activate(h.switcher, "2", "b@example.com", active=False)
    assert h.switcher._read_account_credentials("2", "b@example.com") == before


def test_add_token_fallback_keeps_the_full_login(temp_home, capsys):
    h = _harness(temp_home)
    before = h.switcher._read_account_credentials("2", "b@example.com")
    fallback.add_from_token(h.switcher, "sk-ant-oat01-NEW", 2)
    assert h.switcher._read_account_credentials("2", "b@example.com") == before
    creds, dates = fallback.read(h.switcher, "2", "b@example.com")
    assert oauth.extract_access_token(creds) == "sk-ant-oat01-NEW"
    rec = h.switcher._get_sequence_data()["accounts"]["2"]
    assert rec["setupToken"] == dates


def test_renew_advice_protects_a_full_login():
    exp = {"addedAt": "2026-01-01T00:00:00+00:00", "expiresAt": "2026-01-02T00:00:00+00:00"}
    oauth_slot = {"email": "b@x", "organizationUuid": "org", "setupToken": exp}
    token_slot = {"email": "b@x", "organizationUuid": "", "setupToken": exp}
    assert "--fallback --slot 2" in doctor.expiry_finding("2", oauth_slot).fix
    assert "--fallback" not in doctor.expiry_finding("2", token_slot).fix
