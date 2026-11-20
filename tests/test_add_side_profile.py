"""`cswap add` from a SIDE profile stores the slot and nothing else.

MEASURED 2026-11-20 (Oracle, 7835b96): the live login was slot 4, the cloud pin
named slot 1 (a setup token, no org), and `CLAUDE_CONFIG_DIR=<side> cswap add
--slot 1` (a fresh full sensei@ login) removed the pin, set
`activeAccountNumber` to 1 and dropped slot 1's alias.
"""
from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from claude_swap import fallback
from claude_swap import settings as _s
from tests.test_autoswitch import EngineHarness

EMAIL = "sensei@example.com"
ORG = "org-full"
SETUP = json.dumps({"claudeAiOauth": {
    "accessToken": "sk-ant-oat01-T", "scopes": ["user:inference"]}})
FULL = json.dumps({"claudeAiOauth": {
    "accessToken": "sk-ant-oat01-FULL", "refreshToken": "rt-full",
    "scopes": ["user:inference", "user:profile"],
    "expiresAt": 99999999999000}})
DATES = {"addedAt": "2026-10-04T04:44:37+00:00",
         "expiresAt": "2027-10-04T04:44:37+00:00"}
PROFILE = {"uuid": "u-s", "email": EMAIL, "organizationUuid": ORG}
ENV_BLOCK = {"HTTPS_PROXY": "http://127.0.0.1:52516"}


def _world(temp_home, *, side: bool):
    """Slot 1 = setup token with alias+dates, slot 4 = live and active, a pin
    on slot 1 and a wired live config. Returns (harness, capture env)."""
    h = EngineHarness(temp_home)
    h.seed(1, EMAIL)
    h.seed(4, "four@example.com")
    sw = h.switcher
    sw._write_account_credentials("1", EMAIL, SETUP, attributed=True)
    data = sw._get_sequence_data()
    data["accounts"]["1"].update(alias="main", setupToken=DATES)
    data["activeAccountNumber"] = 4
    sw._write_json(sw.sequence_file, data)
    h.make_live("four@example.com", 4)
    live_cfg = temp_home / ".claude.json"
    cfg = json.loads(live_cfg.read_text())
    cfg["env"] = dict(ENV_BLOCK)
    live_cfg.write_text(json.dumps(cfg))
    raw = _s._read_raw(_s.settings_path(sw.backup_dir))
    raw["remoteControl"] = {"pinnedEmail": EMAIL, "pinnedOrganizationUuid": ""}
    _s.settings_path(sw.backup_dir).write_text(json.dumps(raw))
    env = {}
    if side:
        side_dir = temp_home / "side"
        side_dir.mkdir()
        (side_dir / ".credentials.json").write_text(FULL)
        (side_dir / ".claude.json").write_text(json.dumps({"oauthAccount": {
            "emailAddress": EMAIL, "organizationUuid": ORG,
            "accountUuid": "u-s"}}))
        env["CLAUDE_CONFIG_DIR"] = str(side_dir)
    return h, env


def _add(h, env, **kw):
    with patch.dict(os.environ, env), \
         patch("claude_swap.oauth.fetch_oauth_profile", return_value=PROFILE):
        h.switcher.add_account(slot=1, assume_yes=True, **kw)


def test_side_profile_add_leaves_pin_active_slot_and_live_login(temp_home):
    h, env = _world(temp_home, side=True)
    sw = h.switcher
    live_cfg = (temp_home / ".claude.json").read_text()
    live_creds = (temp_home / ".claude" / ".credentials.json").read_text()

    _add(h, env)

    data = sw._get_sequence_data()
    assert data["activeAccountNumber"] == 4
    assert (temp_home / ".claude.json").read_text() == live_cfg
    assert json.loads(live_cfg)["env"] == ENV_BLOCK
    assert (temp_home / ".claude" / ".credentials.json").read_text() == live_creds
    from claude_swap import pin as _pin
    assert _pin._pinned_email_now(sw) == (EMAIL, "")
    # ... and the slot itself now holds the full login.
    rec = data["accounts"]["1"]
    assert rec["organizationUuid"] == ORG
    assert "sk-ant-oat01-FULL" in sw._read_account_credentials("1", EMAIL)


def test_readding_same_email_keeps_alias_unless_given(temp_home):
    h, env = _world(temp_home, side=True)
    _add(h, env)
    assert h.switcher._get_sequence_data()["accounts"]["1"]["alias"] == "main"

    _add(h, env, alias="boss")
    assert h.switcher._get_sequence_data()["accounts"]["1"]["alias"] == "boss"


@pytest.mark.parametrize("side", [True, False], ids=["side", "live"])
def test_full_login_over_setup_token_keeps_it_as_fallback(temp_home, side):
    h, env = _world(temp_home, side=side)
    if not side:
        # The live profile IS the captured login: slot 4's seat is taken by
        # sensei@ for this case.
        (temp_home / ".claude" / ".credentials.json").write_text(FULL)
        (temp_home / ".claude.json").write_text(json.dumps({"oauthAccount": {
            "emailAddress": EMAIL, "organizationUuid": ORG,
            "accountUuid": "u-s"}}))
    _add(h, env)
    got = fallback.read(h.switcher, "1", EMAIL)
    assert got is not None and "sk-ant-oat01-T" in got[0]
    assert got[1] == DATES
    assert h.switcher._get_sequence_data()["accounts"]["1"]["setupToken"] == DATES


def test_live_login_add_still_activates_the_slot(temp_home):
    """CONTROL: the live-profile add keeps marking the added slot active."""
    h, env = _world(temp_home, side=False)
    (temp_home / ".claude" / ".credentials.json").write_text(FULL)
    (temp_home / ".claude.json").write_text(json.dumps({"oauthAccount": {
        "emailAddress": EMAIL, "organizationUuid": ORG, "accountUuid": "u-s"}}))
    _add(h, env)
    assert h.switcher._get_sequence_data()["activeAccountNumber"] == 1
