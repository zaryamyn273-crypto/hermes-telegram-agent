"""
Unit and Integration tests for Prometheus Moderation, Governance & Group Authorization Engine:
- User ban & unban with username and numeric ID persistence
- Timed user muting, non-response enforcement, and auto-expiry
- Group ban & unban
- Group bot muting & unmuting
- Group approval workflow (pending, approved, rejected)
- Admin commands audit logging & persistent settings storage
- Gatekeeper guard verification
"""

import time
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

import database
from config import settings, is_admin
from tools.moderation import (
    init_moderation_engine,
    is_user_banned,
    is_user_muted,
    is_group_banned,
    is_group_muted,
    is_group_approved,
    get_group_status,
    register_group_event,
    approve_group,
    reject_group,
    ban_user,
    unban_user,
    mute_user,
    unmute_user,
    ban_group,
    unban_group,
    mute_group,
    unmute_group,
    get_banned_users_list,
    get_muted_users_list,
    get_banned_groups_list,
    get_muted_groups_list,
    get_pending_groups_list,
    get_unbanned_history,
    get_admin_commands_log,
    set_admin_setting,
    get_admin_setting,
    get_all_admin_settings,
    parse_duration_string,
    format_duration_persian,
    _MOD_LOCK,
    _BANNED_USERS,
    _BANNED_USERNAMES,
    _MUTED_USERS,
    _MUTED_USERNAMES,
    _BANNED_GROUPS,
    _MUTED_GROUPS,
    _TRACKED_GROUPS,
)
from main import _check_moderation_guard, extract_target_entity


def test_duration_parser_and_formatter():
    # English patterns
    assert parse_duration_string("10s") == 10.0
    assert parse_duration_string("15m") == 900.0
    assert parse_duration_string("2h") == 7200.0
    assert parse_duration_string("1d") == 86400.0
    assert parse_duration_string("1w") == 604800.0
    assert parse_duration_string("45") == 2700.0  # Default minutes

    # Persian patterns & digits
    assert parse_duration_string("۳۰ دقیقه") == 1800.0
    assert parse_duration_string("۲ ساعت") == 7200.0
    assert parse_duration_string("۱ روز") == 86400.0

    # Formatter
    assert "2 ساعت" in format_duration_persian(7200)
    assert "30 دقیقه" in format_duration_persian(1800)
    assert "1 روز" in format_duration_persian(86400)


@pytest.fixture(scope="session", autouse=True)
def init_db():
    asyncio.run(init_moderation_engine())


@pytest.mark.asyncio
async def test_user_ban_and_unban():
    test_uid = 987654321
    test_uname = "bad_actor_test"
    admin_id = 8814471014

    # 1. Ban user
    await ban_user(
        user_id=test_uid,
        username=test_uname,
        name="Test Bad User",
        reason="Violated rules",
        banned_by=admin_id,
        chat_id=-100111,
        chat_title="Test Chat"
    )

    # In-memory & function checks
    assert is_user_banned(test_uid) is True
    assert is_user_banned(None, test_uname) is True
    assert is_user_banned(None, f"@{test_uname}") is True
    assert is_user_banned(111111) is False

    # List check
    banned_list = await get_banned_users_list()
    found = [u for u in banned_list if u.get("user_id") == test_uid]
    assert len(found) > 0
    assert found[0].get("username") == test_uname

    # 2. Unban user
    ok, prev = await unban_user(user_id=test_uid, unbanned_by=admin_id, reason="Apologized")
    assert ok is True
    assert is_user_banned(test_uid) is False
    assert is_user_banned(None, test_uname) is False

    # Unban audit log check
    unbans = await get_unbanned_history(limit=5)
    unban_entry = [u for u in unbans if u.get("entity_id") == test_uid]
    assert len(unban_entry) > 0


@pytest.mark.asyncio
async def test_user_timed_mute_and_expiry():
    test_uid = 88887777
    test_uname = "noisy_user_test"
    admin_id = 8814471014

    # 1. Mute user for 2 seconds
    ok, until_ts = await mute_user(
        user_id=test_uid,
        duration_sec=2.0,
        username=test_uname,
        first_name="Noisy",
        reason="Spamming",
        muted_by=admin_id
    )
    assert ok is True
    assert until_ts > time.time()

    # Verify muted
    muted, rem = is_user_muted(test_uid)
    assert muted is True
    assert 0.0 < rem <= 2.5

    muted_by_uname, _ = is_user_muted(None, f"@{test_uname}")
    assert muted_by_uname is True

    # 2. Early manual unmute
    ok_unmute, _ = await unmute_user(test_uid, unmuted_by=admin_id)
    assert ok_unmute is True
    assert is_user_muted(test_uid)[0] is False

    # 3. Test automatic expiry
    await mute_user(test_uid, duration_sec=10.0, username=test_uname)
    # Manually backdate until_ts in cache to simulate time expiration
    with _MOD_LOCK:
        _MUTED_USERS[test_uid]["until_ts"] = time.time() - 5.0
    expired_check, _ = is_user_muted(test_uid)
    assert expired_check is False


@pytest.mark.asyncio
async def test_group_ban_and_mute():
    test_chat_id = -1009988776655
    admin_id = 8814471014

    # 1. Ban group
    await ban_group(test_chat_id, title="Trouble Group", reason="Spam source", banned_by=admin_id)
    assert is_group_banned(test_chat_id) is True

    # Unban group
    ok, _ = await unban_group(test_chat_id, unbanned_by=admin_id)
    assert ok is True
    assert is_group_banned(test_chat_id) is False

    # 2. Mute bot in group (indefinite: 0s)
    await mute_group(test_chat_id, duration_sec=0.0, title="Quiet Group", muted_by=admin_id)
    assert is_group_muted(test_chat_id)[0] is True

    # Unmute bot in group
    await unmute_group(test_chat_id, unmuted_by=admin_id)
    assert is_group_muted(test_chat_id)[0] is False


@pytest.mark.asyncio
async def test_group_approval_workflow():
    ts = int(time.time() * 1000) % 100000000
    chat_id_admin = -(100000000000 + ts)
    chat_id_user = -(200000000000 + ts)
    bot_admin_id = 8814471014
    regular_user_id = 55555555

    # 1. Added by bot admin -> auto approved
    st_admin, is_new_admin = await register_group_event(
        chat_id=chat_id_admin,
        title="Admin Group",
        chat_type="supergroup",
        added_by_id=bot_admin_id
    )
    assert st_admin == "approved"
    assert is_new_admin is False
    assert is_group_approved(chat_id_admin) is True

    # 2. Added by regular user -> pending & inactive
    st_user, is_new_user = await register_group_event(
        chat_id=chat_id_user,
        title="Random User Group",
        chat_type="supergroup",
        added_by_id=regular_user_id
    )
    assert st_user == "pending"
    assert is_new_user is True
    assert is_group_approved(chat_id_user) is False
    assert get_group_status(chat_id_user) == "pending"

    # Pending list
    pending = await get_pending_groups_list()
    assert any(g.get("chat_id") == chat_id_user for g in pending)

    # 3. Admin approves group
    await approve_group(chat_id_user, reviewed_by=bot_admin_id)
    assert is_group_approved(chat_id_user) is True
    assert get_group_status(chat_id_user) == "approved"

    # 4. Admin rejects group
    await reject_group(chat_id_user, reviewed_by=bot_admin_id)
    assert is_group_approved(chat_id_user) is False
    assert get_group_status(chat_id_user) == "rejected"


@pytest.mark.asyncio
async def test_admin_settings_and_command_logging():
    admin_id = 8814471014
    key = "test_custom_rule"
    val = "Always respond in Persian"

    # Set setting
    ok = await set_admin_setting(key, val, category="policy", admin_id=admin_id)
    assert ok is True

    # Get setting
    fetched = await get_admin_setting(key)
    assert fetched == val

    # Verify command log
    logs = await get_admin_commands_log(limit=10)
    assert any(l.get("command") == "set_setting" for l in logs)


@pytest.mark.asyncio
async def test_gatekeeper_guard():
    # Mock updates
    banned_uid = 777666
    muted_uid = 555444
    good_uid = 111222
    admin_uid = 8814471014

    await ban_user(banned_uid, username="banned_guy", banned_by=admin_uid)
    await mute_user(muted_uid, duration_sec=3600.0, username="muted_guy", muted_by=admin_uid)

    def make_mock_update(uid, username, chat_id, chat_type="private"):
        up = MagicMock()
        up.effective_user.id = uid
        up.effective_user.username = username
        up.effective_chat.id = chat_id
        up.effective_chat.type = chat_type
        up.effective_chat.title = "Test"
        return up

    context = MagicMock()

    # 1. Banned user is blocked
    up_banned = make_mock_update(banned_uid, "banned_guy", chat_id=123)
    assert await _check_moderation_guard(up_banned, context) is False

    # 2. Muted user is blocked
    up_muted = make_mock_update(muted_uid, "muted_guy", chat_id=123)
    assert await _check_moderation_guard(up_muted, context) is False

    # 3. Good user in private chat is allowed
    up_good = make_mock_update(good_uid, "good_guy", chat_id=456)
    assert await _check_moderation_guard(up_good, context) is True

    # 4. Good user in unapproved group is blocked
    unapproved_group_id = -10044332211
    up_group_unapproved = make_mock_update(good_uid, "good_guy", chat_id=unapproved_group_id, chat_type="supergroup")
    assert await _check_moderation_guard(up_group_unapproved, context) is False

    # But admin issuing admin command in unapproved group is allowed
    up_admin_cmd = make_mock_update(admin_uid, "admin_user", chat_id=unapproved_group_id, chat_type="supergroup")
    assert await _check_moderation_guard(up_admin_cmd, context, is_admin_cmd=True) is True
