"""
Unit Tests for New Prometheus OSINT Features:
- Telegram OSINT & entity reconnaissance
- Public Database & Threat Intel (Wayback Machine, breaches, CVEs)
- Admin Leave Group (/pb_leave)
- Private Chat (PV) strict lockdown for non-admins
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from telegram.constants import ChatType
from main import _check_moderation_guard, leavegroup_command
from tools.telegram_osint import (
    clean_telegram_target,
    format_telegram_osint_report,
    track_user_in_known_groups,
)
from tools.public_db_intel import (
    format_public_intel_report,
    query_wayback_snapshots,
    query_cve_vulnerabilities,
)
from tools.moderation import mark_group_left, _TRACKED_GROUPS


def test_clean_telegram_target():
    assert clean_telegram_target("@durov") == "durov"
    assert clean_telegram_target("https://t.me/durov") == "durov"
    assert clean_telegram_target("https://t.me/s/telegram") == "telegram"
    assert clean_telegram_target("12345678") == "12345678"


def test_format_telegram_osint_report():
    sample_report = {
        "success": True,
        "target": "durov",
        "numeric_id": 777000,
        "name": "Pavel Durov",
        "web_info": {
            "type": "کانال عمومی (Channel)",
            "members_count": "2.5M subscribers",
            "description": "Founder of Telegram",
            "verified": True,
        },
        "api_info": {},
        "tracker_info": {
            "groups_count": 1,
            "groups": [{"title": "گروه تست", "chat_id": -100112233, "last_seen": "2026-09-18"}],
            "known_names": ["Pavel Durov"],
        },
        "public_mentions": {
            "findings": [{"title": "Post 1", "url": "https://t.me/durov/1", "snippet": "Hello world"}]
        }
    }
    output = format_telegram_osint_report(sample_report)
    assert "@durov" in output
    assert "777000" in output
    assert "Pavel Durov" in output
    assert "گروه تست" in output
    assert "Post 1" in output


def test_format_public_intel_report():
    sample_report = {
        "success": True,
        "query": "target.com",
        "wayback": {
            "success": True,
            "snapshots": [
                {"date": "2024/01/01 12:00", "archive_url": "https://web.archive.org/web/1/target.com", "status": "200", "mimetype": "text/html"}
            ]
        },
        "urlscan": {
            "success": True,
            "scans": [
                {"scan_date": "2024-05-01", "ip": "1.2.3.4", "asn": "AS13335 Cloudflare", "malicious": False, "result_page": "https://urlscan.io/r/123", "country": "US"}
            ]
        },
        "breaches": {
            "success": True,
            "breaches": [{"source": "COMB", "count": 150, "description": "Compromised list"}],
            "pastes": []
        },
        "cves": {
            "success": True,
            "vulnerabilities": [{"id": "CVE-2024-0001", "cvss": "9.8", "published": "2024-01-10", "summary": "Remote code execution"}]
        }
    }
    output = format_public_intel_report(sample_report)
    assert "target.com" in output
    assert "Wayback Machine" in output
    assert "1.2.3.4" in output
    assert "COMB" in output
    assert "CVE-2024-0001" in output


@pytest.mark.asyncio
async def test_pv_strict_lockdown_for_non_admins():
    """Verifies that non-admins messaging the bot in private are strictly blocked with warning notice."""
    update = MagicMock()
    context = MagicMock()

    # Normal user in PV
    update.effective_chat.type = ChatType.PRIVATE
    update.effective_chat.id = 99887766
    update.effective_user.id = 99887766  # non-admin
    update.effective_user.username = "normal_user"
    update.effective_message.reply_text = AsyncMock()

    res = await _check_moderation_guard(update, context)
    assert res is False
    update.effective_message.reply_text.assert_called()
    warn_text = update.effective_message.reply_text.call_args[0][0]
    assert "دسترسی به گفتگوی خصوصی محدود است" in warn_text

    # Admin user in PV
    admin_id = 8814471014
    update.effective_user.id = admin_id
    update.effective_chat.id = admin_id
    res_admin = await _check_moderation_guard(update, context)
    assert res_admin is True


@pytest.mark.asyncio
async def test_leavegroup_command_admin_only():
    """Verifies that leavegroup_command allows admins to leave a group and blocks non-admins."""
    update = MagicMock()
    context = MagicMock()
    context.bot.leave_chat = AsyncMock()
    context.bot.send_message = AsyncMock()

    # 1. Non-admin attempt
    update.effective_user.id = 12345
    update.effective_chat.type = ChatType.SUPERGROUP
    update.effective_chat.id = -10055443322
    update.effective_message.reply_text = AsyncMock()
    await leavegroup_command(update, context)
    update.effective_message.reply_text.assert_called_with("⛔️ دسترسی غیرمجاز. این فرمان منحصراً در اختیار مدیران ربات می‌باشد.")
    context.bot.leave_chat.assert_not_called()

    # 2. Admin leaves current group
    admin_id = 8814471014
    update.effective_user.id = admin_id
    update.effective_message.reply_text.reset_mock()
    context.args = []
    await leavegroup_command(update, context)
    context.bot.leave_chat.assert_called_with(chat_id=-10055443322)
    assert _TRACKED_GROUPS.get(-10055443322, {}).get("status") == "left"


@pytest.mark.asyncio
async def test_approved_group_no_duplicate_requests_from_new_users():
    """
    Verifies that once a group is approved, ANY user (even a brand new user who has never
    spoken to the bot) can send messages without triggering an approval request to the admin.
    """
    from tools.moderation import approve_group, get_group_status, is_group_approved

    test_cid = -1003949505012
    admin_id = 8814471014
    await approve_group(test_cid, reviewed_by=admin_id, title="OSINT Community")

    assert is_group_approved(test_cid) is True
    assert get_group_status(test_cid) == "approved"

    # Now a completely new user who has never messaged before speaks in the group
    update = MagicMock()
    context = MagicMock()
    context.bot.send_message = AsyncMock()

    update.effective_chat.type = ChatType.SUPERGROUP
    update.effective_chat.id = test_cid
    update.effective_chat.title = "OSINT Community"
    update.effective_chat.username = "osint_community"

    update.effective_user.id = 99887766  # Brand new user
    update.effective_user.username = "brand_new_user"
    update.effective_user.full_name = "New User"

    # Moderation guard check
    res = await _check_moderation_guard(update, context)
    assert res is True  # Permitted through!
    # No approval request sent to admin!
    context.bot.send_message.assert_not_called()


@pytest.mark.asyncio
async def test_admin_interaction_auto_approves_group():
    """
    Verifies that if a bot administrator speaks in any group, the group is
    automatically and permanently approved on the spot.
    """
    from tools.moderation import get_group_status, _TRACKED_GROUPS

    new_cid = -10077889900
    admin_id = 8814471014

    _TRACKED_GROUPS.pop(new_cid, None)

    update = MagicMock()
    context = MagicMock()
    context.bot.send_message = AsyncMock()

    update.effective_chat.type = ChatType.SUPERGROUP
    update.effective_chat.id = new_cid
    update.effective_chat.title = "Admin Testing Group"
    update.effective_chat.username = ""

    update.effective_user.id = admin_id
    update.effective_user.username = "admin"
    update.effective_user.full_name = "Bot Admin"

    res = await _check_moderation_guard(update, context)
    assert res is True
    # Group must now be automatically approved!
    assert get_group_status(new_cid) == "approved"
