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


def test_parse_summary_request_ranges():
    """Verifies that parse_summary_request intelligently extracts counts from 1 to 5000."""
    from tools.summary_tool import parse_summary_request

    # Single message
    is_sum, cnt = parse_summary_request("آخرین پیام رو بخون و توضیح بده")
    assert is_sum is True
    assert cnt == 1

    is_sum, cnt = parse_summary_request("۱ پیام اخیر رو خلاصه کن")
    assert is_sum is True
    assert cnt == 1

    # Exact numbers
    is_sum, cnt = parse_summary_request("خلاصه ۵ پیام اخیر")
    assert is_sum is True
    assert cnt == 5

    is_sum, cnt = parse_summary_request("خلاصه ۵۰ پیام")
    assert is_sum is True
    assert cnt == 50

    is_sum, cnt = parse_summary_request("/summarize 250")
    assert is_sum is True
    assert cnt == 250

    is_sum, cnt = parse_summary_request("۵۰۰ تا پیام رو بررسی کن و خلاصه بده")
    assert is_sum is True
    assert cnt == 500

    is_sum, cnt = parse_summary_request("خلاصه 1k پیام اخیر")
    assert is_sum is True
    assert cnt == 1000

    is_sum, cnt = parse_summary_request("خلاصه ۲.۵ هزار پیام")
    assert is_sum is True
    assert cnt == 2500

    is_sum, cnt = parse_summary_request("۵۰۰۰ پیام گروه رو کامل بخون و خلاصه کن")
    assert is_sum is True
    assert cnt == 5000

    # Persian written words
    is_sum, cnt = parse_summary_request("پنج هزار تا پیام اخیر رو خلاصه کن")
    assert is_sum is True
    assert cnt == 5000

    is_sum, cnt = parse_summary_request("پانصد تا پیام گذشته رو گزارش بده")
    assert is_sum is True
    assert cnt == 500

    # Full-group / maximum triggers
    is_sum, cnt = parse_summary_request("کل پیام‌های گروه رو خلاصه کن")
    assert is_sum is True
    assert cnt == 5000

    is_sum, cnt = parse_summary_request("همه چت‌ها رو بخون و جمع‌بندی کن")
    assert is_sum is True
    assert cnt == 5000

    is_sum, cnt = parse_summary_request("تا سقف پیام‌ها رو خلاصه بگو")
    assert is_sum is True
    assert cnt == 5000

    # Upper bound capping
    is_sum, cnt = parse_summary_request("/summarize 10000")
    assert is_sum is True
    assert cnt == 5000

    # Non-summary queries
    is_sum, _ = parse_summary_request("سلام چطوری پرومته")
    assert is_sum is False


@pytest.mark.asyncio
async def test_database_5000_message_persistence_and_retrieval():
    """Verifies that database persists and retrieves messages up to 5,000 for a group in order."""
    import database
    test_cid = -100555444333

    # Clean previous test entries if any
    await database.clear_session_in_d1(test_cid)

    # Insert 120 sequential messages
    for i in range(1, 121):
        await database.persist_message(
            chat_id=test_cid,
            user_id=1000 + (i % 5),
            role="user",
            content=f"پیام شماره {i} برای تست ظرفیت خلاصه گروه",
            username=f"user_{i % 5}",
            full_name=f"کاربر {i % 5}",
            message_id=i
        )

    # Retrieve all 120 messages
    retrieved = await database.get_chat_messages_for_summary(test_cid, limit=120)
    assert len(retrieved) == 120
    # Check chronological order (first message should be #1, last #120)
    assert "شماره 1 " in retrieved[0]["content"]
    assert "شماره 120 " in retrieved[-1]["content"]

    # Retrieve subset of 10 messages
    subset = await database.get_chat_messages_for_summary(test_cid, limit=10)
    assert len(subset) == 10
    # Should be the most recent 10 messages (111 to 120) in chronological order
    assert "شماره 111 " in subset[0]["content"]
    assert "شماره 120 " in subset[-1]["content"]

    # Cleanup
    await database.clear_session_in_d1(test_cid)


@pytest.mark.asyncio
async def test_summarize_group_messages_execution():
    """Verifies that summarize_group_messages executes rapidly and generates valid HTML with expandable blockquote."""
    import database
    from tools.summary_tool import summarize_group_messages

    test_cid = -100999111222
    await database.clear_session_in_d1(test_cid)

    # Insert 30 realistic conversation messages
    sample_dialogue = [
        ("علی", "سلام به همه، جلسه فنی امروز ساعت چند برگزار میشه؟"),
        ("رضا", "سلام علی جان، ساعت ۵ بعدازظهر توی گوگل میت."),
        ("مریم", "من پرزنتیشن بخش هوش مصنوعی و مدل جدید رو آماده کردم."),
        ("علی", "عالیه، لطفا اسلایدها رو قبلش توی گروه بفرست تا مرور کنیم."),
        ("رضا", "سرور تست هم کانفیگ شد و آماده بنچمارک لود ۵۰۰۰ درخواست هست."),
        ("مریم", "نتایج ارزیابی اولیه دقت ۹۸ درصدی رو نشون میده."),
        ("علی", "فوق‌العاده‌ست، پس روی سرور اصلی دیپلوی میکنیم."),
        ("رضا", "موافقم، تسک‌های مربوط به مانیتورینگ رو هم تیک زدم."),
    ]
    for idx, (speaker, txt) in enumerate(sample_dialogue * 3, 1):
        await database.persist_message(
            chat_id=test_cid,
            user_id=2000 + (idx % 3),
            role="user",
            content=txt,
            username=f"user_{idx}",
            full_name=speaker,
            message_id=idx
        )

    # Execute summarizer
    report = await summarize_group_messages(chat_id=test_cid, count=30, chat_title="تیم مهندسی پرومته")
    assert "<blockquote expandable>" in report
    assert "</blockquote>" in report
    assert "گزارش و خلاصه هوشمند گفتگو" in report
    assert "تیم مهندسی پرومته" in report
    assert "پیام‌های بررسی‌شده" in report
    assert "کاربران فعال" in report

    # Test single message summarization
    single_rep = await summarize_group_messages(chat_id=test_cid, count=1, chat_title="تیم مهندسی پرومته")
    assert "<blockquote expandable>" in single_rep
    assert "<code>1</code> پیام" in single_rep

    # Cleanup
    await database.clear_session_in_d1(test_cid)


@pytest.mark.asyncio
async def test_categorized_groups_active_vs_inactive():
    """
    Verifies that get_live_telegram_groups and grouplist_command accurately
    categorize groups into Active and Inactive (present but inactive) sections.
    """
    import time
    from tools.moderation import (
        _TRACKED_GROUPS, _BANNED_GROUPS, _MUTED_GROUPS, _MOD_LOCK,
        get_live_telegram_groups, mute_group, ban_group, approve_group
    )
    from main import grouplist_command

    admin_id = 8814471014
    cid_active = -10088888801
    cid_muted = -10088888802
    cid_banned = -10088888803
    cid_pending = -10088888804

    with _MOD_LOCK:
        _TRACKED_GROUPS.clear()
        _TRACKED_GROUPS[cid_active] = {"chat_id": cid_active, "title": "گروه فعال مهندسی", "status": "approved"}
        _TRACKED_GROUPS[cid_muted] = {"chat_id": cid_muted, "title": "گروه میوت شده", "status": "approved"}
        _TRACKED_GROUPS[cid_banned] = {"chat_id": cid_banned, "title": "گروه بن شده", "status": "banned"}
        _TRACKED_GROUPS[cid_pending] = {"chat_id": cid_pending, "title": "گروه در انتظار تایید", "status": "pending"}

        _MUTED_GROUPS[cid_muted] = {"chat_id": cid_muted, "until_ts": time.time() + 3600}
        _BANNED_GROUPS[cid_banned] = {"chat_id": cid_banned, "reason": "اسپم"}

    # Mock bot
    mock_bot = MagicMock()
    mock_bot.id = 8939248291

    def mock_get_chat(chat_id):
        chat_mock = MagicMock()
        chat_mock.id = chat_id
        chat_mock.type = "supergroup"
        chat_mock.member_count = 150
        chat_mock.username = "testgroup"
        if chat_id == cid_active:
            chat_mock.title = "گروه فعال مهندسی"
        elif chat_id == cid_muted:
            chat_mock.title = "گروه میوت شده"
        elif chat_id == cid_banned:
            chat_mock.title = "گروه بن شده"
        else:
            chat_mock.title = "گروه در انتظار تایید"
        return AsyncMock(return_value=chat_mock)()

    def mock_get_chat_member(chat_id, user_id):
        member_mock = MagicMock()
        member_mock.status = "administrator"
        member_mock.can_send_messages = True
        return AsyncMock(return_value=member_mock)()

    mock_bot.get_chat = mock_get_chat
    mock_bot.get_chat_member = mock_get_chat_member
    mock_bot.get_chat_member_count = AsyncMock(return_value=150)

    # 1. Test get_live_telegram_groups categorization
    groups = await get_live_telegram_groups(mock_bot)
    g_map = {g["chat_id"]: g for g in groups}

    assert cid_active in g_map
    assert g_map[cid_active]["is_active"] is True
    assert len(g_map[cid_active]["inactive_reasons"]) == 0

    assert cid_muted in g_map
    assert g_map[cid_muted]["is_active"] is False
    assert any("میوت" in r for r in g_map[cid_muted]["inactive_reasons"])

    assert cid_banned in g_map
    assert g_map[cid_banned]["is_active"] is False
    assert any("مسدود" in r for r in g_map[cid_banned]["inactive_reasons"])

    assert cid_pending in g_map
    assert g_map[cid_pending]["is_active"] is False
    assert any("انتظار" in r for r in g_map[cid_pending]["inactive_reasons"])

    # 2. Test grouplist_command output rendering
    update = MagicMock()
    update.effective_user.id = admin_id
    update.effective_chat.id = admin_id
    status_msg = MagicMock()
    status_msg.edit_text = AsyncMock()
    update.effective_message.reply_text = AsyncMock(return_value=status_msg)

    context = MagicMock()
    context.bot = mock_bot
    context.args = []

    await grouplist_command(update, context)

    assert status_msg.edit_text.called
    texts = [status_msg.edit_text.call_args[0][0]]
    for call in update.effective_message.reply_text.call_args_list[1:]:
        texts.append(call[0][0])
    output_text = "\n".join(texts)

    # Verify both sections exist and are categorized separately
    assert "گروه‌های فعال و آنلاین" in output_text or "گروه‌های فعال و پاسخگو" in output_text
    assert "گروه‌های غیرفعال (ربات در گروه هست ولی غیرفعاله)" in output_text
    assert "گروه فعال مهندسی" in output_text
    assert "گروه میوت شده" in output_text
    assert "گروه بن شده" in output_text
    assert "گروه در انتظار تایید" in output_text

    # Verify quick action hints are rendered for inactive groups
    assert "/unmutegroup" in output_text
    assert "/unbangroup" in output_text
    assert "/approvegroup" in output_text

    # Cleanup
    with _MOD_LOCK:
        for cid in [cid_active, cid_muted, cid_banned, cid_pending]:
            _TRACKED_GROUPS.pop(cid, None)
            _MUTED_GROUPS.pop(cid, None)
            _BANNED_GROUPS.pop(cid, None)


