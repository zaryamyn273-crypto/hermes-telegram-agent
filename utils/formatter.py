"""
Telegram HTML formatter and markdown conversion utilities.
Engineered specifically for Telegram's native formatting constraints.
"""

import re
import html
from typing import List, Set

# Allowed HTML tags by Telegram Bot API
ALLOWED_TELEGRAM_TAGS: Set[str] = {
    "b", "strong", "i", "em", "u", "ins", "s", "strike", "del",
    "tg-spoiler", "a", "code", "pre", "blockquote"
}

_THINKING_REGEX = re.compile(
    r"(?:<thought>[\s\S]*?</thought>|<think>[\s\S]*?</think>|\[thinking\][\s\S]*?\[/thinking\])",
    re.IGNORECASE
)


def strip_thinking(text: str) -> str:
    """Removes model reasoning / internal thought blocks."""
    if not text:
        return ""
    cleaned = _THINKING_REGEX.sub("", text).strip()
    return cleaned


def balance_html_tags(html_str: str) -> str:
    """
    Ensures all opened HTML tags in a Telegram chunk are properly closed,
    preventing Telegram 'tag not closed' entity parsing errors.
    """
    if not html_str:
        return ""
    tag_regex = re.compile(r"</?([a-zA-Z0-9_-]+)(?:\s+[^>]*)?>")
    stack = []
    for match in tag_regex.finditer(html_str):
        full_tag = match.group(0)
        tag_name = match.group(1).lower()
        if full_tag.startswith("</"):
            if stack and stack[-1] == tag_name:
                stack.pop()
        elif not full_tag.endswith("/>"):
            stack.append(tag_name)

    # Close unclosed tags in reverse order
    for tag_name in reversed(stack):
        html_str += f"</{tag_name}>"
    return html_str


def sanitize_telegram_html(text: str) -> str:
    """
    Strips unsupported web/HTML tags and converts them into clean Telegram equivalents,
    guaranteeing that Telegram's HTML parser will never reject the payload.
    """
    if not text:
        return ""

    # 1. Convert common unsupported web tags to text/whitespace
    text = re.sub(r"<\s*br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<\s*hr\s*/?>", "\n⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<\s*/?\s*(?:p|div)\s*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<\s*li\s*>", "\n• ", text, flags=re.IGNORECASE)
    text = re.sub(r"<\s*/\s*li\s*>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<\s*/?\s*(?:ul|ol)\s*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<\s*h[1-6]\s*>(.*?)</\s*h[1-6]\s*>", r"\n<b>\1</b>\n", text, flags=re.IGNORECASE | re.DOTALL)

    # 2. Strip any remaining unrecognized HTML tags that Telegram rejects
    def _filter_tag(match):
        full = match.group(0)
        tag = match.group(1).lower()
        if tag in ALLOWED_TELEGRAM_TAGS:
            return full
        return ""

    tag_pat = re.compile(r"</?([a-zA-Z0-9_-]+)(?:\s+[^>]*)?>")
    cleaned = tag_pat.sub(_filter_tag, text)

    # 3. Clean up excessive whitespace/newlines (max 2 consecutive newlines)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return balance_html_tags(cleaned)


def convert_markdown_tables_to_box(text: str) -> str:
    """
    Detects Markdown pipe tables (| a | b |) and converts them into
    aligned Unicode box-drawing tables enclosed in monospace code blocks
    for optimal presentation in Telegram clients.
    """
    table_regex = re.compile(
        r"((?:^[ \t]*\|[^\n]+\|[ \t]*\n)"
        r"(?:^[ \t]*\|[\s\-:|]+\|[ \t]*\n)"
        r"(?:^[ \t]*\|[^\n]+\|[ \t]*(?:\n|$))+)",
        re.MULTILINE
    )

    def _replace_table(match):
        raw_table = match.group(1)
        lines = [l.strip() for l in raw_table.strip().split("\n") if l.strip()]
        if len(lines) < 2:
            return raw_table

        rows = []
        for line in lines:
            if line.startswith("|") and line.endswith("|"):
                line = line[1:-1]
            cells = [c.strip() for c in line.split("|")]
            # Skip separator line (e.g. |---|:---|)
            if all(set(c).issubset({"-", ":", " "}) for c in cells):
                continue
            rows.append(cells)

        if not rows or len(rows) < 2:
            return raw_table

        num_cols = max(len(r) for r in rows)
        for r in rows:
            while len(r) < num_cols:
                r.append("")

        col_widths = [0] * num_cols
        for r in rows:
            for i, c in enumerate(r):
                col_widths[i] = max(col_widths[i], len(c) + 2)

        top = "┌" + "┬".join("─" * w for w in col_widths) + "┐"
        mid = "├" + "┼".join("─" * w for w in col_widths) + "┤"
        bot = "└" + "┴".join("─" * w for w in col_widths) + "┘"

        out = [top]
        header_cells = [f" {c} ".center(col_widths[i]) for i, c in enumerate(rows[0])]
        out.append("│" + "│".join(header_cells) + "│")
        out.append(mid)

        for r in rows[1:]:
            row_cells = [f" {c} ".center(col_widths[i]) for i, c in enumerate(r)]
            out.append("│" + "│".join(row_cells) + "│")
        out.append(bot)

        box_table = "\n".join(out)
        return "\n```\n" + box_table + "\n```\n"

    return table_regex.sub(_replace_table, text)


def markdown_to_telegram_html(text: str) -> str:
    """
    Converts standard Markdown into Telegram-compatible HTML format.
    Supports:
    - Headers (#, ##, ###) -> bold <b>
    - Blockquotes (> ) -> <blockquote>
    - Code blocks (```lang ... ```) -> <pre><code class="...">
    - Inline code (`code`) -> <code>
    - Dividers (---, ***) -> Unicode divider line
    - Bold (**bold**) -> <b>
    - Italic (*italic*, _italic_) -> <i>
    - Underline (__underline__) -> <u>
    - Strikethrough (~~strike~~) -> <s>
    - Spoilers (||spoiler||) -> <tg-spoiler>
    - Links ([text](url)) -> <a href="...">
    - Tables -> Monospaced box tables
    - Full tag balancing & sanitization
    """
    if not text:
        return ""

    text = strip_thinking(text)

    # 1. Convert raw markdown tables to aligned Unicode box tables
    text = convert_markdown_tables_to_box(text)

    # 2. Protect code blocks (```code```)
    code_blocks = []
    def _save_code_block(match):
        lang = (match.group(1) or "").strip()
        code = match.group(2)
        escaped_code = html.escape(code)
        if lang:
            tag = f'<pre><code class="language-{html.escape(lang)}">{escaped_code}</code></pre>'
        else:
            tag = f'<pre>{escaped_code}</pre>'
        code_blocks.append(tag)
        return f"###CB{len(code_blocks)-1}###"

    text = re.sub(r"```([a-zA-Z0-9_\-+]*)\n?([\s\S]*?)```", _save_code_block, text)

    # 3. Protect inline code (`code`)
    inline_codes = []
    def _save_inline_code(match):
        code = match.group(1)
        tag = f"<code>{html.escape(code)}</code>"
        inline_codes.append(tag)
        return f"###IC{len(inline_codes)-1}###"

    text = re.sub(r"`([^`\n]+)`", _save_inline_code, text)

    # 4. Protect Blockquotes (> text)
    bqs = []
    def _save_blockquote(match):
        raw_lines = match.group(0).strip().split("\n")
        inner_lines = [re.sub(r"^\s*>\s?", "", l) for l in raw_lines]
        inner_content = "\n".join(inner_lines).strip()
        bqs.append(inner_content)
        return f"###BQ{len(bqs)-1}###\n"

    text = re.sub(r"(?:^[ \t]*>.*(?:\n|$))+", _save_blockquote, text, flags=re.MULTILINE)

    # 5. Escape all raw HTML characters
    text = html.escape(text)

    # 6. Convert Markdown Headers (#, ##, ###, ####) to bold
    # Done after html.escape so <b> tags are preserved!
    text = re.sub(r"(?m)^#{1,6}\s+(.+)$", r"<b>\1</b>", text)

    # 7. Convert Markdown Horizontal Rules (---, ***, ___) to elegant Unicode divider
    text = re.sub(r"(?m)^(\s*[-*_]){3,}\s*$", "⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯", text)

    # 8. Spoilers: ||text||
    text = re.sub(r"\|\|(.+?)\|\|", r"<tg-spoiler>\1</tg-spoiler>", text)

    # 9. Bold: **text**
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)

    # 10. Underline: __text__
    text = re.sub(r"__(.+?)__", r"<u>\1</u>", text)

    # 11. Strike: ~~text~~
    text = re.sub(r"~~(.+?)~~", r"<s>\1</s>", text)

    # 12. Italic: *text* and _text_
    text = re.sub(r"(?<!\*)\*([^\*\n]+)\*(?!\*)", r"<i>\1</i>", text)
    text = re.sub(r"(?<![a-zA-Z0-9_])_([^_\n]+)_(?![a-zA-Z0-9_])", r"<i>\1</i>", text)

    # 13. Links: [label](url) - unescape &amp; in URL href for Telegram
    text = re.sub(
        r"\[([^\]]+)\]\((https?://[^\s\)]+)\)",
        lambda m: f'<a href="{m.group(2).replace("&amp;", "&")}">{m.group(1)}</a>',
        text
    )

    # 14. Restore Blockquotes with formatted inner text
    for idx, bq_text in enumerate(bqs):
        escaped_bq = html.escape(bq_text)
        # Format bold, italic, code inside blockquote
        escaped_bq = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped_bq)
        escaped_bq = re.sub(r"(?<!\*)\*([^\*\n]+)\*(?!\*)", r"<i>\1</i>", escaped_bq)
        escaped_bq = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", escaped_bq)
        text = text.replace(f"###BQ{idx}###", f"<blockquote>{escaped_bq}</blockquote>")

    # 15. Restore inline codes & code blocks
    for idx, tag in enumerate(inline_codes):
        text = text.replace(f"###IC{idx}###", tag)

    for idx, tag in enumerate(code_blocks):
        text = text.replace(f"###CB{idx}###", tag)

    # 16. Sanitize and balance all tags for 100% Telegram compliance
    return sanitize_telegram_html(text)


def split_message(text: str, max_len: int = 3900) -> List[str]:
    """
    Splits long text into Telegram-compliant chunks under max_len.
    HTML-aware: automatically closes open tags at chunk end and reopens them in the next chunk,
    preventing any Telegram 'tag not closed' parsing exceptions.
    """
    if len(text) <= max_len:
        return [balance_html_tags(text)]

    chunks = []
    current_text = text
    while current_text:
        if len(current_text) <= max_len:
            chunks.append(balance_html_tags(current_text))
            break

        # Find best split boundary (double newline, single newline, or space)
        split_idx = current_text.rfind("\n\n", 0, max_len)
        if split_idx == -1:
            split_idx = current_text.rfind("\n", 0, max_len)
        if split_idx == -1:
            split_idx = current_text.rfind(" ", 0, max_len)
        if split_idx == -1:
            split_idx = max_len

        chunk = current_text[:split_idx].strip()
        remaining = current_text[split_idx:].strip()

        # Track which tags are currently open in this chunk
        tag_regex = re.compile(r"</?([a-zA-Z0-9_-]+)(?:\s+[^>]*)?>")
        open_tags = []
        for match in tag_regex.finditer(chunk):
            full_tag = match.group(0)
            tag_name = match.group(1).lower()
            if full_tag.startswith("</"):
                if open_tags and open_tags[-1] == tag_name:
                    open_tags.pop()
            elif not full_tag.endswith("/>"):
                open_tags.append(tag_name)

        # Close any open tags in this chunk
        for tag in reversed(open_tags):
            chunk += f"</{tag}>"

        chunks.append(chunk)

        # Reopen those tags at the start of the next chunk
        if open_tags and remaining:
            reopened = "".join(f"<{tag}>" for tag in open_tags)
            remaining = reopened + remaining

        current_text = remaining

    return [c for c in chunks if c]
