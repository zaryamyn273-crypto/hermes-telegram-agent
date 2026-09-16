"""
Telegram HTML formatter and markdown conversion utilities.
"""

import re
import html
from typing import List


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
    Converts standard Markdown to Telegram-compatible HTML.
    Safely escapes raw HTML characters, preserving formatting.
    """
    if not text:
        return ""

    text = strip_thinking(text)

    # Convert raw markdown tables to aligned Unicode box tables
    text = convert_markdown_tables_to_box(text)

    # 1. Protect code blocks (```code```)
    code_blocks = []
    def _save_code_block(match):
        lang = match.group(1) or ""
        code = match.group(2)
        escaped_code = html.escape(code)
        if lang:
            tag = f'<pre><code class="language-{html.escape(lang)}">{escaped_code}</code></pre>'
        else:
            tag = f'<pre>{escaped_code}</pre>'
        code_blocks.append(tag)
        return f"###CB{len(code_blocks)-1}###"

    text = re.sub(r"```([a-zA-Z0-9_\-+]*)\n?([\s\S]*?)```", _save_code_block, text)

    # 2. Protect inline code (`code`)
    inline_codes = []
    def _save_inline_code(match):
        code = match.group(1)
        tag = f"<code>{html.escape(code)}</code>"
        inline_codes.append(tag)
        return f"###IC{len(inline_codes)-1}###"

    text = re.sub(r"`([^`\n]+)`", _save_inline_code, text)

    # 3. Escape all remaining raw HTML characters
    text = html.escape(text)

    # 4. Bold: **text** or *text*
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*([^\*\n]+)\*(?!\*)", r"<b>\1</b>", text)

    # 5. Italic: _text_ (ensure it doesn't match inside tags)
    text = re.sub(r"(?<![a-zA-Z0-9_])_([^_\n]+)_(?![a-zA-Z0-9_])", r"<i>\1</i>", text)

    # 6. Strike: ~~text~~
    text = re.sub(r"~~(.+?)~~", r"<s>\1</s>", text)

    # 7. Links: [label](url)
    text = re.sub(r"\[([^\]]+)\]\((https?://[^\s\)]+)\)", r'<a href="\2">\1</a>', text)

    # 8. Restore inline codes & code blocks
    for idx, tag in enumerate(inline_codes):
        text = text.replace(f"###IC{idx}###", tag)

    for idx, tag in enumerate(code_blocks):
        text = text.replace(f"###CB{idx}###", tag)

    return text


def split_message(text: str, max_len: int = 3900) -> List[str]:
    """Splits long text into Telegram-compliant chunks under max_len."""
    if len(text) <= max_len:
        return [text]

    chunks = []
    while text:
        if len(text) <= max_len:
            chunks.append(text)
            break

        split_idx = text.rfind("\n\n", 0, max_len)
        if split_idx == -1:
            split_idx = text.rfind("\n", 0, max_len)
        if split_idx == -1:
            split_idx = text.rfind(" ", 0, max_len)
        if split_idx == -1:
            split_idx = max_len

        chunks.append(text[:split_idx].strip())
        text = text[split_idx:].strip()

    return [c for c in chunks if c]
