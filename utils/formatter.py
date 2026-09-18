"""
Telegram HTML formatter and markdown conversion utilities.
Engineered specifically for Telegram's native formatting constraints.
"""

import re
import html
import unicodedata
from typing import List, Set, Optional, Tuple

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


def get_char_width(char: str) -> int:
    """Returns visual display width of a single character in monospaced terminal/chat."""
    cat = unicodedata.category(char)
    # Zero-width: nonspacing marks, enclosing marks, format chars (ZWNJ \u200c, LRM \u200e, etc.)
    if cat in ("Mn", "Me", "Cf"):
        return 0
    ea = unicodedata.east_asian_width(char)
    if ea in ("W", "F"):
        return 2
    return 1


def get_display_width(s: str) -> int:
    """Calculates visual display width considering Unicode categories, ZWNJ, and wide chars/emojis."""
    if not s:
        return 0
    return sum(get_char_width(c) for c in s)


def _clean_cell_text(cell: str) -> str:
    """Strips markdown bold, italic, inline code, strike, link syntax, and raw HTML from table cells."""
    s = cell.strip()
    s = re.sub(r"<\s*br\s*/?>", " ", s, flags=re.IGNORECASE)
    s = re.sub(r"<[^>]+>", "", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"\1", s)
    s = re.sub(r"__([^_]+)__", r"\1", s)
    s = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"\1", s)
    s = re.sub(r"`([^`]+)`", r"\1", s)
    s = re.sub(r"~~([^~]+)~~", r"\1", s)
    s = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", s)
    return s.strip()


def format_table_as_cards(rows: List[List[str]]) -> str:
    """
    Renders wide or multi-column tables into beautiful, mobile-friendly Telegram cards.
    Each row becomes a clean visual card with bold item header and bulleted attributes.
    Prevents horizontal scrolling and border corruption on mobile devices.
    """
    if not rows or len(rows) < 2:
        return ""

    headers = rows[0]
    data_rows = rows[1:]
    cards = []

    for r in data_rows:
        if not any(c.strip() for c in r):
            continue
        first_cell = r[0].strip() if r else ""
        card_lines = []
        if first_cell:
            card_lines.append(f"🔹 **{first_cell}**")
        for idx in range(1, len(r)):
            hdr = headers[idx].strip() if idx < len(headers) else f"ویژگی {idx+1}"
            val = r[idx].strip()
            if val:
                card_lines.append(f"▫️ **{hdr}:** {val}")
        if card_lines:
            cards.append("\n".join(card_lines))

    return "\n\n".join(cards)


def pad_display_cell(text: str, target_width: int, align: str = "center") -> str:
    """Pads a cell string with spaces to achieve target visual display width."""
    cur_w = get_display_width(text)
    pad = max(0, target_width - cur_w)
    if align == "left":
        left = 1 if pad >= 2 else 0
        right = pad - left
        return (" " * left) + text + (" " * right)
    elif align == "right":
        right = 1 if pad >= 2 else 0
        left = pad - right
        return (" " * left) + text + (" " * right)
    else:  # center
        left = pad // 2
        right = pad - left
        return (" " * left) + text + (" " * right)


def format_table_as_box(
    rows: List[List[str]],
    alignments: Optional[List[str]] = None,
    min_padding: int = 2
) -> str:
    """
    Renders a 2D array of string cells into a perfectly aligned Unicode box table
    with Left-to-Right marks (\u200e) on each line to ensure consistent LTR column
    layout across all Telegram clients (preventing RTL column scrambling).
    """
    if not rows or len(rows) < 2:
        return ""

    num_cols = max(len(r) for r in rows)
    norm_rows = []
    for r in rows:
        r_copy = [_clean_cell_text(c) for c in r]
        while len(r_copy) < num_cols:
            r_copy.append("")
        norm_rows.append(r_copy)

    col_widths = [0] * num_cols
    for r in norm_rows:
        for i, cell in enumerate(r):
            col_widths[i] = max(col_widths[i], get_display_width(cell) + min_padding)

    col_widths = [max(w, 4) for w in col_widths]

    if not alignments:
        alignments = ["center"] * num_cols
    while len(alignments) < num_cols:
        alignments.append("center")

    lrm = "\u200e"
    top = lrm + "┌" + "┬".join("─" * w for w in col_widths) + "┐"
    mid = lrm + "├" + "┼".join("─" * w for w in col_widths) + "┤"
    bot = lrm + "└" + "┴".join("─" * w for w in col_widths) + "┘"

    out = [top]
    # Header row (always centered for clean aesthetics)
    header_cells = [pad_display_cell(c, col_widths[i], align="center") for i, c in enumerate(norm_rows[0])]
    out.append(lrm + "│" + "│".join(header_cells) + "│")
    out.append(mid)

    # Data rows
    for r in norm_rows[1:]:
        row_cells = [pad_display_cell(c, col_widths[i], align=alignments[i]) for i, c in enumerate(r)]
        out.append(lrm + "│" + "│".join(row_cells) + "│")

    out.append(bot)
    return "\n".join(out)


TABLE_REGEX = re.compile(
    r"((?:^[ \t]*(?:>[ \t]*)?\|?[^\n|]+\|[^\n]+\|?[ \t]*\n)"
    r"(?:^[ \t]*(?:>[ \t]*)?\|?(?:[ \t]*:?-+:?[ \t]*\|)+[ \t]*:?-+:?[ \t]*\|?[ \t]*\n)"
    r"(?:^[ \t]*(?:>[ \t]*)?\|?[^\n|]+\|[^\n]+\|?[ \t]*(?:\n|$))+)",
    re.MULTILINE
)


def _split_table_row(line: str) -> List[str]:
    clean = line.strip()
    if clean.startswith(">"):
        clean = clean[1:].strip()
    if clean.startswith("|") and clean.endswith("|"):
        clean = clean[1:-1]
    elif clean.startswith("|"):
        clean = clean[1:]
    elif clean.endswith("|"):
        clean = clean[:-1]
    return [c.strip() for c in clean.split("|")]


def _detect_alignments(separator_line: str, num_cols: int) -> List[str]:
    clean = separator_line.strip()
    if clean.startswith(">"):
        clean = clean[1:].strip()
    if clean.startswith("|") and clean.endswith("|"):
        clean = clean[1:-1]
    elif clean.startswith("|"):
        clean = clean[1:]
    elif clean.endswith("|"):
        clean = clean[:-1]
    parts = [p.strip() for p in clean.split("|")]
    alignments = []
    for p in parts:
        if p.startswith(":") and p.endswith(":"):
            alignments.append("center")
        elif p.endswith(":"):
            alignments.append("right")
        elif p.startswith(":"):
            alignments.append("left")
        else:
            alignments.append("center")
    while len(alignments) < num_cols:
        alignments.append("center")
    return alignments[:num_cols]


def convert_markdown_tables_to_box(text: str) -> str:
    """
    Detects Markdown pipe tables (with or without outer boundary pipes) and converts them
    into mathematically aligned Unicode box-drawing tables enclosed in monospace blocks (for compact tables),
    or into clean, mobile-responsive visual cards (for wide tables).
    Respects existing code blocks to avoid broken nested backticks.
    """
    if not text or "|" not in text:
        return text

    def _replace_table(match):
        raw_table = match.group(1)
        lines = [l.strip() for l in raw_table.strip().split("\n") if l.strip()]
        if len(lines) < 2:
            return raw_table

        header_line = lines[0]
        sep_line = lines[1]
        data_lines = lines[2:]

        header_cells = [_clean_cell_text(c) for c in _split_table_row(header_line)]
        alignments = _detect_alignments(sep_line, len(header_cells))

        rows = [header_cells]
        for dl in data_lines:
            cells = [_clean_cell_text(c) for c in _split_table_row(dl)]
            if all(set(c).issubset({"-", ":", " "}) for c in cells):
                continue
            rows.append(cells)

        if len(rows) < 2:
            return raw_table

        # Normalize column counts across all rows
        num_cols = max(len(r) for r in rows)
        for r in rows:
            while len(r) < num_cols:
                r.append("")

        is_inside_code = (text[:match.start()].count("```") % 2 == 1)

        # Check if table exceeds typical mobile screen limits (~36-40 chars monospace)
        col_w = [max(get_display_width(r[i]) for r in rows) for i in range(num_cols)]
        total_w = sum(col_w) + (num_cols * 3) + 1
        is_wide = (num_cols > 3) or (total_w > 42) or any(len(c) > 22 for r in rows for c in r)

        if is_wide and not is_inside_code:
            cards = format_table_as_cards(rows)
            if cards:
                return f"\n{cards}\n"

        box_table = format_table_as_box(rows, alignments)
        if not box_table:
            return raw_table

        if is_inside_code:
            return box_table + "\n"
        return f"\n```\n{box_table}\n```\n"

    return TABLE_REGEX.sub(_replace_table, text)


HTML_TABLE_REGEX = re.compile(r"<table[^>]*>([\s\S]*?)</table>", re.IGNORECASE)


def convert_html_tables_to_box(text: str) -> str:
    """
    Detects raw HTML <table>...</table> elements and converts them into
    aligned Telegram-compatible Unicode box tables inside monospace blocks.
    """
    if not text or "<table" not in text.lower():
        return text

    def _replace_html_table(match):
        content = match.group(1)
        row_pattern = re.compile(r"<tr[^>]*>([\s\S]*?)</tr>", re.IGNORECASE)
        cell_pattern = re.compile(r"<(?:th|td)[^>]*>([\s\S]*?)</(?:th|td)>", re.IGNORECASE)

        rows = []
        for tr in row_pattern.finditer(content):
            tr_content = tr.group(1)
            cells = []
            for cell in cell_pattern.finditer(tr_content):
                raw_cell = cell.group(1)
                clean_cell = re.sub(r"<[^>]+>", "", raw_cell)
                clean_cell = html.unescape(clean_cell).strip()
                cells.append(_clean_cell_text(clean_cell))
            if cells:
                rows.append(cells)

        if len(rows) < 2:
            return match.group(0)

        num_cols = max(len(r) for r in rows)
        for r in rows:
            while len(r) < num_cols:
                r.append("")

        is_inside_code = (text[:match.start()].count("```") % 2 == 1)

        col_w = [max(get_display_width(r[i]) for r in rows) for i in range(num_cols)]
        total_w = sum(col_w) + (num_cols * 3) + 1
        is_wide = (num_cols > 3) or (total_w > 42) or any(len(c) > 22 for r in rows for c in r)

        if is_wide and not is_inside_code:
            cards = format_table_as_cards(rows)
            if cards:
                return f"\n{cards}\n"

        box_table = format_table_as_box(rows)
        if not box_table:
            return match.group(0)

        if is_inside_code:
            return box_table + "\n"
        return f"\n```\n{box_table}\n```\n"

    return HTML_TABLE_REGEX.sub(_replace_html_table, text)


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
    - Tables -> Monospaced box tables (Markdown & HTML)
    - Full tag balancing & sanitization
    """
    if not text:
        return ""

    text = strip_thinking(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # 1. Convert raw HTML tables to aligned Unicode box tables
    text = convert_html_tables_to_box(text)

    # 2. Convert raw markdown tables to aligned Unicode box tables
    text = convert_markdown_tables_to_box(text)

    # 3. Protect code blocks (```code```)
    code_blocks = []
    def _save_code_block(match):
        lang = (match.group(1) or "").strip()
        code = match.group(2)
        escaped_code = html.escape(code)
        if "┌" in code and "└" in code:
            tag = f'<pre>{escaped_code}</pre>'
        elif lang:
            tag = f'<pre><code class="language-{html.escape(lang)}">{escaped_code}</code></pre>'
        else:
            tag = f'<pre>{escaped_code}</pre>'
        code_blocks.append(tag)
        return f"###CB{len(code_blocks)-1}###"

    text = re.sub(r"```([a-zA-Z0-9_\-+]*)\n?([\s\S]*?)```", _save_code_block, text)

    # 4. Protect inline code (`code`)
    inline_codes = []
    def _save_inline_code(match):
        code = match.group(1)
        tag = f"<code>{html.escape(code)}</code>"
        inline_codes.append(tag)
        return f"###IC{len(inline_codes)-1}###"

    text = re.sub(r"`([^`\n]+)`", _save_inline_code, text)

    # 5. Protect raw HTML blockquotes (<blockquote ...>...</blockquote>) preserving tags while allowing inner markdown formatting
    raw_bqs = []
    def _save_raw_bq(match):
        open_tag = match.group(1)
        inner_body = match.group(2)
        idx = len(raw_bqs)
        raw_bqs.append(open_tag)
        return f"###RBQ_OPEN_{idx}###\n{inner_body}\n###RBQ_CLOSE_{idx}###"

    text = re.sub(r"(<blockquote(?:\s+[^>]*)?>)([\s\S]*?)(</blockquote>)", _save_raw_bq, text, flags=re.IGNORECASE)

    # 4. Protect Blockquotes (> text, >! text for expandable, >> text)
    bqs = []
    def _save_blockquote(match):
        raw_lines = match.group(0).strip().split("\n")
        is_expandable = False
        inner_lines = []
        for l in raw_lines:
            cleaned_l = re.sub(r"^\s*>\s?", "", l)
            if cleaned_l.startswith("!") or cleaned_l.startswith(">"):
                is_expandable = True
                cleaned_l = cleaned_l[1:].strip()
            elif "[expandable]" in cleaned_l.lower():
                is_expandable = True
                cleaned_l = re.sub(r"\[expandable\]", "", cleaned_l, flags=re.IGNORECASE).strip()
            inner_lines.append(cleaned_l)
        inner_content = "\n".join(inner_lines).strip()
        bqs.append((inner_content, is_expandable))
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

    # 14. Restore Blockquotes with formatted inner text (including expandable blockquotes)
    for idx, (bq_text, is_expandable) in enumerate(bqs):
        escaped_bq = html.escape(bq_text)
        # Format bold, italic, code inside blockquote
        escaped_bq = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped_bq)
        escaped_bq = re.sub(r"(?<!\*)\*([^\*\n]+)\*(?!\*)", r"<i>\1</i>", escaped_bq)
        escaped_bq = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", escaped_bq)
        tag_open = "<blockquote expandable>" if is_expandable else "<blockquote>"
        text = text.replace(f"###BQ{idx}###", f"{tag_open}{escaped_bq}</blockquote>")

    # 14.5 Restore raw HTML blockquotes
    for idx, open_tag in enumerate(raw_bqs):
        text = text.replace(f"###RBQ_OPEN_{idx}###", open_tag)
        text = text.replace(f"###RBQ_CLOSE_{idx}###", "</blockquote>")

    # 15. Restore inline codes & code blocks
    for idx, tag in enumerate(inline_codes):
        text = text.replace(f"###IC{idx}###", tag)

    for idx, tag in enumerate(code_blocks):
        text = text.replace(f"###CB{idx}###", tag)

    # 16. Sanitize and balance all tags for 100% Telegram compliance
    return sanitize_telegram_html(text)


def wrap_in_expandable_blockquote(text: str) -> str:
    """Wraps text in a Telegram-native expandable blockquote container."""
    if not text or not text.strip():
        return ""
    return f"<blockquote expandable>\n{text.strip()}\n</blockquote>"


def apply_expandable_containers(text: str, char_threshold: int = 550) -> str:
    """
    Telegram Collapsible Container (کانتینر بازشونده تلگرام):
    If text length exceeds char_threshold, wraps the detailed body in <blockquote expandable>,
    keeping the opening summary or headline visible outside for instant comprehension.
    """
    if not text or len(text) < char_threshold:
        return text

    # If the text already has a blockquote, leave it as is
    if "<blockquote" in text.lower():
        return text

    # First attempt: break at first double newline (intro headline + body)
    parts = text.split("\n\n", 1)
    if len(parts) == 2 and len(parts[0]) <= 250:
        intro = parts[0].strip()
        body = parts[1].strip()
        return f"{intro}\n\n<blockquote expandable>\n{body}\n</blockquote>"

    # Second attempt: break at newline after line 1 or 2
    lines = text.split("\n")
    if len(lines) >= 4:
        intro = "\n".join(lines[:2]).strip()
        body = "\n".join(lines[2:]).strip()
        return f"{intro}\n\n<blockquote expandable>\n{body}\n</blockquote>"

    return f"<blockquote expandable>\n{text.strip()}\n</blockquote>"



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
