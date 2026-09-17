"""
File Tool for Prometheus (Hermes Telegram Agent).
Empowers the bot to:
1. Read, parse, and extract text from diverse document formats:
   - PDF (.pdf) via pypdf
   - Microsoft Word (.docx) via python-docx
   - Microsoft Excel (.xlsx, .xls) via openpyxl
   - Comma-Separated Values (.csv)
   - Code & Text (.py, .js, .ts, .html, .css, .json, .txt, .md, .sh, .sql, .xml, .yaml, etc.)
   - Archives (.zip)
2. Generate and export documents dynamically:
   - Python & code scripts (.py, .js, .html, .sh, .json, etc.)
   - Plain text & Markdown (.txt, .md)
   - PDF documents (.pdf) via reportlab
   - Microsoft Word documents (.docx) via python-docx
   - Microsoft Excel spreadsheets (.xlsx) via openpyxl
   - CSV spreadsheets (.csv)
3. Detect user file creation and conversion intents.
"""

import io
import os
import re
import csv
import json
import html
import zipfile
import logging
from typing import Optional, Tuple, Dict, Any, Union, List

logger = logging.getLogger("HermesTelegramAgent.FileTool")

# Common code & text extensions
TEXT_CODE_EXTENSIONS = {
    "txt", "md", "markdown", "py", "pyw", "js", "mjs", "ts", "jsx", "tsx",
    "html", "htm", "css", "scss", "sass", "json", "jsonl", "csv", "tsv",
    "xml", "yaml", "yml", "sql", "sh", "bash", "zsh", "env", "ini", "cfg",
    "conf", "log", "c", "cpp", "h", "hpp", "java", "go", "rs", "php", "rb",
    "pl", "r", "swift", "kt", "lua", "dart", "dockerfile", "makefile", "tex"
}

# Executable / script extensions requiring security alertness
EXECUTABLE_EXTENSIONS = {
    "exe", "dll", "so", "dylib", "apk", "bat", "cmd", "vbs", "vbe", "js",
    "jse", "wsf", "wsh", "ps1", "psm1", "msi", "msp", "com", "scr", "hta",
    "cpl", "jar", "bin", "elf", "iso", "img"
}


# =========================================================================
# 1. File Reading & Parsing Engine
# =========================================================================

def extract_file_content(
    file_bytes: bytes,
    file_name: str,
    mime_type: Optional[str] = None,
    max_chars: int = 45000
) -> Dict[str, Any]:
    """
    Parses and extracts structured content from file bytes based on extension and mime-type.
    Returns:
      {
        "success": bool,
        "file_name": str,
        "file_type": str,
        "size_bytes": int,
        "content": str,
        "preview": str,
        "page_count": Optional[int],
        "line_count": Optional[int],
        "is_executable_or_script": bool,
        "error": Optional[str]
      }
    """
    size_bytes = len(file_bytes)
    ext = (file_name.rsplit(".", 1)[-1].lower() if "." in file_name else "").strip()
    is_exec = ext in EXECUTABLE_EXTENSIONS

    res: Dict[str, Any] = {
        "success": False,
        "file_name": file_name,
        "file_type": ext.upper() or "UNKNOWN",
        "size_bytes": size_bytes,
        "content": "",
        "preview": "",
        "page_count": None,
        "line_count": None,
        "is_executable_or_script": is_exec,
        "error": None
    }

    if not file_bytes:
        res["error"] = "فایل ارسال‌شده خالی است (حجم صفر بایت)."
        return res

    # 1. PDF Document
    if ext == "pdf" or (mime_type and "pdf" in mime_type.lower()):
        res["file_type"] = "PDF"
        try:
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            num_pages = len(reader.pages)
            res["page_count"] = num_pages
            text_parts = []
            for i, page in enumerate(reader.pages):
                page_str = (page.extract_text() or "").strip()
                if page_str:
                    text_parts.append(f"📄 [صفحه {i+1}]:\n{page_str}")
                if sum(len(p) for p in text_parts) > max_chars:
                    text_parts.append(f"\n⚠️ [ادامه محتوا به دلیل حجم بالا ({num_pages} صفحه) خلاصه شد]")
                    break

            raw_text = "\n\n".join(text_parts).strip()
            if not raw_text:
                res["content"] = "⚠️ سند PDF شامل متن قابل استخراج نیست (احتمالاً تصویر اسکن‌شده است)."
                res["preview"] = res["content"]
            else:
                res["content"] = raw_text[:max_chars]
                res["preview"] = raw_text[:1200]
            res["success"] = True
            return res
        except Exception as e:
            logger.warning(f"Error parsing PDF '{file_name}': {e}")
            res["error"] = f"خطا در خواندن فایل PDF: {e}"
            return res

    # 2. Word Document (.docx)
    if ext == "docx" or (mime_type and "wordprocessingml" in mime_type.lower()):
        res["file_type"] = "DOCX"
        try:
            import docx
            doc = docx.Document(io.BytesIO(file_bytes))
            lines: List[str] = []
            for p in doc.paragraphs:
                p_txt = p.text.strip()
                if p_txt:
                    lines.append(p_txt)

            # Also extract tables
            for t_idx, table in enumerate(doc.tables):
                t_lines = [f"\n📊 [جدول {t_idx + 1}]:"]
                for row in table.rows:
                    cells = [c.text.strip() for c in row.cells if c.text.strip()]
                    if cells:
                        t_lines.append(" | ".join(cells))
                if len(t_lines) > 1:
                    lines.append("\n".join(t_lines))

            raw_text = "\n\n".join(lines).strip()
            res["content"] = raw_text[:max_chars]
            res["preview"] = raw_text[:1200]
            res["line_count"] = len(lines)
            res["success"] = True
            return res
        except Exception as e:
            logger.warning(f"Error parsing DOCX '{file_name}': {e}")
            res["error"] = f"خطا در خواندن فایل Word: {e}"
            return res

    # 3. Excel Spreadsheet (.xlsx, .xls)
    if ext in ("xlsx", "xls") or (mime_type and "spreadsheetml" in mime_type.lower()):
        res["file_type"] = "EXCEL"
        try:
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True)
            sheet_blocks: List[str] = []
            for sheet_name in wb.sheetnames[:5]:  # limit to first 5 sheets
                sheet = wb[sheet_name]
                rows_accum: List[str] = []
                for row in sheet.iter_rows(values_only=True):
                    r_str = " | ".join(str(val) for val in row if val is not None)
                    if r_str.strip():
                        rows_accum.append(r_str)
                    if len(rows_accum) >= 120:
                        rows_accum.append("... [سایر ردیف‌ها به دلیل حجم بالا نمایش داده نشدند]")
                        break
                if rows_accum:
                    sheet_blocks.append(f"📊 [شیت: {sheet_name} ({len(rows_accum)} ردیف)]:\n" + "\n".join(rows_accum))

            raw_text = "\n\n".join(sheet_blocks).strip()
            res["content"] = raw_text[:max_chars]
            res["preview"] = raw_text[:1200]
            res["success"] = True
            return res
        except Exception as e:
            logger.warning(f"Error parsing Excel '{file_name}': {e}")
            res["error"] = f"خطا در خواندن فایل اکسل: {e}"
            return res

    # 4. CSV Document (.csv)
    if ext == "csv" or (mime_type and "csv" in mime_type.lower()):
        res["file_type"] = "CSV"
        try:
            decoded = None
            for enc in ("utf-8", "utf-8-sig", "cp1256", "latin-1"):
                try:
                    decoded = file_bytes.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            if decoded is None:
                decoded = file_bytes.decode("utf-8", errors="replace")

            csv_lines = [l.strip() for l in decoded.splitlines() if l.strip()]
            res["line_count"] = len(csv_lines)
            res["content"] = decoded[:max_chars]
            res["preview"] = "\n".join(csv_lines[:25])
            res["success"] = True
            return res
        except Exception as e:
            res["error"] = f"خطا در خواندن فایل CSV: {e}"
            return res

    # 5. ZIP Archive (.zip)
    if ext == "zip" or (mime_type and "zip" in mime_type.lower()):
        res["file_type"] = "ZIP"
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                info_list = z.infolist()
                # Zip Bomb Guard: Limit file count and uncompressed ratio
                if len(info_list) > 1000:
                    res["error"] = "خطای امنیتی: تعداد فایل‌های درون آرشیو ZIP بیش از حد مجاز است (حداکثر ۱۰۰۰ فایل)."
                    return res
                total_uncompressed = sum(item.file_size for item in info_list)
                if total_uncompressed > 50 * 1024 * 1024:
                    res["error"] = "خطای امنیتی: حجم فایل‌های فشرده درون آرشیو ZIP از سقف ۵۰ مگابایت فراتر است (حفاظت در برابر Zip Bomb)."
                    return res

                report_lines = [f"📦 فهرست محتویات آرشیو ZIP ({len(info_list)} فایل):"]
                for item in info_list[:40]:
                    size_kb = item.file_size / 1024
                    # Sanitize filename in report
                    safe_name = html.escape(os.path.basename(item.filename) or item.filename)
                    report_lines.append(f"• <code>{safe_name}</code> ({size_kb:.1f} KB)")
                if len(info_list) > 40:
                    report_lines.append(f"• ... و {len(info_list) - 40} فایل دیگر")
                raw_text = "\n".join(report_lines)
                res["content"] = raw_text
                res["preview"] = raw_text
                res["success"] = True
                return res
        except Exception as e:
            res["error"] = f"خطا در بازگشایی آرشیو ZIP: {e}"
            return res

    # 6. Text & Code Files (Default for all text/code types)
    if ext in TEXT_CODE_EXTENSIONS or (mime_type and any(t in mime_type.lower() for t in ("text", "json", "xml", "javascript", "python"))):
        res["file_type"] = ext.upper() if ext else "TEXT"
        decoded = None
        for enc in ("utf-8", "utf-8-sig", "cp1256", "latin-1"):
            try:
                decoded = file_bytes.decode(enc)
                break
            except UnicodeDecodeError:
                continue

        if decoded is None:
            decoded = file_bytes.decode("utf-8", errors="replace")

        lines = decoded.splitlines()
        res["line_count"] = len(lines)
        res["content"] = decoded[:max_chars]
        res["preview"] = "\n".join(lines[:35])
        res["success"] = True
        return res

    # 7. Fallback: Try decoding as UTF-8 text; if binary, report metadata
    try:
        decoded = file_bytes.decode("utf-8")
        lines = decoded.splitlines()
        res["line_count"] = len(lines)
        res["content"] = decoded[:max_chars]
        res["preview"] = "\n".join(lines[:30])
        res["file_type"] = "TEXT"
        res["success"] = True
        return res
    except UnicodeDecodeError:
        res["file_type"] = "BINARY"
        res["content"] = f"⚠️ فایل «{file_name}» باینری ({res['file_type']}) است و متن خام مستقیم ندارد."
        res["preview"] = res["content"]
        res["success"] = True
        return res


# =========================================================================
# 2. File Generation & Creation Engine
# =========================================================================

def create_document_file(
    filename: str,
    content: Union[str, bytes],
    file_type: Optional[str] = None
) -> Tuple[io.BytesIO, str]:
    """
    Generates and formats an in-memory document file ready for Telegram upload.
    Supports .py, .txt, .json, .csv, .html, .md, .docx, .xlsx, .pdf, etc.
    Returns: (BytesIO_buffer, final_filename)
    """
    # Clean and sanitize filename to prevent path traversal
    clean_name = os.path.basename(filename.strip()).replace("/", "_").replace("\\", "_").replace("\x00", "").strip(" .")
    fname = clean_name if clean_name else "document.txt"

    ext = (fname.rsplit(".", 1)[-1].lower() if "." in fname else "").strip()
    if not ext:
        target_ext = (file_type or "txt").lower().strip(".")
        fname = f"{fname}.{target_ext}"
        ext = target_ext

    text_content = content if isinstance(content, str) else content.decode("utf-8", errors="replace")

    # 1. PDF Generation via ReportLab
    if ext == "pdf":
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            buf = io.BytesIO()
            c = canvas.Canvas(buf, pagesize=letter)
            width, height = letter
            c.setTitle(fname)

            # Write text lines with auto-wrapping
            y = height - 50
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y, f"Prometheus Document: {fname}")
            y -= 30
            c.setFont("Helvetica", 10)

            for raw_line in text_content.splitlines():
                # Simple line chunking
                chunks = [raw_line[i:i+85] for i in range(0, max(1, len(raw_line)), 85)] or [""]
                for chunk in chunks:
                    if y < 50:
                        c.showPage()
                        c.setFont("Helvetica", 10)
                        y = height - 50
                    c.drawString(50, y, chunk)
                    y -= 14

            c.save()
            buf.seek(0)
            return buf, fname
        except Exception as e:
            logger.warning(f"Failed to generate PDF via ReportLab: {e}; falling back to raw text.")

    # 2. Word (.docx) Generation
    if ext == "docx":
        try:
            import docx
            doc = docx.Document()
            doc.add_heading(fname, level=1)
            for block in text_content.split("\n\n"):
                b_str = block.strip()
                if b_str:
                    doc.add_paragraph(b_str)
            buf = io.BytesIO()
            doc.save(buf)
            buf.seek(0)
            return buf, fname
        except Exception as e:
            logger.warning(f"Failed to generate DOCX: {e}; falling back to raw text.")

    # 3. Excel (.xlsx) Generation
    if ext in ("xlsx", "xls"):
        try:
            import openpyxl
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Data"
            # Try CSV or line-based table parsing
            for r_idx, line in enumerate(text_content.splitlines(), start=1):
                if "|" in line:
                    parts = [p.strip() for p in line.split("|")]
                elif "," in line:
                    parts = [p.strip() for p in line.split(",")]
                elif "\t" in line:
                    parts = [p.strip() for p in line.split("\t")]
                else:
                    parts = [line]
                for c_idx, val in enumerate(parts, start=1):
                    ws.cell(row=r_idx, column=c_idx, value=val)

            buf = io.BytesIO()
            wb.save(buf)
            buf.seek(0)
            return buf, fname
        except Exception as e:
            logger.warning(f"Failed to generate XLSX: {e}; falling back to raw text.")

    # 4. Standard UTF-8 Text / Code files (.py, .txt, .json, .csv, .html, .md, .sh, etc.)
    if isinstance(content, bytes):
        raw_bytes = content
    else:
        raw_bytes = content.encode("utf-8")

    buf = io.BytesIO(raw_bytes)
    buf.seek(0)
    return buf, fname


# =========================================================================
# 3. File Request & Extraction Detectors
# =========================================================================

_FILE_CREATE_PATTERNS = [
    r"^(?:/)?(?:p_|pro_|p|pro)?(?:file|createfile|makefile|make_file|create_file|savefile|save_file)(?:\s+(.*))?$",
    r"(?:یک\s+)?فایل\s+([a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9]+)\s+(?:بساز|ایجاد\s+کن|آماده\s+کن|بفرست)",
    r"(?:به\s+صورت|در\s+قالب|توی)\s+فایل\s+([a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9]+)\s*(?:بده|بفرست|دانلود|ارسال\s+کن)",
    r"(?:این\s+رو|متن\s+رو|کد\s+رو)?\s*فایلش\s+کن",
    r"به\s+صورت\s+فایل\s*(?:پایتون|متنی|اکسل|ورد|پی\s*دی\s*اف|pdf|docx|xlsx|py|txt)\s*(?:بفرست|ارسال\s+کن|بده)"
]


def detect_file_creation_intent(text: str, reply_text: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """
    Detects if the user is asking to generate and receive a downloadable file.
    Returns: (filename, content) if matched, else None.
    """
    t = (text or "").strip()
    if not t and not reply_text:
        return None

    # Check direct command: /file [filename] [content]
    cmd_m = re.match(r"^(?:/)?(?:p_|pro_|p|pro)?(?:file|createfile|makefile|make_file|create_file|savefile)(?:\s+([a-zA-Z0-9_\-\.]+))?(?:\s+([\s\S]+))?$", t, re.IGNORECASE)
    if cmd_m:
        fn = cmd_m.group(1) or "document.txt"
        cnt = cmd_m.group(2) or ""
        if not cnt and reply_text:
            cnt = reply_text
        if cnt:
            return fn, cnt

    # Check Persian phrases like: "یک فایل پایتون به نام bot.py بساز" or "این رو فایل کن به نام script.py"
    named_m = re.search(r"(?:به\s+نام|با\s+نام|نام\s+فایل|فایل)\s+([a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+)", t, re.IGNORECASE)
    if named_m:
        fn = named_m.group(1)
        cnt = reply_text or ""
        if not cnt:
            # Check if there is code inside markdown code block in text
            code_blocks = re.findall(r"```(?:[a-zA-Z0-9_+\-]+)?\n([\s\S]*?)```", t)
            if code_blocks:
                cnt = code_blocks[0].strip()
        if cnt:
            return fn, cnt

    # Check reply conversion request: "فایلش کن" or "به صورت فایل پایتون بفرست" or "فایل پایتونش کن"
    if reply_text:
        t_low = t.lower()
        is_conv = (
            any(p in t_low for p in ("فایلش کن", "فایل کن", "به صورت فایل", "توی فایل", "دانلود فایل"))
            or ("فایل" in t_low and any(c in t_low for c in ("کن", "بساز", "بفرست", "بده", "ارسال")))
        )
        if is_conv:
            # Deduce extension
            ext = "txt"
            if any(k in t_low for k in ("پایتون", "python", "py")):
                ext = "py"
            elif any(k in t_low for k in ("اکسل", "excel", "xlsx")):
                ext = "xlsx"
            elif any(k in t_low for k in ("ورد", "word", "docx")):
                ext = "docx"
            elif any(k in t_low for k in ("پی دی اف", "پی‌دی‌اف", "pdf")):
                ext = "pdf"
            elif any(k in t_low for k in ("جیسون", "json")):
                ext = "json"
            elif any(k in t_low for k in ("سی اس وی", "csv")):
                ext = "csv"
            elif any(k in t_low for k in ("اچ تی ام ال", "html")):
                ext = "html"
            elif any(k in t_low for k in ("جاوااسکریپت", "javascript", "js")):
                ext = "js"

            # Extract code block from reply if present
            code_blocks = re.findall(r"```(?:[a-zA-Z0-9_+\-]+)?\n([\s\S]*?)```", reply_text)
            cnt = code_blocks[0].strip() if code_blocks else reply_text.strip()
            fn = f"exported_file.{ext}"
            return fn, cnt

    return None
