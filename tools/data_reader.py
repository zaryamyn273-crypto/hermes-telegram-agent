"""
Prometheus Data Storage Intelligence Engine (ابزار جامع خواندن، تحلیل و کالبدشکافی انواع فایل‌های ذخیره‌سازی داده)
Deep inspection, schema discovery, statistical analysis, row sampling, and multi-format parsing for:
- Tabular & Analytics: CSV, TSV, Excel (.xlsx, .xls), Parquet
- Semi-structured & Serialization: JSON, JSONL/NDJSON, YAML, XML, TOML
- Databases & Dumps: SQLite (.sqlite, .sqlite3, .db), SQL dumps (.sql)
- System & Timeseries: Log files (.log), Config/Env (.env, .ini, .conf)
- Document Containers: PDF (.pdf), Word (.docx), Archives (.zip, .tar.gz)
"""

import io
import os
import re
import csv
import json
import html
import zipfile
import logging
import asyncio
import tempfile
import sqlite3
from typing import Optional, Dict, Any, List, Union, Tuple

logger = logging.getLogger("PrometheusDataReader")

# Optional 3rd-party libraries
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import tomllib
    HAS_TOMLLIB = True
except ImportError:
    HAS_TOMLLIB = False

try:
    import openpyxl
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

try:
    import docx
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False

import xml.etree.ElementTree as ET


# =========================================================================
# 1. Format Detection
# =========================================================================

def detect_data_format(file_name: str, file_bytes: bytes, mime_type: Optional[str] = None) -> str:
    """
    Identifies the exact data storage format using magic bytes, headers, and extensions.
    """
    f_lower = file_name.lower().strip()
    ext = (f_lower.rsplit(".", 1)[-1] if "." in f_lower else "").strip()
    mime = (mime_type or "").lower().strip()

    # 1. Magic Bytes Checking (Takes priority over extension)
    if file_bytes.startswith(b"SQLite format 3\x00"):
        return "SQLITE"
    if file_bytes.startswith(b"PAR1"):
        return "PARQUET"
    if file_bytes.startswith(b"%PDF"):
        return "PDF"

    # 2. Extension Checking
    if ext in ("sqlite", "sqlite3", "db", "db3", "s3db", "sl3"):
        return "SQLITE"
    if ext in ("csv",):
        return "CSV"
    if ext in ("tsv", "tab"):
        return "TSV"
    if ext in ("xlsx", "xls", "xlsm"):
        return "EXCEL"
    if ext in ("json",):
        return "JSON"
    if ext in ("jsonl", "ndjson"):
        return "JSONL"
    if ext in ("yaml", "yml"):
        return "YAML"
    if ext in ("xml",):
        return "XML"
    if ext in ("toml",):
        return "TOML"
    if ext in ("sql", "dump"):
        return "SQL"
    if ext in ("log",):
        return "LOG"
    if ext in ("docx",):
        return "DOCX"
    if ext in ("zip",):
        return "ZIP"
    if ext in ("parquet",):
        return "PARQUET"

    # 3. MIME Checking
    if "sqlite" in mime:
        return "SQLITE"
    if "spreadsheet" in mime or "excel" in mime:
        return "EXCEL"
    if "csv" in mime:
        return "CSV"
    if "json" in mime:
        return "JSON"
    if "yaml" in mime or "yml" in mime:
        return "YAML"
    if "xml" in mime:
        return "XML"

    # 4. Content Sniffing fallback for text data
    sample_head = file_bytes[:2048].strip()
    if sample_head.startswith(b"{") or sample_head.startswith(b"["):
        try:
            json.loads(sample_head.decode("utf-8", errors="ignore"))
            return "JSON"
        except Exception:
            pass

    return ext.upper() if ext else "TEXT"


# =========================================================================
# 2. Specialized Data Parsers
# =========================================================================

def _decode_text_bytes(file_bytes: bytes) -> str:
    """Tries UTF-8, UTF-8-SIG, CP1256 (Persian/Arabic), and Latin-1."""
    for enc in ("utf-8-sig", "utf-8", "cp1256", "latin-1"):
        try:
            return file_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return file_bytes.decode("utf-8", errors="replace")


def _infer_column_type(values: List[Any]) -> str:
    """Infers predominant data type of a column list."""
    non_nulls = [v for v in values if v is not None and str(v).strip() != ""]
    if not non_nulls:
        return "Empty"

    is_int = True
    is_float = True
    is_bool = True

    for v in non_nulls[:100]:
        s = str(v).strip().lower()
        if s not in ("true", "false", "0", "1", "بله", "خیر"):
            is_bool = False
        try:
            int(s)
        except ValueError:
            is_int = False
        try:
            float(s)
        except ValueError:
            is_float = False

    if is_bool and len(non_nulls) > 2:
        return "Boolean"
    if is_int:
        return "Integer"
    if is_float:
        return "Float"
    return "String / Text"


def _parse_sqlite(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Inspects a SQLite database file safely in read-only mode."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        # 1. Fetch tables and views
        cursor.execute("SELECT type, name, sql FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'")
        entries = cursor.fetchall()

        tables_info = []
        total_rows_all = 0

        for ent_type, name, sql in entries:
            # Columns metadata
            cursor.execute(f"PRAGMA table_info(\"{name}\")")
            cols_pragma = cursor.fetchall()
            cols = [
                {
                    "cid": c[0],
                    "name": c[1],
                    "type": c[2] or "TEXT",
                    "notnull": bool(c[3]),
                    "is_pk": bool(c[5])
                }
                for c in cols_pragma
            ]

            # Count rows safely
            row_count = 0
            try:
                cursor.execute(f"SELECT COUNT(*) FROM \"{name}\"")
                row_count = cursor.fetchone()[0]
                total_rows_all += row_count
            except Exception:
                row_count = 0

            # Sample rows
            sample_rows = []
            try:
                cursor.execute(f"SELECT * FROM \"{name}\" LIMIT 6")
                col_names = [c["name"] for c in cols]
                for r in cursor.fetchall():
                    row_dict = {}
                    for i, val in enumerate(r):
                        col_k = col_names[i] if i < len(col_names) else f"col_{i}"
                        row_dict[col_k] = str(val)[:100] if val is not None else None
                    sample_rows.append(row_dict)
            except Exception:
                pass

            tables_info.append({
                "name": name,
                "type": ent_type,
                "row_count": row_count,
                "column_count": len(cols),
                "columns": cols,
                "sample_rows": sample_rows,
                "sql": sql
            })

        conn.close()

        return {
            "success": True,
            "format": "SQLITE",
            "file_name": file_name,
            "size_bytes": len(file_bytes),
            "table_count": len([t for t in tables_info if t["type"] == "table"]),
            "view_count": len([t for t in tables_info if t["type"] == "view"]),
            "total_records": total_rows_all,
            "tables": tables_info
        }

    except Exception as e:
        logger.error(f"Error parsing SQLite '{file_name}': {e}")
        return {"success": False, "format": "SQLITE", "file_name": file_name, "error": f"خطا در خواندن پایگاه‌داده SQLite: {e}"}
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _parse_csv(file_bytes: bytes, file_name: str, delimiter_hint: Optional[str] = None) -> Dict[str, Any]:
    """Parses and computes statistical analysis on CSV/TSV data."""
    text = _decode_text_bytes(file_bytes)
    lines = [l for l in text.splitlines() if l.strip()]

    if not lines:
        return {"success": False, "format": "CSV", "file_name": file_name, "error": "فایل خالی است."}

    # Delimiter auto-detection
    delim = delimiter_hint
    if not delim:
        if "\t" in lines[0] and lines[0].count("\t") > lines[0].count(","):
            delim = "\t"
        elif ";" in lines[0] and lines[0].count(";") > lines[0].count(","):
            delim = ";"
        elif "|" in lines[0] and lines[0].count("|") > lines[0].count(","):
            delim = "|"
        else:
            delim = ","

    reader = csv.reader(io.StringIO(text), delimiter=delim)
    all_rows = []
    for r in reader:
        if r:
            all_rows.append(r)

    if not all_rows:
        return {"success": False, "format": "CSV", "file_name": file_name, "error": "داده‌ای در فایل CSV شناسایی نشد."}

    headers = [h.strip() for h in all_rows[0]]
    data_rows = all_rows[1:]
    row_count = len(data_rows)
    col_count = len(headers)

    # Column statistics & type discovery
    columns_analysis = []
    for c_idx, col_name in enumerate(headers):
        vals = [r[c_idx] if c_idx < len(r) else None for r in data_rows]
        c_type = _infer_column_type(vals)
        null_count = sum(1 for v in vals if v is None or str(v).strip() == "")

        stats = {}
        if c_type in ("Integer", "Float"):
            numeric_vals = []
            for v in vals:
                try:
                    if v is not None and str(v).strip() != "":
                        numeric_vals.append(float(v))
                except ValueError:
                    pass
            if numeric_vals:
                stats = {
                    "min": round(min(numeric_vals), 2),
                    "max": round(max(numeric_vals), 2),
                    "avg": round(sum(numeric_vals) / len(numeric_vals), 2),
                    "sum": round(sum(numeric_vals), 2)
                }

        columns_analysis.append({
            "name": col_name,
            "type": c_type,
            "null_count": null_count,
            "null_percentage": round((null_count / max(1, row_count)) * 100, 1),
            "stats": stats
        })

    # Sample rows formatted as records
    sample_records = []
    for r in data_rows[:6]:
        rec = {}
        for c_idx, h in enumerate(headers):
            rec[h] = r[c_idx] if c_idx < len(r) else ""
        sample_records.append(rec)

    return {
        "success": True,
        "format": "CSV" if delim == "," else "TSV",
        "file_name": file_name,
        "size_bytes": len(file_bytes),
        "delimiter": delim,
        "row_count": row_count,
        "column_count": col_count,
        "headers": headers,
        "columns": columns_analysis,
        "sample_records": sample_records,
    }


def _parse_excel(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Parses multi-sheet Excel workbooks with columns and samples."""
    if not HAS_OPENPYXL:
        return {"success": False, "format": "EXCEL", "file_name": file_name, "error": "ماژول openpyxl در سیستم نصب نیست."}

    try:
        wb = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True, read_only=True)
        sheets = []
        total_rows_all = 0

        for sname in wb.sheetnames[:8]:
            sheet = wb[sname]
            rows_iter = sheet.iter_rows(values_only=True)
            first_row = next(rows_iter, None)
            if not first_row:
                continue

            headers = [str(c).strip() if c is not None else f"Column_{i+1}" for i, c in enumerate(first_row)]
            sample_rows = []
            row_count = 0

            for r in rows_iter:
                if any(v is not None for v in r):
                    row_count += 1
                    if len(sample_rows) < 6:
                        row_dict = {}
                        for i, h in enumerate(headers):
                            row_dict[h] = str(r[i]) if (i < len(r) and r[i] is not None) else ""
                        sample_rows.append(row_dict)

            total_rows_all += row_count
            sheets.append({
                "sheet_name": sname,
                "row_count": row_count,
                "column_count": len(headers),
                "headers": headers,
                "sample_rows": sample_rows
            })

        wb.close()
        return {
            "success": True,
            "format": "EXCEL",
            "file_name": file_name,
            "size_bytes": len(file_bytes),
            "sheet_count": len(sheets),
            "total_records": total_rows_all,
            "sheets": sheets
        }
    except Exception as e:
        logger.error(f"Error reading Excel '{file_name}': {e}")
        return {"success": False, "format": "EXCEL", "file_name": file_name, "error": f"خطا در خواندن فایل اکسل: {e}"}


def _parse_json(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Parses JSON data: supports array of objects, key-value hierarchies, and nested schemas."""
    text = _decode_text_bytes(file_bytes)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return {"success": False, "format": "JSON", "file_name": file_name, "error": f"خطا در ساختار JSON (نامعتبر): {e}"}

    # Case A: List of objects (typical tabular JSON dataset)
    if isinstance(data, list):
        record_count = len(data)
        if record_count > 0 and isinstance(data[0], dict):
            # Gather all distinct keys across sample
            all_keys = []
            for item in data[:100]:
                if isinstance(item, dict):
                    for k in item.keys():
                        if k not in all_keys:
                            all_keys.append(k)

            sample = data[:6]
            return {
                "success": True,
                "format": "JSON",
                "json_type": "array_of_objects",
                "file_name": file_name,
                "size_bytes": len(file_bytes),
                "record_count": record_count,
                "field_count": len(all_keys),
                "fields": all_keys,
                "sample_records": sample,
            }
        else:
            return {
                "success": True,
                "format": "JSON",
                "json_type": "array_of_primitives",
                "file_name": file_name,
                "size_bytes": len(file_bytes),
                "record_count": record_count,
                "sample_records": data[:10]
            }

    # Case B: Top-level Dictionary
    if isinstance(data, dict):
        top_keys = list(data.keys())
        key_details = []
        for k in top_keys[:25]:
            val = data[k]
            v_type = type(val).__name__
            length = len(val) if isinstance(val, (list, dict, str)) else None
            key_details.append({"key": k, "type": v_type, "length": length})

        sample_dict = {k: data[k] for k in top_keys[:6]}
        return {
            "success": True,
            "format": "JSON",
            "json_type": "object",
            "file_name": file_name,
            "size_bytes": len(file_bytes),
            "top_key_count": len(top_keys),
            "top_keys": top_keys,
            "key_details": key_details,
            "sample_content": sample_dict
        }

    return {
        "success": True,
        "format": "JSON",
        "json_type": "primitive",
        "file_name": file_name,
        "size_bytes": len(file_bytes),
        "value": str(data)[:500]
    }


def _parse_jsonl(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Parses JSONL / NDJSON (line-delimited JSON) streaming data files."""
    text = _decode_text_bytes(file_bytes)
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    valid_records = []
    parse_errors = 0
    all_keys = []

    for i, line in enumerate(lines):
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                for k in item.keys():
                    if k not in all_keys:
                        all_keys.append(k)
            valid_records.append(item)
        except Exception:
            parse_errors += 1

    return {
        "success": True,
        "format": "JSONL",
        "file_name": file_name,
        "size_bytes": len(file_bytes),
        "total_lines": len(lines),
        "record_count": len(valid_records),
        "parse_errors": parse_errors,
        "field_count": len(all_keys),
        "fields": all_keys[:30],
        "sample_records": valid_records[:6]
    }


def _parse_yaml(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Parses YAML documents safely."""
    if not HAS_YAML:
        return {"success": False, "format": "YAML", "file_name": file_name, "error": "ماژول PyYAML در سیستم نصب نیست."}

    text = _decode_text_bytes(file_bytes)
    try:
        data = yaml.safe_load(text)
    except Exception as e:
        return {"success": False, "format": "YAML", "file_name": file_name, "error": f"خطا در ساختار YAML: {e}"}

    if isinstance(data, list):
        return {
            "success": True,
            "format": "YAML",
            "yaml_type": "list",
            "file_name": file_name,
            "size_bytes": len(file_bytes),
            "record_count": len(data),
            "sample_content": data[:6]
        }
    elif isinstance(data, dict):
        keys = list(data.keys())
        return {
            "success": True,
            "format": "YAML",
            "yaml_type": "dict",
            "file_name": file_name,
            "size_bytes": len(file_bytes),
            "key_count": len(keys),
            "keys": keys[:30],
            "sample_content": {k: data[k] for k in keys[:6]}
        }
    return {
        "success": True,
        "format": "YAML",
        "yaml_type": "primitive",
        "file_name": file_name,
        "size_bytes": len(file_bytes),
        "value": str(data)[:500]
    }


def _parse_xml(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Parses XML data files, detects schema, repeating elements, and attributes."""
    text = _decode_text_bytes(file_bytes)
    try:
        root = ET.fromstring(text)
    except Exception as e:
        return {"success": False, "format": "XML", "file_name": file_name, "error": f"خطا در ساختار XML: {e}"}

    child_tags = {}
    for c in root:
        child_tags[c.tag] = child_tags.get(c.tag, 0) + 1

    # Check for repeating record rows
    repeating_items = []
    common_tag = None
    if child_tags:
        common_tag = max(child_tags, key=child_tags.get)
        for c in root.findall(common_tag)[:6]:
            row = dict(c.attrib)
            for sub in c:
                row[sub.tag] = (sub.text or "").strip()
            repeating_items.append(row)

    return {
        "success": True,
        "format": "XML",
        "file_name": file_name,
        "size_bytes": len(file_bytes),
        "root_tag": root.tag,
        "root_attributes": dict(root.attrib),
        "child_counts": child_tags,
        "total_children": len(root),
        "primary_record_tag": common_tag,
        "sample_records": repeating_items
    }


def _parse_toml(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Parses TOML configuration & data files."""
    if not HAS_TOMLLIB:
        return {"success": False, "format": "TOML", "file_name": file_name, "error": "ماژول tomllib در پایتون در دسترس نیست."}

    text = _decode_text_bytes(file_bytes)
    try:
        data = tomllib.loads(text)
    except Exception as e:
        return {"success": False, "format": "TOML", "file_name": file_name, "error": f"خطا در ساختار TOML: {e}"}

    sections = list(data.keys())
    return {
        "success": True,
        "format": "TOML",
        "file_name": file_name,
        "size_bytes": len(file_bytes),
        "section_count": len(sections),
        "sections": sections,
        "sample_content": {s: data[s] for s in sections[:5]}
    }


def _parse_sql(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Parses SQL dump files for table definitions and insert volumes."""
    text = _decode_text_bytes(file_bytes)
    lines = text.splitlines()

    create_matches = re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`']?([a-zA-Z0-9_]+)[\"`']?\s*\((.*?)\);", text, re.IGNORECASE | re.DOTALL)
    tables = []
    for t_name, t_cols in create_matches:
        col_defs = [c.strip() for c in t_cols.split(",") if c.strip() and not c.strip().upper().startswith(("PRIMARY", "KEY", "CONSTRAINT", "FOREIGN"))]
        clean_cols = [c.split()[0].strip("`\"'") for c in col_defs if c.split()]
        tables.append({
            "table_name": t_name,
            "column_count": len(clean_cols),
            "columns": clean_cols[:15]
        })

    insert_count = len(re.findall(r"INSERT\s+INTO\s+[\"`']?([a-zA-Z0-9_]+)[\"`']?", text, re.IGNORECASE))

    return {
        "success": True,
        "format": "SQL",
        "file_name": file_name,
        "size_bytes": len(file_bytes),
        "line_count": len(lines),
        "table_count": len(tables),
        "tables": tables,
        "estimated_inserts": insert_count
    }


def _parse_log(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Parses application and system log files for metrics and errors."""
    text = _decode_text_bytes(file_bytes)
    lines = text.splitlines()

    error_lines = []
    warn_lines = []
    info_count = 0

    for l in lines:
        l_upper = l.upper()
        if any(err in l_upper for err in ("ERROR", "CRITICAL", "FATAL", "EXCEPTION", "FAIL")):
            if len(error_lines) < 10:
                error_lines.append(l.strip()[:180])
        elif "WARN" in l_upper:
            if len(warn_lines) < 5:
                warn_lines.append(l.strip()[:180])
        elif "INFO" in l_upper:
            info_count += 1

    return {
        "success": True,
        "format": "LOG",
        "file_name": file_name,
        "size_bytes": len(file_bytes),
        "total_lines": len(lines),
        "error_count": len(error_lines),
        "warn_count": len(warn_lines),
        "sample_errors": error_lines,
        "recent_lines": lines[-6:]
    }


# =========================================================================
# 3. Main Entrypoint & Dispatcher
# =========================================================================

def read_data_file(
    file_bytes: bytes,
    file_name: str,
    mime_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Unified Data Storage Reader: parses, inspects, extracts schema, and calculates statistics
    for any data file format in Python.
    """
    if not file_bytes:
        return {"success": False, "file_name": file_name, "error": "حجم فایل صفر بایت است."}

    fmt = detect_data_format(file_name, file_bytes, mime_type=mime_type)

    if fmt == "SQLITE":
        return _parse_sqlite(file_bytes, file_name)
    elif fmt in ("CSV", "TSV"):
        delim = "\t" if fmt == "TSV" else None
        return _parse_csv(file_bytes, file_name, delimiter_hint=delim)
    elif fmt == "EXCEL":
        return _parse_excel(file_bytes, file_name)
    elif fmt == "JSON":
        return _parse_json(file_bytes, file_name)
    elif fmt == "JSONL":
        return _parse_jsonl(file_bytes, file_name)
    elif fmt == "YAML":
        return _parse_yaml(file_bytes, file_name)
    elif fmt == "XML":
        return _parse_xml(file_bytes, file_name)
    elif fmt == "TOML":
        return _parse_toml(file_bytes, file_name)
    elif fmt == "SQL":
        return _parse_sql(file_bytes, file_name)
    elif fmt == "LOG":
        return _parse_log(file_bytes, file_name)

    # Fallback to general text parser
    text = _decode_text_bytes(file_bytes)
    lines = text.splitlines()
    return {
        "success": True,
        "format": fmt or "TEXT",
        "file_name": file_name,
        "size_bytes": len(file_bytes),
        "line_count": len(lines),
        "sample_lines": lines[:15],
        "content": text[:10000]
    }


async def read_data_file_async(
    file_bytes: bytes,
    file_name: str,
    mime_type: Optional[str] = None
) -> Dict[str, Any]:
    """Asynchronous non-blocking data reader offloaded to threadpool."""
    return await asyncio.to_thread(read_data_file, file_bytes, file_name, mime_type)


# =========================================================================
# 4. Telegram HTML & LLM Context Formatters
# =========================================================================

def format_data_inspection_report(data: Dict[str, Any]) -> str:
    """Generates rich, clean Telegram HTML report with stats and collapsible preview."""
    if not data.get("success"):
        return f"❌ <b>خطا در پردازش فایل داده:</b> {html.escape(data.get('error', 'فرمت ناشناخته است.'))}"

    fname = html.escape(data.get("file_name", "data_file"))
    fmt = html.escape(data.get("format", "DATA"))
    size_kb = data.get("size_bytes", 0) / 1024

    lines = [
        f"📊 <b>تحلیل و کالبدشکافی داده‌ها:</b> <code>{fname}</code>",
        f"• فرمت ذخیره‌سازی: <code>{fmt}</code> | حجم: <code>{size_kb:.1f} KB</code>\n"
    ]

    # SQLite
    if fmt == "SQLITE":
        t_count = data.get("table_count", 0)
        v_count = data.get("view_count", 0)
        tot_records = data.get("total_records", 0)
        lines.append(f"🗄 <b>مشخصات پایگاه‌داده SQLite:</b>")
        lines.append(f"• تعداد جداول: <code>{t_count}</code> | نماها (Views): <code>{v_count}</code>")
        lines.append(f"• مجموع کل رکوردها: <code>{tot_records:,}</code> ردیف\n")

        for t in data.get("tables", [])[:4]:
            t_name = html.escape(t.get("name", ""))
            r_cnt = t.get("row_count", 0)
            c_cnt = t.get("column_count", 0)
            cols_str = ", ".join([f"<code>{html.escape(c['name'])}</code> ({c['type']})" for c in t.get("columns", [])[:5]])
            lines.append(f"📋 جدول <b>{t_name}</b> ({r_cnt:,} ردیف | {c_cnt} ستون):")
            lines.append(f"  ستون‌ها: {cols_str}")
            samples = t.get("sample_rows", [])
            if samples:
                sample_json = json.dumps(samples[:3], ensure_ascii=False, indent=2)
                lines.append(f"  نمونه داده‌ها:\n  <blockquote expandable>{html.escape(sample_json)}</blockquote>\n")

    # CSV / TSV
    elif fmt in ("CSV", "TSV"):
        r_cnt = data.get("row_count", 0)
        c_cnt = data.get("column_count", 0)
        lines.append(f"📈 <b>ساختار جدول داده ({fmt}):</b>")
        lines.append(f"• تعداد سطرها: <code>{r_cnt:,}</code> | تعداد ستون‌ها: <code>{c_cnt}</code>")
        lines.append(f"• جداکننده: <code>'{html.escape(data.get('delimiter', ','))}'</code>\n")

        cols = data.get("columns", [])
        if cols:
            lines.append("📌 <b>ستون‌ها و انواع داده:</b>")
            for c in cols[:8]:
                c_name = html.escape(c["name"])
                c_type = c["type"]
                null_p = c.get("null_percentage", 0)
                stats = c.get("stats")
                stat_str = f" [میانگین: {stats['avg']:,}]" if stats and "avg" in stats else ""
                lines.append(f"• <code>{c_name}</code> ({c_type}){stat_str} - خالی: {null_p}%")

        samples = data.get("sample_records", [])
        if samples:
            sample_json = json.dumps(samples[:4], ensure_ascii=False, indent=2)
            lines.append(f"\n👁 <b>نمونه سطرهای اول:</b>\n<blockquote expandable>{html.escape(sample_json)}</blockquote>")

    # Excel
    elif fmt == "EXCEL":
        s_cnt = data.get("sheet_count", 0)
        tot_rec = data.get("total_records", 0)
        lines.append(f"📑 <b>شیت‌های اکسل ({s_cnt} شیت | {tot_rec:,} ردیف کل):</b>\n")
        for s in data.get("sheets", [])[:4]:
            s_name = html.escape(s.get("sheet_name", ""))
            s_rows = s.get("row_count", 0)
            headers_str = ", ".join([f"<code>{html.escape(h)}</code>" for h in s.get("headers", [])[:5]])
            lines.append(f"• شیت <b>{s_name}</b> ({s_rows:,} ردیف): {headers_str}")
            samples = s.get("sample_rows", [])
            if samples:
                sample_json = json.dumps(samples[:3], ensure_ascii=False, indent=2)
                lines.append(f"  <blockquote expandable>{html.escape(sample_json)}</blockquote>")

    # JSON & JSONL
    elif fmt in ("JSON", "JSONL"):
        jtype = data.get("json_type", "")
        rec_cnt = data.get("record_count", 0)
        lines.append(f"📦 <b>ساختار داده‌های JSON ({jtype}):</b>")
        if rec_cnt:
            lines.append(f"• تعداد کل رکوردها: <code>{rec_cnt:,}</code>")
        if data.get("fields"):
            f_str = ", ".join([f"<code>{html.escape(k)}</code>" for k in data["fields"][:8]])
            lines.append(f"• فیلدهای شناسایی‌شده: {f_str}")
        if data.get("top_keys"):
            k_str = ", ".join([f"<code>{html.escape(k)}</code>" for k in data["top_keys"][:8]])
            lines.append(f"• کلیدهای اصلی: {k_str}")

        samples = data.get("sample_records") or data.get("sample_content")
        if samples:
            sample_json = json.dumps(samples, ensure_ascii=False, indent=2)
            lines.append(f"\n👁 <b>نمونه داده‌ها:</b>\n<blockquote expandable>{html.escape(sample_json[:2000])}</blockquote>")

    # Fallback
    else:
        l_cnt = data.get("line_count", 0)
        lines.append(f"📄 تعداد خطوط: <code>{l_cnt:,}</code>")
        content = data.get("content") or "\n".join(data.get("sample_lines", []))
        if content:
            lines.append(f"\n👁 <b>گزیده محتوا:</b>\n<blockquote expandable>{html.escape(content[:1500])}</blockquote>")

    lines.append("\n💡 <i>می‌توانید روی این پیام ریپلای کنید و هر سوالی یا تحلیل آماری درباره این دیتا دارید بپرسید.</i>")
    return "\n".join(lines)


def format_data_for_llm(data: Dict[str, Any], max_chars: int = 15000) -> str:
    """Formats full structured data into clean text context ready for LLM prompt injection."""
    if not data.get("success"):
        return f"[خطا در استخراج دیتا از {data.get('file_name')}]: {data.get('error')}"

    fname = data.get("file_name", "data_file")
    fmt = data.get("format", "DATA")

    parts = [
        f"=== [محتوا و کالبدشکافی فایل ذخیره‌سازی داده: {fname} (فرمت: {fmt})] ==="
    ]

    if fmt == "SQLITE":
        parts.append(f"• تعداد جداول: {data.get('table_count')} | تعداد رکوردها: {data.get('total_records'):,}")
        for t in data.get("tables", []):
            parts.append(f"\n--- جدول: {t['name']} ({t['row_count']} ردیف) ---")
            parts.append(f"اسکیما: {t.get('sql') or ''}")
            parts.append(f"نمونه ردیف‌ها:\n{json.dumps(t.get('sample_rows', []), ensure_ascii=False, indent=2)}")

    elif fmt in ("CSV", "TSV"):
        parts.append(f"• سطرها: {data.get('row_count'):,} | ستون‌ها: {data.get('column_count')}")
        parts.append(f"• ستون‌ها و تایپ‌ها: {json.dumps(data.get('columns', []), ensure_ascii=False)}")
        parts.append(f"• ردیف‌های نمونه:\n{json.dumps(data.get('sample_records', []), ensure_ascii=False, indent=2)}")

    elif fmt == "EXCEL":
        parts.append(f"• تعداد شیت‌ها: {data.get('sheet_count')} | مجموع ردیف‌ها: {data.get('total_records')}")
        for s in data.get("sheets", []):
            parts.append(f"\n--- شیت: {s['sheet_name']} ({s['row_count']} سطر) ---")
            parts.append(f"ستون‌ها: {', '.join(s.get('headers', []))}")
            parts.append(f"ردیف‌های نمونه:\n{json.dumps(s.get('sample_rows', []), ensure_ascii=False, indent=2)}")

    elif fmt in ("JSON", "JSONL"):
        parts.append(f"• ساختار: {data.get('json_type', 'JSON')} | تعداد رکوردها: {data.get('record_count', data.get('top_key_count'))}")
        samples = data.get("sample_records") or data.get("sample_content")
        parts.append(f"• محتوا و رکوردها:\n{json.dumps(samples, ensure_ascii=False, indent=2)}")

    else:
        content = data.get("content") or "\n".join(data.get("sample_lines", []))
        parts.append(f"• گزیده محتوا:\n{content[:max_chars]}")

    full_res = "\n".join(parts)
    return full_res[:max_chars]
