"""
Barcode and QR Code Generator Tool for Prometheus:
Generates high-resolution QR codes and 1D standard barcodes (Code128 / EAN13) in memory
and delivers them directly to Telegram chats.
"""

import io
import re
import logging
from typing import Tuple, Optional
import qrcode
from qrcode.constants import ERROR_CORRECT_M

try:
    import barcode
    from barcode.writer import ImageWriter
    _HAS_BARCODE = True
except ImportError:
    _HAS_BARCODE = False

logger = logging.getLogger("BarcodeTool")


def generate_qr_code(data: str) -> io.BytesIO:
    """Generates high-contrast, high-resolution QR code PNG image in memory."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_M,
        box_size=12,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def generate_barcode(code_data: str, b_type: str = "code128") -> io.BytesIO:
    """Generates standard 1D Barcode (Code128 / EAN) PNG image in memory."""
    buf = io.BytesIO()
    clean_code = code_data.strip()

    if _HAS_BARCODE:
        try:
            # Select code type (default code128 for alphanumeric)
            target_type = b_type.lower()
            if target_type not in barcode.PROVIDED_BARCODES:
                target_type = "code128"

            bc_class = barcode.get_barcode_class(target_type)
            writer = ImageWriter()
            writer.format = "PNG"
            bc_instance = bc_class(clean_code, writer=writer)
            bc_instance.write(buf, options={"write_text": True, "font_size": 12, "text_distance": 4})
            buf.seek(0)
            return buf
        except Exception as e:
            logger.warning(f"Barcode generation error: {e}, falling back to QR code")

    # Fallback to QR code if barcode generation is not supported for this string
    return generate_qr_code(clean_code)


def parse_barcode_request(text: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Parses user input to determine if a barcode or QR code is requested.
    Returns:
        (is_matched, code_type ['qr' or 'barcode'], content_string)
    """
    t = text.strip()
    # 1. Command triggers: /qr, /barcode, /بارکد, /کیوآر
    cmd_match = re.match(r"^/(?:qr|qrcode|کیوآر)(?:@\w+)?(?:\s+(.+))?$", t, re.IGNORECASE)
    if cmd_match:
        content = cmd_match.group(1)
        return True, "qr", content.strip() if content else None

    bc_match = re.match(r"^/(?:barcode|بارکد)(?:@\w+)?(?:\s+(.+))?$", t, re.IGNORECASE)
    if bc_match:
        content = bc_match.group(1)
        return True, "barcode", content.strip() if content else None

    # 2. Natural language QR triggers
    nl_qr = re.search(r"(?:ساخت|ایجاد|تولید|بساز|درست\s*کن|کد)?\s*(?:qr|کیوآر|کیو\s*ار|کیوار)\s*(?:کد|code)?\s*(?:برای|از|به)?\s*[:\s]?\s*(.+)", t, re.IGNORECASE)
    if nl_qr:
        content = nl_qr.group(1).strip()
        if content and not any(content.startswith(w) for w in ("چیست", "چگونه", "چطور", "رو توضیح")):
            return True, "qr", content

    # 3. Natural language Barcode triggers
    nl_bc = re.search(r"(?:ساخت|ایجاد|تولید|بساز|درست\s*کن)\s*(?:بارکد|barcode)\s*(?:برای|از|به)?\s*[:\s]?\s*(.+)", t, re.IGNORECASE)
    if nl_bc:
        content = nl_bc.group(1).strip()
        if content and not any(content.startswith(w) for w in ("چیست", "چگونه", "چطور", "رو توضیح")):
            return True, "barcode", content

    return False, None, None
