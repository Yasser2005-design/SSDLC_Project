import io
from pathlib import Path
from typing import Optional

from pypdf import PdfReader, PdfWriter
from reportlab.lib.colors import HexColor
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

from core.security_logger import get_app_logger
_log = get_app_logger()


QR_POSITIONS = {
    'bottom-right': lambda pw, ph, qr_size, margin: (pw - qr_size - margin, margin + 18 * mm),
    'bottom-left': lambda pw, ph, qr_size, margin: (margin, margin + 18 * mm),
    'top-right': lambda pw, ph, qr_size, margin: (pw - qr_size - margin, ph - qr_size - margin),
    'top-left': lambda pw, ph, qr_size, margin: (margin, ph - qr_size - margin),
}


def embed_qr_to_pdf(
    source_pdf: str,
    qr_image_path: str,
    output_pdf: str,
    position: str = 'bottom-right',
    qr_size_mm: float = 35.0,
) -> str:
    source_path = Path(source_pdf)
    qr_path = Path(qr_image_path)
    if not source_path.exists():
        raise FileNotFoundError(f'PDF sumber tidak ditemukan: {source_pdf}')
    if not qr_path.exists():
        raise FileNotFoundError(f'Gambar QR tidak ditemukan: {qr_image_path}')
    if position not in QR_POSITIONS:
        raise ValueError(f"Posisi tidak valid: '{position}'. Opsi: {list(QR_POSITIONS.keys())}")

    reader = PdfReader(str(source_path))
    if len(reader.pages) == 0:
        raise ValueError(f'PDF sumber tidak memiliki halaman: {source_pdf}')

    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    ref_page = reader.pages[-1]
    page_width = float(ref_page.mediabox.width)
    page_height = float(ref_page.mediabox.height)
    signature_page = _build_signature_page(qr_path, page_width, page_height, position, qr_size_mm)
    writer.add_page(signature_page)

    output_path = Path(output_pdf)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(output_path), 'wb') as f:
        writer.write(f)
    _log.debug(f"[PDF Embedder] Signature page appended at '{position}': {output_path.name}")
    return str(output_path.resolve())


def _build_signature_page(qr_path: Path, page_width: float, page_height: float, position: str, qr_size_mm: float):
    qr_size = qr_size_mm * mm
    margin = 18 * mm
    qr_x, qr_y = QR_POSITIONS[position](page_width, page_height, qr_size, margin)

    overlay_buffer = io.BytesIO()
    c = canvas.Canvas(overlay_buffer, pagesize=(page_width, page_height))
    c.setFillColor(HexColor('#FFFFFF'))
    c.rect(0, 0, page_width, page_height, fill=1, stroke=0)

    c.setFillColor(HexColor('#1D1D1F'))
    c.setFont('Helvetica-Bold', 16)
    c.drawString(margin, page_height - margin, 'CertiGuard Digital Signature')
    c.setFont('Helvetica', 9)
    c.setFillColor(HexColor('#6E6E73'))
    c.drawString(margin, page_height - margin - 15, 'This page contains the verification QR for the signed document pages.')

    bg_padding = 4 * mm
    c.setFillColor(HexColor('#F5F5F7'))
    c.setStrokeColor(HexColor('#D2D2D7'))
    c.setLineWidth(1)
    c.roundRect(
        qr_x - bg_padding,
        qr_y - bg_padding - 12 * mm,
        qr_size + 2 * bg_padding,
        qr_size + 2 * bg_padding + 12 * mm,
        radius=4 * mm,
        fill=1,
        stroke=1,
    )
    c.drawImage(str(qr_path), qr_x, qr_y, width=qr_size, height=qr_size, preserveAspectRatio=True, anchor='sw')
    c.setFont('Helvetica', 7)
    c.setFillColor(HexColor('#1D1D1F'))
    label_x = qr_x + qr_size / 2
    label_y = qr_y - 7 * mm
    c.drawCentredString(label_x, label_y, 'Scan to verify')
    c.drawCentredString(label_x, label_y - 9, 'CertiGuard v2.0')
    c.save()

    overlay_buffer.seek(0)
    overlay_reader = PdfReader(overlay_buffer)
    return overlay_reader.pages[0]


def extract_qr_from_pdf(pdf_path: str) -> Optional[str]:
    path = Path(pdf_path)
    if not path.exists():
        raise FileNotFoundError(f'File PDF tidak ditemukan: {pdf_path}')
    try:
        import fitz
    except ImportError as e:
        raise ImportError('Library PyMuPDF diperlukan untuk ekstraksi QR. Install dengan: pip install PyMuPDF') from e
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
    except ImportError as e:
        raise ImportError('Library pyzbar diperlukan untuk membaca QR Code. Install dengan: pip install pyzbar') from e
    from PIL import Image

    doc = fitz.open(str(path))
    try:
        for page_idx in range(len(doc) - 1, -1, -1):
            page = doc[page_idx]
            mat = fitz.Matrix(3.0, 3.0)
            pix = page.get_pixmap(matrix=mat)
            img = Image.frombytes('RGB', [pix.width, pix.height], pix.samples)
            decoded_objects = pyzbar_decode(img)
            if decoded_objects:
                qr_data = decoded_objects[0].data.decode('utf-8')
                _log.debug(f'[PDF Embedder] QR Code found on page {page_idx + 1}: {Path(pdf_path).name}')
                return qr_data
    finally:
        doc.close()

    _log.debug(f'[PDF Embedder] No QR Code found in: {Path(pdf_path).name}')
    return None
