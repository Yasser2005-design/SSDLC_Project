import hashlib
import time
from pathlib import Path
from typing import Optional

from core.security_logger import get_app_logger
_log = get_app_logger()

def hash_pdf_content(pdf_path: str, page_count: Optional[int] = None) -> tuple[str, float]:
    path = Path(pdf_path)
    if not path.exists():
        raise FileNotFoundError(f'File PDF tidak ditemukan: {pdf_path}')
    if not path.is_file():
        raise ValueError(f'Path bukan file: {pdf_path}')
    start_time = time.perf_counter()
    try:
        import fitz
    except ImportError as e:
        raise ImportError('Library PyMuPDF diperlukan untuk hashing PDF visual. Install dengan: pip install PyMuPDF') from e

    digest = hashlib.sha256()
    doc = fitz.open(str(path))
    try:
        total_pages = len(doc)
        if total_pages == 0:
            raise ValueError(f'PDF tidak memiliki halaman: {pdf_path}')
        pages_to_hash = total_pages if page_count is None else page_count
        if pages_to_hash <= 0 or pages_to_hash > total_pages:
            raise ValueError(f'Jumlah halaman untuk hash tidak valid: {pages_to_hash} dari {total_pages}')

        digest.update(b'CertiGuard-PDF-Visual-Hash-v2')
        digest.update(str(pages_to_hash).encode('ascii'))
        matrix = fitz.Matrix(2.0, 2.0)
        for page_idx in range(pages_to_hash):
            page = doc[page_idx]
            pix = page.get_pixmap(matrix=matrix, alpha=False)
            digest.update(str(page_idx).encode('ascii'))
            digest.update(str(pix.width).encode('ascii'))
            digest.update(str(pix.height).encode('ascii'))
            digest.update(bytes(pix.samples))
    finally:
        doc.close()

    hex_digest = digest.hexdigest()
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    # VUL-004 Mitigation: log only first 16 chars of hash, not the full value
    _log.debug(f'[Hasher] SHA-256 computed in {elapsed_ms:.2f} ms | hash_prefix={hex_digest[:16]}...')
    return (hex_digest, elapsed_ms)

def hash_bytes(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError(f'Expected bytes, got {type(data).__name__}')
    return hashlib.sha256(data).hexdigest()
