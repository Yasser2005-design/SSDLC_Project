import base64
import json
from pathlib import Path
from typing import Optional

import qrcode
from PIL import Image
from qrcode.constants import ERROR_CORRECT_H

from core.security_logger import get_app_logger
_log = get_app_logger()


def create_qr_payload(
    doc_hash: str,
    signature: bytes,
    signer_name: str,
    timestamp: str,
    signed_page_count: int,
) -> str:
    if not doc_hash or len(doc_hash) != 64:
        raise ValueError(f'doc_hash harus 64 karakter hex, diterima: {(len(doc_hash) if doc_hash else 0)}')
    if not signature:
        raise ValueError('Signature tidak boleh kosong')
    if not signer_name or not signer_name.strip():
        raise ValueError('Nama penandatangan tidak boleh kosong')
    if not timestamp:
        raise ValueError('Timestamp tidak boleh kosong')
    if signed_page_count <= 0:
        raise ValueError('Jumlah halaman dokumen yang ditandatangani harus lebih dari 0')

    payload = {
        'version': '2.0',
        'doc_hash': doc_hash,
        'signature': base64.b64encode(signature).decode('ascii'),
        'signer': signer_name.strip(),
        'timestamp': timestamp,
        'algorithm': 'RSA-PSS-SHA256',
        'hash_method': 'PDF_RENDER_SHA256_V2',
        'signed_page_count': signed_page_count,
        'signature_page': True,
    }
    json_str = json.dumps(payload, separators=(',', ':'))
    payload_b64 = base64.b64encode(json_str.encode('utf-8')).decode('ascii')
    # VUL-004: Log signer name but NOT hash or signature
    _log.debug(f'[QR Manager] Payload created for signer: {signer_name[:32]}')
    return payload_b64


def decode_qr_payload(payload_b64: str) -> dict:
    try:
        json_bytes = base64.b64decode(payload_b64)
        data = json.loads(json_bytes.decode('utf-8'))
    except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f'Payload QR tidak valid atau corrupt: {e}') from e

    required_fields = {'version', 'doc_hash', 'signature', 'signer', 'timestamp', 'algorithm'}
    missing = required_fields - set(data.keys())
    if missing:
        raise ValueError(f'Payload QR tidak lengkap, field hilang: {missing}')
    if data['algorithm'] != 'RSA-PSS-SHA256':
        raise ValueError(f"Algoritma tanda tangan tidak didukung: {data['algorithm']}")
    if not isinstance(data['doc_hash'], str) or len(data['doc_hash']) != 64:
        raise ValueError('doc_hash dalam payload tidak valid.')

    try:
        data['signature'] = base64.b64decode(data['signature'])
    except base64.binascii.Error as e:
        raise ValueError(f'Signature dalam payload tidak valid: {e}') from e

    if data.get('version') == '2.0':
        if data.get('hash_method') != 'PDF_RENDER_SHA256_V2':
            raise ValueError('Metode hash payload tidak didukung.')
        signed_page_count = data.get('signed_page_count')
        if not isinstance(signed_page_count, int) or signed_page_count <= 0:
            raise ValueError('Jumlah halaman yang ditandatangani dalam payload tidak valid.')
    else:
        raise ValueError(f"Versi payload tidak didukung untuk mode aman: {data.get('version')}")

    _log.debug(f"[QR Manager] Payload decoded - signer: {data['signer'][:32]}, version: {data['version']}")
    return data


def generate_qr_image(payload_b64: str, output_path: str) -> str:
    if not payload_b64:
        raise ValueError('Payload tidak boleh kosong')
    qr = qrcode.QRCode(version=None, error_correction=ERROR_CORRECT_H, box_size=10, border=4)
    qr.add_data(payload_b64)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(str(path))
    _log.debug(f'[QR Manager] QR Code saved (version {qr.version}): {Path(output_path).name}')
    return str(path.resolve())


def read_qr_from_image(image_path: str) -> Optional[str]:
    path = Path(image_path)
    if not path.exists():
        raise FileNotFoundError(f'File gambar tidak ditemukan: {image_path}')
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
    except ImportError as e:
        raise ImportError('Library pyzbar diperlukan untuk membaca QR Code. Install dengan: pip install pyzbar') from e
    img = Image.open(str(path))
    decoded_objects = pyzbar_decode(img)
    if not decoded_objects:
        _log.debug(f'[QR Manager] No QR Code found in: {Path(image_path).name}')
        return None
    qr_data = decoded_objects[0].data.decode('utf-8')
    _log.debug(f'[QR Manager] QR Code read successfully from: {Path(image_path).name}')
    return qr_data
