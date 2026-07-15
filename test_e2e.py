import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def create_sample_pdf(output_path: str) -> str:
    c = canvas.Canvas(output_path, pagesize=A4)
    c.setFont('Helvetica-Bold', 24)
    c.drawString(72, 750, 'CertiGuard Test Certificate')
    c.setFont('Helvetica', 14)
    c.drawString(72, 700, 'This is a sample document for testing')
    c.drawString(72, 675, 'digital signature and QR code verification.')
    c.setFont('Helvetica', 12)
    c.drawString(72, 630, 'Name: John Doe')
    c.drawString(72, 610, 'Course: Applied Cryptography')
    c.drawString(72, 590, 'Date: 2026-06-23')
    c.drawString(72, 560, 'This document certifies that the above named person')
    c.drawString(72, 540, 'has successfully completed the course requirements.')
    c.save()
    print(f'[Test] Sample PDF created: {output_path}')
    return output_path

def test_end_to_end():
    print('=' * 60)
    print('  CertiGuard — End-to-End Test')
    print('=' * 60)
    print()
    test_dir = os.path.join(tempfile.gettempdir(), 'certiguard_test')
    os.makedirs(test_dir, exist_ok=True)
    print('[TEST 1] Creating sample PDF...')
    pdf_path = os.path.join(test_dir, 'test_certificate.pdf')
    create_sample_pdf(pdf_path)
    print('  PASS\n')
    print('[TEST 2] Hashing PDF content...')
    from core.hasher import hash_pdf_content
    doc_hash, hash_time = hash_pdf_content(pdf_path)
    assert len(doc_hash) == 64, f'Hash length should be 64, got {len(doc_hash)}'
    print(f'  Hash: {doc_hash}')
    print(f'  Time: {hash_time:.2f} ms')
    print('  PASS\n')
    print('[TEST 3] Generating RSA-2048 keypair...')
    from core.signer import generate_keypair, save_private_key, save_public_key
    private_key, public_key = generate_keypair(2048)
    priv_path = os.path.join(test_dir, 'test_private.pem')
    pub_path = os.path.join(test_dir, 'test_public.pem')
    save_private_key(private_key, priv_path)
    save_public_key(public_key, pub_path)
    print('  PASS\n')
    print('[TEST 4] Signing hash...')
    from core.signer import sign_hash
    signature, sign_time = sign_hash(private_key, doc_hash)
    assert len(signature) > 0, 'Signature should not be empty'
    print(f'  Signature length: {len(signature)} bytes')
    print(f'  Time: {sign_time:.2f} ms')
    print('  PASS\n')
    print('[TEST 5] Creating QR Code...')
    from datetime import datetime, timezone
    from core.qr_manager import create_qr_payload, generate_qr_image, decode_qr_payload
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = create_qr_payload(doc_hash, signature, 'John Doe', timestamp)
    qr_path = os.path.join(test_dir, 'test_qr.png')
    generate_qr_image(payload, qr_path)
    assert os.path.exists(qr_path), 'QR image should exist'
    print(f'  Payload length: {len(payload)} chars')
    print('  PASS\n')
    print('[TEST 6] Embedding QR to PDF...')
    from utils.pdf_embedder import embed_qr_to_pdf
    signed_pdf = os.path.join(test_dir, 'test_certificate_signed.pdf')
    embed_qr_to_pdf(pdf_path, qr_path, signed_pdf, 'bottom-right')
    assert os.path.exists(signed_pdf), 'Signed PDF should exist'
    print('  PASS\n')
    print('[TEST 7] Extracting QR from signed PDF...')
    from utils.pdf_embedder import extract_qr_from_pdf
    extracted_data = extract_qr_from_pdf(signed_pdf)
    assert extracted_data is not None, 'Should extract QR data from signed PDF'
    print('  PASS\n')
    print('[TEST 8] Decoding payload & verifying signature...')
    decoded = decode_qr_payload(extracted_data)
    assert decoded['signer'] == 'John Doe', f"Signer should be 'John Doe', got '{decoded['signer']}'"
    assert decoded['doc_hash'] == doc_hash, 'Hash should match'
    from core.signer import load_public_key, verify_signature
    loaded_pub = load_public_key(pub_path)
    is_valid, verify_time = verify_signature(loaded_pub, decoded['doc_hash'], decoded['signature'])
    assert is_valid, 'Signature should be VALID'
    print(f'  Signature valid: {is_valid}')
    print(f'  Verify time: {verify_time:.2f} ms')
    print('  PASS\n')
    print('[TEST 9] Testing with wrong key (should be INVALID)...')
    from core.signer import generate_keypair as gen2
    wrong_priv, wrong_pub = gen2(2048)
    is_invalid, _ = verify_signature(wrong_pub, decoded['doc_hash'], decoded['signature'])
    assert not is_invalid, 'Signature should be INVALID with wrong key'
    print(f'  Signature valid with wrong key: {is_invalid}')
    print('  PASS\n')
    print('=' * 60)
    print('  ALL 9 TESTS PASSED!')
    print(f'  Test files in: {test_dir}')
    print('=' * 60)
if __name__ == '__main__':
    test_end_to_end()