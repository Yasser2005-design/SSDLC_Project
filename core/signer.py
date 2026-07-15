import time
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import InvalidSignature

from core.security_logger import get_app_logger
_log = get_app_logger()

def generate_keypair(key_size: int=2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
    if key_size not in (2048, 4096):
        raise ValueError(f'Key size harus 2048 atau 4096, diterima: {key_size}')
    start_time = time.perf_counter()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    _log.debug(f'[Signer] RSA-{key_size} keypair generated in {elapsed_ms:.2f} ms')
    return (private_key, public_key)

def save_private_key(private_key: RSAPrivateKey, filepath: str, password: Optional[str]=None) -> None:
    if not password:
        raise ValueError('Password private key wajib diisi agar key tidak tersimpan tanpa enkripsi.')
    encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))
    pem_data = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=encryption)
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem_data)
    _log.debug(f'[Signer] Private key saved: {Path(filepath).name}')

def save_public_key(public_key: RSAPublicKey, filepath: str) -> None:
    pem_data = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem_data)
    _log.debug(f'[Signer] Public key saved: {Path(filepath).name}')

def load_private_key(filepath: str, password: Optional[str]=None) -> RSAPrivateKey:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f'Private key tidak ditemukan: {filepath}')
    pem_data = path.read_bytes()
    pwd_bytes = password.encode('utf-8') if password else None
    try:
        private_key = serialization.load_pem_private_key(pem_data, password=pwd_bytes)
    except (ValueError, TypeError) as e:
        raise ValueError(f'Gagal memuat private key: {e}. Pastikan password benar dan file dalam format PEM yang valid.') from e
    if not isinstance(private_key, RSAPrivateKey):
        raise ValueError('File bukan RSA private key yang valid.')
    _log.debug(f'[Signer] Private key loaded: {Path(filepath).name}')
    return private_key

def load_public_key(filepath: str) -> RSAPublicKey:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f'Public key tidak ditemukan: {filepath}')
    pem_data = path.read_bytes()
    try:
        public_key = serialization.load_pem_public_key(pem_data)
    except (ValueError, TypeError) as e:
        raise ValueError(f'Gagal memuat public key: {e}. Pastikan file dalam format PEM yang valid.') from e
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError('File bukan RSA public key yang valid.')
    _log.debug(f'[Signer] Public key loaded: {Path(filepath).name}')
    return public_key

def sign_hash(private_key: RSAPrivateKey, hash_hex: str) -> tuple[bytes, float]:
    if not isinstance(hash_hex, str) or len(hash_hex) != 64:
        raise ValueError(f"Hash harus berupa hex string 64 karakter, diterima: panjang {(len(hash_hex) if isinstance(hash_hex, str) else 'bukan string')}")
    try:
        int(hash_hex, 16)
    except ValueError as e:
        raise ValueError(f'Hash bukan hex string valid: {hash_hex}') from e
    start_time = time.perf_counter()
    hash_bytes = hash_hex.encode('utf-8')
    signature = private_key.sign(hash_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    # VUL-004: Never log full signature bytes
    _log.debug(f'[Signer] Hash signed (RSA-PSS-SHA256) in {elapsed_ms:.2f} ms')
    return (signature, elapsed_ms)

def verify_signature(public_key: RSAPublicKey, hash_hex: str, signature: bytes) -> tuple[bool, float]:
    start_time = time.perf_counter()
    hash_bytes = hash_hex.encode('utf-8')
    try:
        public_key.verify(signature, hash_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        is_valid = True
    except InvalidSignature:
        is_valid = False
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    status = 'VALID' if is_valid else 'INVALID'
    _log.debug(f'[Signer] Signature verification: {status} ({elapsed_ms:.2f} ms)')
    return (is_valid, elapsed_ms)
