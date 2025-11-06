"""Symmetric cryptography utilities used by the distributed V3S protocol."""

import json
import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoManager:
    """加密管理器，处理对称加密 / Handles key derivation and AES-GCM encryption/decryption."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """从密码派生密钥 / Derive a symmetric key from the shared password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_data(data: dict, key: bytes) -> Tuple[bytes, bytes]:
        """使用AES-GCM加密数据 / Encrypt serialized data with AES-GCM."""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        serialized_data = json.dumps(data).encode()
        ciphertext = aesgcm.encrypt(nonce, serialized_data, None)
        return ciphertext, nonce

    @staticmethod
    def decrypt_data(ciphertext: bytes, nonce: bytes, key: bytes) -> dict:
        """使用AES-GCM解密数据 / Decrypt ciphertext produced by AES-GCM."""
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())
