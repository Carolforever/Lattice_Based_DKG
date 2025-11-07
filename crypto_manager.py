"""Symmetric and asymmetric cryptography utilities for the distributed V3S protocol."""

import base64
import json
import os
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from data_models import EncryptedSharePackage


class CryptoManager:
    """加密管理器，处理密钥派生、KEM封装以及签名校验."""

    KEM_INFO = b"v3s-kem-share"

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

    # —— KEM 与签名相关工具 ——

    @staticmethod
    def generate_signature_keypair() -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
        """生成Ed25519签名密钥对 / Generate an Ed25519 signing key pair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return private_key, public_key

    @staticmethod
    def generate_kem_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
        """生成X25519密钥对用于KEM封装 / Generate an X25519 key pair for KEM encapsulation."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return private_key, public_key

    @staticmethod
    def encapsulate_key(receiver_public_bytes: bytes, context: bytes) -> Tuple[bytes, bytes]:
        """使用接收者公钥封装对称密钥，返回(对称密钥, 发送方临时公钥)."""
        receiver_public = x25519.X25519PublicKey.from_public_bytes(receiver_public_bytes)
        ephemeral_private = x25519.X25519PrivateKey.generate()
        shared_secret = ephemeral_private.exchange(receiver_public)
        symmetric_key = CryptoManager._derive_symmetric_key(shared_secret, context)
        ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return symmetric_key, ephemeral_public_bytes

    @staticmethod
    def decapsulate_key(ephemeral_public_bytes: bytes, receiver_private: x25519.X25519PrivateKey, context: bytes) -> bytes:
        """解封装对称密钥 / Decapsulate the symmetric key using receiver's private key."""
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
        shared_secret = receiver_private.exchange(ephemeral_public)
        return CryptoManager._derive_symmetric_key(shared_secret, context)

    @staticmethod
    def sign_message(message: bytes, signing_private: ed25519.Ed25519PrivateKey) -> bytes:
        """对消息进行签名 / Sign a message with Ed25519."""
        return signing_private.sign(message)

    @staticmethod
    def verify_signature(signature: bytes, message: bytes, signing_public_bytes: bytes) -> bool:
        """验证Ed25519签名，返回是否有效."""
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(signing_public_bytes)
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def serialize_share_package(package: EncryptedSharePackage, include_signature: bool = False) -> bytes:
        """序列化加密份额包用于签名 / Serialize package deterministically for signing."""
        payload = {
            'sender_id': package.sender_id,
            'receiver_id': package.receiver_id,
            'nonce': base64.b64encode(package.nonce).decode(),
            'encrypted_data': base64.b64encode(package.encrypted_data).decode(),
            'kem_public': base64.b64encode(package.kem_public).decode(),
            'key_signature': base64.b64encode(package.key_signature).decode(),
        }

        if include_signature and package.signature:
            payload['signature'] = base64.b64encode(package.signature).decode()

        return json.dumps(payload, sort_keys=True).encode()

    @staticmethod
    def serialize_complaint_evidence(package: EncryptedSharePackage, symmetric_key: bytes) -> bytes:
        """序列化投诉证据供投诉者签名 / Serialize complaint evidence for signing."""
        payload = {
            'sender_id': package.sender_id,
            'receiver_id': package.receiver_id,
            'nonce': base64.b64encode(package.nonce).decode(),
            'encrypted_data': base64.b64encode(package.encrypted_data).decode(),
            'kem_public': base64.b64encode(package.kem_public).decode(),
            'symmetric_key': base64.b64encode(symmetric_key).decode(),
            'sender_key_signature': base64.b64encode(package.key_signature).decode(),
        }
        return json.dumps(payload, sort_keys=True).encode()

    @staticmethod
    def serialize_key_binding(sender_id: int, receiver_id: int, symmetric_key: bytes) -> bytes:
        """序列化发送者对对称密钥的绑定信息 / Serialize key binding for signing and verification."""
        payload = {
            'receiver_id': receiver_id,
            'sender_id': sender_id,
            'symmetric_key': base64.b64encode(symmetric_key).decode(),
        }
        return json.dumps(payload, sort_keys=True).encode()

    @staticmethod
    def _derive_symmetric_key(shared_secret: bytes, context: bytes) -> bytes:
        """通过HKDF从共享秘密导出对称密钥."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=context or CryptoManager.KEM_INFO,
            backend=default_backend(),
        )
        return hkdf.derive(shared_secret)
