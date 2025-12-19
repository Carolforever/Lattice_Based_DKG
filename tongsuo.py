from __future__ import annotations

import ctypes
import ctypes.util
import os
from pathlib import Path
from typing import Any, Optional, Tuple

try:  # pragma: no cover - cryptography 是可选依赖
    from cryptography.exceptions import InvalidSignature, InvalidTag  # type: ignore
except Exception:  # pragma: no cover
    class InvalidTag(Exception):
        """Fallback InvalidTag when cryptography is unavailable."""

    class InvalidSignature(Exception):
        """Fallback InvalidSignature when cryptography is unavailable."""


class TongsuoUnavailableError(RuntimeError):
    """Raised when libcrypto from Tongsuo cannot be loaded."""


EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11
GCM_TAG_SIZE = 16
ED25519_PUBLIC_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
ED25519_SEED_SIZE = 32
ED25519_PRIVATE_SIZE = 64  # legacy (seed + public)
X25519_KEY_SIZE = 32
EVP_PKEY_ED25519 = 1087
EVP_PKEY_X25519 = 1034
EVP_PKEY_HKDF = 1036


# ---------------------------------------------------------------------------
# libcrypto loader & helpers
# ---------------------------------------------------------------------------

def _load_libcrypto() -> ctypes.CDLL:
    env_path = os.environ.get("TONGSUO_LIBCRYPTO_PATH")
    candidates: list[str] = []

    if env_path:
        candidates.append(env_path)

    root_candidate = Path(__file__).resolve().parent / "Tongsuo"
    for name in ("libcrypto.so", "libcrypto.dylib", "libcrypto.dll"):
        candidate = root_candidate / name
        if candidate.exists():
            candidates.append(str(candidate))

    found = ctypes.util.find_library("crypto")
    if found:
        candidates.append(found)

    last_error: Optional[Exception] = None
    for candidate in candidates:
        try:
            return ctypes.CDLL(candidate)
        except OSError as exc:  # pragma: no cover - depends on env
            last_error = exc

    raise TongsuoUnavailableError(
        "Unable to load Tongsuo libcrypto. Set TONGSUO_LIBCRYPTO_PATH to the "
        "built library (e.g. /path/to/Tongsuo/libcrypto.so)."
    ) from last_error


_lib = _load_libcrypto()
LIBCRYPTO_PATH = getattr(_lib, "_name", "")

_c_void_p = ctypes.c_void_p
_c_int = ctypes.c_int
_c_size_t = ctypes.c_size_t
_c_ulong = ctypes.c_ulong
_c_uchar_p = ctypes.POINTER(ctypes.c_ubyte)


def _error_message(context: str) -> str:
    parts: list[str] = []
    while True:
        err = _lib.ERR_get_error()
        if err == 0:
            break
        buf = ctypes.create_string_buffer(256)
        _lib.ERR_error_string_n(err, buf, len(buf))
        msg = buf.value.decode() or f"0x{err:x}"
        parts.append(msg)
    if not parts:
        return f"{context} failed without OpenSSL error information"
    return f"{context} failed: {'; '.join(parts)}"


# ---------------------------------------------------------------------------
# C API signatures
# ---------------------------------------------------------------------------

_lib.EVP_CIPHER_CTX_new.restype = _c_void_p
_lib.EVP_CIPHER_CTX_new.argtypes = []
_lib.EVP_CIPHER_CTX_free.restype = None
_lib.EVP_CIPHER_CTX_free.argtypes = [_c_void_p]

_lib.EVP_aes_128_gcm.restype = _c_void_p
_lib.EVP_aes_128_gcm.argtypes = []
_lib.EVP_aes_192_gcm.restype = _c_void_p
_lib.EVP_aes_192_gcm.argtypes = []
_lib.EVP_aes_256_gcm.restype = _c_void_p
_lib.EVP_aes_256_gcm.argtypes = []

_lib.EVP_EncryptInit_ex.restype = _c_int
_lib.EVP_EncryptInit_ex.argtypes = [_c_void_p, _c_void_p, _c_void_p, _c_void_p, _c_void_p]
_lib.EVP_EncryptUpdate.restype = _c_int
_lib.EVP_EncryptUpdate.argtypes = [_c_void_p, _c_void_p, ctypes.POINTER(_c_int), _c_void_p, _c_int]
_lib.EVP_EncryptFinal_ex.restype = _c_int
_lib.EVP_EncryptFinal_ex.argtypes = [_c_void_p, _c_void_p, ctypes.POINTER(_c_int)]

_lib.EVP_DecryptInit_ex.restype = _c_int
_lib.EVP_DecryptInit_ex.argtypes = [_c_void_p, _c_void_p, _c_void_p, _c_void_p, _c_void_p]
_lib.EVP_DecryptUpdate.restype = _c_int
_lib.EVP_DecryptUpdate.argtypes = [_c_void_p, _c_void_p, ctypes.POINTER(_c_int), _c_void_p, _c_int]
_lib.EVP_DecryptFinal_ex.restype = _c_int
_lib.EVP_DecryptFinal_ex.argtypes = [_c_void_p, _c_void_p, ctypes.POINTER(_c_int)]

_lib.EVP_CIPHER_CTX_ctrl.restype = _c_int
_lib.EVP_CIPHER_CTX_ctrl.argtypes = [_c_void_p, _c_int, _c_int, _c_void_p]

_lib.ERR_get_error.restype = _c_ulong
_lib.ERR_get_error.argtypes = []
_lib.ERR_error_string_n.restype = None
_lib.ERR_error_string_n.argtypes = [_c_ulong, ctypes.c_char_p, _c_size_t]

_lib.RAND_bytes.restype = _c_int
_lib.RAND_bytes.argtypes = [_c_uchar_p, _c_int]

_lib.EVP_PKEY_CTX_new_id.restype = _c_void_p
_lib.EVP_PKEY_CTX_new_id.argtypes = [_c_int, _c_void_p]
_lib.EVP_PKEY_CTX_free.restype = None
_lib.EVP_PKEY_CTX_free.argtypes = [_c_void_p]
_lib.EVP_PKEY_keygen_init.restype = _c_int
_lib.EVP_PKEY_keygen_init.argtypes = [_c_void_p]
_lib.EVP_PKEY_keygen.restype = _c_int
_lib.EVP_PKEY_keygen.argtypes = [_c_void_p, ctypes.POINTER(_c_void_p)]
_lib.EVP_PKEY_free.restype = None
_lib.EVP_PKEY_free.argtypes = [_c_void_p]
_lib.EVP_PKEY_get_raw_private_key.restype = _c_int
_lib.EVP_PKEY_get_raw_private_key.argtypes = [_c_void_p, _c_uchar_p, ctypes.POINTER(_c_size_t)]
_lib.EVP_PKEY_get_raw_public_key.restype = _c_int
_lib.EVP_PKEY_get_raw_public_key.argtypes = [_c_void_p, _c_uchar_p, ctypes.POINTER(_c_size_t)]
_lib.EVP_PKEY_new_raw_private_key.restype = _c_void_p
_lib.EVP_PKEY_new_raw_private_key.argtypes = [_c_int, _c_void_p, _c_uchar_p, _c_size_t]
_lib.EVP_PKEY_new_raw_public_key.restype = _c_void_p
_lib.EVP_PKEY_new_raw_public_key.argtypes = [_c_int, _c_void_p, _c_uchar_p, _c_size_t]
_lib.EVP_MD_CTX_new.restype = _c_void_p
_lib.EVP_MD_CTX_new.argtypes = []
_lib.EVP_MD_CTX_free.restype = None
_lib.EVP_MD_CTX_free.argtypes = [_c_void_p]
_lib.EVP_DigestSignInit.restype = _c_int
_lib.EVP_DigestSignInit.argtypes = [_c_void_p, ctypes.POINTER(_c_void_p), _c_void_p, _c_void_p, _c_void_p]
_lib.EVP_DigestSign.restype = _c_int
_lib.EVP_DigestSign.argtypes = [_c_void_p, _c_uchar_p, ctypes.POINTER(_c_size_t), _c_uchar_p, _c_size_t]
_lib.EVP_DigestVerifyInit.restype = _c_int
_lib.EVP_DigestVerifyInit.argtypes = [_c_void_p, ctypes.POINTER(_c_void_p), _c_void_p, _c_void_p, _c_void_p]
_lib.EVP_DigestVerify.restype = _c_int
_lib.EVP_DigestVerify.argtypes = [_c_void_p, _c_uchar_p, _c_size_t, _c_uchar_p, _c_size_t]

_lib.EVP_PKEY_CTX_new.restype = _c_void_p
_lib.EVP_PKEY_CTX_new.argtypes = [_c_void_p, _c_void_p]
_lib.EVP_PKEY_derive_init.restype = _c_int
_lib.EVP_PKEY_derive_init.argtypes = [_c_void_p]
_lib.EVP_PKEY_derive_set_peer.restype = _c_int
_lib.EVP_PKEY_derive_set_peer.argtypes = [_c_void_p, _c_void_p]
_lib.EVP_PKEY_derive.restype = _c_int
_lib.EVP_PKEY_derive.argtypes = [_c_void_p, _c_uchar_p, ctypes.POINTER(_c_size_t)]
_lib.EVP_PKEY_CTX_set_hkdf_md.restype = _c_int
_lib.EVP_PKEY_CTX_set_hkdf_md.argtypes = [_c_void_p, _c_void_p]
_lib.EVP_PKEY_CTX_set1_hkdf_salt.restype = _c_int
_lib.EVP_PKEY_CTX_set1_hkdf_salt.argtypes = [_c_void_p, _c_uchar_p, _c_int]
_lib.EVP_PKEY_CTX_set1_hkdf_key.restype = _c_int
_lib.EVP_PKEY_CTX_set1_hkdf_key.argtypes = [_c_void_p, _c_uchar_p, _c_int]
_lib.EVP_PKEY_CTX_add1_hkdf_info.restype = _c_int
_lib.EVP_PKEY_CTX_add1_hkdf_info.argtypes = [_c_void_p, _c_uchar_p, _c_int]

_lib.EVP_sha256.restype = _c_void_p
_lib.EVP_sha256.argtypes = []


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _to_buffer(data: bytes) -> Optional[ctypes.Array]:
    if not data:
        return None
    array_type = ctypes.c_ubyte * len(data)
    return array_type.from_buffer_copy(data)


def _ptr(buf: Optional[ctypes.Array]) -> Optional[_c_void_p]:
    if buf is None:
        return None
    return ctypes.cast(buf, _c_void_p)


def _rand_bytes(size: int) -> bytes:
    if size <= 0:
        raise ValueError("size must be positive")
    out = (ctypes.c_ubyte * size)()
    if _lib.RAND_bytes(out, size) != 1:
        raise RuntimeError(_error_message("RAND_bytes"))
    return bytes(out)


def _clamp_x25519_scalar(scalar: bytearray) -> None:
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64


def _data_buffer(data: bytes) -> Tuple[ctypes.Array, int]:
    if len(data) == 0:
        return (ctypes.c_ubyte * 1)(), 0
    array_type = ctypes.c_ubyte * len(data)
    return array_type.from_buffer_copy(data), len(data)


def _as_uchar_ptr(buf: Any):
    return ctypes.cast(buf, _c_uchar_p)


def _ed25519_new_private_pkey(seed: bytes) -> _c_void_p:
    if len(seed) != ED25519_SEED_SIZE:
        raise ValueError("Ed25519 seeds must be 32 bytes")
    seed_buf, seed_len = _data_buffer(seed)
    pkey = _lib.EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        None,
        _as_uchar_ptr(seed_buf),
        seed_len,
    )
    if not pkey:
        raise RuntimeError(_error_message("EVP_PKEY_new_raw_private_key(Ed25519)"))
    return pkey


def _ed25519_new_public_pkey(public: bytes) -> _c_void_p:
    if len(public) != ED25519_PUBLIC_SIZE:
        raise ValueError("Ed25519 public keys must be 32 bytes")
    pub_buf, pub_len = _data_buffer(public)
    pkey = _lib.EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        None,
        _as_uchar_ptr(pub_buf),
        pub_len,
    )
    if not pkey:
        raise RuntimeError(_error_message("EVP_PKEY_new_raw_public_key(Ed25519)"))
    return pkey


def _evp_pkey_get_raw_private_key_bytes(pkey: _c_void_p, size: int) -> bytes:
    buf = (ctypes.c_ubyte * size)()
    buf_len = _c_size_t(size)
    if _lib.EVP_PKEY_get_raw_private_key(pkey, _as_uchar_ptr(buf), ctypes.byref(buf_len)) != 1:
        raise RuntimeError(_error_message("EVP_PKEY_get_raw_private_key"))
    return bytes(buf)[: buf_len.value]


def _evp_pkey_get_raw_public_key_bytes(pkey: _c_void_p, size: int) -> bytes:
    buf = (ctypes.c_ubyte * size)()
    buf_len = _c_size_t(size)
    if _lib.EVP_PKEY_get_raw_public_key(pkey, _as_uchar_ptr(buf), ctypes.byref(buf_len)) != 1:
        raise RuntimeError(_error_message("EVP_PKEY_get_raw_public_key"))
    return bytes(buf)[: buf_len.value]


def _ed25519_extract_private_seed(pkey: _c_void_p) -> bytes:
    return _evp_pkey_get_raw_private_key_bytes(pkey, ED25519_SEED_SIZE)


def _ed25519_extract_public_key(pkey: _c_void_p) -> bytes:
    return _evp_pkey_get_raw_public_key_bytes(pkey, ED25519_PUBLIC_SIZE)


def _ed25519_generate_raw_keypair() -> Tuple[bytes, bytes]:
    ctx = _lib.EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, None)
    if not ctx:
        raise RuntimeError(_error_message("EVP_PKEY_CTX_new_id(Ed25519)"))
    try:
        if _lib.EVP_PKEY_keygen_init(ctx) != 1:
            raise RuntimeError(_error_message("EVP_PKEY_keygen_init(Ed25519)"))
        pkey = _c_void_p()
        if _lib.EVP_PKEY_keygen(ctx, ctypes.byref(pkey)) != 1 or not pkey:
            raise RuntimeError(_error_message("EVP_PKEY_keygen(Ed25519)"))
    finally:
        _lib.EVP_PKEY_CTX_free(ctx)

    try:
        seed = _ed25519_extract_private_seed(pkey)
        public = _ed25519_extract_public_key(pkey)
        return seed, public
    finally:
        _lib.EVP_PKEY_free(pkey)


def _ed25519_derive_public_from_seed(seed: bytes) -> bytes:
    pkey = _ed25519_new_private_pkey(seed)
    try:
        return _ed25519_extract_public_key(pkey)
    finally:
        _lib.EVP_PKEY_free(pkey)


def _x25519_new_private_pkey(private: bytes) -> _c_void_p:
    if len(private) != X25519_KEY_SIZE:
        raise ValueError("X25519 private keys must be 32 bytes")
    priv_buf, priv_len = _data_buffer(private)
    pkey = _lib.EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519,
        None,
        _as_uchar_ptr(priv_buf),
        priv_len,
    )
    if not pkey:
        raise RuntimeError(_error_message("EVP_PKEY_new_raw_private_key(X25519)"))
    return pkey


def _x25519_new_public_pkey(public: bytes) -> _c_void_p:
    if len(public) != X25519_KEY_SIZE:
        raise ValueError("X25519 public keys must be 32 bytes")
    pub_buf, pub_len = _data_buffer(public)
    pkey = _lib.EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        None,
        _as_uchar_ptr(pub_buf),
        pub_len,
    )
    if not pkey:
        raise RuntimeError(_error_message("EVP_PKEY_new_raw_public_key(X25519)"))
    return pkey


def _x25519_derive_public(private: bytes) -> bytes:
    pkey = _x25519_new_private_pkey(private)
    try:
        return _evp_pkey_get_raw_public_key_bytes(pkey, X25519_KEY_SIZE)
    finally:
        _lib.EVP_PKEY_free(pkey)


def _x25519_exchange(private: bytes, peer_public: bytes) -> bytes:
    priv_pkey = _x25519_new_private_pkey(private)
    peer_pkey = _x25519_new_public_pkey(peer_public)
    try:
        ctx = _lib.EVP_PKEY_CTX_new(priv_pkey, None)
        if not ctx:
            raise RuntimeError(_error_message("EVP_PKEY_CTX_new(X25519)"))
        try:
            if _lib.EVP_PKEY_derive_init(ctx) != 1:
                raise RuntimeError(_error_message("EVP_PKEY_derive_init"))
            if _lib.EVP_PKEY_derive_set_peer(ctx, peer_pkey) != 1:
                raise RuntimeError(_error_message("EVP_PKEY_derive_set_peer"))
            shared = (ctypes.c_ubyte * X25519_KEY_SIZE)()
            shared_len = _c_size_t(X25519_KEY_SIZE)
            if _lib.EVP_PKEY_derive(ctx, _as_uchar_ptr(shared), ctypes.byref(shared_len)) != 1:
                raise RuntimeError(_error_message("EVP_PKEY_derive"))
            return bytes(shared)[: shared_len.value]
        finally:
            _lib.EVP_PKEY_CTX_free(ctx)
    finally:
        _lib.EVP_PKEY_free(peer_pkey)
        _lib.EVP_PKEY_free(priv_pkey)


# ---------------------------------------------------------------------------
# AES-GCM implementation
# ---------------------------------------------------------------------------


class TongsuoAESGCM:
    """Minimal AES-GCM wrapper around Tongsuo's EVP interface."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES-GCM key must be 128, 192, or 256 bits long")
        self._key = bytes(key)
        self._cipher = self._select_cipher(len(key))

    @staticmethod
    def _select_cipher(key_len: int) -> _c_void_p:
        if key_len == 16:
            cipher = _lib.EVP_aes_128_gcm()
        elif key_len == 24:
            cipher = _lib.EVP_aes_192_gcm()
        else:
            cipher = _lib.EVP_aes_256_gcm()
        if not cipher:
            raise RuntimeError("Failed to obtain AES-GCM cipher from Tongsuo")
        return cipher

    def encrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        ctx = _lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise RuntimeError("Unable to allocate EVP_CIPHER_CTX")
        try:
            self._encrypt_init(ctx, nonce)
            if associated_data:
                self._process_aad(ctx, associated_data)
            ciphertext = self._process_cipher(ctx, data, encrypt=True)
            self._finalize_encrypt(ctx)
            tag = self._get_tag(ctx)
            return ciphertext + tag
        finally:
            _lib.EVP_CIPHER_CTX_free(ctx)

    def decrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        if len(data) < GCM_TAG_SIZE:
            raise ValueError("Ciphertext too short to contain GCM tag")
        ciphertext = data[:-GCM_TAG_SIZE]
        tag = data[-GCM_TAG_SIZE:]

        ctx = _lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise RuntimeError("Unable to allocate EVP_CIPHER_CTX")
        try:
            self._decrypt_init(ctx, nonce)
            if associated_data:
                self._process_aad(ctx, associated_data)
            plaintext = self._process_cipher(ctx, ciphertext, encrypt=False)
            self._set_expected_tag(ctx, tag)
            self._finalize_decrypt(ctx)
            return plaintext
        finally:
            _lib.EVP_CIPHER_CTX_free(ctx)

    def _encrypt_init(self, ctx: _c_void_p, nonce: bytes) -> None:
        if _lib.EVP_EncryptInit_ex(ctx, self._cipher, None, None, None) != 1:
            raise RuntimeError(_error_message("EVP_EncryptInit_ex"))
        if _lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
            raise RuntimeError(_error_message("EVP_CIPHER_CTX_ctrl(SET_IVLEN)"))
        key_buf = _to_buffer(self._key)
        nonce_buf = _to_buffer(nonce)
        if _lib.EVP_EncryptInit_ex(ctx, None, None, _ptr(key_buf), _ptr(nonce_buf)) != 1:
            raise RuntimeError(_error_message("EVP_EncryptInit_ex(key, iv)"))

    def _decrypt_init(self, ctx: _c_void_p, nonce: bytes) -> None:
        if _lib.EVP_DecryptInit_ex(ctx, self._cipher, None, None, None) != 1:
            raise RuntimeError(_error_message("EVP_DecryptInit_ex"))
        if _lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
            raise RuntimeError(_error_message("EVP_CIPHER_CTX_ctrl(SET_IVLEN)"))
        key_buf = _to_buffer(self._key)
        nonce_buf = _to_buffer(nonce)
        if _lib.EVP_DecryptInit_ex(ctx, None, None, _ptr(key_buf), _ptr(nonce_buf)) != 1:
            raise RuntimeError(_error_message("EVP_DecryptInit_ex(key, iv)"))

    def _finalize_encrypt(self, ctx: _c_void_p) -> None:
        out_len = _c_int(0)
        if _lib.EVP_EncryptFinal_ex(ctx, None, ctypes.byref(out_len)) != 1:
            raise RuntimeError(_error_message("EVP_EncryptFinal_ex"))

    def _finalize_decrypt(self, ctx: _c_void_p) -> None:
        out_len = _c_int(0)
        if _lib.EVP_DecryptFinal_ex(ctx, None, ctypes.byref(out_len)) != 1:
            raise InvalidTag("Tongsuo AES-GCM authentication failed")

    def _process_aad(self, ctx: _c_void_p, aad: bytes) -> None:
        aad_buf = _to_buffer(aad)
        out_len = _c_int(0)
        if _lib.EVP_EncryptUpdate(ctx, None, ctypes.byref(out_len), _ptr(aad_buf), len(aad)) != 1:
            raise RuntimeError(_error_message("EVP_EncryptUpdate(AAD)"))

    def _process_cipher(self, ctx: _c_void_p, data: bytes, *, encrypt: bool) -> bytes:
        if not data:
            return b""
        in_buf = _to_buffer(data)
        out_buf = (ctypes.c_ubyte * len(data))()
        out_ptr = _ptr(out_buf)
        in_ptr = _ptr(in_buf)
        out_len = _c_int(0)
        func = _lib.EVP_EncryptUpdate if encrypt else _lib.EVP_DecryptUpdate
        if func(ctx, out_ptr, ctypes.byref(out_len), in_ptr, len(data)) != 1:
            op = "Encrypt" if encrypt else "Decrypt"
            raise RuntimeError(_error_message(f"EVP_{op}Update"))
        return bytes(bytearray(out_buf)[: out_len.value])

    def _get_tag(self, ctx: _c_void_p) -> bytes:
        tag_buf = (ctypes.c_ubyte * GCM_TAG_SIZE)()
        if _lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, _ptr(tag_buf)) != 1:
            raise RuntimeError(_error_message("EVP_CIPHER_CTX_ctrl(GET_TAG)"))
        return bytes(tag_buf)

    def _set_expected_tag(self, ctx: _c_void_p, tag: bytes) -> None:
        tag_buf = _to_buffer(tag)
        if _lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, len(tag), _ptr(tag_buf)) != 1:
            raise RuntimeError(_error_message("EVP_CIPHER_CTX_ctrl(SET_TAG)"))


# ---------------------------------------------------------------------------
# Ed25519 primitives
# ---------------------------------------------------------------------------


class Ed25519PublicKey:
    def __init__(self, public_bytes: bytes):
        if len(public_bytes) != ED25519_PUBLIC_SIZE:
            raise ValueError("Ed25519 public keys must be 32 bytes")
        self._public_bytes = bytes(public_bytes)

    @staticmethod
    def from_public_bytes(data: bytes) -> "Ed25519PublicKey":
        return Ed25519PublicKey(data)

    def public_bytes(self) -> bytes:
        return self._public_bytes

    def _as_evp_pkey(self) -> _c_void_p:
        return _ed25519_new_public_pkey(self._public_bytes)

    def verify(self, signature: bytes, message: bytes) -> None:
        if len(signature) != ED25519_SIGNATURE_SIZE:
            raise ValueError("Ed25519 signatures must be 64 bytes")
        sig_buf, sig_len = _data_buffer(signature)
        msg_buf, msg_len = _data_buffer(message)
        pkey = self._as_evp_pkey()
        md_ctx = _lib.EVP_MD_CTX_new()
        if not md_ctx:
            _lib.EVP_PKEY_free(pkey)
            raise RuntimeError("EVP_MD_CTX_new failed")
        try:
            if _lib.EVP_DigestVerifyInit(md_ctx, None, None, None, pkey) != 1:
                raise RuntimeError(_error_message("EVP_DigestVerifyInit"))
            result = _lib.EVP_DigestVerify(
                md_ctx,
                _as_uchar_ptr(sig_buf),
                sig_len,
                _as_uchar_ptr(msg_buf),
                msg_len,
            )
            if result != 1:
                raise InvalidSignature("Ed25519 signature verification failed")
        finally:
            _lib.EVP_MD_CTX_free(md_ctx)
            _lib.EVP_PKEY_free(pkey)


class Ed25519PrivateKey:
    def __init__(self, private_bytes: bytes, public_bytes: Optional[bytes] = None):
        private_bytes = bytes(private_bytes)
        if len(private_bytes) == ED25519_SEED_SIZE:
            seed = private_bytes
            pub = bytes(public_bytes) if public_bytes is not None else _ed25519_derive_public_from_seed(seed)
            private_combined = seed + pub
        elif len(private_bytes) == ED25519_PRIVATE_SIZE:
            seed = private_bytes[:ED25519_SEED_SIZE]
            pub = bytes(public_bytes) if public_bytes is not None else private_bytes[ED25519_SEED_SIZE:]
            private_combined = private_bytes
        else:
            raise ValueError("Ed25519 private keys must be 32-byte seeds or 64-byte seed+pub")

        if len(pub) != ED25519_PUBLIC_SIZE:
            raise ValueError("Ed25519 public keys must be 32 bytes")

        self._private_seed = seed
        self._private_bytes = private_combined
        self._public_key = Ed25519PublicKey(pub)

    @staticmethod
    def generate() -> "Ed25519PrivateKey":
        seed, public = _ed25519_generate_raw_keypair()
        return Ed25519PrivateKey(seed + public, public)

    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def public_bytes(self) -> bytes:
        return self._public_key.public_bytes()

    def sign(self, message: bytes) -> bytes:
        pkey = _ed25519_new_private_pkey(self._private_seed)
        md_ctx = _lib.EVP_MD_CTX_new()
        if not md_ctx:
            _lib.EVP_PKEY_free(pkey)
            raise RuntimeError("EVP_MD_CTX_new failed")
        try:
            if _lib.EVP_DigestSignInit(md_ctx, None, None, None, pkey) != 1:
                raise RuntimeError(_error_message("EVP_DigestSignInit"))
            sig_buf = (ctypes.c_ubyte * ED25519_SIGNATURE_SIZE)()
            sig_len = _c_size_t(ED25519_SIGNATURE_SIZE)
            msg_buf, msg_len = _data_buffer(message)
            if _lib.EVP_DigestSign(
                md_ctx,
                _as_uchar_ptr(sig_buf),
                ctypes.byref(sig_len),
                _as_uchar_ptr(msg_buf),
                msg_len,
            ) != 1:
                raise RuntimeError(_error_message("EVP_DigestSign"))
            return bytes(sig_buf)[: sig_len.value]
        finally:
            _lib.EVP_MD_CTX_free(md_ctx)
            _lib.EVP_PKEY_free(pkey)


# ---------------------------------------------------------------------------
# X25519 primitives
# ---------------------------------------------------------------------------


class X25519PublicKey:
    def __init__(self, public_bytes: bytes):
        if len(public_bytes) != X25519_KEY_SIZE:
            raise ValueError("X25519 public keys must be 32 bytes")
        self._public_bytes = bytes(public_bytes)

    @staticmethod
    def from_public_bytes(data: bytes) -> "X25519PublicKey":
        return X25519PublicKey(data)

    def public_bytes(self) -> bytes:
        return self._public_bytes


class X25519PrivateKey:
    def __init__(self, private_bytes: bytes):
        if len(private_bytes) != X25519_KEY_SIZE:
            raise ValueError("X25519 private keys must be 32 bytes")
        scalar = bytearray(private_bytes)
        _clamp_x25519_scalar(scalar)
        self._private_bytes = bytes(scalar)
        self._public_key = self._derive_public_key()

    @staticmethod
    def generate() -> "X25519PrivateKey":
        secret = bytearray(_rand_bytes(X25519_KEY_SIZE))
        _clamp_x25519_scalar(secret)
        return X25519PrivateKey(bytes(secret))

    @staticmethod
    def from_private_bytes(data: bytes) -> "X25519PrivateKey":
        return X25519PrivateKey(data)

    def _derive_public_key(self) -> X25519PublicKey:
        public = _x25519_derive_public(self._private_bytes)
        return X25519PublicKey(public)

    def public_key(self) -> X25519PublicKey:
        return self._public_key

    def exchange(self, peer_public: X25519PublicKey) -> bytes:
        return _x25519_exchange(self._private_bytes, peer_public.public_bytes())


# ---------------------------------------------------------------------------
# HKDF (SHA-256 only, matching CryptoManager usage)
# ---------------------------------------------------------------------------


def hkdf_sha256(ikm: bytes, *, length: int, salt: Optional[bytes] = None, info: Optional[bytes] = None) -> bytes:
    if length <= 0:
        raise ValueError("length must be positive")
    digest = _lib.EVP_sha256()
    if not digest:
        raise RuntimeError("EVP_sha256 unavailable in Tongsuo")

    ctx = _lib.EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, None)
    if not ctx:
        raise RuntimeError(_error_message("EVP_PKEY_CTX_new_id(HKDF)"))
    try:
        if _lib.EVP_PKEY_derive_init(ctx) != 1:
            raise RuntimeError(_error_message("EVP_PKEY_derive_init(HKDF)"))
        if _lib.EVP_PKEY_CTX_set_hkdf_md(ctx, digest) != 1:
            raise RuntimeError(_error_message("EVP_PKEY_CTX_set_hkdf_md"))

        salt_bytes = salt or b""
        if salt_bytes:
            salt_buf, salt_len = _data_buffer(salt_bytes)
            salt_ptr = _as_uchar_ptr(salt_buf)
        else:
            salt_ptr = None
            salt_len = 0
        if _lib.EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt_ptr, salt_len) != 1:
            raise RuntimeError(_error_message("EVP_PKEY_CTX_set1_hkdf_salt"))

        ikm_buf, ikm_len = _data_buffer(ikm)
        if _lib.EVP_PKEY_CTX_set1_hkdf_key(ctx, _as_uchar_ptr(ikm_buf), ikm_len) != 1:
            raise RuntimeError(_error_message("EVP_PKEY_CTX_set1_hkdf_key"))

        info_bytes = info or b""
        if info_bytes:
            info_buf, info_len = _data_buffer(info_bytes)
            if _lib.EVP_PKEY_CTX_add1_hkdf_info(ctx, _as_uchar_ptr(info_buf), info_len) != 1:
                raise RuntimeError(_error_message("EVP_PKEY_CTX_add1_hkdf_info"))

        out_buf = (ctypes.c_ubyte * length)()
        out_len = _c_size_t(length)
        if _lib.EVP_PKEY_derive(ctx, _as_uchar_ptr(out_buf), ctypes.byref(out_len)) != 1:
            raise RuntimeError(_error_message("EVP_PKEY_derive(HKDF)"))
        if out_len.value != length:
            raise RuntimeError("HKDF derived unexpected length")
        return bytes(out_buf)
    finally:
        _lib.EVP_PKEY_CTX_free(ctx)


AESGCM = TongsuoAESGCM

__all__ = [
    "TongsuoAESGCM",
    "AESGCM",
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
    "X25519PrivateKey",
    "X25519PublicKey",
    "hkdf_sha256",
    "InvalidSignature",
    "InvalidTag",
    "TongsuoUnavailableError",
    "LIBCRYPTO_PATH",
]
