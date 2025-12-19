from __future__ import annotations

import base64
import hashlib
import json
import math
import time
import threading
import asyncio
import pickle
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union
from dataclasses import dataclass, field
from queue import Queue
import numpy as np
import os
import sys
import datetime
from pathlib import Path
import atexit

from secure_rng import SecureRandom

TONGSUO_LOAD_ERROR: Optional[Exception] = None
AESCIPHER_SOURCE = ""
try:
    from tongsuo import (
        TongsuoAESGCM as AESGCMImpl,
        Ed25519PrivateKey,
        Ed25519PublicKey,
        X25519PrivateKey,
        X25519PublicKey,
        hkdf_sha256,
        InvalidSignature,
        LIBCRYPTO_PATH,
    )

    AES_BACKEND = "tongsuo"
    AESCIPHER_SOURCE = LIBCRYPTO_PATH
except Exception as exc:  # noqa: BLE001 - 显式要求依赖 Tongsuo
    TONGSUO_LOAD_ERROR = exc
    raise RuntimeError(
        "无法加载 Tongsuo 提供的密码学原语，请先构建 libcrypto 并设置 TONGSUO_LIBCRYPTO_PATH"
    ) from exc

PRIME = 12289
RING_DEGREE = 8  # degree n of X^n + 1
LOG_DIR = Path(__file__).resolve().parent / "log"
RUN_LOG_HANDLE = None
CURRENT_LOG_PATH: Optional[Path] = None


def setup_run_logger() -> Path:
    """在 ./log 目录创建按日期递增的日志文件并重定向标准输出/错误。"""
    global RUN_LOG_HANDLE, CURRENT_LOG_PATH
    if RUN_LOG_HANDLE is not None and CURRENT_LOG_PATH is not None:
        return CURRENT_LOG_PATH

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    date_str = datetime.datetime.now().strftime("%Y%m%d")

    sequence = 1
    for path in sorted(LOG_DIR.glob(f"{date_str}-*.log")):
        stem = path.stem
        if not stem.startswith(date_str + "-"):
            continue
        suffix = stem[len(date_str) + 1 :]
        if suffix.isdigit():
            sequence = max(sequence, int(suffix) + 1)

    log_path = LOG_DIR / f"{date_str}-{sequence:03d}.log"
    RUN_LOG_HANDLE = open(log_path, "w", encoding="utf-8")
    CURRENT_LOG_PATH = log_path
    sys.stdout = RUN_LOG_HANDLE  # type: ignore[assignment]
    sys.stderr = RUN_LOG_HANDLE  # type: ignore[assignment]
    atexit.register(RUN_LOG_HANDLE.close)
    return log_path


def _center(value: int, modulus: int) -> int:
    """将模 q 系数映射到 [-q/2, q/2] 区间，方便做范数计算。"""
    half = modulus // 2
    value %= modulus
    if value > half:
        value -= modulus
    return value


_NTT_ROOT_CACHE: Dict[Tuple[int, int], Tuple[int, int]] = {}
_NTT_FACTOR_CACHE: Dict[int, Set[int]] = {}
_NTT_NAIVE_THRESHOLD = 32


def _prime_factors(n: int) -> Set[int]:
    """返回整数 n 的素因子集合，结果会被缓存复用。"""
    if n in _NTT_FACTOR_CACHE:
        return _NTT_FACTOR_CACHE[n]

    factors: Set[int] = set()
    remaining = n
    divisor = 2
    while divisor * divisor <= remaining:
        if remaining % divisor == 0:
            factors.add(divisor)
            while remaining % divisor == 0:
                remaining //= divisor
        divisor = 3 if divisor == 2 else divisor + 2
    if remaining > 1:
        factors.add(remaining)

    _NTT_FACTOR_CACHE[n] = factors
    return factors


def _get_ntt_roots(modulus: int, size: int) -> Tuple[int, int]:
    """获取给定模数与长度的原始根及其逆元（NTT）."""
    if size <= 1:
        raise ValueError("NTT size must be greater than 1")
    if (modulus - 1) % size != 0:
        raise ValueError("Modulus does not support requested NTT size")
    if size & (size - 1):
        raise ValueError("NTT size must be a power of two")

    cache_key = (modulus, size)
    if cache_key in _NTT_ROOT_CACHE:
        return _NTT_ROOT_CACHE[cache_key]

    order_factors = _prime_factors(size)
    exponent = (modulus - 1) // size

    for candidate in range(2, modulus):
        root = pow(candidate, exponent, modulus)
        if root == 1:
            continue
        is_primitive = True
        for factor in order_factors:
            if pow(root, size // factor, modulus) == 1:
                is_primitive = False
                break
        if is_primitive:
            inv_root = pow(root, modulus - 2, modulus)
            _NTT_ROOT_CACHE[cache_key] = (root, inv_root)
            return root, inv_root

    raise ValueError("Unable to find primitive root for NTT")


def _ntt_inplace(vec: List[int], modulus: int, root: int) -> None:
    """原地执行Cooley–Tukey NTT 或 INTT（传入对应根）。"""
    n = len(vec)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            vec[i], vec[j] = vec[j], vec[i]

    length = 2
    while length <= n:
        step = pow(root, n // length, modulus)
        for start in range(0, n, length):
            w = 1
            half = length // 2
            for idx in range(start, start + half):
                u = vec[idx]
                v = (vec[idx + half] * w) % modulus
                vec[idx] = (u + v) % modulus
                vec[idx + half] = (u - v) % modulus
                w = (w * step) % modulus
        length <<= 1


def _bit_reverse_indices(size: int) -> np.ndarray:
    """生成给定长度的位反序索引（NumPy 版本）。"""
    bits = (size - 1).bit_length()
    indices = np.arange(size, dtype=np.uint32)
    reversed_indices = np.zeros(size, dtype=np.uint32)
    for bit in range(bits):
        reversed_indices |= ((indices >> bit) & 1) << (bits - 1 - bit)
    return reversed_indices


def _ntt_inplace_numpy(vec: np.ndarray, modulus: int, root: int) -> None:
    """使用 NumPy 加速的原地 NTT/INTT 实现。"""
    n = vec.size
    bit_reversed = _bit_reverse_indices(n)
    vec[:] = vec[bit_reversed]

    length = 2
    while length <= n:
        half = length // 2
        step = pow(root, n // length, modulus)
        w_pows = np.array([pow(step, k, modulus) for k in range(half)], dtype=np.int64)
        blocks = vec.reshape(-1, length)
        left = blocks[:, :half].copy()
        right = blocks[:, half:]
        right = (right * w_pows) % modulus
        blocks[:, :half] = (left + right) % modulus
        blocks[:, half:] = (left - right) % modulus
        length <<= 1


def _negacyclic_ntt_convolution(
    a: Sequence[int],
    b: Sequence[int],
    modulus: int,
    degree: int,
) -> List[int]:
    """使用 NTT 计算 (a * b) mod (X^degree + 1, modulus)。"""
    conv_len = 1
    target = degree * 2
    while conv_len < target:
        conv_len <<= 1

    root, inv_root = _get_ntt_roots(modulus, conv_len)
    use_numpy = np is not None
    if not use_numpy:
        a_pad = list(a) + [0] * (conv_len - degree)
        b_pad = list(b) + [0] * (conv_len - degree)
    else:
        a_pad = np.zeros(conv_len, dtype=np.int64)
        b_pad = np.zeros(conv_len, dtype=np.int64)
        a_pad[:degree] = a
        b_pad[:degree] = b

    if use_numpy:
        _ntt_inplace_numpy(a_pad, modulus, root)
        _ntt_inplace_numpy(b_pad, modulus, root)
        a_pad = (a_pad * b_pad) % modulus
        _ntt_inplace_numpy(a_pad, modulus, inv_root)
        inv_len = pow(conv_len, modulus - 2, modulus)
        a_pad = (a_pad * inv_len) % modulus
        coeff_source = a_pad.tolist()
    else:
        _ntt_inplace(a_pad, modulus, root)
        _ntt_inplace(b_pad, modulus, root)
        for idx in range(conv_len):
            a_pad[idx] = (a_pad[idx] * b_pad[idx]) % modulus

        _ntt_inplace(a_pad, modulus, inv_root)
        inv_len = pow(conv_len, modulus - 2, modulus)
        for idx in range(conv_len):
            a_pad[idx] = (a_pad[idx] * inv_len) % modulus
        coeff_source = a_pad

    result = coeff_source[:degree]
    for idx in range(degree, min(2 * degree, conv_len)):
        coeff = coeff_source[idx]
        if coeff:
            result[idx - degree] = (result[idx - degree] - coeff) % modulus
    return result


def _negacyclic_naive_convolution(
    a: Sequence[int],
    b: Sequence[int],
    modulus: int,
    degree: int,
) -> List[int]:
    """朴素的 O(n^2) 卷积实现 (X^n + 1) 模。"""
    result = [0] * degree
    for i, coeff_a in enumerate(a):
        if coeff_a == 0:
            continue
        for j, coeff_b in enumerate(b):
            if coeff_b == 0:
                continue
            deg = i + j
            product = (coeff_a * coeff_b) % modulus
            if deg < degree:
                result[deg] = (result[deg] + product) % modulus
            else:
                idx = deg - degree
                result[idx] = (result[idx] - product) % modulus
    return result


class PolyR:
    """R_q = Z_q[X]/(X^n + 1) 中的环元素抽象，封装常见算术操作。"""

    __slots__ = ("coeffs", "modulus", "degree")

    def __init__(self, coeffs: Sequence[int], modulus: int = PRIME, degree: int = RING_DEGREE):
        """创建多项式，长度必须等于 degree，并会自动做模规约。"""
        if len(coeffs) != degree:
            raise ValueError(f"Polynomial must have exactly {degree} coefficients")
        self.modulus = modulus
        self.degree = degree
        self.coeffs = [int(c) % modulus for c in coeffs]

    @staticmethod
    def zero(modulus: int = PRIME, degree: int = RING_DEGREE) -> "PolyR":
        """返回零多项式。"""
        return PolyR([0] * degree, modulus, degree)

    @staticmethod
    def one(modulus: int = PRIME, degree: int = RING_DEGREE) -> "PolyR":
        """返回常数项为 1 的单位多项式。"""
        coeffs = [0] * degree
        coeffs[0] = 1
        return PolyR(coeffs, modulus, degree)

    def copy(self) -> "PolyR":
        """生成当前多项式的深拷贝。"""
        return PolyR(list(self.coeffs), self.modulus, self.degree)

    # Arithmetic ---------------------------------------------------------
    def _check(self, other: "PolyR") -> None:
        """确保参与运算的多项式位于相同的环参数。"""
        if self.modulus != other.modulus or self.degree != other.degree:
            raise ValueError("Mismatched ring parameters for PolyR operation")

    def __add__(self, other: "PolyR") -> "PolyR":
        """逐系数相加并模规约，实现环加法。"""
        self._check(other)
        return PolyR(
            [(a + b) % self.modulus for a, b in zip(self.coeffs, other.coeffs)],
            self.modulus,
            self.degree,
        )

    def __sub__(self, other: "PolyR") -> "PolyR":
        """逐系数相减并模规约，实现环减法。"""
        self._check(other)
        return PolyR(
            [(a - b) % self.modulus for a, b in zip(self.coeffs, other.coeffs)],
            self.modulus,
            self.degree,
        )

    def __neg__(self) -> "PolyR":
        """返回当前多项式的加法逆元。"""
        return PolyR([(-c) % self.modulus for c in self.coeffs], self.modulus, self.degree)

    def __mul__(self, other: Any) -> "PolyR":
        """支持多项式卷积乘法或整数标量乘法。"""
        if isinstance(other, PolyR):
            self._check(other)
            if self.degree <= _NTT_NAIVE_THRESHOLD:
                coeffs = _negacyclic_naive_convolution(
                    self.coeffs,
                    other.coeffs,
                    self.modulus,
                    self.degree,
                )
            else:
                try:
                    coeffs = _negacyclic_ntt_convolution(
                        self.coeffs,
                        other.coeffs,
                        self.modulus,
                        self.degree,
                    )
                except ValueError:
                    coeffs = _negacyclic_naive_convolution(
                        self.coeffs,
                        other.coeffs,
                        self.modulus,
                        self.degree,
                    )
            return PolyR(coeffs, self.modulus, self.degree)
        elif isinstance(other, int):
            scalar = other % self.modulus
            return PolyR([(scalar * c) % self.modulus for c in self.coeffs], self.modulus, self.degree)
        else:
            return NotImplemented

    def __rmul__(self, other: int) -> "PolyR":
        """支持整数在左侧的乘法语法。"""
        return self.__mul__(other)

    def __eq__(self, other: object) -> bool:
        """比较两个多项式在同一环参数下是否完全一致。"""
        if not isinstance(other, PolyR):
            return False
        return (
            self.modulus == other.modulus
            and self.degree == other.degree
            and all((a - b) % self.modulus == 0 for a, b in zip(self.coeffs, other.coeffs))
        )

    def centered_coeffs(self) -> List[int]:
        """返回映射到中心区间后的系数列表。"""
        return [_center(c, self.modulus) for c in self.coeffs]

    def __repr__(self) -> str:
        """提供简洁的调试表示，只展示前几个系数。"""
        preview = ", ".join(map(str, self.coeffs[:3]))
        if self.degree > 3:
            preview += ", ..."
        return f"PolyR([{preview}], q={self.modulus}, n={self.degree})"


VectorR = List[PolyR]
MatrixR = List[List[PolyR]]


def poly_from_coeffs(coeffs: Sequence[int], modulus: int = PRIME, degree: int = RING_DEGREE) -> PolyR:
    """根据给定系数生成 PolyR，多余或不足的项使用截断/补零方式处理。"""
    if len(coeffs) != degree:
        coeffs = list(coeffs)[:degree] + [0] * max(0, degree - len(coeffs))
    return PolyR(coeffs, modulus, degree)


def vector_from_coeff_lists(data: Sequence[Sequence[int]], modulus: int, degree: int) -> VectorR:
    """将二维整数数组转换为 PolyR 向量。"""
    return [poly_from_coeffs(coeffs, modulus, degree) for coeffs in data]


def matrix_from_coeff_lists(data: Sequence[Sequence[Sequence[int]]], modulus: int, degree: int) -> MatrixR:
    """把三维整数数组映射为环矩阵，每个元素均为 PolyR。"""
    return [vector_from_coeff_lists(row, modulus, degree) for row in data]


def vector_to_coeff_lists(vec: Sequence[PolyR]) -> List[List[int]]:
    """将 PolyR 向量展开为普通整数系数列表，方便序列化。"""
    return [list(poly.coeffs) for poly in vec]


def matrix_to_coeff_lists(matrix: Sequence[Sequence[PolyR]]) -> List[List[List[int]]]:
    """将 PolyR 矩阵展开成三维整数数组，便于 JSON/哈希处理。"""
    return [vector_to_coeff_lists(row) for row in matrix]


def coeff_lists_to_tuple(data: Sequence[Sequence[int]]) -> Tuple[Tuple[int, ...], ...]:
    """把嵌套列表转为不可变元组，便于比较与去重。"""
    return tuple(tuple(int(coeff) for coeff in poly) for poly in data)


def vector_to_serial(vec: Sequence[PolyR]) -> Tuple[Tuple[int, ...], ...]:
    """把 PolyR 向量转换为可哈希的嵌套元组表示。"""
    return coeff_lists_to_tuple(vector_to_coeff_lists(vec))


def matrix_to_serial(matrix: Sequence[Sequence[PolyR]]) -> Tuple[Tuple[Tuple[int, ...], ...], ...]:
    """将环矩阵转换为嵌套元组序列，确保矩阵可进行集合/字典比较。"""
    return tuple(tuple(tuple(int(coeff) for coeff in poly.coeffs) for poly in row) for row in matrix)


def mat_vec_mul(matrix: MatrixR, vector: VectorR, modulus: int, degree: int) -> VectorR:
    """在 R_q^k 中执行矩阵向量乘法，累加结果并返回新向量。"""
    result: VectorR = []
    for row in matrix:
        acc = PolyR.zero(modulus, degree)
        for coeff, vec_entry in zip(row, vector):
            acc = acc + (coeff * vec_entry)
        result.append(acc)
    return result


def encode_poly(poly: PolyR) -> bytes:
    """把单个多项式的系数编码为字节流（每项 16bit，小端序）。"""
    out = bytearray()
    for coeff in poly.coeffs:
        out.extend(int(coeff % poly.modulus).to_bytes(2, "little"))
    return bytes(out)


def encode_vector(vec: Sequence[PolyR]) -> bytes:
    """串联多个 PolyR 的编码结果，得到完整向量的字节表示。"""
    blob = bytearray()
    for poly in vec:
        blob.extend(encode_poly(poly))
    return bytes(blob)


def gaussian_poly(rng: SecureRandom, degree: int, sigma: float, modulus: int) -> PolyR:
    """从高斯分布采样多项式的每个系数，并投影到给定模数。"""
    coeffs = [rng.gaussian_int_unbounded(0.0, sigma) % modulus for _ in range(degree)]
    return PolyR(coeffs, modulus, degree)


def poly_l2(poly: PolyR) -> float:
    """计算单个多项式系数的 L2 范数。"""
    return math.sqrt(sum(c * c for c in poly.centered_coeffs()))


def vector_l2(vec: Sequence[PolyR]) -> float:
    """计算多项式向量的 L2 范数：逐个元素取范数后再平方求和。"""
    return math.sqrt(sum(poly_l2(poly) ** 2 for poly in vec))

@dataclass
class Share:
    """Generic Shamir share that can hold either scalars or PolyR elements."""

    value: Any
    index: int

@dataclass
class PerformanceStats:
    """性能统计数据类"""
    phase_name: str
    duration: float  # 秒
    operations: Dict[str, int] = None
    
    def __post_init__(self):
        """确保 operations 字段在 dataclass 初始化后总是指向独立可变字典。"""
        if self.operations is None:
            self.operations = {}

@dataclass
class EncryptedSharePackage:
    """加密的份额包"""
    sender_id: int
    receiver_id: int
    encrypted_data: bytes
    nonce: bytes
    kem_public: bytes
    key_signature: bytes
    signature: bytes

@dataclass
class PublicProof:
    """公开证明 (序列化后的环向量数据)."""

    participant_id: int
    merkle_root: str
    salt: str
    participant_salt: str  # 参与者的随机盐值 salt_i
    v_shares: List[List[List[int]]]
    aggregated_v: List[List[int]]
    R: List[List[List[int]]]
    bound: float
    spectral_norm: float

@dataclass
class AggregatedShare:
    """聚合份额消息"""

    participant_id: int      # 发送者ID
    aggregated_values: VectorR  # 聚合后的d维份额值（在该参与者位置）

@dataclass
class Complaint:
    """投诉消息"""
    complainer_id: int      # 投诉者ID
    accused_id: int         # 被投诉者ID
    reason: str             # 投诉原因
    timestamp: float        # 投诉时间戳
    evidence_package: Optional[EncryptedSharePackage] = None
    symmetric_key: Optional[bytes] = None
    complainer_signature: Optional[bytes] = None
    sender_key_signature: Optional[bytes] = None


@dataclass
class ValidationVector:
    """验证结果广播"""

    participant_id: int
    accepted_ids: List[int]

class MerkleNode:
    """Merkle 树节点，持有节点哈希以及可选的左右子节点引用。"""

    def __init__(self, hash_value: str, left=None, right=None):
        """构造一个节点；叶子节点仅存储哈希，内部节点还链接左右子节点。"""
        self.hash = hash_value
        self.left = left
        self.right = right

class MerkleTree:
    """用于生成、证明与验证份额承诺的 Merkle 树封装。"""

    def __init__(self, leaves: List[str]):
        """对叶子列表做偶数填充并立即构建整棵树，保存根哈希。"""
        if len(leaves) % 2 == 1:
            leaves = leaves + [leaves[-1]]
        self.leaves = leaves
        self.root = self.build_tree([MerkleNode(h) for h in leaves])

    @staticmethod
    def hash_item(item: Union[str, bytes]) -> str:
        """对字符串或字节做 SHA-256，统一返回十六进制字符串。"""
        if isinstance(item, str):
            item_bytes = item.encode()
        else:
            item_bytes = item
        return hashlib.sha256(item_bytes).hexdigest()

    def build_tree(self, nodes: List[MerkleNode]):
        """自底向上迭代合并节点，必要时复制最后一个节点以保持满二叉结构。"""
        if not nodes:
            return MerkleNode('')
        while len(nodes) > 1:
            if len(nodes) % 2 == 1:
                nodes = nodes + [nodes[-1]]
            new_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i+1]
                parent_hash = self.hash_item(left.hash + right.hash)
                new_level.append(MerkleNode(parent_hash, left, right))
            nodes = new_level
        return nodes[0]

    def get_proof(self, index: int) -> List[Tuple[str, str]]:
        """生成指定叶子的默克尔证明，记录兄弟节点哈希及其相对位置。"""
        proof = []
        idx = index
        level = [MerkleNode(h) for h in self.leaves]
        while len(level) > 1:
            if len(level) % 2 == 1:
                level = level + [level[-1]]
            new_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i+1]
                parent_hash = self.hash_item(left.hash + right.hash)
                new_level.append(MerkleNode(parent_hash, left, right))
            sibling_idx = idx ^ 1
            if sibling_idx < len(level) and sibling_idx != idx:
                position = 'left' if idx % 2 else 'right'
                proof.append((level[sibling_idx].hash, position))
            idx //= 2
            level = new_level
        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Tuple[str, str]], root_hash: str) -> bool:
        """沿证明路径重算根哈希，用于校验 leaf_hash 是否属于给定根。"""
        computed_hash = leaf_hash
        for sibling_hash, position in proof:
            if position == 'left':
                computed_hash = MerkleTree.hash_item(sibling_hash + computed_hash)
            else:
                computed_hash = MerkleTree.hash_item(computed_hash + sibling_hash)
        return computed_hash == root_hash

class CryptoManager:
    """加密管理器，处理密钥派生、KEM封装以及签名校验."""

    KEM_INFO = b"v3s-kem-share"

    @staticmethod
    def encrypt_data(data: dict, key: bytes) -> Tuple[bytes, bytes]:
        """使用AES-GCM加密数据 / Encrypt serialized data with AES-GCM."""
        aesgcm = AESGCMImpl(key)
        nonce = os.urandom(12)
        serialized_data = json.dumps(data).encode()
        ciphertext = aesgcm.encrypt(nonce, serialized_data, None)
        return ciphertext, nonce

    @staticmethod
    def decrypt_data(ciphertext: bytes, nonce: bytes, key: bytes) -> dict:
        """使用AES-GCM解密数据 / Decrypt ciphertext produced by AES-GCM."""
        aesgcm = AESGCMImpl(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())

    # —— KEM 与签名相关工具 ——

    @staticmethod
    def generate_signature_keypair() -> Tuple[Ed25519PrivateKey, bytes]:
        """生成Ed25519签名密钥对 / Generate an Ed25519 signing key pair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes()
        return private_key, public_key

    @staticmethod
    def generate_kem_keypair() -> Tuple[X25519PrivateKey, bytes]:
        """生成X25519密钥对用于KEM封装 / Generate an X25519 key pair for KEM encapsulation."""
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes()
        return private_key, public_key

    @staticmethod
    def encapsulate_key(receiver_public_bytes: bytes, context: bytes) -> Tuple[bytes, bytes]:
        """使用接收者公钥封装对称密钥，返回(对称密钥, 发送方临时公钥)."""
        receiver_public = X25519PublicKey.from_public_bytes(receiver_public_bytes)
        ephemeral_private = X25519PrivateKey.generate()
        shared_secret = ephemeral_private.exchange(receiver_public)
        symmetric_key = CryptoManager._derive_symmetric_key(shared_secret, context)
        ephemeral_public_bytes = ephemeral_private.public_key().public_bytes()
        return symmetric_key, ephemeral_public_bytes

    @staticmethod
    def decapsulate_key(ephemeral_public_bytes: bytes, receiver_private: X25519PrivateKey, context: bytes) -> bytes:
        """解封装对称密钥 / Decapsulate the symmetric key using receiver's private key."""
        ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
        shared_secret = receiver_private.exchange(ephemeral_public)
        return CryptoManager._derive_symmetric_key(shared_secret, context)

    @staticmethod
    def sign_message(message: bytes, signing_private: Ed25519PrivateKey) -> bytes:
        """对消息进行签名 / Sign a message with Ed25519."""
        return signing_private.sign(message)

    @staticmethod
    def verify_signature(signature: bytes, message: bytes, signing_public_bytes: bytes) -> bool:
        """验证Ed25519签名，返回是否有效."""
        try:
            public_key = Ed25519PublicKey.from_public_bytes(signing_public_bytes)
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
        info = context or CryptoManager.KEM_INFO
        return hkdf_sha256(shared_secret, length=32, salt=None, info=info)

class NetworkSimulator:
    """利用 asyncio + 实际 TCP 端口模拟去中心化节点通信。"""

    class NetworkEndpoint(threading.Thread):
        """每个参与者独立的通信线程，负责监听端口并通过 asyncio 处理 I/O。"""

        def __init__(self, participant_id: int, host: str, port: int, inbound_queue: Queue):
            super().__init__(
                name=f"NetworkEndpoint-P{participant_id}",
                daemon=True,
            )
            self.participant_id = participant_id
            self.host = host
            self.port = port
            self.inbound_queue = inbound_queue
            self.loop = asyncio.new_event_loop()
            self._server: Optional[asyncio.AbstractServer] = None
            self._ready = threading.Event()

        async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                header = await reader.readexactly(4)
                length = int.from_bytes(header, "big")
                payload = await reader.readexactly(length)
                message = pickle.loads(payload)
                self.inbound_queue.put(message)
            except asyncio.IncompleteReadError:
                pass
            except Exception as exc:  # noqa: BLE001 - 记录异常但不中断服务
                print(f"[NetworkSimulator] Endpoint P{self.participant_id} handler error: {exc}")
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        async def _serve(self) -> None:
            try:
                self._server = await asyncio.start_server(
                    self._handle_client,
                    self.host,
                    self.port,
                )
                self._ready.set()
                await self._server.serve_forever()
            except Exception as exc:
                self._ready.set()
                print(f"[NetworkSimulator] Endpoint P{self.participant_id} failed to start: {exc}")

        async def _send(self, target_host: str, target_port: int, payload: bytes) -> None:
            last_exc: Optional[Exception] = None
            for attempt in range(5):
                try:
                    reader, writer = await asyncio.open_connection(target_host, target_port)
                    writer.write(len(payload).to_bytes(4, "big") + payload)
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
                except OSError as exc:
                    last_exc = exc
                    await asyncio.sleep(0.01 * (attempt + 1))
            if last_exc:
                raise last_exc

        def send(self, target_host: str, target_port: int, payload: bytes) -> None:
            if not self._ready.wait(timeout=5):
                raise RuntimeError(f"Endpoint P{self.participant_id} is not ready to send data")
            future = asyncio.run_coroutine_threadsafe(
                self._send(target_host, target_port, payload),
                self.loop,
            )
            future.result()

        def wait_ready(self, timeout: float = 2.0) -> bool:
            return self._ready.wait(timeout)

        def stop(self) -> None:
            def _shutdown() -> None:
                if self._server is not None:
                    self._server.close()
                for task in asyncio.all_tasks(self.loop):
                    task.cancel()
                self.loop.stop()

            self.loop.call_soon_threadsafe(_shutdown)

        def run(self) -> None:
            asyncio.set_event_loop(self.loop)
            self.loop.create_task(self._serve())
            try:
                self.loop.run_forever()
            finally:
                try:
                    self.loop.run_until_complete(self.loop.shutdown_asyncgens())
                except Exception:
                    pass
                self.loop.close()

    def __init__(self, base_host: str = "127.0.0.1", base_port: int = 9000):
        self.message_queues: Dict[int, Queue] = {}
        self.lock = threading.Lock()
        self.signing_public_keys: Dict[int, bytes] = {}
        self.kem_public_keys: Dict[int, bytes] = {}
        self.base_host = base_host
        self.base_port = base_port
        self.node_addresses: Dict[int, Tuple[str, int]] = {}
        self.nodes: Dict[int, NetworkSimulator.NetworkEndpoint] = {}

    def _serialize_message(self, msg_type: str, payload: Any) -> bytes:
        return pickle.dumps((msg_type, payload), protocol=pickle.HIGHEST_PROTOCOL)

    def _all_participant_ids(self) -> List[int]:
        with self.lock:
            return list(self.message_queues.keys())

    def _send_message(self, sender_id: int, participant_id: int, msg_type: str, payload: Any) -> None:
        with self.lock:
            sender_node = self.nodes.get(sender_id)
            target_addr = self.node_addresses.get(participant_id)
        if sender_node is None or target_addr is None:
            return
        message_bytes = self._serialize_message(msg_type, payload)
        sender_node.send(target_addr[0], target_addr[1], message_bytes)

    def _broadcast(self, sender_id: int, msg_type: str, payload: Any) -> None:
        for participant_id in self._all_participant_ids():
            self._send_message(sender_id, participant_id, msg_type, payload)

    def register_participant(
        self,
        participant_id: int,
        signing_public_key: Optional[bytes] = None,
        kem_public_key: Optional[bytes] = None,
    ) -> None:
        endpoint_to_start: Optional[NetworkSimulator.NetworkEndpoint] = None
        with self.lock:
            if participant_id not in self.message_queues:
                self.message_queues[participant_id] = Queue()
            if participant_id not in self.node_addresses:
                host = self.base_host
                port = self.base_port + participant_id
                self.node_addresses[participant_id] = (host, port)
            else:
                host, port = self.node_addresses[participant_id]

            if participant_id not in self.nodes:
                endpoint = NetworkSimulator.NetworkEndpoint(
                    participant_id,
                    host,
                    port,
                    self.message_queues[participant_id],
                )
                self.nodes[participant_id] = endpoint
                endpoint_to_start = endpoint

            if signing_public_key is not None and kem_public_key is not None:
                self.signing_public_keys[participant_id] = signing_public_key
                self.kem_public_keys[participant_id] = kem_public_key

        if endpoint_to_start is not None:
            endpoint_to_start.start()
            endpoint_to_start.wait_ready()

    def get_signing_public_key(self, participant_id: int) -> bytes:
        with self.lock:
            return self.signing_public_keys[participant_id]

    def get_kem_public_key(self, participant_id: int) -> bytes:
        with self.lock:
            return self.kem_public_keys[participant_id]

    def send_encrypted_share(self, sender_id: int, package: EncryptedSharePackage) -> None:
        self._send_message(sender_id, package.receiver_id, 'share', package)

    def broadcast_proof(self, sender_id: int, proof: PublicProof) -> None:
        self._broadcast(sender_id, 'proof', proof)

    def broadcast_complaint(self, sender_id: int, complaint: Complaint) -> None:
        self._broadcast(sender_id, 'complaint', complaint)

    def broadcast_aggregated_share(self, sender_id: int, agg_share: 'AggregatedShare') -> None:
        self._broadcast(sender_id, 'aggregated', agg_share)

    def broadcast_validation_vector(self, sender_id: int, validation: ValidationVector) -> None:
        self._broadcast(sender_id, 'validation', validation)

    def broadcast_global_public_key(self, sender_id: int, leader_id: int, global_key: List[List[int]]) -> None:
        payload = {
            'leader_id': leader_id,
            'global_public_key': global_key,
        }
        self._broadcast(sender_id, 'global_key', payload)

    def broadcast_partial_public_key(self, sender_id: int, message: Dict[str, Any]) -> None:
        self._broadcast(sender_id, 'partial_key', message)
    
    def receive_encrypted_shares(self, participant_id: int, timeout: float = 5.0) -> List[EncryptedSharePackage]:
        """接收加密份额"""
        shares = []
        messages_to_requeue = []
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                msg_type, data = self.message_queues[participant_id].get(timeout=0.1)
                if msg_type == 'share':
                    shares.append(data)
                else:
                    # 如果是proof消息，重新放回队列
                    messages_to_requeue.append((msg_type, data))
            except:
                break
        
        # 将非share消息重新放回队列
        for msg in messages_to_requeue:
            self.message_queues[participant_id].put(msg)
        
        return shares
    
    def receive_all_proofs(self, participant_id: int, expected_count: int, timeout: float = 5.0) -> List[PublicProof]:
        """接收所有公开证明"""
        proofs = []
        messages_to_requeue = []
        start_time = time.time()
        
        while len(proofs) < expected_count and time.time() - start_time < timeout:
            try:
                msg_type, data = self.message_queues[participant_id].get(timeout=0.1)
                if msg_type == 'proof':
                    proofs.append(data)
                else:
                    # 如果是share或complaint消息，重新放回队列
                    messages_to_requeue.append((msg_type, data))
            except:
                break
        
        # 将非proof消息重新放回队列
        for msg in messages_to_requeue:
            self.message_queues[participant_id].put(msg)
        
        return proofs
    
    def receive_complaints(self, participant_id: int, timeout: float = 2.0) -> List[Complaint]:
        """接收投诉消息"""
        complaints = []
        messages_to_requeue = []
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                msg_type, data = self.message_queues[participant_id].get(timeout=0.1)
                if msg_type == 'complaint':
                    complaints.append(data)
                else:
                    # 如果是其他类型消息，重新放回队列
                    messages_to_requeue.append((msg_type, data))
            except:
                break
        
        # 将非complaint消息重新放回队列
        for msg in messages_to_requeue:
            self.message_queues[participant_id].put(msg)
        
        return complaints
    
    def receive_aggregated_shares(self, participant_id: int, expected_count: int, timeout: float = 3.0) -> List['AggregatedShare']:
        """接收聚合份额"""
        agg_shares = []
        messages_to_requeue = []
        start_time = time.time()
        
        while len(agg_shares) < expected_count and time.time() - start_time < timeout:
            try:
                msg_type, data = self.message_queues[participant_id].get(timeout=0.1)
                if msg_type == 'aggregated':
                    agg_shares.append(data)
                else:
                    # 如果是其他类型消息，重新放回队列
                    messages_to_requeue.append((msg_type, data))
            except:
                break
        
        # 将非aggregated消息重新放回队列
        for msg in messages_to_requeue:
            self.message_queues[participant_id].put(msg)
        
        return agg_shares

    def receive_validation_vectors(
        self,
        participant_id: int,
        expected_count: int,
        timeout: float = 3.0,
    ) -> List[ValidationVector]:
        """接收验证结果广播"""
        vectors: List[ValidationVector] = []
        messages_to_requeue = []
        start_time = time.time()

        while len(vectors) < expected_count and time.time() - start_time < timeout:
            try:
                msg_type, data = self.message_queues[participant_id].get(timeout=0.1)
                if msg_type == 'validation':
                    vectors.append(data)
                else:
                    messages_to_requeue.append((msg_type, data))
            except:
                break

        for msg in messages_to_requeue:
            self.message_queues[participant_id].put(msg)

        return vectors

class V3S:
    """V3S 协议核心：负责分享、验证、重构以及性能统计。"""

    def __init__(
        self,
        n: int,
        t: int,
        prime: int = PRIME,
        slack_factor: float = 10.0,
        rng: Optional[SecureRandom] = None,
        ring_degree: int = RING_DEGREE,
    ):
        """记录系统参数并准备随机源与性能统计容器。"""
        self.n = n
        self.t = t
        self.prime = prime
        self.slack_factor = slack_factor
        self.performance_stats = []
        self.rng = rng or SecureRandom("legacy-v3s-core")
        self.ring_degree = ring_degree
    
    def add_performance_stat(self, phase_name: str, duration: float, operations: Dict[str, int] = None):
        """收集单个阶段的时间与操作计数，便于后续打印报告。"""
        stat = PerformanceStats(phase_name, duration, operations or {})
        self.performance_stats.append(stat)
    
    def print_performance_report(self):
        """打印优雅的性能报告"""
        print("\n" + "="*80)
        print("***  PROTOCOL PERFORMANCE ANALYSIS REPORT  ***".center(80))
        print("="*80 + "\n")
        
        total_time = sum(stat.duration for stat in self.performance_stats)
        
        # 打印每个阶段的统计
        for idx, stat in enumerate(self.performance_stats, 1):
            percentage = (stat.duration / total_time * 100) if total_time > 0 else 0
            
            print(f"┌─ Phase {idx}: {stat.phase_name}")
            print(f"│  ⏱  Duration:    {stat.duration*1000:.4f} ms  ({percentage:.4f}% of total)")
            
            if stat.operations:
                print(f"│  📊 操作次数:")
                for op_name, count in stat.operations.items():
                    print(f"│     • {op_name}: {count:,}")
            print(f"└{'─'*78}\n")
        
        # 打印总计
        print("="*80)
        print(f"🕐 TOTAL EXECUTION TIME: {total_time*1000:.4f} ms ({total_time:.6f} seconds)")
        print("="*80 + "\n")
    
    def compute_spectral_norm(self, matrix: MatrixR) -> float:
        """粗略估计环矩阵的谱范数，基于系数向量的L2范数。"""

        coeffs: List[int] = []
        for row in matrix:
            for poly in row:
                coeffs.extend(poly.centered_coeffs())
        if not coeffs:
            return 0.0
        return math.sqrt(sum(c * c for c in coeffs))
    
    def compute_bound(self, R: MatrixR, sigma_x: float, sigma_y: float, d: int) -> float:
        """Estimate verification bound using coefficient-level variances."""

        spectral_norm = self.compute_spectral_norm(R)
        sigma_p = spectral_norm * sigma_x / max(1, d)
        sigma_v = math.sqrt(sigma_p ** 2 + sigma_y ** 2)
        return self.slack_factor * sigma_v * math.sqrt(d * self.ring_degree)
    
    def lagrange_interpolate(self, shares: List[Share]) -> int:
        """对标量 Shamir 份额执行拉格朗日插值，返回秘密值。"""
        secret = 0
        k = len(shares)
        
        for i in range(k):
            xi = shares[i].index
            yi = shares[i].value
            
            numerator = 1
            denominator = 1
            
            for j in range(k):
                if i != j:
                    xj = shares[j].index
                    numerator = (numerator * (0 - xj)) % self.prime
                    denominator = (denominator * (xi - xj)) % self.prime
            
            denominator_inv = pow(denominator, self.prime - 2, self.prime)
            secret = (secret + yi * numerator * denominator_inv) % self.prime
        
        return int(secret)

    @staticmethod
    def _solve_linear_system_mod(matrix: List[List[int]], vector: List[int], prime: int) -> List[int]:
        """在有限域GF(prime)上求解线性方程组"""
        if not matrix:
            raise ValueError("Empty linear system")

        rows = len(matrix)
        cols = len(matrix[0])
        aug = [row[:] + [vector[i] % prime] for i, row in enumerate(matrix)]
        rank = 0

        for col in range(cols):
            pivot_row = None
            for r in range(rank, rows):
                if aug[r][col] % prime != 0:
                    pivot_row = r
                    break
            if pivot_row is None:
                continue

            aug[rank], aug[pivot_row] = aug[pivot_row], aug[rank]
            pivot_inv = pow(aug[rank][col] % prime, prime - 2, prime)
            for c in range(col, cols + 1):
                aug[rank][c] = (aug[rank][c] * pivot_inv) % prime

            for r in range(rows):
                if r != rank and aug[r][col] % prime != 0:
                    factor = aug[r][col] % prime
                    for c in range(col, cols + 1):
                        aug[r][c] = (aug[r][c] - factor * aug[rank][c]) % prime

            rank += 1
            if rank == cols:
                break

        solution = [0] * cols

        for row in range(rank - 1, -1, -1):
            lead_col = None
            for col in range(cols):
                if aug[row][col] % prime != 0:
                    lead_col = col
                    break
            if lead_col is None:
                if aug[row][-1] % prime != 0:
                    raise ValueError("Inconsistent linear system")
                continue

            rhs = aug[row][-1]
            for col in range(lead_col + 1, cols):
                rhs = (rhs - aug[row][col] * solution[col]) % prime
            solution[lead_col] = rhs % prime

        for r in range(rows):
            lhs = 0
            for c in range(cols):
                lhs = (lhs + (matrix[r][c] % prime) * solution[c]) % prime
            if lhs != vector[r] % prime:
                raise ValueError("Linear system has no solution")

        return solution

    def generate_random_matrix(self, rows: int, cols: int, seed: str) -> MatrixR:
        """通过 SHAKE-128 流生成确定性的随机环矩阵，用于公共参数。"""
        coeffs_needed = rows * cols * self.ring_degree
        bits_needed = coeffs_needed * 2  # 每个系数需要两个随机比特
        byte_len = (bits_needed + 7) // 8
        shake = hashlib.shake_128(seed.encode())
        random_bytes = shake.digest(byte_len)

        matrix: MatrixR = []
        bit_cursor = 0
        total_bits = byte_len * 8

        def next_bit() -> int:
            nonlocal bit_cursor
            if bit_cursor >= total_bits:
                raise ValueError("Insufficient randomness for matrix generation")
            byte_index = bit_cursor // 8
            bit_offset = bit_cursor % 8
            bit_cursor += 1
            return (random_bytes[byte_index] >> bit_offset) & 1

        for i in range(rows):
            row: List[PolyR] = []
            for _ in range(cols):
                coeffs = []
                for _ in range(self.ring_degree):
                    bit_a = next_bit()
                    bit_b = next_bit()
                    if bit_a == bit_b:
                        coeff = 0  # 00 或 11，对应 0
                    elif bit_a == 0 and bit_b == 1:
                        coeff = 1  # 01 -> 1
                    else:
                        coeff = self.prime - 1  # 10 -> -1 (mod q)
                    coeffs.append(coeff)
                row.append(PolyR(coeffs, self.prime, self.ring_degree))
            matrix.append(row)
        return matrix

    def aggregate_v_shares(self, v_shares: List[List[PolyR]]) -> VectorR:
        """对验证向量份额按坐标重构，得到聚合后的全局 v 值。"""
        if not v_shares:
            return []

        dimension = len(v_shares[0])
        aggregated: VectorR = []

        for idx in range(dimension):
            shares_for_coord = [
                Share(vector[idx], participant_index + 1)
                for participant_index, vector in enumerate(v_shares)
            ]

            reconstructed = self.reconstruct_ring_from_shares(shares_for_coord, self.t)
            aggregated.append(reconstructed)

        return aggregated

    def _random_uniform_poly(self) -> PolyR:
        """采样均匀分布的环元素，作为 Shamir 多项式的随机系数。"""
        coeffs = [self.rng.randbelow(self.prime) for _ in range(self.ring_degree)]
        return PolyR(coeffs, self.prime, self.ring_degree)

    def shamir_share_ring(self, secret: PolyR, n: int, t: int) -> List[Share]:
        """对 R_q 元素执行环级 Shamir Secret Sharing。"""
        if t < 1 or n < t:
            raise ValueError("Invalid Shamir parameters for ring sharing")

        coefficients: List[PolyR] = [secret.copy()]
        for _ in range(t - 1):
            coefficients.append(self._random_uniform_poly())

        shares: List[Share] = []
        for participant in range(1, n + 1):
            share_value = PolyR.zero(self.prime, self.ring_degree)
            for power, coeff in enumerate(coefficients):
                scalar = pow(participant, power, self.prime)
                share_value = share_value + (scalar * coeff)
            shares.append(Share(share_value, participant))
        return shares

    def reconstruct_ring_from_shares(self, shares: List[Share], threshold: int) -> PolyR:
        """在 R_q 上执行拉格朗日插值，直接重构环元素。"""
        if len(shares) < threshold:
            raise ValueError("Insufficient shares for ring reconstruction")

        selected = shares[:]  # 使用全部可用份额，至少年数满足阈值
        modulus = self.prime
        secret = PolyR.zero(modulus, self.ring_degree)

        for idx, share in enumerate(selected):
            share_index = share.index % modulus
            if share_index == 0:
                raise ValueError("Share index must be non-zero modulo prime")

            lagrange_coeff = 1
            for other_idx, other_share in enumerate(selected):
                if idx == other_idx:
                    continue
                other_index = other_share.index % modulus
                lagrange_coeff = (lagrange_coeff * other_index) % modulus
                denom = (other_index - share_index) % modulus
                if denom == 0:
                    raise ValueError("Duplicate share indices detected")
                inv = pow(denom, modulus - 2, modulus)
                lagrange_coeff = (lagrange_coeff * inv) % modulus

            secret = secret + (lagrange_coeff * share.value)

        return secret

    def reed_solomon_decode_scalar(self, shares: List[Share], threshold: int) -> int:
        """使用Berlekamp–Welch思想对标量份额执行Reed–Solomon纠错，并返回f(0)。"""

        total_shares = len(shares)
        if total_shares < threshold:
            raise ValueError("Insufficient shares for Reed–Solomon decoding")

        max_errors = max(0, (total_shares - threshold) // 2)

        # 当没有错误份额时，直接用拉格朗日插值即可。
        if max_errors == 0:
            return self.lagrange_interpolate(shares[:threshold])

        for errors in range(max_errors, -1, -1):
            required_equations = threshold + 2 * errors
            if total_shares < required_equations:
                continue

            degree_e = errors
            degree_q = threshold + errors - 1

            # Unknowns: e_coeffs (degree_e terms, monic leading coefficient omitted) + q_coeffs
            matrix: List[List[int]] = []
            rhs: List[int] = []

            for share in shares:
                xi = share.index % self.prime
                yi = int(share.value) % self.prime

                row: List[int] = []

                for power in range(degree_e):
                    coeff = (-yi * pow(xi, power, self.prime)) % self.prime
                    row.append(coeff)

                for power in range(degree_q + 1):
                    row.append(pow(xi, power, self.prime))

                matrix.append(row)
                rhs.append((yi * pow(xi, degree_e, self.prime)) % self.prime)

            try:
                solution = self._solve_linear_system_mod(matrix, rhs, self.prime)
            except ValueError:
                continue

            e_coeffs = solution[:degree_e]
            q_coeffs = solution[degree_e:]

            q0 = q_coeffs[0] if q_coeffs else 0

            if degree_e == 0:
                e0 = 1
            else:
                e0 = e_coeffs[0]
                if e0 == 0:
                    continue

            inv_e0 = pow(e0, self.prime - 2, self.prime)
            return (q0 * inv_e0) % self.prime

        raise ValueError("Reed–Solomon decoding failed for provided shares")

    def reed_solomon_decode_poly(self, shares: List[Share], threshold: int) -> PolyR:
        """对PolyR份额执行系数级Reed–Solomon纠错，恢复原始多项式。"""

        if not shares:
            raise ValueError("No shares provided for Reed–Solomon decoding")

        degree = shares[0].value.degree if isinstance(shares[0].value, PolyR) else self.ring_degree
        coeffs: List[int] = []

        for coeff_idx in range(degree):
            scalar_shares = [
                Share(int(share.value.coeffs[coeff_idx]), share.index)
                for share in shares
            ]
            coeff = self.reed_solomon_decode_scalar(scalar_shares, threshold)
            coeffs.append(coeff)

        return poly_from_coeffs(coeffs, self.prime, degree)

    def reed_solomon_decode_vector(self, vector_shares: List[Tuple[int, VectorR]], threshold: int) -> VectorR:
        """对多项式向量份额执行Reed–Solomon纠错，逐坐标重构原向量。"""

        if not vector_shares:
            raise ValueError("No vector shares available for decoding")

        dimension = len(vector_shares[0][1])
        reconstructed: VectorR = []

        for coord_idx in range(dimension):
            coord_shares = [
                Share(vector[coord_idx], participant_id)
                for participant_id, vector in vector_shares
            ]
            reconstructed_poly = self.reed_solomon_decode_poly(coord_shares, threshold)
            reconstructed.append(reconstructed_poly)

        return reconstructed

    def share_vector(
        self,
        secret_vector: VectorR,
        sigma_x: float = 1.0,
        sigma_y: float = 18.36,
    ) -> Tuple[Any, List[Any], List[Any]]:
        """为单个参与者的秘密向量生成份额（在 R_q^k 中）。"""

        d = len(secret_vector)

        # Step 1: sample noise polynomials per coordinate
        start_time = time.time()
        y_vector = [
            gaussian_poly(self.rng, self.ring_degree, sigma_y, self.prime)
            for _ in range(d)
        ]
        step1_time = time.time() - start_time

        # Step 2: Ring-level Shamir sharing for each PolyR
        start_time = time.time()
        x_shares = [self.shamir_share_ring(secret_vector[i], self.n, self.t) for i in range(d)]
        y_shares = [self.shamir_share_ring(y_vector[i], self.n, self.t) for i in range(d)]
        step2_time = time.time() - start_time
        phase1_duration = step1_time + step2_time
        self.add_performance_stat(
            "Shamir秘密共享",
            phase1_duration,
            {
                "Gaussian采样 (多项式噪声)": d * self.ring_degree,
                "环级多项式份额生成 (x,y)": 2 * d * self.n,
                "Shamir多项式评估 (R_q)": 2 * d * self.n * self.t,
            },
        )

        # Step 3: Merkle commitments over encoded polynomials
        start_time = time.time()
        salt = self.rng.decimal_salt(128)
        leaf_hashes: List[str] = []
        salts: List[str] = []

        for participant in range(self.n):
            x_participant = [x_shares[i][participant].value for i in range(d)]
            y_participant = [y_shares[i][participant].value for i in range(d)]
            participant_salt = self.rng.decimal_salt(128)
            salts.append(participant_salt)
            leaf_bytes = (
                encode_vector(x_participant)
                + encode_vector(y_participant)
                + participant_salt.encode()
            )
            leaf_hashes.append(MerkleTree.hash_item(leaf_bytes))

        merkle_tree = MerkleTree(leaf_hashes)
        h = merkle_tree.root.hash
        step3_time = time.time() - start_time

        merkle_hashes = self.n
        tree_levels = 0
        nodes = self.n
        while nodes > 1:
            nodes = (nodes + 1) // 2
            merkle_hashes += nodes
            tree_levels += 1

        self.add_performance_stat(
            "Merkle树构建",
            step3_time,
            {
                "叶子节点": self.n,
                "树层数": tree_levels,
                "SHA-256哈希": merkle_hashes,
                "随机盐": self.n,
            },
        )

        # Step 4: random ring matrix challenge
        start_time = time.time()
        R = self.generate_random_matrix(d, d, h)
        spectral_norm = self.compute_spectral_norm(R)
        bound = self.compute_bound(R, sigma_x, sigma_y, d)
        step4_time = time.time() - start_time
        self.add_performance_stat(
            "挑战矩阵与界限计算",
            step4_time,
            {
                "矩阵元素 (PolyR)": d * d,
                "SHAKE-128字节": d * d * self.ring_degree,
                "谱范数近似": 1,
            },
        )

        # Step 5: compute v-shares in R_q
        start_time = time.time()
        v_shares: List[VectorR] = []
        matrix_mults = 0

        for participant in range(self.n):
            x_participant = [x_shares[i][participant].value for i in range(d)]
            y_participant = [y_shares[i][participant].value for i in range(d)]
            v_i: VectorR = []
            for i_idx in range(d):
                acc = y_participant[i_idx].copy()
                for j_idx in range(d):
                    acc = acc + (R[i_idx][j_idx] * x_participant[j_idx])
                    matrix_mults += 1
                v_i.append(acc)
            v_shares.append(v_i)

        aggregated_v = self.aggregate_v_shares(v_shares)
        step5_time = time.time() - start_time

        self.add_performance_stat(
            "验证向量计算",
            step5_time,
            {
                "环上乘加": matrix_mults,
                "拉格朗日插值 (聚合v)": d,
            },
        )

        # Prepare share payloads (JSON friendly coefficient lists)
        share_data = []
        for participant in range(self.n):
            merkle_proof = merkle_tree.get_proof(participant)
            x_participant = [x_shares[i][participant].value for i in range(d)]
            y_participant = [y_shares[i][participant].value for i in range(d)]
            share_info = {
                "x_shares": vector_to_coeff_lists(x_participant),
                "y_shares": vector_to_coeff_lists(y_participant),
                "salt": salts[participant],
                "merkle_proof": merkle_proof,
            }
            share_data.append(share_info)

        public_proof = {
            "h": h,
            "v_shares": [vector_to_coeff_lists(vec) for vec in v_shares],
            "aggregated_v": vector_to_coeff_lists(aggregated_v),
            "R": matrix_to_coeff_lists(R),
            "bound": bound,
            "spectral_norm": spectral_norm,
            "sigma_x": sigma_x,
            "sigma_y": sigma_y,
            "main_salt": salt,
        }

        return public_proof, share_data, x_shares

    def verify_share(self, participant_id: int, public_proof: dict, participant_proof: dict) -> Tuple[bool, float, Dict[str, int]]:
        """
        验证接收到的份额
        
        返回: (验证结果, 耗时, 操作统计)
        """
        start_time = time.time()
        operations = {}
        
        d = len(participant_proof['x_shares'])

        x_polys = vector_from_coeff_lists(participant_proof['x_shares'], self.prime, self.ring_degree)
        y_polys = vector_from_coeff_lists(participant_proof['y_shares'], self.prime, self.ring_degree)

        leaf_bytes = encode_vector(x_polys) + encode_vector(y_polys) + participant_proof['salt'].encode()
        leaf_hash = MerkleTree.hash_item(leaf_bytes)
        operations['SHA-256叶子哈希 (重构参与者的叶子节点哈希)'] = 1

        merkle_proof_len = len(participant_proof['merkle_proof'])
        if not MerkleTree.verify_proof(leaf_hash, participant_proof['merkle_proof'], public_proof['h']):
            duration = time.time() - start_time
            operations['SHA-256路径哈希 (验证从叶子到根的路径)'] = merkle_proof_len
            return False, duration, operations

        operations['SHA-256路径哈希 (验证从叶子到根的路径)'] = merkle_proof_len
        operations['Merkle证明验证 (检查份额属于承诺树)'] = 1

        R_matrix = matrix_from_coeff_lists(public_proof['R'], self.prime, self.ring_degree)
        v_public_vecs = [
            vector_from_coeff_lists(vec, self.prime, self.ring_degree)
            for vec in public_proof['v_shares']
        ]
        v_public = v_public_vecs[participant_id - 1]

        v_calc: VectorR = []
        mult_ops = 0
        for i_idx in range(d):
            acc = y_polys[i_idx].copy()
            for j_idx in range(d):
                acc = acc + (R_matrix[i_idx][j_idx] * x_polys[j_idx])
                mult_ops += 1
            v_calc.append(acc)

        operations['环上乘法 (验证R·x+y)'] = mult_ops

        for calc, public in zip(v_calc, v_public):
            if calc != public:
                duration = time.time() - start_time
                return False, duration, operations

        operations['线性关系检查 (v_i一致)'] = len(v_calc)

        aggregated_coeffs = public_proof.get('aggregated_v')
        if aggregated_coeffs is None:
            aggregated_polys = self.aggregate_v_shares(v_public_vecs)
        else:
            aggregated_polys = vector_from_coeff_lists(aggregated_coeffs, self.prime, self.ring_degree)

        norm = vector_l2(aggregated_polys)
        operations['范数计算 (聚合v)'] = 1

        duration = time.time() - start_time

        if norm > public_proof['bound']:
            return False, duration, operations

        return True, duration, operations
    
class DistributedParticipant(threading.Thread):
    """分布式参与者"""
    
    def __init__(
        self,
        participant_id: int,
        n: int,
        t: int,
        d: int,
        network: NetworkSimulator,
        ring_degree: int = RING_DEGREE,
        sigma_x: float = 1.0,
        sigma_y: float = 18.36,
    ):
        """绑定参与者参数、衍生局部 V3S 实例并初始化通信/统计状态。"""
        super().__init__()
        self.participant_id = participant_id
        self.n = n
        self.t = t
        self.d = d
        self.network = network
        self.sigma_x = sigma_x
        self.sigma_y = sigma_y
        self.poly_degree = ring_degree

        self.rng = SecureRandom(f"legacy-participant-{participant_id}")
        self.v3s = V3S(
            n,
            t,
            rng=self.rng.derive_child(f"legacy-v3s-core-{participant_id}"),
            ring_degree=self.poly_degree,
        )
        self.secret_vector = None
        self.public_proof = None
        self.share_data = None
        self.noise_share_vector = None
        self.x_shares = None

        # 存储接收到的份额
        self.received_shares: Dict[int, Dict[str, Any]] = {}
        self.received_proofs: Dict[int, Dict[str, Any]] = {}
        self.received_share_packages: Dict[int, EncryptedSharePackage] = {}
        self.received_share_keys: Dict[int, bytes] = {}
        
        # 有效份额数组（验证通过的份额）
        self.valid_shares = []  # 存储有效的participant_id列表
        self.local_valid_ids: Set[int] = set()  # 本地判定为有效的发送者
        self.received_validation_vectors: Dict[int, List[int]] = {}
        
        # 投诉相关
        self.complaints_sent = []      # 本参与者发送的投诉
        self.complaints_received = []  # 接收到的投诉
        
        # 盐值相关
        self.participant_salt = self.rng.decimal_salt(256)  # 生成256位随机盐值 salt_i
        self.received_salts = {}  # 存储接收到的其他参与者的盐值 {participant_id: salt}
        self.consensus_salt = None  # 共识盐值
        
        # 验证统计
        self.verification_results = []
        self.verification_times = []
        self.verification_ops = []
        
        # 重构统计
        self.reconstruction_time = 0
        
        # 全局秘密相关
        self.aggregated_shares = None  # 聚合后的份额（所有有效参与者的份额之和）
        self.global_secret = None      # 重构的全局秘密
        
        # 公钥相关
        self.public_matrix_A = None    # 基于共识盐值生成的公共矩阵A
        self.partial_public_key = None # 部分公钥 b_i = A * s_i
        self.global_public_key = None  # 全局公钥 b = sum(b_i)
        self.global_public_key_vector = None
        self.reconstructor_id: Optional[int] = None
        
        # 公钥生成统计
        self.public_key_generation_time = 0  # 全局公钥生成总时间
        
        # 网络通信统计
        self.network_send_time = 0
        self.network_receive_time = 0
        self.network_ops = {}
        self.reconstruction_ops: Dict[str, int] = {}
        self.public_key_ops: Dict[str, int] = {}
        
        # 同步机制
        self.done_event = threading.Event()
        
        # 生成并注册签名密钥与KEM密钥
        self.signing_private_key, self.signing_public_key = CryptoManager.generate_signature_keypair()
        self.kem_private_key, self.kem_public_key = CryptoManager.generate_kem_keypair()

        self.network.register_participant(
            self.participant_id,
            self.signing_public_key,
            self.kem_public_key,
        )
    
    def run(self):
        """参与者主流程"""
        try:
            # 第1步：生成自己的秘密向量
            self.generate_secret()
            
            # 第2步：生成份额并构建Merkle树
            self.create_shares()
            
            # 第3步：加密并发送份额给其他参与者
            self.encrypt_and_send_shares()
            
            # 第4步：广播公开证明
            self.broadcast_public_proof()
            
            # 第5步：接收其他参与者的份额和证明
            self.receive_and_verify_shares()
            
            self.done_event.set()
            
        except Exception as e:
            print(f"[Participant {self.participant_id}] Error: {e}")
            import traceback
            traceback.print_exc()
    
    def generate_secret(self):
        """生成自己的短秘密向量"""
        self.secret_vector = [
            gaussian_poly(self.rng, self.poly_degree, self.sigma_x, self.v3s.prime)
            for _ in range(self.d)
        ]
        preview = [poly.coeffs[:2] for poly in self.secret_vector]
        print(f"[Participant {self.participant_id}] Generated secret vector (coeff preview): {preview}")
        print(f"[Participant {self.participant_id}] Generated participant salt: {self.participant_salt[:16]}...")
    
    def create_shares(self):
        """使用V3S协议创建份额"""
        print(f"[Participant {self.participant_id}] Creating shares...")
        start_time = time.time()
        
        self.public_proof, self.share_data, self.x_shares = self.v3s.share_vector(
            self.secret_vector, self.sigma_x, self.sigma_y
        )

        if self.share_data is not None:
            own_index = self.participant_id - 1
            if 0 <= own_index < len(self.share_data):
                coeff_lists = self.share_data[own_index]['y_shares']
                self.noise_share_vector = vector_from_coeff_lists(
                    coeff_lists,
                    self.v3s.prime,
                    self.poly_degree,
                )
        
        duration = time.time() - start_time
        print(f"[Participant {self.participant_id}] Shares created in {duration*1000:.2f} ms")
        print(f"[Participant {self.participant_id}] Merkle root: {self.public_proof['h'][:16]}...")
    
    def encrypt_and_send_shares(self):
        """加密并发送份额给其他参与者"""
        print(f"[Participant {self.participant_id}] Encrypting and sending shares with KEM + signatures...")

        send_start_time = time.time()
        shares_sent = 0
        encryptions_performed = 0
        kem_ops = 0
        signature_ops = 0

        for receiver_id in range(1, self.n + 1):
            if receiver_id == self.participant_id:
                continue

            share_info = self.share_data[receiver_id - 1]
            receiver_kem_public = self.network.get_kem_public_key(receiver_id)
            context = f"v3s-share-{self.participant_id}-{receiver_id}".encode()
            symmetric_key, kem_public = CryptoManager.encapsulate_key(receiver_kem_public, context)
            kem_ops += 1

            encrypted_data, nonce = CryptoManager.encrypt_data(share_info, symmetric_key)
            encryptions_performed += 1

            key_binding = CryptoManager.serialize_key_binding(self.participant_id, receiver_id, symmetric_key)
            key_signature = CryptoManager.sign_message(key_binding, self.signing_private_key)
            signature_ops += 1

            package = EncryptedSharePackage(
                sender_id=self.participant_id,
                receiver_id=receiver_id,
                encrypted_data=encrypted_data,
                nonce=nonce,
                kem_public=kem_public,
                key_signature=key_signature,
                signature=b"",
            )

            serialized = CryptoManager.serialize_share_package(package)
            signature = CryptoManager.sign_message(serialized, self.signing_private_key)
            package.signature = signature
            signature_ops += 1

            self.network.send_encrypted_share(self.participant_id, package)
            shares_sent += 1

        self.network_send_time = time.time() - send_start_time
        self.network_ops['发送加密份额 (KEM+AES-GCM)'] = shares_sent
        self.network_ops['AES-GCM加密操作 (对称加密保护份额隐私)'] = encryptions_performed
        self.network_ops['X25519封装操作 (KEM)'] = kem_ops
        self.network_ops['Ed25519签名 (份额包+密钥绑定)'] = signature_ops

        print(
            f"[Participant {self.participant_id}] Sent {self.n-1} encrypted shares "
            f"({self.network_send_time*1000:.2f} ms, KEM ops: {kem_ops}, signatures: {signature_ops})"
        )
    
    def broadcast_public_proof(self):
        """广播盐值和公开证明"""
        print(f"[Participant {self.participant_id}] Broadcasting public proof...")
        
        broadcast_start_time = time.time()
        
        proof = PublicProof(
            participant_id=self.participant_id,
            merkle_root=self.public_proof['h'],
            salt=self.public_proof['main_salt'],
            participant_salt=self.participant_salt,  # 广播参与者盐值 salt_i
            v_shares=self.public_proof['v_shares'],
            aggregated_v=self.public_proof['aggregated_v'],
            R=self.public_proof['R'],
            bound=self.public_proof['bound'],
            spectral_norm=self.public_proof['spectral_norm']
        )
        
        self.network.broadcast_proof(self.participant_id, proof)
        
        broadcast_time = time.time() - broadcast_start_time
        self.network_send_time += broadcast_time
        self.network_ops['广播公开证明 (Merkle根+验证向量+挑战矩阵)'] = 1
        
        print(f"[Participant {self.participant_id}] Public proof broadcasted ({broadcast_time*1000:.2f} ms)")
    
    def receive_and_verify_shares(self):
        """接收并验证其他参与者的份额"""
        self.valid_shares = []
        self.local_valid_ids.clear()
        self.received_validation_vectors = {}

        print(f"[Participant {self.participant_id}] Receiving shares from other participants...")

        receive_start_time = time.time()

        time.sleep(1.0)
        encrypted_packages = self.network.receive_encrypted_shares(self.participant_id)

        receive_shares_time = time.time() - receive_start_time

        print(f"[Participant {self.participant_id}] Received {len(encrypted_packages)} encrypted shares")

        decrypt_start_time = time.time()
        decryptions_performed = 0
        kem_decaps_ops = 0
        signature_verifications = 0

        for package in encrypted_packages:
            try:
                context = f"v3s-share-{package.sender_id}-{self.participant_id}".encode()
                symmetric_key = CryptoManager.decapsulate_key(
                    package.kem_public,
                    self.kem_private_key,
                    context,
                )
                kem_decaps_ops += 1

                sender_public_key = self.network.get_signing_public_key(package.sender_id)
                key_binding = CryptoManager.serialize_key_binding(package.sender_id, self.participant_id, symmetric_key)
                key_signature_ok = CryptoManager.verify_signature(
                    package.key_signature,
                    key_binding,
                    sender_public_key,
                )
                signature_verifications += 1

                if not key_signature_ok:
                    self.local_valid_ids.discard(package.sender_id)
                    evidence_payload = CryptoManager.serialize_complaint_evidence(package, symmetric_key)
                    complaint_signature = CryptoManager.sign_message(evidence_payload, self.signing_private_key)
                    complaint = Complaint(
                        complainer_id=self.participant_id,
                        accused_id=package.sender_id,
                        reason="Invalid key binding signature",
                        timestamp=time.time(),
                        evidence_package=package,
                        symmetric_key=symmetric_key,
                        complainer_signature=complaint_signature,
                        sender_key_signature=package.key_signature,
                    )
                    self.network.broadcast_complaint(self.participant_id, complaint)
                    self.complaints_sent.append(complaint)
                    print(
                        f"[Participant {self.participant_id}] ✗ Invalid key signature on share from Participant {package.sender_id}"
                    )
                    print(
                        f"[Participant {self.participant_id}] 📢 Broadcasting complaint against Participant {package.sender_id}"
                    )
                    continue

                serialized = CryptoManager.serialize_share_package(package)
                signature_ok = CryptoManager.verify_signature(
                    package.signature,
                    serialized,
                    sender_public_key,
                )
                signature_verifications += 1

                if not signature_ok:
                    self.local_valid_ids.discard(package.sender_id)
                    evidence_payload = CryptoManager.serialize_complaint_evidence(package, symmetric_key)
                    complaint_signature = CryptoManager.sign_message(evidence_payload, self.signing_private_key)
                    complaint = Complaint(
                        complainer_id=self.participant_id,
                        accused_id=package.sender_id,
                        reason="Invalid share signature",
                        timestamp=time.time(),
                        evidence_package=package,
                        symmetric_key=symmetric_key,
                        complainer_signature=complaint_signature,
                        sender_key_signature=package.key_signature,
                    )
                    self.network.broadcast_complaint(self.participant_id, complaint)
                    self.complaints_sent.append(complaint)
                    print(
                        f"[Participant {self.participant_id}] ✗ Invalid signature on share from Participant {package.sender_id}"
                    )
                    print(
                        f"[Participant {self.participant_id}] 📢 Broadcasting complaint against Participant {package.sender_id}"
                    )
                    continue

                self.received_share_packages[package.sender_id] = package
                self.received_share_keys[package.sender_id] = symmetric_key

                share_info = CryptoManager.decrypt_data(
                    package.encrypted_data,
                    package.nonce,
                    symmetric_key,
                )

                share_info['x_polys'] = vector_from_coeff_lists(
                    share_info['x_shares'],
                    self.v3s.prime,
                    self.poly_degree,
                )
                share_info['y_polys'] = vector_from_coeff_lists(
                    share_info['y_shares'],
                    self.v3s.prime,
                    self.poly_degree,
                )

                self.received_shares[package.sender_id] = share_info
                decryptions_performed += 1
                print(f"[Participant {self.participant_id}] Decrypted share from Participant {package.sender_id}")

            except Exception as e:
                self.local_valid_ids.discard(package.sender_id)
                print(f"[Participant {self.participant_id}] Failed to process share from {package.sender_id}: {e}")

        decrypt_time = time.time() - decrypt_start_time

        receive_proofs_start_time = time.time()
        all_proofs = self.network.receive_all_proofs(self.participant_id, self.n)
        receive_proofs_time = time.time() - receive_proofs_start_time

        self.network_receive_time = receive_shares_time + decrypt_time + receive_proofs_time
        self.network_ops['接收加密份额 (网络接收+队列操作)'] = len(encrypted_packages)
        self.network_ops['AES-GCM解密操作 (解密接收到的份额)'] = decryptions_performed
        self.network_ops['X25519解封装操作 (KEM)'] = kem_decaps_ops
        self.network_ops['Ed25519验签 (份额包+密钥绑定)'] = signature_verifications
        self.network_ops['接收公开证明 (广播消息接收)'] = len(all_proofs)

        print(f"[Participant {self.participant_id}] Received {len(all_proofs)} public proofs ({self.network_receive_time*1000:.2f} ms total)")

        verified_count = 0
        failed_count = 0

        for proof in all_proofs:
            if proof.participant_id == self.participant_id:
                continue

            self.received_salts[proof.participant_id] = proof.participant_salt

            self.received_proofs[proof.participant_id] = {
                'h': proof.merkle_root,
                'v_shares': proof.v_shares,
                'aggregated_v': proof.aggregated_v,
                'R': proof.R,
                'bound': proof.bound,
                'spectral_norm': proof.spectral_norm,
                'sigma_x': self.sigma_x,
                'sigma_y': self.sigma_y
            }

            if proof.participant_id in self.received_shares:
                share_info = self.received_shares[proof.participant_id]
                public_proof = self.received_proofs[proof.participant_id]

                is_valid, duration, operations = self.v3s.verify_share(
                    self.participant_id,
                    public_proof,
                    share_info,
                )

                self.verification_results.append(is_valid)
                self.verification_times.append(duration)
                self.verification_ops.append(operations)

                if is_valid:
                    self.local_valid_ids.add(proof.participant_id)
                    verified_count += 1
                    print(
                        f"[Participant {self.participant_id}] ✓ Verified share from Participant {proof.participant_id} ({duration*1000:.2f} ms)"
                    )
                else:
                    self.local_valid_ids.discard(proof.participant_id)
                    failed_count += 1
                    package = self.received_share_packages.get(proof.participant_id)
                    symmetric_key = self.received_share_keys.get(proof.participant_id)
                    complaint_signature = None

                    if package is not None and symmetric_key is not None:
                        evidence_payload = CryptoManager.serialize_complaint_evidence(package, symmetric_key)
                        complaint_signature = CryptoManager.sign_message(evidence_payload, self.signing_private_key)

                    complaint = Complaint(
                        complainer_id=self.participant_id,
                        accused_id=proof.participant_id,
                        reason="Share verification failed",
                        timestamp=time.time(),
                        evidence_package=package,
                        symmetric_key=symmetric_key,
                        complainer_signature=complaint_signature,
                        sender_key_signature=getattr(package, "key_signature", None),
                    )
                    self.network.broadcast_complaint(self.participant_id, complaint)
                    self.complaints_sent.append(complaint)
                    print(
                        f"[Participant {self.participant_id}] ✗ Failed to verify share from Participant {proof.participant_id}"
                    )
                    print(
                        f"[Participant {self.participant_id}] 📢 Broadcasting complaint against Participant {proof.participant_id}"
                    )

        print(
            f"[Participant {self.participant_id}] Verification complete: {verified_count} valid, {failed_count} invalid (out of {len(all_proofs)-1})"
        )

        print(f"[Participant {self.participant_id}] Listening for complaints...")
        time.sleep(0.5)
        received_complaints = self.network.receive_complaints(self.participant_id)

        if received_complaints:
            print(f"[Participant {self.participant_id}] Received {len(received_complaints)} complaint(s)")

            for complaint in received_complaints:
                self.complaints_received.append(complaint)
                evidence_verified = False

                if (
                    complaint.evidence_package is not None
                    and complaint.symmetric_key is not None
                    and complaint.complainer_signature is not None
                ):
                    package = complaint.evidence_package
                    symmetric_key = complaint.symmetric_key

                    serialized_package = CryptoManager.serialize_share_package(package)
                    sender_pub = self.network.get_signing_public_key(package.sender_id)
                    package_signature_ok = CryptoManager.verify_signature(
                        package.signature,
                        serialized_package,
                        sender_pub,
                    )

                    complainer_pub = self.network.get_signing_public_key(complaint.complainer_id)
                    evidence_payload = CryptoManager.serialize_complaint_evidence(package, symmetric_key)
                    complainer_signature_ok = CryptoManager.verify_signature(
                        complaint.complainer_signature,
                        evidence_payload,
                        complainer_pub,
                    )

                    sender_key_signature = complaint.sender_key_signature or package.key_signature
                    key_signature_ok = False
                    if sender_key_signature is not None:
                        key_binding = CryptoManager.serialize_key_binding(
                            package.sender_id,
                            package.receiver_id,
                            symmetric_key,
                        )
                        key_signature_ok = CryptoManager.verify_signature(
                            sender_key_signature,
                            key_binding,
                            sender_pub,
                        )

                    if package_signature_ok and complainer_signature_ok and key_signature_ok:
                        try:
                            share_info = CryptoManager.decrypt_data(
                                package.encrypted_data,
                                package.nonce,
                                symmetric_key,
                            )
                        except Exception as exc:
                            print(
                                f"[Participant {self.participant_id}] ⚠️  Failed to decrypt evidence from complaint against Participant {complaint.accused_id}: {exc}"
                            )
                        else:
                            if package.sender_id == self.participant_id and self.public_proof is not None:
                                public_proof = self.public_proof
                            else:
                                public_proof = self.received_proofs.get(package.sender_id)

                            if public_proof is None:
                                print(
                                    f"[Participant {self.participant_id}] ⚠️  Missing public proof for Participant {package.sender_id}, cannot verify complaint evidence"
                                )
                            else:
                                is_valid, _, _ = self.v3s.verify_share(
                                    complaint.complainer_id,
                                    public_proof,
                                    share_info,
                                )
                                if not is_valid:
                                    evidence_verified = True
                                else:
                                    print(
                                        f"[Participant {self.participant_id}] ℹ️  Complaint evidence indicates share from Participant {package.sender_id} is valid"
                                    )
                    else:
                        if not package_signature_ok:
                            print(
                                f"[Participant {self.participant_id}] ⚠️  Invalid package signature in complaint against Participant {complaint.accused_id}"
                            )
                        elif not key_signature_ok:
                            print(
                                f"[Participant {self.participant_id}] ⚠️  Invalid key signature in complaint against Participant {complaint.accused_id}"
                            )
                        else:
                            print(
                                f"[Participant {self.participant_id}] ⚠️  Invalid complainer signature in complaint against Participant {complaint.accused_id}"
                            )

                if evidence_verified:
                    if complaint.accused_id in self.local_valid_ids:
                        self.local_valid_ids.remove(complaint.accused_id)
                        print(
                            f"[Participant {self.participant_id}] ⚠️  Revoked trust in Participant {complaint.accused_id} after verified complaint by Participant {complaint.complainer_id}"
                        )
                else:
                    print(
                        f"[Participant {self.participant_id}] ℹ️  Complaint from Participant {complaint.complainer_id} lacked verifiable evidence"
                    )

        self.broadcast_and_collect_validation_vectors()

        print(f"[Participant {self.participant_id}] Final valid shares (intersection): {self.valid_shares} ({len(self.valid_shares)} participants)")

        self.compute_consensus_salt()
        self.aggregate_shares_for_public_key()
    
    def broadcast_and_collect_validation_vectors(self) -> None:
        """广播本地验证结果并与其他参与者求交集."""

        accepted_ids = set(self.local_valid_ids)
        accepted_ids.add(self.participant_id)

        validation_vector = ValidationVector(
            participant_id=self.participant_id,
            accepted_ids=sorted(accepted_ids),
        )

        send_start = time.time()
        self.network.broadcast_validation_vector(self.participant_id, validation_vector)
        broadcast_duration = time.time() - send_start
        self.network_send_time += broadcast_duration
        self.network_ops['广播验证结果 (valid_i 集合)'] = 1

        self.received_validation_vectors[self.participant_id] = list(validation_vector.accepted_ids)

        time.sleep(0.2)
        receive_start = time.time()
        vectors = self.network.receive_validation_vectors(self.participant_id, self.n)
        receive_duration = time.time() - receive_start
        self.network_receive_time += receive_duration

        for vector in vectors:
            self.received_validation_vectors[vector.participant_id] = list(vector.accepted_ids)

        if len(self.received_validation_vectors) < self.n:
            print(
                f"[Participant {self.participant_id}] ⚠️  Received validation vectors from {len(self.received_validation_vectors)} participants (expected {self.n})"
            )

        if self.received_validation_vectors:
            common_valid = set(range(1, self.n + 1))
            common_valid.discard(self.participant_id)
            for accepted_ids in self.received_validation_vectors.values():
                common_valid &= set(accepted_ids)
        else:
            common_valid = set(self.local_valid_ids)

        self.valid_shares = sorted(common_valid)
        self.network_ops['接收验证结果 (valid_i 集合)'] = len(vectors)

    def compute_consensus_salt(self):
        """根据有效参与者数组计算共识盐值"""
        print(f"[Participant {self.participant_id}] Computing consensus salt...")
        
        # 收集有效参与者的盐值（按participant_id排序以确保一致性）
        valid_salts = []
        
        # 将自己的盐值也加入（如果自己在有效份额中）
        # 注意：valid_shares存储的是其他参与者的ID，需要判断自己是否应该包含
        # 在正常情况下，每个参与者都应该包含自己的盐值
        sorted_valid_ids = sorted(self.valid_shares)
        
        # 如果自己的ID不在valid_shares中但自己是诚实的，应该加入自己
        # 这里我们根据业务逻辑：只有其他参与者验证通过的才在valid_shares中
        # 所以我们需要同时考虑自己的盐值
        all_valid_ids = sorted(set(sorted_valid_ids + [self.participant_id]))
        
        for pid in all_valid_ids:
            if pid == self.participant_id:
                valid_salts.append(self.participant_salt)
            elif pid in self.received_salts:
                valid_salts.append(self.received_salts[pid])
            else:
                print(f"[Participant {self.participant_id}] ⚠️  Warning: Salt for Participant {pid} not found!")
        
        # 拼接所有盐值并计算哈希
        concatenated_salts = '||'.join(valid_salts)
        
        # 使用SHA-256作为Hsalt哈希函数
        self.consensus_salt = hashlib.sha256(concatenated_salts.encode()).hexdigest()
        
        print(f"[Participant {self.participant_id}] Consensus salt computed from {len(all_valid_ids)} participants: {self.consensus_salt[:16]}...")
        print(f"[Participant {self.participant_id}] Valid participant IDs: {all_valid_ids}")
    
    def aggregate_shares_for_public_key(self):
        """聚合所有有效份额，为公钥阶段准备全局秘密份额。"""
        print(f"[Participant {self.participant_id}] Aggregating verified shares for public key generation...")

        all_valid_ids = sorted(set(self.valid_shares + [self.participant_id]))

        if len(all_valid_ids) < self.t:
            print(
                f"[Participant {self.participant_id}] ⚠️  Insufficient valid shares ({len(all_valid_ids)} < {self.t}),"
                " cannot obtain resilient aggregated share"
            )
            return

        aggregation_start = time.time()

        my_position = self.participant_id - 1
        aggregated_shares_d_values: List[PolyR] = []

        for dim in range(self.d):
            my_share_value = self.x_shares[dim][my_position].value
            aggregated_value = my_share_value.copy()

            for valid_pid in self.valid_shares:
                if valid_pid in self.received_shares:
                    share_info = self.received_shares[valid_pid]
                    aggregated_value = aggregated_value + share_info['x_polys'][dim]

            aggregated_shares_d_values.append(aggregated_value)

        aggregation_time = time.time() - aggregation_start
        self.aggregated_shares = aggregated_shares_d_values
        self.reconstruction_time = aggregation_time
        self.global_secret = None  # 全局秘密不再在每个参与者处重构

        print(
            f"[Participant {self.participant_id}] Prepared aggregated secret share at own position "
            f"({aggregation_time*1000:.2f} ms)"
        )

        self.reconstruction_ops = {
            "聚合份额加法 (PolyR)": self.d * len(self.valid_shares),
            "生成聚合份额 (每个参与者)": 1,
        }

        self.generate_public_matrix_and_compute_keys()
    
    def generate_public_matrix_and_compute_keys(self):
        """基于共识盐值生成公共矩阵A，并计算部分公钥和全局公钥"""
        print(f"[Participant {self.participant_id}] Generating public matrix A from consensus salt...")
        
        if self.consensus_salt is None:
            print(f"[Participant {self.participant_id}] ⚠️  No consensus salt available!")
            return
        if not self.aggregated_shares:
            print(f"[Participant {self.participant_id}] ⚠️  Aggregated share unavailable, aborting public key generation")
            return

        all_valid_ids = sorted(set(self.valid_shares + [self.participant_id]))
        if len(all_valid_ids) < self.t:
            print(
                f"[Participant {self.participant_id}] ⚠️  Not enough valid participants ({len(all_valid_ids)} < {self.t}) for public key generation"
            )
            return

        self.reconstructor_id = self.select_global_key_reconstructor(all_valid_ids)
        is_reconstructor = self.participant_id == self.reconstructor_id
        role = "(global key reconstructor)" if is_reconstructor else ""
        print(
            f"[Participant {self.participant_id}] Selected reconstructor P{self.reconstructor_id} via consensus salt {role}"
        )

        start_time = time.time()

        matrix_size = self.d * self.d
        coeffs_per_poly = self.v3s.ring_degree
        bytes_per_coeff = 2
        bytes_needed = matrix_size * coeffs_per_poly * bytes_per_coeff
        random_bytes = hashlib.shake_256(self.consensus_salt.encode()).digest(bytes_needed)

        A: MatrixR = []
        byte_cursor = 0
        for i in range(self.d):
            row: List[PolyR] = []
            for j in range(self.d):
                coeffs = [0] * coeffs_per_poly
                for k in range(coeffs_per_poly):
                    chunk = random_bytes[byte_cursor:byte_cursor + bytes_per_coeff]
                    if len(chunk) < bytes_per_coeff:
                        chunk = chunk.ljust(bytes_per_coeff, b"\x00")
                    coeffs[k] = int.from_bytes(chunk, "big") % self.v3s.prime
                    byte_cursor += bytes_per_coeff
                row.append(poly_from_coeffs(coeffs, self.v3s.prime, self.v3s.ring_degree))
            A.append(row)

        self.public_matrix_A = A

        matrix_gen_time = time.time() - start_time
        print(f"[Participant {self.participant_id}] Generated {self.d}×{self.d} public matrix A ({matrix_gen_time*1000:.2f} ms)")
        print(f"[Participant {self.participant_id}] Matrix structure: A_{self.d}×{self.d} over PolyR")

        partial_key_start = time.time()
        partial_public_key_vec = mat_vec_mul(self.public_matrix_A, self.aggregated_shares, self.v3s.prime, self.v3s.ring_degree)
        self.partial_public_key = vector_to_coeff_lists(partial_public_key_vec)
        preview_polys = [
            poly.coeffs[:min(4, len(poly.coeffs))]
            for poly in partial_public_key_vec[:min(2, len(partial_public_key_vec))]
        ]
        partial_key_time = time.time() - partial_key_start
        print(
            f"[Participant {self.participant_id}] Computed partial key b_{self.participant_id} = A * share_{self.participant_id} {role} "
            f"({partial_key_time*1000:.2f} ms)"
        )
        print(f"[Participant {self.participant_id}] Partial public key preview: {preview_polys} (first coeffs)")

        broadcast_start = time.time()
        partial_key_message = {
            'participant_id': self.participant_id,
            'partial_public_key': self.partial_public_key,
        }
        self.network.broadcast_partial_public_key(self.participant_id, partial_key_message)
        broadcast_time = time.time() - broadcast_start
        print(f"[Participant {self.participant_id}] Broadcasted partial public key ({broadcast_time*1000:.2f} ms)")

        received_partial_keys: Dict[int, VectorR] = {}
        collection_time = 0.0
        reconstruction_time = 0.0
        broadcast_global_time = 0.0
        wait_time = 0.0

        if is_reconstructor:
            collection_start = time.time()
            received_partial_keys = self.collect_partial_public_keys(all_valid_ids, partial_public_key_vec)
            collection_time = time.time() - collection_start
            print(
                f"[Participant {self.participant_id}] Collected {len(received_partial_keys)} partial keys for RS reconstruction"
            )

            if len(received_partial_keys) < self.t:
                raise RuntimeError("Insufficient partial public keys for reconstruction")

            reconstruction_start = time.time()
            vector_shares = [(pid, vec) for pid, vec in received_partial_keys.items()]
            global_public_key_vec = self.v3s.reed_solomon_decode_vector(vector_shares, self.t)
            reconstruction_time = time.time() - reconstruction_start

            correctable_errors = max(0, (len(received_partial_keys) - self.t) // 2)

            self.global_public_key_vector = global_public_key_vec
            self.global_public_key = vector_to_coeff_lists(global_public_key_vec)

            broadcast_global_start = time.time()
            self.network.broadcast_global_public_key(
                self.participant_id,
                self.participant_id,
                self.global_public_key,
            )
            broadcast_global_time = time.time() - broadcast_global_start
            print(
                f"[Participant {self.participant_id}] ✓ Reconstructed global public key via RS ({reconstruction_time*1000:.2f} ms)"
            )
            print(
                f"[Participant {self.participant_id}] Reed–Solomon tolerance: ⌊(I−T)/2⌋ = {correctable_errors} (I={len(received_partial_keys)}, T={self.t})"
            )
        else:
            pass

        total_key_time = matrix_gen_time + partial_key_time + broadcast_time + collection_time + reconstruction_time + broadcast_global_time + wait_time
        self.public_key_generation_time = total_key_time

        ops_receive = len(received_partial_keys) - 1 if received_partial_keys else 0
        pub_ops = {
            "SHAKE-256字节 (生成矩阵A)": bytes_needed,
            "矩阵生成 (PolyR全系数)": self.d * self.d,
            "环上乘法 (A×share_i)": self.d * self.d,
            "部分公钥广播": 1,
        }

        if is_reconstructor:
            pub_ops["部分公钥接收"] = max(0, ops_receive)
            pub_ops["Reed–Solomon纠错 (b_i)"] = self.d * len(received_partial_keys)
            pub_ops["全局公钥广播"] = 1
        else:
            pass

        self.public_key_ops = pub_ops

        try:
            self.v3s.add_performance_stat(
                "全局公钥生成",
                total_key_time,
                pub_ops,
            )
        except Exception:
            pass

        if not getattr(self, "global_public_key_vector", None) and self.global_public_key is not None:
            self.global_public_key_vector = vector_from_coeff_lists(
                self.global_public_key,
                self.v3s.prime,
                self.v3s.ring_degree,
            )

        if self.global_public_key_vector is not None:
            preview = [
                poly.coeffs[:min(4, len(poly.coeffs))]
                for poly in self.global_public_key_vector[:min(2, len(self.global_public_key_vector))]
            ]
            print(
                f"[Participant {self.participant_id}] Global public key preview: {preview} (first coeffs)."
            )
        else:
            if is_reconstructor:
                print(
                    f"[Participant {self.participant_id}] ⚠️  Reconstructor failed to produce global public key"
                )

        print(f"[Participant {self.participant_id}] Total public key generation time: {total_key_time*1000:.2f} ms")

    def select_global_key_reconstructor(self, candidate_ids: List[int]) -> int:
        """依据共识盐值确定唯一的全局公钥重构者，以确保所有参与者一致。"""

        if not candidate_ids:
            return self.participant_id

        salt_material = (self.consensus_salt or self.participant_salt or "0").encode()
        digest = hashlib.sha256(salt_material + b"::global-key").digest()
        index = int.from_bytes(digest, "big") % len(candidate_ids)
        return candidate_ids[index]

    def collect_partial_public_keys(
        self,
        expected_ids: List[int],
        own_partial: VectorR,
        timeout: float = 3.0,
    ) -> Dict[int, VectorR]:
        """收集指定集合内的部分公钥，供重构者执行纠错与插值。"""

        collected: Dict[int, VectorR] = {self.participant_id: own_partial}
        messages_to_requeue: List[Tuple[str, Any]] = []
        start_wait = time.time()

        while len(collected) < len(expected_ids) and time.time() - start_wait < timeout:
            try:
                msg_type, data = self.network.message_queues[self.participant_id].get(timeout=0.1)
            except Exception:
                continue

            if msg_type == 'partial_key':
                pid = data.get('participant_id')
                if pid in expected_ids and pid not in collected:
                    collected[pid] = vector_from_coeff_lists(
                        data['partial_public_key'],
                        self.v3s.prime,
                        self.v3s.ring_degree,
                    )
                    print(f"[Participant {self.participant_id}] Received partial public key from Participant {pid}")
            else:
                messages_to_requeue.append((msg_type, data))

        for msg in messages_to_requeue:
            self.network.message_queues[self.participant_id].put(msg)

        if len(collected) < len(expected_ids):
            missing = sorted(set(expected_ids) - set(collected.keys()))
            print(
                f"[Participant {self.participant_id}] ⚠️  Missing partial keys from participants: {missing}"
            )

        return collected

    def wait_for_global_public_key(self, timeout: float = 5.0) -> None:
        """等待重构者广播最终公钥，若超时则保留None以提示上层逻辑。"""

        start_time = time.time()
        messages_to_requeue: List[Tuple[str, Any]] = []

        while time.time() - start_time < timeout:
            try:
                msg_type, data = self.network.message_queues[self.participant_id].get(timeout=0.2)
            except Exception:
                continue

            if msg_type == 'global_key':
                self.global_public_key = data['global_public_key']
                self.reconstructor_id = data.get('leader_id')
                self.global_public_key_vector = vector_from_coeff_lists(
                    self.global_public_key,
                    self.v3s.prime,
                    self.v3s.ring_degree,
                )
                print(
                    f"[Participant {self.participant_id}] Received global public key broadcast from Participant {self.reconstructor_id}"
                )
                break
            else:
                messages_to_requeue.append((msg_type, data))

        for msg in messages_to_requeue:
            self.network.message_queues[self.participant_id].put(msg)

        if self.global_public_key is None:
            print(
                f"[Participant {self.participant_id}] ⚠️  Timed out while waiting for global public key broadcast"
            )

def test_distributed_v3s():
    """测试分布式V3S协议"""
    print("\n" + "="*80)
    print("***  DISTRIBUTED V3S PROTOCOL TEST  ***".center(80))
    print("="*80 + "\n")
    
    # 协议参数
    num_participants = 6
    threshold = 2
    dimension = 4
    sigma_x = 1.0
    sigma_y = sigma_x * (337 ** 0.5)
    ring_degree = RING_DEGREE
    prime_modulus = PRIME
    
    print("*** Protocol Parameters ***")
    print(f"  • Number of participants (N): {num_participants}")
    print(f"  • Threshold (T):              {threshold}")
    print(f"  • sigma_x:                    {sigma_x:.2f}")
    print(f"  • sigma_y:                    {sigma_y:.2f} (= √337 × sigma_x)")
    print(f"  • Algebraic setting:          Module lattice R_q^k")
    print(f"       – Base ring R_q:         ℤ_q[X]/(X^{ring_degree}+1)")
    print(f"       – Modulus q:             {prime_modulus}")
    print(f"       – Ring dimension n:      {ring_degree}")
    print(f"       – Module rank k (d):     {dimension}")
    print(f"  • Encryption:                 X25519 KEM + AES-256-GCM (Ed25519 signatures)")
    print("-" * 80 + "\n")
    
    # 创建网络模拟器
    network = NetworkSimulator()
    
    # 创建所有参与者
    participants = []
    for i in range(1, num_participants + 1):
        network.register_participant(i)
        participant = DistributedParticipant(
            participant_id=i,
            n=num_participants,
            t=threshold,
            d=dimension,
            network=network,
            sigma_x=sigma_x,
            sigma_y=sigma_y
        )
        participants.append(participant)
    
    print("*** Starting Distributed Protocol ***\n")
    print("\n" + "="*80)
    print("***  SHARE AND VERIFY PHRASE  ***".center(80))
    print("="*80 + "\n")
    
    # 启动所有参与者线程
    start_time = time.time()
    for participant in participants:
        participant.start()
    
    # 等待所有参与者完成
    for participant in participants:
        participant.join()
    
    total_time = time.time() - start_time
    
    # 统计验证结果和投诉情况
    all_verified = True
    total_verification_time = 0
    all_verification_ops = []
    total_complaints = 0
    
    print("\n")
    
    for participant in participants:
        verified_count = sum(participant.verification_results)
        expected_count = num_participants - 1
        valid_shares_count = len(participant.valid_shares)
        complaints_sent = len(participant.complaints_sent)
        complaints_received = len(participant.complaints_received)
        
        status = "✓ SUCCESS" if verified_count == expected_count else "✗ PARTIAL"
        consensus_salt_preview = participant.consensus_salt[:16] + "..." if participant.consensus_salt else "None"
        print(f"  Participant {participant.participant_id}: {status} - Verified {verified_count}/{expected_count} shares | Valid: {valid_shares_count} | Complaints sent: {complaints_sent} | Complaints received: {complaints_received} | Consensus: {consensus_salt_preview}")
        
        if verified_count != expected_count:
            all_verified = False
        
        # 收集验证统计
        total_verification_time += sum(participant.verification_times)
        all_verification_ops.extend(participant.verification_ops)
        total_complaints += complaints_sent
    
    print(f"\n  ⏱  Total execution time: {total_time*1000:.2f} ms")
    print(f"  📊 Total messages sent: {(num_participants * (num_participants - 1)) + num_participants * num_participants + total_complaints * num_participants}")
    print(f"     - Encrypted shares:  {num_participants * (num_participants - 1)}")
    print(f"     - Public proofs:     {num_participants} (broadcasted to all)")
    print(f"     - Complaints:        {total_complaints} (broadcasted to all)")
    
    # 投诉统计
    if total_complaints > 0:
        print(f"\n  ⚠️  Complaint Summary:")
        for participant in participants:
            if participant.complaints_sent:
                for complaint in participant.complaints_sent:
                    print(f"     - P{complaint.complainer_id} complained about P{complaint.accused_id}: {complaint.reason}")
    
    # 共识盐值验证
    print(f"\n  🔐 Consensus Salt Verification:")
    consensus_salts = [p.consensus_salt for p in participants if p.consensus_salt]
    if consensus_salts:
        unique_salts = set(consensus_salts)
        if len(unique_salts) == 1:
            print(f"     ✓ All participants reached consensus!")
            print(f"     Consensus salt: {consensus_salts[0][:32]}...")
        else:
            print(f"     ✗ WARNING: Participants have different consensus salts!")
            for i, participant in enumerate(participants):
                print(f"     P{participant.participant_id}: {participant.consensus_salt[:32]}...")
    else:
        print(f"     ✗ No consensus salt computed")
    
    # 合并所有验证操作统计
    if all_verification_ops:
        combined_verify_ops = {}
        for ops in all_verification_ops:
            for key, value in ops.items():
                combined_verify_ops[key] = combined_verify_ops.get(key, 0) + value
        
        avg_verify_time = total_verification_time / len(all_verification_ops) if all_verification_ops else 0
        print(f"\n  🔍 Average verification time: {avg_verify_time*1000:.4f} ms per share")
    
    # 聚合份额阶段（与旧版全局秘密重构阶段对应）
    print("\n" + "="*80)
    print("***  AGGREGATED SECRET SHARES  ***".center(80))
    print("="*80 + "\n")

    aggregated_norms = []
    ring_degree = participants[0].v3s.ring_degree if participants else RING_DEGREE

    for participant in participants:
        reconstructor = participant.reconstructor_id or "?"
        if participant.aggregated_shares is not None:
            share_norm = vector_l2(participant.aggregated_shares)
            aggregated_norms.append(share_norm)
            share_preview = vector_to_coeff_lists(participant.aggregated_shares)[:1]
            print(
                f"  Participant {participant.participant_id}: ✓ Aggregated share ready | ||share_i|| = {share_norm:.4f} | "
                f"Leader: P{reconstructor}"
            )
            print(f"     Share preview: {share_preview}")
        else:
            print(
                f"  Participant {participant.participant_id}: ✗ Missing aggregated share | Leader: P{reconstructor}"
            )

    if aggregated_norms:
        print(f"\n  ⏱  Average aggregated share norm: {np.mean(aggregated_norms):.4f}")
    else:
        print("\n  ✗ No aggregated shares were finalized")

    # 全局公钥阶段汇总
    print("\n" + "="*80)
    print("***  GLOBAL PUBLIC KEY GENERATION  ***".center(80))
    print("="*80 + "\n")

    public_matrices: Dict[int, MatrixR] = {}
    leaders_with_keys: List[DistributedParticipant] = []

    for participant in participants:
        pid = participant.participant_id
        reconstructor = participant.reconstructor_id or "?"
        has_matrix = participant.public_matrix_A is not None
        has_partial = participant.partial_public_key is not None
        leader_tag = ""
        if participant.reconstructor_id == pid and participant.global_public_key is not None:
            leader_tag = " (global key reconstructor)"

        matrix_status = "✓" if has_matrix else "✗"
        partial_status = "✓" if has_partial else "✗"
        print(
            f"  Participant {pid}: {matrix_status} Public matrix | {partial_status} Partial key | Leader: P{reconstructor}{leader_tag}"
        )

        if has_matrix:
            public_matrices[pid] = participant.public_matrix_A
            first_row = participant.public_matrix_A[0] if participant.public_matrix_A else []
            row_preview = [poly.coeffs[:2] for poly in first_row[:min(2, len(first_row))]] if first_row else []
            print(f"     Matrix A first row preview: {row_preview}")

        if has_partial and participant.partial_public_key:
            partial_preview = [poly[:4] for poly in participant.partial_public_key[:1]]
            print(f"     Partial key preview: {partial_preview}")

        if participant.global_public_key is not None:
            leaders_with_keys.append(participant)
            global_preview = [poly[:4] for poly in participant.global_public_key[:1]]
            print(f"     Global key preview: {global_preview}")

    print(f"\n  🔑 Global Public Key Broadcast:")
    if leaders_with_keys:
        for leader in leaders_with_keys:
            preview = [poly[:4] for poly in leader.global_public_key[:1]] if leader.global_public_key else []
            print(
                f"     • Leader P{leader.participant_id} reconstructed global key | Preview: {preview}"
            )
    else:
        print("     ✗ No participant reported a reconstructed global public key")
    
    # 打印性能报告（聚合所有参与者的数据）
    if participants:
        # 创建聚合的性能统计
        aggregated_v3s = V3S(num_participants, threshold)
        
        # 统一定义并按顺序聚合固定的 7 个阶段（已移除噪声生成阶段）
        phase_names = [
            "Shamir秘密共享",
            "Merkle树构建",
            "挑战矩阵与界限计算",
            "验证向量计算",
            "网络通信",
            "聚合份额生成",
            "全局公钥生成"
        ]
        
        # 聚合前四个计算阶段（这些阶段的统计保存在每个参与者的 v3s.performance_stats 中，且顺序一致）
        for phase_idx, phase_name in enumerate(phase_names[:4]):
            phase_durations = []
            combined_operations = {}
            for participant in participants:
                if phase_idx < len(participant.v3s.performance_stats):
                    stat = participant.v3s.performance_stats[phase_idx]
                    phase_durations.append(stat.duration)
                    for op_name, count in stat.operations.items():
                        combined_operations[op_name] = combined_operations.get(op_name, 0) + count
            max_duration = max(phase_durations) if phase_durations else 0
            aggregated_v3s.add_performance_stat(phase_name, max_duration, combined_operations)
        
        # 网络通信阶段（并发，取最大值）
        network_times = [p.network_send_time + p.network_receive_time for p in participants]
        max_network_time = max(network_times) if network_times else 0
        combined_network_ops = {}
        for participant in participants:
            for op_name, count in participant.network_ops.items():
                combined_network_ops[op_name] = combined_network_ops.get(op_name, 0) + count
        aggregated_v3s.add_performance_stat("网络通信", max_network_time, combined_network_ops)
        
        # 聚合份额生成阶段（原全局秘密重构阶段，现仅保留聚合逻辑）
        aggregation_times = [getattr(p, "reconstruction_time", 0.0) for p in participants]
        max_global_recon_time = max(aggregation_times) if aggregation_times else 0
        combined_recon_ops: Dict[str, int] = {}
        for participant in participants:
            for op_name, count in getattr(participant, "reconstruction_ops", {}).items():
                combined_recon_ops[op_name] = combined_recon_ops.get(op_name, 0) + count
        if not combined_recon_ops:
            combined_recon_ops = {
                "聚合份额加法 (每个参与者)": num_participants * dimension,
                "聚合份额准备 (广播取消)": num_participants,
            }
        aggregated_v3s.add_performance_stat(
            "聚合份额生成",
            max_global_recon_time,
            combined_recon_ops,
        )
        
        # 全局公钥生成（并发，取最大值）—— Phase 7
        public_key_times = [p.public_key_generation_time for p in participants]
        max_pub_key_time = max(public_key_times) if public_key_times else 0
        combined_pub_ops: Dict[str, int] = {}
        for participant in participants:
            for op_name, count in getattr(participant, "public_key_ops", {}).items():
                combined_pub_ops[op_name] = combined_pub_ops.get(op_name, 0) + count
        if not combined_pub_ops:
            combined_pub_ops = {
                "SHAKE-256摘要 (生成矩阵伪随机字节)": num_participants * dimension * dimension * 4,
                "矩阵生成 (A, d×d, 所有参与者)": num_participants * dimension * dimension,
                "部分公钥计算 (A×s_i, 所有参与者)": num_participants * dimension * dimension,
                "部分公钥广播 (估计)": num_participants,
                "部分公钥接收 (估计)": num_participants * num_participants,
                "全局公钥聚合 (求和所有部分公钥)": num_participants * num_participants * dimension,
            }
        aggregated_v3s.add_performance_stat("全局公钥生成", max_pub_key_time, combined_pub_ops)
        
        aggregated_v3s.print_performance_report()

if __name__ == "__main__":
    setup_run_logger()
    print(
        f"[Crypto] AES backend: {AES_BACKEND} (source: {AESCIPHER_SOURCE})"
    )
    if TONGSUO_LOAD_ERROR:
        print(f"[Crypto] Warning: failed to load Tongsuo backend: {TONGSUO_LOAD_ERROR}")
    test_distributed_v3s()
