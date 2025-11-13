import base64
import hashlib
import json
import time
import threading
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from queue import Queue
import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

from secure_rng import SecureRandom

# 使用大素数以保证Shamir秘密共享的安全性
PRIME = 2**255 - 19

@dataclass
class Share:
    value: int
    index: int

@dataclass
class PerformanceStats:
    """性能统计数据类"""
    phase_name: str
    duration: float  # 秒
    operations: Dict[str, int] = None
    
    def __post_init__(self):
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
    """公开证明"""
    participant_id: int
    merkle_root: str
    salt: str
    participant_salt: str  # 参与者的随机盐值 salt_i
    v_shares: List[List[int]]
    aggregated_v: List[int]
    R: List[List[int]]
    bound: float
    spectral_norm: float

@dataclass
class AggregatedShare:
    """聚合份额消息"""
    participant_id: int      # 发送者ID
    aggregated_values: List[int]  # 聚合后的d维份额值（在该参与者位置）

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
    def __init__(self, hash_value: str, left=None, right=None):
        self.hash = hash_value
        self.left = left
        self.right = right

class MerkleTree:
    def __init__(self, leaves: List[str]):
        if len(leaves) % 2 == 1:
            leaves = leaves + [leaves[-1]]
        self.leaves = leaves
        self.root = self.build_tree([MerkleNode(h) for h in leaves])

    @staticmethod
    def hash_item(item: str) -> str:
        return hashlib.sha256(item.encode()).hexdigest()

    def build_tree(self, nodes: List[MerkleNode]):
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

class NetworkSimulator:
    """网络模拟器，用于参与者之间的通信"""
    
    def __init__(self):
        self.message_queues: Dict[int, Queue] = {}
        self.broadcast_queue: Queue = Queue()
        self.lock = threading.Lock()
        self.signing_public_keys: Dict[int, bytes] = {}
        self.kem_public_keys: Dict[int, bytes] = {}
    
    def register_participant(
        self,
        participant_id: int,
        signing_public_key: Optional[bytes] = None,
        kem_public_key: Optional[bytes] = None,
    ) -> None:
        """注册参与者并记录其公钥"""
        with self.lock:
            if participant_id not in self.message_queues:
                self.message_queues[participant_id] = Queue()
            if signing_public_key is not None and kem_public_key is not None:
                self.signing_public_keys[participant_id] = signing_public_key
                self.kem_public_keys[participant_id] = kem_public_key

    def get_signing_public_key(self, participant_id: int) -> bytes:
        with self.lock:
            return self.signing_public_keys[participant_id]

    def get_kem_public_key(self, participant_id: int) -> bytes:
        with self.lock:
            return self.kem_public_keys[participant_id]
    
    def send_encrypted_share(self, package: EncryptedSharePackage):
        """发送加密份额"""
        with self.lock:
            if package.receiver_id in self.message_queues:
                self.message_queues[package.receiver_id].put(('share', package))
    
    def broadcast_proof(self, proof: PublicProof):
        """广播公开证明"""
        with self.lock:
            for participant_id in self.message_queues.keys():
                self.message_queues[participant_id].put(('proof', proof))
    
    def broadcast_complaint(self, complaint: Complaint):
        """广播投诉消息"""
        with self.lock:
            for participant_id in self.message_queues.keys():
                self.message_queues[participant_id].put(('complaint', complaint))
    
    def broadcast_aggregated_share(self, agg_share: 'AggregatedShare'):
        """广播聚合份额"""
        with self.lock:
            for participant_id in self.message_queues.keys():
                self.message_queues[participant_id].put(('aggregated', agg_share))

    def broadcast_validation_vector(self, validation: ValidationVector) -> None:
        """广播本地验证结果"""
        with self.lock:
            for participant_id in self.message_queues.keys():
                self.message_queues[participant_id].put(('validation', validation))
    
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
    def __init__(self, n: int, t: int, prime: int = PRIME, slack_factor: float = 10.0, rng: Optional[SecureRandom] = None):
        self.n = n
        self.t = t
        self.prime = prime
        self.slack_factor = slack_factor
        self.performance_stats = []
        self.rng = rng or SecureRandom("legacy-v3s-core")
    
    def add_performance_stat(self, phase_name: str, duration: float, operations: Dict[str, int] = None):
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
            print(f"│  ⏱  Duration:    {stat.duration*1000:.4f} ms  ({percentage:.1f}% of total)")
            
            if stat.operations:
                print(f"│  📊 操作次数:")
                for op_name, count in stat.operations.items():
                    print(f"│     • {op_name}: {count:,}")
            print(f"└{'─'*78}\n")
        
        # 打印总计
        print("="*80)
        print(f"🕐 TOTAL EXECUTION TIME: {total_time*1000:.4f} ms ({total_time:.6f} seconds)")
        print("="*80 + "\n")
    
    def compute_spectral_norm(self, matrix: np.ndarray) -> float:
        singular_values = np.linalg.svd(matrix, compute_uv=False)
        return float(singular_values[0])
    
    def compute_bound(self, R: np.ndarray, sigma_x: float, sigma_y: float, d: int) -> float:
        spectral_norm = self.compute_spectral_norm(R)
        sigma_p = spectral_norm * sigma_x
        sigma_v = sigma_p + sigma_y
        bound = self.slack_factor * sigma_v * np.sqrt(2 * d)
        return bound
    
    def lagrange_interpolate(self, shares: List[Share]) -> int:
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

    def reed_solomon_reconstruct(self, shares: List[Share]) -> int:
        """使用Reed–Solomon纠错重构秘密"""
        num_shares = len(shares)
        if num_shares < self.t:
            raise ValueError("Insufficient shares for reconstruction")

        max_correctable = max(0, (num_shares - self.t) // 2)
        if max_correctable == 0:
            return self.lagrange_interpolate(shares[:self.t])

        unknowns = self.t + max_correctable
        if num_shares < unknowns:
            return self.lagrange_interpolate(shares[:self.t])

        matrix: List[List[int]] = []
        vector: List[int] = []

        for share in shares:
            x_val = share.index % self.prime
            y_val = share.value % self.prime

            row: List[int] = []
            x_power = 1
            for _ in range(self.t):
                row.append(x_power)
                x_power = (x_power * x_val) % self.prime

            for error_deg in range(1, max_correctable + 1):
                term = (-y_val * pow(x_val, error_deg, self.prime)) % self.prime
                row.append(term)

            matrix.append(row)
            vector.append(y_val)

        try:
            solution = self._solve_linear_system_mod(matrix, vector, self.prime)
        except ValueError:
            return self.lagrange_interpolate(shares[:self.t])

        secret = solution[0] % self.prime
        return int(secret)

    def generate_random_matrix(self, d: int, n: int, seed: str) -> np.ndarray:
        random_bytes = hashlib.shake_128(seed.encode()).digest(n * d // 4 + 1)
        matrix = np.zeros((d, n), dtype=int)
        byte_idx = 0
        bit_pair_idx = 0
        current_byte = random_bytes[0]
        for i in range(d):
            for j in range(n):
                if bit_pair_idx == 4:
                    byte_idx += 1
                    current_byte = random_bytes[byte_idx]
                    bit_pair_idx = 0
                bit_pair = (current_byte >> (2 * bit_pair_idx)) & 0b11
                bit_pair_idx += 1
                if bit_pair == 0 or bit_pair == 1:
                    matrix[i, j] = 0
                elif bit_pair == 2:
                    matrix[i, j] = 1
                else:
                    matrix[i, j] = -1
        return matrix

    def aggregate_v_shares(self, v_shares: List[List[int]]) -> List[int]:
        if not v_shares:
            return []

        dimension = len(v_shares[0])
        aggregated: List[int] = []

        for idx in range(dimension):
            shares_for_coord = [
                Share(int(vector[idx]) % self.prime, participant_index + 1)
                for participant_index, vector in enumerate(v_shares)
            ]

            reconstructed = self.lagrange_interpolate(shares_for_coord)
            if reconstructed > self.prime // 2:
                reconstructed -= self.prime
            aggregated.append(int(reconstructed))

        return aggregated

    def shamir_share(self, secret: int, n: int, t: int) -> List[Share]:
        coefficients = [secret % self.prime] + [self.rng.randbelow(self.prime) for _ in range(t-1)]
        
        shares = []
        for i in range(1, n+1):
            value = 0
            for power, coeff in enumerate(coefficients):
                value = (value + coeff * pow(i, power, self.prime)) % self.prime
            shares.append(Share(value, i))
        return shares

    def share_vector(self, secret_vector: List[int], sigma_x: float = 1.0, sigma_y: float = 18.36) -> Tuple[Any, List[Any], List[Any]]:
        """为单个参与者的秘密向量生成份额"""
        d = len(secret_vector)
        
        # 步骤1: 生成噪声向量
        start_time = time.time()
        y_vector = self.rng.gaussian_vector(d, 0.0, sigma_y)
        step1_time = time.time() - start_time
        
        # 步骤2: Shamir秘密共享
        start_time = time.time()
        x_shares = [self.shamir_share(secret_vector[i], self.n, self.t) for i in range(d)]
        y_shares = [self.shamir_share(y_vector[i], self.n, self.t) for i in range(d)]
        step2_time = time.time() - start_time
        self.add_performance_stat("Shamir秘密共享", step2_time, {
            "多项式构造 (为x和y的每个分量创建t-1次多项式)": 2 * d,
            "份额生成 (对每个多项式生成n个份额点)": 2 * d * self.n,
            "模幂运算 (计算i^power mod p,用于多项式求值)": 2 * d * self.n * self.t,
            "模乘法运算 (多项式系数乘法,在有限域GF(p)上)": 2 * d * self.n * self.t
        })
        
        # 步骤3: 构建Merkle树
        start_time = time.time()
        salt = self.rng.decimal_salt(128)
        leaf_data = []
        salts = []
        
        for participant in range(self.n):
            x_participant = [x_shares[i][participant].value for i in range(d)]
            y_participant = [y_shares[i][participant].value for i in range(d)]
            participant_salt = self.rng.decimal_salt(128)
            salts.append(participant_salt)
            leaf = '|'.join(map(str, x_participant + y_participant)) + '|' + participant_salt
            leaf_hash = MerkleTree.hash_item(leaf)
            leaf_data.append(leaf_hash)
        
        merkle_tree = MerkleTree(leaf_data)
        h = merkle_tree.root.hash
        step3_time = time.time() - start_time
        
        # 计算Merkle树的哈希次数
        merkle_hashes = self.n  # 叶子节点哈希
        tree_levels = 0
        nodes = self.n
        while nodes > 1:
            nodes = (nodes + 1) // 2
            merkle_hashes += nodes
            tree_levels += 1
        
        self.add_performance_stat("Merkle树构建", step3_time, {
            "叶子节点数 (每个参与者对应一个叶子)": self.n,
            "树的层数 (二叉树高度=log₂(n))": tree_levels,
            "SHA-256哈希 (叶子哈希+所有内部节点哈希)": merkle_hashes,
            "随机盐生成 (128位随机数,防止叶子碰撞)": self.n
        })
        
        # 步骤4: 生成挑战矩阵R
        start_time = time.time()
        R = self.generate_random_matrix(d, d, h)
        spectral_norm = self.compute_spectral_norm(R)
        bound = self.compute_bound(R, sigma_x, sigma_y, d)
        step4_time = time.time() - start_time
        self.add_performance_stat("挑战矩阵与界限计算", step4_time, {
            "矩阵元素生成 (d×d矩阵,元素为{-1,0,1})": d * d,
            "SHAKE-128摘要 (可扩展输出函数,生成伪随机字节)": d * d // 4 + 1,
            "SVD分解 (奇异值分解,O(d³)复杂度)": 1,
            "谱范数计算 (取最大奇异值σ₁,衡量矩阵拉伸能力)": 1
        })
        
        # 步骤5: 计算验证向量v
        start_time = time.time()
        v_shares = []
        half_prime = self.prime // 2
        matrix_mults = 0
        modular_ops = 0
        
        for participant in range(self.n):
            x_participant = [x_shares[i][participant].value for i in range(d)]
            y_participant = [y_shares[i][participant].value for i in range(d)]
            v_i = []
            for i in range(d):
                v_elem = int(y_participant[i]) % self.prime
                modular_ops += 1
                for j in range(d):
                    v_elem = (v_elem + int(R[i][j]) * int(x_participant[j])) % self.prime
                    matrix_mults += 1
                    modular_ops += 2
                
                if v_elem > half_prime:
                    v_elem = v_elem - self.prime
                    
                v_i.append(int(v_elem))
            v_shares.append(v_i)
        
        aggregated_v = self.aggregate_v_shares(v_shares)

        step5_time = time.time() - start_time
        self.add_performance_stat("验证向量计算", step5_time, {
            "矩阵向量乘法 (计算R·x_i,每个参与者一次)": self.n,
            "标量乘法 (矩阵元素×向量元素,共n×d×d次)": matrix_mults,
            "模运算 (加法+取模,保持在有限域GF(p)内)": modular_ops,
            "中心化转换 (将[0,p)映射到[-p/2,p/2],便于范数计算)": self.n * d
        })
        
        # 准备证明数据
        share_data = []
        for participant in range(self.n):
            merkle_proof = merkle_tree.get_proof(participant)
            share_info = {
                'x_shares': [x_shares[i][participant].value for i in range(d)],
                'y_shares': [y_shares[i][participant].value for i in range(d)],
                'salt': salts[participant],
                'merkle_proof': merkle_proof
            }
            share_data.append(share_info)
        
        public_proof = {
            'h': h,
            'v_shares': v_shares,
            'aggregated_v': aggregated_v,
            'R': R.tolist(),
            'bound': bound,
            'spectral_norm': spectral_norm,
            'sigma_x': sigma_x,
            'sigma_y': sigma_y,
            'main_salt': salt
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
        
        # 步骤1: 验证Merkle proof
        leaf = '|'.join(map(str, participant_proof['x_shares'] + participant_proof['y_shares'])) + '|' + participant_proof['salt']
        leaf_hash = MerkleTree.hash_item(leaf)
        operations['SHA-256叶子哈希 (重构参与者的叶子节点哈希)'] = 1
        
        merkle_proof_len = len(participant_proof['merkle_proof'])
        if not MerkleTree.verify_proof(leaf_hash, participant_proof['merkle_proof'], public_proof['h']):
            duration = time.time() - start_time
            operations['SHA-256路径哈希 (验证从叶子到根的路径)'] = merkle_proof_len
            return False, duration, operations
        
        operations['SHA-256路径哈希 (验证从叶子到根的路径)'] = merkle_proof_len
        operations['Merkle证明验证 (检查份额属于承诺树)'] = 1
        
        # 步骤2: 验证线性关系
        R = np.array(public_proof['R'], dtype=object)
        x_share = np.array(participant_proof['x_shares'], dtype=object)
        y_share = np.array(participant_proof['y_shares'], dtype=object)
        
        v_calc = np.zeros(len(x_share), dtype=object)
        scalar_mults = 0
        modular_ops = 0
        
        for i in range(len(v_calc)):
            v_calc[i] = int(y_share[i])
            modular_ops += 1
            for j in range(len(x_share)):
                v_calc[i] = (v_calc[i] + int(R[i][j]) * int(x_share[j])) % self.prime
                scalar_mults += 1
                modular_ops += 2
        
        operations['标量乘法 (计算R·x_i,矩阵元素×向量元素)'] = scalar_mults
        operations['模运算 (加法和取模,保持在有限域内)'] = modular_ops
        
        v_public = np.array(public_proof['v_shares'][participant_id-1], dtype=object);
        
        for i in range(len(v_calc)):
            if int(v_calc[i]) % self.prime != int(v_public[i]) % self.prime:
                duration = time.time() - start_time
                return False, duration, operations
        
        operations['线性关系检查 (验证v_i=R·x_i+y_i是否成立)'] = len(v_calc)
        
        # 步骤3: 验证聚合向量的范数
        aggregated_v = public_proof.get('aggregated_v')
        if aggregated_v is None:
            aggregated_v = self.aggregate_v_shares(public_proof['v_shares'])

        half_prime = self.prime // 2
        aggregated_centered: List[float] = []

        for val in aggregated_v:
            int_val = int(val) % self.prime
            if int_val > half_prime:
                int_val = int_val - self.prime
            aggregated_centered.append(float(int_val))

        operations['中心化转换 (聚合验证向量)'] = len(aggregated_centered)

        norm = np.linalg.norm(aggregated_centered)
        operations['范数计算 (聚合v向量||v||₂)'] = 1
        
        duration = time.time() - start_time
        
        if norm > public_proof['bound']:
            return False, duration, operations
        
        return True, duration, operations
    
    def reconstruct_secret(self, x_shares_list: List[List[Share]], participant_indices: List[int]) -> Tuple[List[int], float, Dict[str, int]]:
        """
        使用拉格朗日插值重构秘密向量
        
        参数:
        x_shares_list: 每个维度的所有份额列表 [dim0_shares, dim1_shares, ...]
        participant_indices: 参与重构的参与者索引（至少t个）
        
        返回: (重构的秘密向量, 耗时, 操作统计)
        """
        start_time = time.time()
        operations = {}
        
        d = len(x_shares_list)
        secret_vector = []
        half_prime = self.prime // 2
        
        lagrange_interps = 0
        modular_inverses = 0
        modular_mults = 0
        
        for i in range(d):
            shares_to_use = [x_shares_list[i][idx] for idx in participant_indices[:self.t]]
            
            # 统计拉格朗日插值的操作
            k = len(shares_to_use)
            for j in range(k):
                for m in range(k):
                    if j != m:
                        modular_mults += 2  # numerator和denominator计算
                modular_inverses += 1  # 每个基函数需要一次模逆
                modular_mults += 2  # yi * numerator * denominator_inv
            
            secret = self.lagrange_interpolate(shares_to_use)
            lagrange_interps += 1
            
            secret = secret % self.prime
            if secret > half_prime:
                secret = secret - self.prime
                
            secret_vector.append(int(secret))
        
        duration = time.time() - start_time
        
        operations['拉格朗日插值 (多项式插值,每个维度一次)'] = lagrange_interps
        operations['模逆元计算 (费马小定理a^(p-2) mod p,255位大数幂运算)'] = modular_inverses * d
        operations['模乘法 (拉格朗日基函数计算,有限域乘法)'] = modular_mults
        operations['中心化转换 (重构结果转回有符号表示)'] = d
        
        return secret_vector, duration, operations

class DistributedParticipant(threading.Thread):
    """分布式参与者"""
    
    def __init__(self, participant_id: int, n: int, t: int, d: int, 
                 network: NetworkSimulator,
                 sigma_x: float = 1.0, sigma_y: float = 18.36):
        super().__init__()
        self.participant_id = participant_id
        self.n = n
        self.t = t
        self.d = d
        self.network = network
        self.sigma_x = sigma_x
        self.sigma_y = sigma_y

        self.rng = SecureRandom(f"legacy-participant-{participant_id}")
        self.v3s = V3S(n, t, rng=self.rng.derive_child(f"legacy-v3s-core-{participant_id}"))
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
        
        # 公钥生成统计
        self.public_key_generation_time = 0  # 全局公钥生成总时间
        
        # 网络通信统计
        self.network_send_time = 0
        self.network_receive_time = 0
        self.network_ops = {}
        
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
        self.secret_vector = self.rng.gaussian_vector(self.d, 0.0, self.sigma_x)
        print(f"[Participant {self.participant_id}] Generated secret vector: {self.secret_vector}")
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
                self.noise_share_vector = [int(val) for val in self.share_data[own_index]['y_shares']]
        
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

            self.network.send_encrypted_share(package)
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
        
        self.network.broadcast_proof(proof)
        
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
                    self.network.broadcast_complaint(complaint)
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
                    self.network.broadcast_complaint(complaint)
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
                    self.network.broadcast_complaint(complaint)
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
        self.aggregate_and_reconstruct_global_secret()
    
    def broadcast_and_collect_validation_vectors(self) -> None:
        """广播本地验证结果并与其他参与者求交集."""

        accepted_ids = set(self.local_valid_ids)
        accepted_ids.add(self.participant_id)

        validation_vector = ValidationVector(
            participant_id=self.participant_id,
            accepted_ids=sorted(accepted_ids),
        )

        send_start = time.time()
        self.network.broadcast_validation_vector(validation_vector)
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
    
    def aggregate_and_reconstruct_global_secret(self):
        """聚合所有有效份额并重构全局秘密"""
        print(f"[Participant {self.participant_id}] Aggregating shares for global secret reconstruction...")
        
        # 确保有足够的有效份额（至少达到阈值）
        all_valid_ids = sorted(set(self.valid_shares + [self.participant_id]))
        
        if len(all_valid_ids) < self.t:
            print(f"[Participant {self.participant_id}] ⚠️  Insufficient valid shares ({len(all_valid_ids)} < {self.t}), cannot reconstruct global secret")
            return
        
        # 步骤1: 计算自己位置的聚合份额
        # share_i(S_global) = share_i(S_1) + share_i(S_2) + ... + share_i(S_n)
        aggregation_start = time.time()
        
        my_position = self.participant_id - 1
        aggregated_shares_d_values = []
        
        for dim in range(self.d):
            # 从自己的 x_shares 中获取自己位置的份额值（自己的秘密）
            my_share_value = self.x_shares[dim][my_position].value
            aggregated_value = my_share_value
            
            # 累加所有有效参与者发给我的份额
            for valid_pid in self.valid_shares:
                if valid_pid in self.received_shares:
                    share_info = self.received_shares[valid_pid]
                    # share_info['x_shares'][dim] 是参与者valid_pid发给我的第dim维的份额
                    aggregated_value = (aggregated_value + share_info['x_shares'][dim]) % self.v3s.prime
            
            aggregated_shares_d_values.append(aggregated_value)
        
        aggregation_time = time.time() - aggregation_start
        self.aggregated_shares = aggregated_shares_d_values
        print(f"[Participant {self.participant_id}] Computed aggregated share at own position ({aggregation_time*1000:.2f} ms)")
        
        # 步骤2: 广播自己的聚合份额
        broadcast_start = time.time()
        agg_share = AggregatedShare(
            participant_id=self.participant_id,
            aggregated_values=aggregated_shares_d_values
        )
        self.network.broadcast_aggregated_share(agg_share)
        broadcast_time = time.time() - broadcast_start
        print(f"[Participant {self.participant_id}] Broadcasted aggregated share ({broadcast_time*1000:.2f} ms)")
        
        # 步骤3: 接收其他参与者的聚合份额
        time.sleep(0.5)  # 等待其他参与者广播
        receive_start = time.time()
        received_agg_shares = self.network.receive_aggregated_shares(self.participant_id, len(all_valid_ids))
        receive_time = time.time() - receive_start
        print(f"[Participant {self.participant_id}] Received {len(received_agg_shares)} aggregated shares ({receive_time*1000:.2f} ms)")
        
        # 步骤4: 使用Reed–Solomon纠错+插值重构全局秘密
        reconstruction_start = time.time()
        
        # 收集至少t个参与者的聚合份额
        available_agg_shares = {}
        available_agg_shares[self.participant_id] = aggregated_shares_d_values
        
        for agg_share in received_agg_shares:
            if agg_share.participant_id in all_valid_ids:
                available_agg_shares[agg_share.participant_id] = agg_share.aggregated_values
        
        if len(available_agg_shares) < self.t:
            print(f"[Participant {self.participant_id}] ⚠️  Insufficient aggregated shares ({len(available_agg_shares)} < {self.t})")
            return
        
        participants_used = sorted(available_agg_shares.keys())
        correctable_errors = max(0, (len(participants_used) - self.t) // 2)
        
        global_secret_vector = []
        
        for dim in range(self.d):
            shares_for_dim = [Share(value=available_agg_shares[pid][dim], index=pid) for pid in participants_used]

            try:
                secret_dim = self.v3s.reed_solomon_reconstruct(shares_for_dim)
            except ValueError:
                print(f"[Participant {self.participant_id}] ❌ Reed–Solomon decoding failed (errors > {correctable_errors})")
                print(f"[Participant {self.participant_id}] Aborting DKG: insufficient clean shares to reconstruct dimension {dim}")
                self.reconstruction_time = aggregation_time + broadcast_time + receive_time + (time.time() - reconstruction_start)
                self.done_event.set()
                raise
            
            # 中心化转换
            half_prime = self.v3s.prime // 2
            if secret_dim > half_prime:
                secret_dim = secret_dim - self.v3s.prime
            
            global_secret_vector.append(int(secret_dim))
        
        reconstruction_time = time.time() - reconstruction_start
        self.reconstruction_time = aggregation_time + broadcast_time + receive_time + reconstruction_time
        self.global_secret = global_secret_vector
        
        # 计算全局秘密的范数
        global_norm = np.linalg.norm(global_secret_vector)
        
        print(f"[Participant {self.participant_id}] ✓ Reconstructed global secret: {global_secret_vector}")
        print(f"[Participant {self.participant_id}] Global secret norm: ||S_global|| = {global_norm:.4f}")
        print(f"[Participant {self.participant_id}] Used {len(participants_used)} participants: {participants_used}")
        print(f"[Participant {self.participant_id}] Reed–Solomon correctable errors ≤ {correctable_errors}")
        print(f"[Participant {self.participant_id}] Total reconstruction time: {self.reconstruction_time*1000:.2f} ms")
        
        # 步骤5: 基于共识盐值生成公共矩阵A并计算部分公钥
        self.generate_public_matrix_and_compute_keys()
    
    def generate_public_matrix_and_compute_keys(self):
        """基于共识盐值生成公共矩阵A，并计算部分公钥和全局公钥"""
        print(f"[Participant {self.participant_id}] Generating public matrix A from consensus salt...")
        
        if self.consensus_salt is None:
            print(f"[Participant {self.participant_id}] ⚠️  No consensus salt available!")
            return
        
        start_time = time.time()
        
        # 使用共识盐值生成随机矩阵A（维度为 d×d）
        # 使用SHAKE-256扩展输出函数生成足够的随机字节
        matrix_size = self.d * self.d
        bytes_needed = matrix_size * 4  # 每个元素用4字节表示
        
        # 从共识盐值派生矩阵元素
        random_bytes = hashlib.shake_256(self.consensus_salt.encode()).digest(bytes_needed)
        
        # 构建随机矩阵A（元素范围：[0, 2^31-1]，使用模运算确保在有限域内）
        A = np.zeros((self.d, self.d), dtype=object)
        
        for i in range(self.d):
            for j in range(self.d):
                byte_idx = (i * self.d + j) * 4
                # 将4个字节转换为一个整数
                value = int.from_bytes(random_bytes[byte_idx:byte_idx+4], byteorder='big')
                # 使用模运算将值限制在有限域内
                A[i, j] = value % self.v3s.prime
        
        self.public_matrix_A = A
        
        matrix_gen_time = time.time() - start_time
        print(f"[Participant {self.participant_id}] Generated {self.d}×{self.d} public matrix A ({matrix_gen_time*1000:.2f} ms)")
        print(f"[Participant {self.participant_id}] Matrix structure: A_{self.d}×{self.d}")
        
        # 计算部分公钥 b_i = A * s_i
        partial_key_start = time.time()
        
        if self.secret_vector is None:
            raise ValueError("Secret vector unavailable for key generation")

        secret_vector = np.array(self.secret_vector, dtype=object)
        
        partial_public_key = np.zeros(self.d, dtype=object)
        for i in range(self.d):
            value = 0
            for j in range(self.d):
                value = (value + int(self.public_matrix_A[i, j]) * int(secret_vector[j])) % self.v3s.prime
            partial_public_key[i] = int(value)
        
        self.partial_public_key = partial_public_key.tolist()
        
        partial_key_time = time.time() - partial_key_start
        print(f"[Participant {self.participant_id}] Computed partial public key b_{self.participant_id} = A * s_{self.participant_id} ({partial_key_time*1000:.2f} ms)")
        print(f"[Participant {self.participant_id}] Partial public key: {[int(val) % 1000 for val in self.partial_public_key[:min(4, len(self.partial_public_key))]]}... (mod 1000)")
        
        # 广播部分公钥
        broadcast_start = time.time()

        # 创建部分公钥消息（使用现有的消息类或创建新的）
        # 这里我们使用网络直接广播
        partial_key_message = {
            'participant_id': self.participant_id,
            'partial_public_key': self.partial_public_key
        }

        # 广播部分公钥给所有参与者
        with self.network.lock:
            for pid in self.network.message_queues.keys():
                self.network.message_queues[pid].put(('partial_key', partial_key_message))

        broadcast_time = time.time() - broadcast_start
        print(f"[Participant {self.participant_id}] Broadcasted partial public key ({broadcast_time*1000:.2f} ms)")
        
        # 接收其他参与者的部分公钥
        time.sleep(0.5)  # 等待其他参与者广播
        receive_start = time.time()
        
        received_partial_keys = {}
        received_partial_keys[self.participant_id] = self.partial_public_key
        
        # 获取所有有效参与者的ID
        all_valid_ids = sorted(set(self.valid_shares + [self.participant_id]))
        
        timeout = 2.0
        start_wait = time.time()
        messages_to_requeue = []
        
        while len(received_partial_keys) < len(all_valid_ids) and time.time() - start_wait < timeout:
            try:
                msg_type, data = self.network.message_queues[self.participant_id].get(timeout=0.1)
                if msg_type == 'partial_key':
                    pid = data['participant_id']
                    if pid in all_valid_ids and pid not in received_partial_keys:
                        received_partial_keys[pid] = data['partial_public_key']
                        print(f"[Participant {self.participant_id}] Received partial public key from Participant {pid}")
                else:
                    messages_to_requeue.append((msg_type, data))
            except:
                break
        
        # 重新放回非部分公钥消息
        for msg in messages_to_requeue:
            self.network.message_queues[self.participant_id].put(msg)
        
        receive_time = time.time() - receive_start
        print(f"[Participant {self.participant_id}] Received {len(received_partial_keys)-1} partial public keys ({receive_time*1000:.2f} ms)")
        
        # 计算全局公钥 b = b_1 + b_2 + ... + b_n
        aggregate_start = time.time()
        
        global_public_key = np.zeros(self.d, dtype=object)
        
        for pid in sorted(received_partial_keys.keys()):
            partial_key = received_partial_keys[pid]
            for i in range(self.d):
                global_public_key[i] = (int(global_public_key[i]) + int(partial_key[i])) % self.v3s.prime
        
        self.global_public_key = global_public_key.tolist()
        
        aggregate_time = time.time() - aggregate_start
        
        total_key_time = matrix_gen_time + partial_key_time + broadcast_time + receive_time + aggregate_time
        
        # 记录并暴露全局公钥生成的时间与统计，便于最后统一聚合为 Phase 7
        self.public_key_generation_time = total_key_time
        try:
            self.v3s.add_performance_stat(
                "全局公钥生成",
                total_key_time,
                {
                    "矩阵生成 (A, d×d)": self.d * self.d,
                    "部分公钥计算 (A×s_i)": self.d * self.d,
                    "部分公钥广播 (每个参与者)": len(self.network.message_queues),
                    "部分公钥接收 (估计每个参与者接收)": len(all_valid_ids)
                }
            )
        except Exception:
            # 兼容性保护：若在某些测试路径中无法记录，不影响主流程
            pass
        
        print(f"[Participant {self.participant_id}] ✓ Computed global public key b = sum(b_i) ({aggregate_time*1000:.2f} ms)")
        print(f"[Participant {self.participant_id}] Global public key: {[int(val) % 1000 for val in self.global_public_key[:min(4, len(self.global_public_key))]]}... (mod 1000)")
        print(f"[Participant {self.participant_id}] Total public key generation time: {total_key_time*1000:.2f} ms")

def test_distributed_v3s():
    """测试分布式V3S协议"""
    print("\n" + "="*80)
    print("***  DISTRIBUTED V3S PROTOCOL TEST  ***".center(80))
    print("="*80 + "\n")
    
    # 协议参数
    num_participants = 5
    threshold = 3
    dimension = 4
    sigma_x = 1.0
    sigma_y = sigma_x * (337 ** 0.5)
    
    print("*** Protocol Parameters ***")
    print(f"  • Number of participants (N): {num_participants}")
    print(f"  • Threshold (T):              {threshold}")
    print(f"  • Vector dimension (d):       {dimension}")
    print(f"  • sigma_x:                    {sigma_x:.2f}")
    print(f"  • sigma_y:                    {sigma_y:.2f} (= √337 × sigma_x)")
    print(f"  • Prime field size:           2^255 - 19")
    print(f"  • Prime bit length:           {PRIME.bit_length()} bits")
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
    
    # 全局秘密重构阶段
    print("\n" + "="*80)
    print("***  GLOBAL SECRET RECONSTRUCTION  ***".center(80))
    print("="*80 + "\n")
    
    # 验证所有参与者是否成功重构全局秘密
    global_secrets = {}
    reconstruction_times = {}
    
    for participant in participants:
        if participant.global_secret is not None:
            global_secrets[participant.participant_id] = participant.global_secret
            reconstruction_times[participant.participant_id] = participant.reconstruction_time
            print(f"  Participant {participant.participant_id}: ✓ Reconstructed global secret")
            print(f"     Global secret: {participant.global_secret}")
            print(f"     ||S_global|| = {np.linalg.norm(participant.global_secret):.4f}")
            print(f"     Reconstruction time: {participant.reconstruction_time*1000:.2f} ms")
        else:
            print(f"  Participant {participant.participant_id}: ✗ Failed to reconstruct global secret")
    
    # 验证一致性：所有参与者重构的全局秘密应该相同
    if global_secrets:
        unique_secrets = list(set([tuple(s) for s in global_secrets.values()]))
        if len(unique_secrets) == 1:
            print(f"\n  ✓ All participants reconstructed the SAME global secret!")
            print(f"  Global secret: {list(unique_secrets[0])}")
            print(f"  ||S_global|| = {np.linalg.norm(unique_secrets[0]):.4f}")
        else:
            print(f"\n  ✗ WARNING: Participants reconstructed DIFFERENT global secrets!")
            for pid, secret in global_secrets.items():
                print(f"     P{pid}: {secret}")
        
        # 验证全局秘密是否等于所有参与者秘密的和
        print(f"\n  📊 Verification: S_global = S_1 + S_2 + ... + S_n")
        
        # 计算期望的全局秘密（所有参与者原始秘密的和）
        expected_global_secret = [0] * dimension
        for participant in participants:
            secret = participant.secret_vector
            for i in range(dimension):
                expected_global_secret[i] += secret[i]
        
        print(f"  Expected global secret (sum of all secrets): {expected_global_secret}")
        print(f"  Expected ||S_global|| = {np.linalg.norm(expected_global_secret):.4f}")
        
        # 比较重构的全局秘密与期望值
        if unique_secrets:
            reconstructed = list(unique_secrets[0])
            match = all(abs(reconstructed[i] - expected_global_secret[i]) < 1e-6 for i in range(dimension))
            if match:
                print(f"  ✓ Reconstructed global secret MATCHES expected sum!")
            else:
                print(f"  ✗ Reconstructed global secret DOES NOT match expected sum!")
                print(f"  Difference: {[reconstructed[i] - expected_global_secret[i] for i in range(dimension)]}")
        
        # 平均重构时间
        avg_recon_time = np.mean(list(reconstruction_times.values()))
        print(f"\n  ⏱  Average global secret reconstruction time: {avg_recon_time*1000:.2f} ms")
    else:
        print(f"\n  ✗ No participants successfully reconstructed the global secret")
    
    # 全局公钥验证阶段
    print("\n" + "="*80)
    print("***  GLOBAL PUBLIC KEY GENERATION  ***".center(80))
    print("="*80 + "\n")
    
    # 验证所有参与者是否成功生成全局公钥
    global_public_keys = {}
    partial_public_keys = {}
    public_matrices = {}
    
    for participant in participants:
        if participant.global_public_key is not None:
            global_public_keys[participant.participant_id] = participant.global_public_key
            partial_public_keys[participant.participant_id] = participant.partial_public_key
            public_matrices[participant.participant_id] = participant.public_matrix_A
            
            print(f"  Participant {participant.participant_id}: ✓ Generated global public key")
            print(f"     Partial key b_{participant.participant_id}: {[int(val) % 1000 for val in participant.partial_public_key[:4]]}... (mod 1000)")
            print(f"     Global key b: {[int(val) % 1000 for val in participant.global_public_key[:4]]}... (mod 1000)")
        else:
            print(f"  Participant {participant.participant_id}: ✗ Failed to generate global public key")
    
    # 验证一致性
    if global_public_keys:
        # 验证所有参与者的公共矩阵A相同
        print(f"\n  🔐 Public Matrix A Verification:")
        if public_matrices:
            # 比较所有矩阵是否相同
            matrix_list = list(public_matrices.values())
            all_same = True
            first_matrix = matrix_list[0]
            
            for matrix in matrix_list[1:]:
                if not np.array_equal(first_matrix, matrix):
                    all_same = False
                    break
            
            if all_same:
                print(f"     ✓ All participants generated the SAME public matrix A!")
                print(f"     Matrix A shape: {first_matrix.shape} (expected: {dimension}×{dimension})")
                print(f"     Matrix A preview (first row, mod 1000): {[int(val) % 1000 for val in first_matrix[0][:min(4, dimension)]]}")
            else:
                print(f"     ✗ WARNING: Participants generated DIFFERENT public matrices!")
        
        # 验证所有参与者计算的全局公钥相同
        print(f"\n  🔑 Global Public Key Verification:")
        unique_keys = list(set([tuple(k) for k in global_public_keys.values()]))
        
        if len(unique_keys) == 1:
            print(f"     ✓ All participants computed the SAME global public key!")
            print(f"     Global public key b: {[int(val) % 1000 for val in unique_keys[0][:4]]}... (mod 1000)")
        else:
            print(f"     ✗ WARNING: Participants computed DIFFERENT global public keys!")
            for pid, key in global_public_keys.items():
                print(f"     P{pid}: {[int(val) % 1000 for val in key[:4]]}... (mod 1000)")
        
        # 验证数学正确性：b = A * s_global
        print(f"\n  📊 Mathematical Verification: b = A * s_global")

        if global_secrets and public_matrices:
            # 使用第一个参与者的矩阵A和全局秘密计算期望的全局公钥
            A_matrix = list(public_matrices.values())[0]
            s_global = np.array(list(global_secrets.values())[0], dtype=object)

            expected_global_key = np.zeros(dimension, dtype=object)
            for i in range(dimension):
                value = 0
                for j in range(dimension):
                    value = (value + int(A_matrix[i, j]) * int(s_global[j])) % PRIME
                expected_global_key[i] = int(value)

            expected_global_key_list = expected_global_key.tolist()

            print(f"  Expected b = A * s_global: {[int(val) % 1000 for val in expected_global_key_list[:4]]}... (mod 1000)")

            # 比较计算的全局公钥与期望值
            if unique_keys:
                computed_key = list(unique_keys[0])
                match = all(int(computed_key[i]) % PRIME == int(expected_global_key_list[i]) % PRIME for i in range(dimension))

                if match:
                    print(f"  ✓ Global public key MATCHES A * s_global!")
                else:
                    print(f"  ✗ Global public key DOES NOT match A * s_global!")
                    print(f"  Difference (first 4): {[int(computed_key[i]) - int(expected_global_key_list[i]) for i in range(min(4, dimension))]}")

        # 验证：b = sum(b_i) = sum(A * s_i)
        print(f"\n  📊 Verification: b = sum(b_i) = sum(A * s_i)")
        
        if partial_public_keys and len(partial_public_keys) >= threshold:
            # 计算所有部分公钥的和
            computed_sum = np.zeros(dimension, dtype=object)
            
            for pid, partial_key in partial_public_keys.items():
                for i in range(dimension):
                    computed_sum[i] = (int(computed_sum[i]) + int(partial_key[i])) % PRIME
            
            computed_sum_list = computed_sum.tolist()
            
            print(f"  Computed sum(b_i): {[int(val) % 1000 for val in computed_sum_list[:4]]}... (mod 1000)")
            
            if unique_keys:
                global_key = list(unique_keys[0])
                match = all(int(global_key[i]) % PRIME == int(computed_sum_list[i]) % PRIME for i in range(dimension))
                
                if match:
                    print(f"  ✓ Global public key b MATCHES sum(b_i)!")
                else:
                    print(f"  ✗ Global public key b DOES NOT match sum(b_i)!")
    else:
        print(f"\n  ✗ No participants successfully generated global public key")
    
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
            "全局秘密重构",
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
        
        # 全局秘密重构（并发，取最大值）
        if reconstruction_times:
            max_global_recon_time = max(reconstruction_times.values())
        else:
            max_global_recon_time = 0
        aggregated_v3s.add_performance_stat(
            "全局秘密重构",
            max_global_recon_time,
            {
                "聚合份额计算 (每个参与者计算自己位置的聚合份额)": num_participants,
                "聚合份额广播 (每个参与者广播自己的聚合份额)": num_participants,
                "聚合份额接收 (每个参与者接收其他人的聚合份额)": num_participants * num_participants,
                "拉格朗日插值 (使用t个聚合份额重构全局秘密)": num_participants * dimension,
                "模逆元计算 (拉格朗日插值中的模逆运算)": num_participants * dimension * threshold * (threshold - 1),
                "模乘法 (拉格朗日基函数计算)": num_participants * dimension * threshold * threshold * 2,
            }
        )
        
        # 全局公钥生成（并发，取最大值）—— Phase 7
        public_key_times = [p.public_key_generation_time for p in participants]
        max_pub_key_time = max(public_key_times) if public_key_times else 0
        combined_pub_ops = {
            "矩阵生成 (A, d×d, 所有参与者)": num_participants * dimension * dimension,
            "部分公钥计算 (A×s_i, 所有参与者)": num_participants * dimension * dimension,
            "部分公钥广播 (估计)": num_participants,
            "部分公钥接收 (估计)": num_participants * num_participants
        }
        aggregated_v3s.add_performance_stat("全局公钥生成", max_pub_key_time, combined_pub_ops)
        
        aggregated_v3s.print_performance_report()

if __name__ == "__main__":
    test_distributed_v3s()
