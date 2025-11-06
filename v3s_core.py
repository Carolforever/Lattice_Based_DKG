"""Core V3S protocol primitives: sharing, verification and reconstruction."""

from __future__ import annotations

import hashlib
import random
import time
from typing import Any, Dict, List, Tuple

import numpy as np

from constants import PRIME
from data_models import PerformanceStats, Share
from merkle import MerkleTree


class V3S:
    def __init__(self, n: int, t: int, prime: int = PRIME, slack_factor: float = 10.0):
        self.n = n
        self.t = t
        self.prime = prime
        self.slack_factor = slack_factor
        self.performance_stats: List[PerformanceStats] = []

    def add_performance_stat(self, phase_name: str, duration: float, operations: Dict[str, int] | None = None) -> None:
        stat = PerformanceStats(phase_name, duration, operations or {})
        self.performance_stats.append(stat)

    def print_performance_report(self) -> None:
        """打印优雅的性能报告 / Pretty-print collected performance statistics."""
        print("\n" + "=" * 80)
        print("***  PROTOCOL PERFORMANCE ANALYSIS REPORT  ***".center(80))
        print("=" * 80 + "\n")

        total_time = sum(stat.duration for stat in self.performance_stats)

        for idx, stat in enumerate(self.performance_stats, 1):
            percentage = (stat.duration / total_time * 100) if total_time > 0 else 0

            print(f"┌─ Phase {idx}: {stat.phase_name}")
            print(f"│  ⏱  Duration:    {stat.duration*1000:.4f} ms  ({percentage:.1f}% of total)")

            if stat.operations:
                print("│  📊 操作次数:")
                for op_name, count in stat.operations.items():
                    print(f"│     • {op_name}: {count:,}")
            print(f"└{'─'*78}\n")

        print("=" * 80)
        print(f"🕐 TOTAL EXECUTION TIME: {total_time*1000:.4f} ms ({total_time:.6f} seconds)")
        print("=" * 80 + "\n")

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

    def shamir_share(self, secret: int, n: int, t: int) -> List[Share]:
        coefficients = [secret % self.prime] + [random.randint(-1, 1) for _ in range(t - 1)]

        shares = []
        for i in range(1, n + 1):
            value = 0
            for power, coeff in enumerate(coefficients):
                value = (value + coeff * pow(i, power, self.prime)) % self.prime
            shares.append(Share(value, i))
        return shares

    def share_vector(self, secret_vector: List[int], sigma_x: float = 1.0, sigma_y: float = 18.36) -> Tuple[Any, List[Any], List[Any]]:
        """为单个参与者的秘密向量生成份额 / Generate shares for a participant's secret vector."""
        d = len(secret_vector)

        # 步骤1: 生成噪声向量
        start_time = time.time()
        y_vector = [max(-15, min(15, int(random.gauss(0, sigma_y)))) for _ in range(d)]
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
        salt = str(random.getrandbits(128))
        leaf_data = []
        salts = []

        for participant in range(self.n):
            x_participant = [x_shares[i][participant].value for i in range(d)]
            y_participant = [y_shares[i][participant].value for i in range(d)]
            participant_salt = str(random.getrandbits(128))
            salts.append(participant_salt)
            leaf = '|'.join(map(str, x_participant + y_participant)) + '|' + participant_salt
            leaf_hash = MerkleTree.hash_item(leaf)
            leaf_data.append(leaf_hash)

        merkle_tree = MerkleTree(leaf_data)
        h = merkle_tree.root.hash
        step3_time = time.time() - start_time

        # 计算Merkle树的哈希次数
        merkle_hashes = self.n
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
            v_i: List[int] = []
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
        operations: Dict[str, int] = {}

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

        v_public = np.array(public_proof['v_shares'][participant_id - 1], dtype=object)

        for i in range(len(v_calc)):
            if int(v_calc[i]) % self.prime != int(v_public[i]) % self.prime:
                duration = time.time() - start_time
                return False, duration, operations

        operations['线性关系检查 (验证v_i=R·x_i+y_i是否成立)'] = len(v_calc)

    # 步骤3: 验证范数
        v_public_centered = []
        half_prime = self.prime // 2
        centering_ops = 0

        for val in v_public:
            int_val = int(val) % self.prime
            if int_val > half_prime:
                centered_val = int_val - self.prime
            else:
                centered_val = int_val
            v_public_centered.append(float(centered_val))
            centering_ops += 1

        operations['中心化转换 (将模表示转为有符号数,便于计算范数)'] = centering_ops

        norm = np.linalg.norm(v_public_centered)
        operations['范数计算 (欧几里得范数||v||₂,检查短向量性质)'] = 1

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
        operations: Dict[str, int] = {}

        d = len(x_shares_list)
        secret_vector: List[int] = []
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
