"""Distributed participant thread driving the V3S protocol."""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Dict, List, Set

import numpy as np

from crypto_manager import CryptoManager
from data_models import (
    AggregatedShare,
    Complaint,
    EncryptedSharePackage,
    PublicProof,
    Share,
    ValidationVector,
)
from network_simulator import NetworkSimulator
from v3s_core import V3S
from secure_rng import SecureRandom


class DistributedParticipant(threading.Thread):
    """分布式参与者 / Distributed participant running the V3S protocol asynchronously."""

    def __init__(
        self,
        participant_id: int,
        n: int,
        t: int,
        d: int,
        network: NetworkSimulator,
        sigma_x: float = 1.0,
        sigma_y: float = 18.36,
    ) -> None:
        super().__init__()
        self.participant_id = participant_id
        self.n = n
        self.t = t
        self.d = d
        self.network = network

        self.sigma_x = sigma_x
        self.sigma_y = sigma_y

        self.rng = SecureRandom(f"participant-{participant_id}")
        self.v3s = V3S(n, t, rng=self.rng.derive_child(f"v3s-core-{participant_id}"))
        self.secret_vector: List[int] | None = None
        self.public_proof: Dict[str, object] | None = None
        self.share_data: List[Dict[str, object]] | None = None
        self.noise_share_vector: List[int] | None = None
        self.x_shares: List[List[Share]] | None = None

        # 存储接收到的份额
        self.received_shares: Dict[int, Dict[str, object]] = {}
        self.received_proofs: Dict[int, Dict[str, object]] = {}
        self.received_share_packages: Dict[int, EncryptedSharePackage] = {}
        self.received_share_keys: Dict[int, bytes] = {}

        # 有效份额与验证广播
        self.valid_shares: List[int] = []  # 最终公共交集
        self.local_valid_ids: Set[int] = set()  # 本地判定为有效的发送者ID
        self.received_validation_vectors: Dict[int, List[int]] = {}

        # 投诉相关
        self.complaints_sent: List[Complaint] = []
        self.complaints_received: List[Complaint] = []

        # 盐值相关
        self.participant_salt = self.rng.decimal_salt(256)  # 生成256位随机盐值 salt_i
        self.received_salts: Dict[int, str] = {}
        self.consensus_salt: str | None = None

        # 验证统计
        self.verification_results: List[bool] = []
        self.verification_times: List[float] = []
        self.verification_ops: List[Dict[str, int]] = []

        # 重构统计
        self.reconstruction_time: float = 0
        self.reconstruction_ops: Dict[str, int] = {}

        # 全局秘密相关
        self.aggregated_shares: List[int] | None = None  # 聚合后的份额（有效参与者份额之和）
        self.global_secret: List[int] | None = None

        # 公钥相关
        self.public_matrix_A: np.ndarray | None = None
        self.partial_public_key: List[int] | None = None
        self.global_public_key: List[int] | None = None

        # 公钥生成统计
        self.public_key_generation_time: float = 0

        # 网络通信统计
        self.network_send_time: float = 0
        self.network_receive_time: float = 0
        self.network_ops: Dict[str, int] = {}

        # 同步机制
        self.ready_event = threading.Event()
        self.done_event = threading.Event()

        self.signing_private_key, self.signing_public_key = CryptoManager.generate_signature_keypair()
        self.kem_private_key, self.kem_public_key = CryptoManager.generate_kem_keypair()

        self.network.register_participant(
            self.participant_id,
            self.signing_public_key,
            self.kem_public_key,
        )

    def run(self) -> None:  # pragma: no cover - threaded entry point
        """参与者主流程 / Main thread routine for a participant."""
        try:
            self.generate_secret()
            self.create_shares()
            self.encrypt_and_send_shares()
            self.broadcast_public_proof()
            self.receive_and_verify_shares()
            self.done_event.set()
        except Exception as exc:  # pragma: no cover - debugging helper
            print(f"[Participant {self.participant_id}] Error: {exc}")
            import traceback

            traceback.print_exc()

    def generate_secret(self) -> None:
        """生成自己的短秘密向量 / Sample the participant's short secret vector."""
        self.secret_vector = self.rng.gaussian_vector(self.d, 0.0, self.sigma_x)
        print(f"[Participant {self.participant_id}] Generated secret vector: {self.secret_vector}")
        print(f"[Participant {self.participant_id}] Generated participant salt: {self.participant_salt[:16]}...")

    def create_shares(self) -> None:
        """使用V3S协议创建份额 / Create shares and proof materials via V3S."""
        if self.secret_vector is None:
            raise ValueError("Secret vector must be generated before creating shares")

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

    def encrypt_and_send_shares(self) -> None:
        """加密并发送份额给其他参与者 / Encrypt each share before sending it out."""
        if self.share_data is None:
            raise ValueError("Share data must be created before encryption")

        print(f"[Participant {self.participant_id}] Encrypting and sending shares with KEM + signatures...")

        send_start_time = time.time()
        shares_sent = 0
        encryptions_performed = 0
        kem_ops = 0
        signature_ops = 0

        for receiver_id in range(1, self.n + 1):
            if receiver_id == self.participant_id:
                continue

            # 获取该接收者的份额
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

    def broadcast_public_proof(self) -> None:
        """广播盐值和公开证明 / Broadcast the Merkle root and proof data."""
        if self.public_proof is None:
            raise ValueError("Public proof must be available before broadcast")

        print(f"[Participant {self.participant_id}] Broadcasting public proof...")

        broadcast_start_time = time.time()

        proof = PublicProof(
            participant_id=self.participant_id,
            merkle_root=self.public_proof['h'],
            salt=self.public_proof['main_salt'],
            participant_salt=self.participant_salt,
            v_shares=self.public_proof['v_shares'],
            aggregated_v=self.public_proof['aggregated_v'],
            R=self.public_proof['R'],
            bound=self.public_proof['bound'],
            spectral_norm=self.public_proof['spectral_norm'],
        )

        self.network.broadcast_proof(proof)

        broadcast_time = time.time() - broadcast_start_time
        self.network_send_time += broadcast_time
        self.network_ops['广播公开证明 (Merkle根+验证向量+挑战矩阵)'] = 1

        print(f"[Participant {self.participant_id}] Public proof broadcasted ({broadcast_time*1000:.2f} ms)")

    def receive_and_verify_shares(self) -> None:
        """接收并验证其他参与者的份额 / Receive encrypted shares and run verification."""
        if self.share_data is None:
            raise ValueError("Share data must be available before receiving others")

        # 重置先前状态
        self.valid_shares = []
        self.local_valid_ids.clear()
        self.received_validation_vectors = {}

        print(f"[Participant {self.participant_id}] Receiving shares from other participants...")

        receive_start_time = time.time()

        # 接收加密份额
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
                serialized = CryptoManager.serialize_share_package(package)
                signature_ok = CryptoManager.verify_signature(
                    package.signature,
                    serialized,
                    sender_public_key,
                )
                signature_verifications += 1

                key_binding = CryptoManager.serialize_key_binding(
                    package.sender_id,
                    package.receiver_id,
                    symmetric_key,
                )
                key_signature_ok = CryptoManager.verify_signature(
                    package.key_signature,
                    key_binding,
                    sender_public_key,
                )
                signature_verifications += 1

                self.received_share_packages[package.sender_id] = package
                self.received_share_keys[package.sender_id] = symmetric_key

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
                        sender_key_signature=package.key_signature,
                        complainer_signature=complaint_signature,
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

                if not key_signature_ok:
                    self.local_valid_ids.discard(package.sender_id)
                    evidence_payload = CryptoManager.serialize_complaint_evidence(package, symmetric_key)
                    complaint_signature = CryptoManager.sign_message(evidence_payload, self.signing_private_key)
                    complaint = Complaint(
                        complainer_id=self.participant_id,
                        accused_id=package.sender_id,
                        reason="Invalid key signature",
                        timestamp=time.time(),
                        evidence_package=package,
                        symmetric_key=symmetric_key,
                        sender_key_signature=package.key_signature,
                        complainer_signature=complaint_signature,
                    )
                    self.network.broadcast_complaint(complaint)
                    self.complaints_sent.append(complaint)
                    print(
                        f"[Participant {self.participant_id}] ✗ Invalid key signature from Participant {package.sender_id}"
                    )
                    print(
                        f"[Participant {self.participant_id}] 📢 Broadcasting key signature complaint against Participant {package.sender_id}"
                    )
                    continue

                share_info = CryptoManager.decrypt_data(
                    package.encrypted_data,
                    package.nonce,
                    symmetric_key,
                )

                self.received_shares[package.sender_id] = share_info
                decryptions_performed += 1
                print(f"[Participant {self.participant_id}] Decrypted share from Participant {package.sender_id}")

            except Exception as exc:  # pragma: no cover - debugging helper
                print(f"[Participant {self.participant_id}] Failed to decrypt share from {package.sender_id}: {exc}")

        decrypt_time = time.time() - decrypt_start_time

        # 接收公开证明
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

            # 存储接收到的盐值与证明
            self.received_salts[proof.participant_id] = proof.participant_salt

            self.received_proofs[proof.participant_id] = {
                'h': proof.merkle_root,
                'v_shares': proof.v_shares,
                'aggregated_v': proof.aggregated_v,
                'R': proof.R,
                'bound': proof.bound,
                'spectral_norm': proof.spectral_norm,
                'sigma_x': self.sigma_x,
                'sigma_y': self.sigma_y,
            }

            if proof.participant_id in self.received_shares:
                share_info = self.received_shares[proof.participant_id]
                public_proof = self.received_proofs[proof.participant_id]

                # 验证份额（返回统计信息）
                is_valid, duration, operations = self.v3s.verify_share(
                    self.participant_id, public_proof, share_info
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
                        sender_key_signature=package.key_signature if package else None,
                        complainer_signature=complaint_signature,
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
                    and complaint.sender_key_signature is not None
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

                    key_binding = CryptoManager.serialize_key_binding(
                        package.sender_id,
                        package.receiver_id,
                        symmetric_key,
                    )
                    sender_key_signature_ok = CryptoManager.verify_signature(
                        complaint.sender_key_signature,
                        key_binding,
                        sender_pub,
                    )

                    complainer_pub = self.network.get_signing_public_key(complaint.complainer_id)
                    evidence_payload = CryptoManager.serialize_complaint_evidence(package, symmetric_key)
                    complainer_signature_ok = CryptoManager.verify_signature(
                        complaint.complainer_signature,
                        evidence_payload,
                        complainer_pub,
                    )

                    if package_signature_ok and sender_key_signature_ok and complainer_signature_ok:
                        try:
                            share_info = CryptoManager.decrypt_data(
                                package.encrypted_data,
                                package.nonce,
                                symmetric_key,
                            )
                        except Exception as exc:  # pragma: no cover - debugging helper
                            print(
                                f"[Participant {self.participant_id}] ⚠️  Failed to decrypt evidence from complaint against Participant {complaint.accused_id}: {exc}"
                            )
                        else:
                            public_proof = None
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
                        print(
                            f"[Participant {self.participant_id}] ⚠️  Invalid signatures in complaint against Participant {complaint.accused_id}"
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

        # 广播本地验证结果并收集公共交集
        self.broadcast_and_collect_validation_vectors()

        print(
            f"[Participant {self.participant_id}] Final valid shares (intersection): {self.valid_shares} ({len(self.valid_shares)} participants)"
        )

        self.compute_consensus_salt()
        self.aggregate_and_reconstruct_global_secret()

    def compute_consensus_salt(self) -> None:
        """根据有效参与者数组计算共识盐值 / Derive the consensus salt from valid participants."""
        print(f"[Participant {self.participant_id}] Computing consensus salt...")

        # 收集有效参与者的盐值（按participant_id排序以确保一致性）
        valid_salts: List[str] = []
        sorted_valid_ids = sorted(self.valid_shares)
        all_valid_ids = sorted(set(sorted_valid_ids + [self.participant_id]))

        for pid in all_valid_ids:
            if pid == self.participant_id:
                valid_salts.append(self.participant_salt)
            elif pid in self.received_salts:
                valid_salts.append(self.received_salts[pid])
            else:
                print(f"[Participant {self.participant_id}] ⚠️  Warning: Salt for Participant {pid} not found!")

        concatenated_salts = '||'.join(valid_salts)
        self.consensus_salt = hashlib.sha256(concatenated_salts.encode()).hexdigest()

        print(
            f"[Participant {self.participant_id}] Consensus salt computed from {len(all_valid_ids)} participants: {self.consensus_salt[:16]}..."
        )
        print(f"[Participant {self.participant_id}] Valid participant IDs: {all_valid_ids}")

    def aggregate_and_reconstruct_global_secret(self) -> None:
        """聚合所有有效份额并重构全局秘密 / Aggregate valid shares and reconstruct the global secret."""
        if self.x_shares is None:
            raise ValueError("Local share data missing for aggregation")

        print(f"[Participant {self.participant_id}] Aggregating shares for global secret reconstruction...")

        all_valid_ids = sorted(set(self.valid_shares + [self.participant_id]))

        # 步骤1: 汇总有效参与者ID
        if len(all_valid_ids) < self.t:
            print(
                f"[Participant {self.participant_id}] ⚠️  Insufficient valid shares ({len(all_valid_ids)} < {self.t}), cannot reconstruct global secret"
            )
            return

        # 步骤2: 计算自己位置的聚合份额
        aggregation_start = time.time()

        my_position = self.participant_id - 1
        aggregated_shares_d_values: List[int] = []

        for dim in range(self.d):
            my_share_value = self.x_shares[dim][my_position].value
            aggregated_value = my_share_value

            # 累加其他有效参与者发来的份额
            for valid_pid in self.valid_shares:
                if valid_pid in self.received_shares:
                    share_info = self.received_shares[valid_pid]
                    aggregated_value = (aggregated_value + share_info['x_shares'][dim]) % self.v3s.prime

            aggregated_shares_d_values.append(aggregated_value)

        aggregation_time = time.time() - aggregation_start
        self.aggregated_shares = aggregated_shares_d_values
        print(f"[Participant {self.participant_id}] Computed aggregated share at own position ({aggregation_time*1000:.2f} ms)")

        # 步骤3: 广播聚合份额
        broadcast_start = time.time()
        agg_share = AggregatedShare(
            participant_id=self.participant_id,
            aggregated_values=aggregated_shares_d_values,
        )
        self.network.broadcast_aggregated_share(agg_share)
        broadcast_time = time.time() - broadcast_start
        print(f"[Participant {self.participant_id}] Broadcasted aggregated share ({broadcast_time*1000:.2f} ms)")

        # 步骤4: 接收其他参与者的聚合份额
        time.sleep(0.5)
        receive_start = time.time()
        received_agg_shares = self.network.receive_aggregated_shares(self.participant_id, len(all_valid_ids))
        receive_time = time.time() - receive_start
        print(f"[Participant {self.participant_id}] Received {len(received_agg_shares)} aggregated shares ({receive_time*1000:.2f} ms)")

        # 步骤5: 使用Reed–Solomon纠错+插值重构全局秘密
        reconstruction_start = time.time()

        available_agg_shares: Dict[int, List[int]] = {self.participant_id: aggregated_shares_d_values}

        for agg_share in received_agg_shares:
            if agg_share.participant_id in all_valid_ids:
                available_agg_shares[agg_share.participant_id] = agg_share.aggregated_values

        if len(available_agg_shares) < self.t:
            print(
                f"[Participant {self.participant_id}] ⚠️  Insufficient aggregated shares ({len(available_agg_shares)} < {self.t})"
            )
            return

        participants_used = sorted(available_agg_shares.keys())
        correctable_errors = max(0, (len(participants_used) - self.t) // 2)

        global_secret_vector: List[int] = []

        for dim in range(self.d):
            shares_for_dim = [Share(value=available_agg_shares[pid][dim], index=pid) for pid in participants_used]

            try:
                secret_dim = self.v3s.reed_solomon_reconstruct(shares_for_dim)
            except ValueError:
                print(
                    f"[Participant {self.participant_id}] ❌ Reed–Solomon decoding failed (errors > {correctable_errors})"
                )
                print(
                    f"[Participant {self.participant_id}] Aborting DKG: insufficient clean shares to reconstruct dimension {dim}"
                )
                self.reconstruction_time = aggregation_time + broadcast_time + receive_time + (time.time() - reconstruction_start)
                self.done_event.set()
                raise

            half_prime = self.v3s.prime // 2
            if secret_dim > half_prime:
                secret_dim = secret_dim - self.v3s.prime

            global_secret_vector.append(int(secret_dim))

        reconstruction_time = time.time() - reconstruction_start
        self.reconstruction_time = aggregation_time + broadcast_time + receive_time + reconstruction_time
        self.global_secret = global_secret_vector

        global_norm = np.linalg.norm(global_secret_vector)

        print(f"[Participant {self.participant_id}] ✓ Reconstructed global secret: {global_secret_vector}")
        print(f"[Participant {self.participant_id}] Global secret norm: ||S_global|| = {global_norm:.4f}")
        print(
            f"[Participant {self.participant_id}] Used {len(participants_used)} participants: {participants_used}"
        )
        print(
            f"[Participant {self.participant_id}] Reed–Solomon correctable errors ≤ {correctable_errors}"
        )
        print(f"[Participant {self.participant_id}] Total reconstruction time: {self.reconstruction_time*1000:.2f} ms")

        # 步骤6: 基于共识盐值生成公共矩阵并计算公钥
        self.generate_public_matrix_and_compute_keys()

    def broadcast_and_collect_validation_vectors(self) -> None:
        """广播本地验证结果并根据公共交集更新有效参与者集合."""

        accepted_ids = set(self.local_valid_ids)
        accepted_ids.add(self.participant_id)

        local_vector = ValidationVector(
            participant_id=self.participant_id,
            accepted_ids=sorted(accepted_ids),
        )

        send_start = time.time()
        self.network.broadcast_validation_vector(local_vector)
        broadcast_duration = time.time() - send_start
        self.network_send_time += broadcast_duration
        self.network_ops['广播验证结果 (valid_i 集合)'] = 1

        # 记录自己的结果，确保参与交集计算
        self.received_validation_vectors[self.participant_id] = list(local_vector.accepted_ids)

        # 等待其他参与者广播
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

        # 计算公共交集
        if self.received_validation_vectors:
            common_valid = set(range(1, self.n + 1))
            common_valid.discard(self.participant_id)
            for accepted_ids in self.received_validation_vectors.values():
                common_valid &= set(accepted_ids)
        else:
            common_valid = set(self.local_valid_ids)

        self.valid_shares = sorted(common_valid)
        self.network_ops['接收验证结果 (valid_i 集合)'] = len(vectors)

    def generate_public_matrix_and_compute_keys(self) -> None:
        """基于共识盐值生成公共矩阵A，并计算部分公钥和全局公钥."""
        if self.global_secret is None:
            print(f"[Participant {self.participant_id}] ⚠️  Global secret unavailable, skip key generation")
            return
        if self.consensus_salt is None:
            print(f"[Participant {self.participant_id}] ⚠️  No consensus salt available!")
            return

        print(f"[Participant {self.participant_id}] Generating public matrix A from consensus salt...")

        start_time = time.time()

        # 使用共识盐值生成随机矩阵A（维度为 d×d）
        matrix_size = self.d * self.d
        bytes_needed = matrix_size * 4
        random_bytes = hashlib.shake_256(self.consensus_salt.encode()).digest(bytes_needed)

        A = np.zeros((self.d, self.d), dtype=object)

        for i in range(self.d):
            for j in range(self.d):
                byte_idx = (i * self.d + j) * 4
                value = int.from_bytes(random_bytes[byte_idx:byte_idx + 4], byteorder='big')
                A[i, j] = value % self.v3s.prime

        self.public_matrix_A = A

        matrix_gen_time = time.time() - start_time
        print(f"[Participant {self.participant_id}] Generated {self.d}×{self.d} public matrix A ({matrix_gen_time*1000:.2f} ms)")
        print(f"[Participant {self.participant_id}] Matrix structure: A_{self.d}×{self.d}")

        partial_key_start = time.time()

        if self.secret_vector is None:
            raise ValueError("Secret vector unavailable for key generation")

        secret_vector = np.array(self.secret_vector, dtype=object)

        # 公钥份额: b_i = A * s_i
        partial_public_key = np.zeros(self.d, dtype=object)
        for i in range(self.d):
            value = 0
            for j in range(self.d):
                value = (value + int(self.public_matrix_A[i, j]) * int(secret_vector[j])) % self.v3s.prime
            partial_public_key[i] = int(value)

        # 记录部分公钥并广播
        self.partial_public_key = partial_public_key.tolist()

        partial_key_time = time.time() - partial_key_start
        print(
            f"[Participant {self.participant_id}] Computed partial public key b_{self.participant_id} = A * s_{self.participant_id} ({partial_key_time*1000:.2f} ms)"
        )
        print(
            f"[Participant {self.participant_id}] Partial public key: {[int(val) % 1000 for val in self.partial_public_key[:min(4, len(self.partial_public_key))]]}... (mod 1000)"
        )

        broadcast_start = time.time()
        # 广播部分公钥给所有参与者，确保可用于后续求和
        partial_key_message = {
            'participant_id': self.participant_id,
            'partial_public_key': self.partial_public_key,
        }

        with self.network.lock:
            for pid in self.network.message_queues.keys():
                self.network.message_queues[pid].put(('partial_key', partial_key_message))

        broadcast_time = time.time() - broadcast_start
        print(f"[Participant {self.participant_id}] Broadcasted partial public key ({broadcast_time*1000:.2f} ms)")

        time.sleep(0.5)
        receive_start = time.time()

        # 初始化自身的部分公钥，避免重复等待
        received_partial_keys: Dict[int, List[int]] = {self.participant_id: self.partial_public_key}

        all_valid_ids = sorted(set(self.valid_shares + [self.participant_id]))

        messages_to_requeue = []
        while len(received_partial_keys) < len(all_valid_ids):
            try:
                msg_type, data = self.network.message_queues[self.participant_id].get(timeout=0.1)
                if msg_type == 'partial_key':
                    pid = data['participant_id']
                    if pid in all_valid_ids and pid not in received_partial_keys:
                        received_partial_keys[pid] = data['partial_public_key']
                        print(f"[Participant {self.participant_id}] Received partial public key from Participant {pid}")
                else:
                    messages_to_requeue.append((msg_type, data))
            except Exception:
                break

        # 非部分公钥消息需要放回队列，以保证后续流程正常消费
        for msg in messages_to_requeue:
            self.network.message_queues[self.participant_id].put(msg)

        receive_time = time.time() - receive_start
        print(f"[Participant {self.participant_id}] Received {len(received_partial_keys)-1} partial public keys ({receive_time*1000:.2f} ms)")

        aggregate_start = time.time()

        # 累加所有部分公钥向量，得到最终全局公钥
        global_public_key = np.zeros(self.d, dtype=object)

        for pid in sorted(received_partial_keys.keys()):
            partial_key = received_partial_keys[pid]
            for i in range(self.d):
                global_public_key[i] = (int(global_public_key[i]) + int(partial_key[i])) % self.v3s.prime

        self.global_public_key = global_public_key.tolist()

        aggregate_time = time.time() - aggregate_start

        total_key_time = matrix_gen_time + partial_key_time + broadcast_time + receive_time + aggregate_time
        self.public_key_generation_time = total_key_time

        # 将性能指标写入统计对象，便于外部观测耗时与操作规模
        try:
            self.v3s.add_performance_stat(
                "全局公钥生成",
                total_key_time,
                {
                    "矩阵生成 (A, d×d)": self.d * self.d,
                    "部分公钥计算 (A×s_i + y_i)": self.d * self.d,
                    "部分公钥广播 (每个参与者)": len(self.network.message_queues),
                    "部分公钥接收 (估计每个参与者接收)": len(all_valid_ids),
                },
            )
        except Exception:
            pass

        print(f"[Participant {self.participant_id}] ✓ Computed global public key b = sum(b_i) ({aggregate_time*1000:.2f} ms)")
        print(
            f"[Participant {self.participant_id}] Global public key: {[int(val) % 1000 for val in self.global_public_key[:min(4, len(self.global_public_key))]]}... (mod 1000)"
        )
        print(f"[Participant {self.participant_id}] Total public key generation time: {total_key_time*1000:.2f} ms")
