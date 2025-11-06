"""High-level orchestration for running the distributed V3S demo."""

from __future__ import annotations

import time
from typing import Dict, List, Tuple

import numpy as np

from constants import PRIME
from network_simulator import NetworkSimulator
from participant import DistributedParticipant
from v3s_core import V3S


def _aggregate_performance(participants: List[DistributedParticipant], dimension: int, threshold: int) -> None:
    """汇总所有参与者的性能统计信息 / Aggregate performance stats across participants."""
    if not participants:
        return

    # 使用与参与者相同参数初始化 V3S 实例，用于集中打印统计信息
    aggregated_v3s = V3S(len(participants), threshold)

    phase_names = [
        "Shamir秘密共享",
        "Merkle树构建",
        "挑战矩阵与界限计算",
        "验证向量计算",
        "网络通信",
        "全局秘密重构",
        "全局公钥生成",
    ]

    # 对共享阶段 (份额生成、Merkle、挑战矩阵、验证向量) 取最大耗时并合并操作数
    for phase_idx, phase_name in enumerate(phase_names[:4]):
        phase_durations = []
        combined_operations: Dict[str, int] = {}
        for participant in participants:
            if phase_idx < len(participant.v3s.performance_stats):
                stat = participant.v3s.performance_stats[phase_idx]
                phase_durations.append(stat.duration)
                for op_name, count in stat.operations.items():
                    combined_operations[op_name] = combined_operations.get(op_name, 0) + count
        max_duration = max(phase_durations) if phase_durations else 0
        aggregated_v3s.add_performance_stat(phase_name, max_duration, combined_operations)

    # 网络阶段：统计发送+接收耗时，聚合所有操作计数
    network_times = [p.network_send_time + p.network_receive_time for p in participants]
    max_network_time = max(network_times) if network_times else 0
    combined_network_ops: Dict[str, int] = {}
    for participant in participants:
        for op_name, count in participant.network_ops.items():
            combined_network_ops[op_name] = combined_network_ops.get(op_name, 0) + count
    aggregated_v3s.add_performance_stat("网络通信", max_network_time, combined_network_ops)

    # 重构阶段：记录耗时与关键运算数量估计（聚合、广播、拉格朗日插值等）
    reconstruction_times: Dict[int, float] = {
        participant.participant_id: participant.reconstruction_time for participant in participants if participant.global_secret
    }
    max_global_recon_time = max(reconstruction_times.values()) if reconstruction_times else 0
    aggregated_v3s.add_performance_stat(
        "全局秘密重构",
        max_global_recon_time,
        {
            "聚合份额计算 (每个参与者计算自己位置的聚合份额)": len(participants),
            "聚合份额广播 (每个参与者广播自己的聚合份额)": len(participants),
            "聚合份额接收 (每个参与者接收其他人的聚合份额)": len(participants) * len(participants),
            "拉格朗日插值 (使用t个聚合份额重构全局秘密)": len(participants) * dimension,
            "模逆元计算 (拉格朗日插值中的模逆运算)": len(participants) * dimension * threshold * (threshold - 1),
            "模乘法 (拉格朗日基函数计算)": len(participants) * dimension * threshold * threshold * 2,
        },
    )

    # 公钥阶段：组合矩阵生成以及部分公钥聚合的操作规模与耗时
    public_key_times = [p.public_key_generation_time for p in participants]
    max_pub_key_time = max(public_key_times) if public_key_times else 0
    combined_pub_ops = {
        "矩阵生成 ([I|A], d×2d, 所有参与者)": len(participants) * dimension * 2 * dimension,
        "部分公钥计算 (矩阵向量乘法, 所有参与者)": len(participants) * dimension * 2 * dimension,
        "部分公钥广播 (估计)": len(participants),
        "部分公钥接收 (估计)": len(participants) * len(participants),
    }
    aggregated_v3s.add_performance_stat("全局公钥生成", max_pub_key_time, combined_pub_ops)

    # 输出统一的性能报告，便于全局观测瓶颈
    aggregated_v3s.print_performance_report()


def test_distributed_v3s() -> None:
    """运行分布式 V3S 演示，覆盖份额分发、验证、重构与公钥生成全流程."""
    print("\n" + "=" * 80)
    print("***  DISTRIBUTED V3S PROTOCOL TEST  ***".center(80))
    print("=" * 80 + "\n")

    # —— 参数初始化：参与者数量、门限、向量维度与噪声标准差 ——
    num_participants = 5
    threshold = 3
    dimension = 4
    sigma_x = 1.0
    sigma_y = sigma_x * (337 ** 0.5)
    shared_password = "secure_shared_password_for_v3s"

    print("*** Protocol Parameters ***")
    print(f"  • Number of participants (N): {num_participants}")
    print(f"  • Threshold (T):              {threshold}")
    print(f"  • Vector dimension (d):       {dimension}")
    print(f"  • sigma_x:                    {sigma_x:.2f}")
    print(f"  • sigma_y:                    {sigma_y:.2f} (= √337 × sigma_x)")
    print(f"  • Prime field size:           2^255 - 19")
    print(f"  • Prime bit length:           {PRIME.bit_length()} bits")
    print(f"  • Encryption:                 AES-256-GCM with PBKDF2")
    print("-" * 80 + "\n")

    # —— 模拟网络与参与者线程注册 ——
    network = NetworkSimulator()

    participants: List[DistributedParticipant] = []
    for i in range(1, num_participants + 1):
        network.register_participant(i)
        participant = DistributedParticipant(
            participant_id=i,
            n=num_participants,
            t=threshold,
            d=dimension,
            network=network,
            shared_password=shared_password,
            sigma_x=sigma_x,
            sigma_y=sigma_y,
        )
        participants.append(participant)

    print("*** Starting Distributed Protocol ***\n")
    print("\n" + "=" * 80)
    print("***  SHARE AND VERIFY PHRASE  ***".center(80))
    print("=" * 80 + "\n")

    # —— 阶段1：启动线程执行份额生成、广播与验证 ——
    start_time = time.time()
    for participant in participants:
        participant.start()

    for participant in participants:
        participant.join()

    total_time = time.time() - start_time

    # 汇总验证阶段指标（成功数量、耗时、投诉记录）
    all_verified = True
    total_verification_time = 0.0
    all_verification_ops: List[Dict[str, int]] = []
    total_complaints = 0

    print("\n")

    # —— 汇报每位参与者的验证状态、有效份额和投诉情况 ——
    for participant in participants:
        verified_count = sum(participant.verification_results)
        expected_count = num_participants - 1
        valid_shares_count = len(participant.valid_shares)
        complaints_sent = len(participant.complaints_sent)
        complaints_received = len(participant.complaints_received)

        status = "✓ SUCCESS" if verified_count == expected_count else "✗ PARTIAL"
        consensus_salt_preview = (
            participant.consensus_salt[:16] + "..." if participant.consensus_salt else "None"
        )
        print(
            f"  Participant {participant.participant_id}: {status} - Verified {verified_count}/{expected_count} shares | "
            f"Valid: {valid_shares_count} | Complaints sent: {complaints_sent} | Complaints received: {complaints_received} | "
            f"Consensus: {consensus_salt_preview}"
        )

        if verified_count != expected_count:
            all_verified = False

        total_verification_time += sum(participant.verification_times)
        all_verification_ops.extend(participant.verification_ops)
        total_complaints += complaints_sent

    print(f"\n  ⏱  Total execution time: {total_time*1000:.2f} ms")
    print(
        f"  📊 Total messages sent: {(num_participants * (num_participants - 1)) + num_participants * num_participants + total_complaints * num_participants}"
    )
    print(f"     - Encrypted shares:  {num_participants * (num_participants - 1)}")
    print(f"     - Public proofs:     {num_participants} (broadcasted to all)")
    print(f"     - Complaints:        {total_complaints} (broadcasted to all)")

    if total_complaints > 0:
        # 输出投诉摘要，帮助定位异常节点
        print(f"\n  ⚠️  Complaint Summary:")
        for participant in participants:
            if participant.complaints_sent:
                for complaint in participant.complaints_sent:
                    print(
                        f"     - P{complaint.complainer_id} complained about P{complaint.accused_id}: {complaint.reason}"
                    )

    print(f"\n  🔐 Consensus Salt Verification:")
    consensus_salts = [p.consensus_salt for p in participants if p.consensus_salt]
    if consensus_salts:
        unique_salts = set(consensus_salts)
        if len(unique_salts) == 1:
            print(f"     ✓ All participants reached consensus!")
            print(f"     Consensus salt: {consensus_salts[0][:32]}...")
        else:
            # 若盐值不一致，逐个打印便于排查
            print(f"     ✗ WARNING: Participants have different consensus salts!")
            for participant in participants:
                print(
                    f"     P{participant.participant_id}: {participant.consensus_salt[:32]}..."
                    if participant.consensus_salt
                    else f"     P{participant.participant_id}: None"
                )
    else:
        print(f"     ✗ No consensus salt computed")

    if all_verification_ops:
        combined_verify_ops: Dict[str, int] = {}
        for ops in all_verification_ops:
            for key, value in ops.items():
                combined_verify_ops[key] = combined_verify_ops.get(key, 0) + value

        avg_verify_time = total_verification_time / len(all_verification_ops)
        print(f"\n  🔍 Average verification time: {avg_verify_time*1000:.4f} ms per share")

    print("\n" + "=" * 80)
    print("***  GLOBAL SECRET RECONSTRUCTION  ***".center(80))
    print("=" * 80 + "\n")

    global_secrets: Dict[int, List[int]] = {}
    reconstruction_times: Dict[int, float] = {}

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

    if global_secrets:
        unique_secrets = list({tuple(s) for s in global_secrets.values()})
        if len(unique_secrets) == 1:
            print(f"\n  ✓ All participants reconstructed the SAME global secret!")
            print(f"  Global secret: {list(unique_secrets[0])}")
            print(f"  ||S_global|| = {np.linalg.norm(unique_secrets[0]):.4f}")
        else:
            print(f"\n  ✗ WARNING: Participants reconstructed DIFFERENT global secrets!")
            for pid, secret in global_secrets.items():
                print(f"     P{pid}: {secret}")

        print(f"\n  📊 Verification: S_global = S_1 + S_2 + ... + S_n")

        # 通过累加所有局部秘密，计算理论上的全局秘密向量
        expected_global_secret = [0] * dimension
        for participant in participants:
            secret = participant.secret_vector or [0] * dimension
            for idx in range(dimension):
                expected_global_secret[idx] += secret[idx]

        print(f"  Expected global secret (sum of all secrets): {expected_global_secret}")
        print(f"  Expected ||S_global|| = {np.linalg.norm(expected_global_secret):.4f}")

        if unique_secrets:
            reconstructed = list(unique_secrets[0])
            match = all(
                abs(reconstructed[idx] - expected_global_secret[idx]) < 1e-6 for idx in range(dimension)
            )
            if match:
                print(f"  ✓ Reconstructed global secret MATCHES expected sum!")
            else:
                # 如果不匹配，输出差值帮助定位问题
                print(f"  ✗ Reconstructed global secret DOES NOT match expected sum!")
                print(
                    f"  Difference: {[reconstructed[idx] - expected_global_secret[idx] for idx in range(dimension)]}"
                )

        avg_recon_time = np.mean(list(reconstruction_times.values())) if reconstruction_times else 0.0
        print(f"\n  ⏱  Average global secret reconstruction time: {avg_recon_time*1000:.2f} ms")
    else:
        print(f"\n  ✗ No participants successfully reconstructed the global secret")

    print("\n" + "=" * 80)
    print("***  GLOBAL PUBLIC KEY GENERATION  ***".center(80))
    print("=" * 80 + "\n")

    global_public_keys: Dict[int, List[int]] = {}
    partial_public_keys: Dict[int, List[int]] = {}
    public_matrices: Dict[int, np.ndarray] = {}

    for participant in participants:
        if participant.global_public_key is not None:
            global_public_keys[participant.participant_id] = participant.global_public_key
            partial_public_keys[participant.participant_id] = participant.partial_public_key or []
            if participant.public_matrix_A is not None:
                public_matrices[participant.participant_id] = participant.public_matrix_A

            print(f"  Participant {participant.participant_id}: ✓ Generated global public key")
            print(
                f"     Partial key b_{participant.participant_id}: {[int(val) % 1000 for val in (participant.partial_public_key or [])[:4]]}... (mod 1000)"
            )
            print(
                f"     Global key b: {[int(val) % 1000 for val in participant.global_public_key[:4]]}... (mod 1000)"
            )
        else:
            print(f"  Participant {participant.participant_id}: ✗ Failed to generate global public key")

    if global_public_keys:
        print(f"\n  🔐 Public Matrix [I|A] Verification:")
        if public_matrices:
            matrix_list = list(public_matrices.values())
            all_same = all(np.array_equal(matrix_list[0], matrix) for matrix in matrix_list[1:])

            if all_same:
                first_matrix = matrix_list[0]
                print(f"     ✓ All participants generated the SAME public matrix [I|A]!")
                print(f"     Matrix [I|A] shape: {first_matrix.shape} (expected: {dimension}×{2*dimension})")
                print(
                    f"     Matrix [I|A] preview (first row, mod 1000): {[int(val) % 1000 for val in first_matrix[0][:min(8, 2*dimension)]]}"
                )
            else:
                # 输出不一致提示，后续可打印矩阵差异（如有需要）
                print(f"     ✗ WARNING: Participants generated DIFFERENT public matrices!")

        print(f"\n  🔑 Global Public Key Verification:")
        unique_keys = list({tuple(key) for key in global_public_keys.values()})

        if len(unique_keys) == 1:
            print(f"     ✓ All participants computed the SAME global public key!")
            print(f"     Global public key b: {[int(val) % 1000 for val in unique_keys[0][:4]]}... (mod 1000)")
        else:
            print(f"     ✗ WARNING: Participants computed DIFFERENT global public keys!")
            for pid, key in global_public_keys.items():
                print(f"     P{pid}: {[int(val) % 1000 for val in key[:4]]}... (mod 1000)")

        print(f"\n  📊 Mathematical Verification: b = [I|A] * [s_global; s_global]")

        if global_secrets and public_matrices:
            IA_matrix = list(public_matrices.values())[0]
            s_global = list(global_secrets.values())[0]

            extended_s_global = np.concatenate([s_global, s_global])

            expected_global_key = np.zeros(dimension, dtype=object)
            for i in range(dimension):
                value = 0
                for j in range(2 * dimension):
                    value = (value + int(IA_matrix[i, j]) * int(extended_s_global[j])) % PRIME
                expected_global_key[i] = int(value)

            expected_global_key_list = expected_global_key.tolist()

            print(
                f"  Expected b = [I|A] * [s_global; s_global]: {[int(val) % 1000 for val in expected_global_key_list[:4]]}... (mod 1000)"
            )
            print(f"  Note: b = I*s_global + A*s_global = s_global + A*s_global (LWE form)")

            if unique_keys:
                computed_key = list(unique_keys[0])
                match = all(
                    int(computed_key[idx]) % PRIME == int(expected_global_key_list[idx]) % PRIME
                    for idx in range(dimension)
                )

                if match:
                    print(f"  ✓ Global public key MATCHES [I|A] * [s_global; s_global]!")
                else:
                    # 打印前若干维差值，便于定位不一致来源
                    print(f"  ✗ Global public key DOES NOT match [I|A] * [s_global; s_global]!")
                    print(
                        f"  Difference (first 4): {[int(computed_key[idx]) - int(expected_global_key_list[idx]) for idx in range(min(4, dimension))]}"
                    )

        print(f"\n  📊 Verification: b = sum(b_i) = sum([I|A] * [s_i; s_i])")

        if partial_public_keys and len(partial_public_keys) >= threshold:
            computed_sum = np.zeros(dimension, dtype=object)

            for partial_key in partial_public_keys.values():
                for idx in range(dimension):
                    computed_sum[idx] = (int(computed_sum[idx]) + int(partial_key[idx])) % PRIME

            computed_sum_list = computed_sum.tolist()

            print(f"  Computed sum(b_i): {[int(val) % 1000 for val in computed_sum_list[:4]]}... (mod 1000)")

            if unique_keys:
                global_key = list(unique_keys[0])
                match = all(
                    int(global_key[idx]) % PRIME == int(computed_sum_list[idx]) % PRIME for idx in range(dimension)
                )

                if match:
                    print(f"  ✓ Global public key b MATCHES sum(b_i)!")
                else:
                    # sum(b_i) 与全局公钥不符时也提示差异
                    print(f"  ✗ Global public key b DOES NOT match sum(b_i)!")
    else:
        print(f"\n  ✗ No participants successfully generated global public key")

    _aggregate_performance(participants, dimension, threshold)
