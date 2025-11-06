"""Thread-safe in-memory network simulator for participant communication."""

import threading
import time
from queue import Empty, Queue
from typing import Dict, List

from data_models import AggregatedShare, Complaint, EncryptedSharePackage, PublicProof


class NetworkSimulator:
    """网络模拟器，用于参与者之间的通信 / Simulates authenticated channels between participants."""

    def __init__(self) -> None:
        self.message_queues: Dict[int, Queue] = {}
        self.broadcast_queue: Queue = Queue()
        self.lock = threading.Lock()

    def register_participant(self, participant_id: int) -> None:
        """注册参与者 / Register a participant mailbox."""
        with self.lock:
            self.message_queues[participant_id] = Queue()

    def send_encrypted_share(self, package: EncryptedSharePackage) -> None:
        """发送加密份额 / Send an encrypted share to its receiver."""
        with self.lock:
            if package.receiver_id in self.message_queues:
                self.message_queues[package.receiver_id].put(('share', package))

    def broadcast_proof(self, proof: PublicProof) -> None:
        """广播公开证明 / Broadcast a public proof to all participants."""
        with self.lock:
            for participant_id in self.message_queues.keys():
                self.message_queues[participant_id].put(('proof', proof))

    def broadcast_complaint(self, complaint: Complaint) -> None:
        """广播投诉消息 / Broadcast a complaint message."""
        with self.lock:
            for participant_id in self.message_queues.keys():
                self.message_queues[participant_id].put(('complaint', complaint))

    def broadcast_aggregated_share(self, agg_share: AggregatedShare) -> None:
        """广播聚合份额 / Broadcast aggregated shares during reconstruction."""
        with self.lock:
            for participant_id in self.message_queues.keys():
                self.message_queues[participant_id].put(('aggregated', agg_share))

    def receive_encrypted_shares(self, participant_id: int, timeout: float = 5.0) -> List[EncryptedSharePackage]:
        """接收加密份额 / Receive encrypted share packages."""
        shares: List[EncryptedSharePackage] = []
        messages_to_requeue = []
        end_time = time.time() + timeout

        while time.time() < end_time:
            try:
                msg_type, data = self.message_queues[participant_id].get(timeout=0.1)
                if msg_type == 'share':
                    shares.append(data)
                else:
                    # 如果是proof等消息，临时保存并稍后放回队列
                    messages_to_requeue.append((msg_type, data))
            except Empty:
                break

        for msg in messages_to_requeue:
            self.message_queues[participant_id].put(msg)
        return shares

    def receive_all_proofs(self, participant_id: int, expected_count: int, timeout: float = 5.0) -> List[PublicProof]:
        """接收所有公开证明 / Receive broadcast proofs until expected count or timeout."""
        proofs: List[PublicProof] = []
        messages_to_requeue = []
        end_time = time.time() + timeout

        while len(proofs) < expected_count and time.time() < end_time:
            try:
                msg_type, data = self.message_queues[participant_id].get(timeout=0.1)
                if msg_type == 'proof':
                    proofs.append(data)
                else:
                    # 如果是share或complaint消息，重新放回队列
                    messages_to_requeue.append((msg_type, data))
            except Empty:
                break

        for msg in messages_to_requeue:
            self.message_queues[participant_id].put(msg)
        return proofs

    def receive_complaints(self, participant_id: int, timeout: float = 2.0) -> List[Complaint]:
        """接收投诉消息 / Receive complaint messages targeting other participants."""
        complaints: List[Complaint] = []
        messages_to_requeue = []
        end_time = time.time() + timeout

        while time.time() < end_time:
            try:
                msg_type, data = self.message_queues[participant_id].get(timeout=0.1)
                if msg_type == 'complaint':
                    complaints.append(data)
                else:
                    # 如果是其他类型消息，重新放回队列
                    messages_to_requeue.append((msg_type, data))
            except Empty:
                break

        for msg in messages_to_requeue:
            self.message_queues[participant_id].put(msg)
        return complaints

    def receive_aggregated_shares(self, participant_id: int, expected_count: int, timeout: float = 3.0) -> List[AggregatedShare]:
        """接收聚合份额 / Receive aggregated shares for reconstruction."""
        agg_shares: List[AggregatedShare] = []
        messages_to_requeue = []
        end_time = time.time() + timeout

        while len(agg_shares) < expected_count and time.time() < end_time:
            try:
                msg_type, data = self.message_queues[participant_id].get(timeout=0.1)
                if msg_type == 'aggregated':
                    agg_shares.append(data)
                else:
                    # 如果是其他类型消息，重新放回队列
                    messages_to_requeue.append((msg_type, data))
            except Empty:
                break

        for msg in messages_to_requeue:
            self.message_queues[participant_id].put(msg)
        return agg_shares
