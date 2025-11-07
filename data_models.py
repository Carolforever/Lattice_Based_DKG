"""Dataclasses shared across the distributed V3S implementation.

原始单文件中的注释在此保留，以方便对应协议步骤的中文说明。
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class Share:
    value: int
    index: int


@dataclass
class PerformanceStats:
    """性能统计数据类 / Collects timing and operation counts for each protocol phase."""

    phase_name: str
    duration: float
    operations: Dict[str, int] | None = None

    def __post_init__(self) -> None:
        if self.operations is None:
            self.operations = {}


@dataclass
class EncryptedSharePackage:
    """加密的份额包 / Encrypted package exchanged between participants."""

    sender_id: int
    receiver_id: int
    encrypted_data: bytes
    nonce: bytes
    kem_public: bytes
    key_signature: bytes
    signature: bytes


@dataclass
class PublicProof:
    """公开证明 / Public proof broadcast by each participant."""

    participant_id: int
    merkle_root: str
    salt: str
    participant_salt: str  # 参与者的随机盐值 salt_i
    v_shares: List[List[int]]
    R: List[List[int]]
    bound: float
    spectral_norm: float


@dataclass
class AggregatedShare:
    """聚合份额消息 / Aggregated share broadcast in the reconstruction phase."""

    participant_id: int      # 发送者ID
    aggregated_values: List[int]  # 聚合后的d维份额值（在该参与者位置）


@dataclass
class Complaint:
    """投诉消息 / Complaint message against a misbehaving participant."""

    complainer_id: int      # 投诉者ID
    accused_id: int         # 被投诉者ID
    reason: str             # 投诉原因
    timestamp: float        # 投诉时间戳
    evidence_package: EncryptedSharePackage | None = None  # 原始加密包
    symmetric_key: bytes | None = None                    # 解密密钥（作为证据发布）
    sender_key_signature: bytes | None = None             # 发送者对密钥的签名
    complainer_signature: bytes | None = None              # 投诉者对证据的签名


@dataclass
class ValidationVector:
    """每个参与者广播的验证结果 / Broadcast of locally accepted sender IDs."""

    participant_id: int
    accepted_ids: List[int]
