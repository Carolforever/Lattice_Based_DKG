"""Merkle树工具 / Merkle tree utilities for commitment and membership proofs."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class MerkleNode:
    """Merkle树节点 / Node within a Merkle tree structure."""

    hash: str
    left: "MerkleNode | None" = None
    right: "MerkleNode | None" = None


class MerkleTree:
    """Merkle树构建与验证 / Build and verify Merkle tree commitments."""

    def __init__(self, leaves: List[str]):
        """使用叶子哈希初始化树 / Initialize the tree with leaf hashes."""
        # 当叶子数量为奇数时，复制最后一个叶子以保证配对
        if len(leaves) % 2 == 1:
            leaves = leaves + [leaves[-1]]
        self.leaves = leaves
        self.root = self.build_tree([MerkleNode(h) for h in leaves])

    @staticmethod
    def hash_item(item: str) -> str:
        """对输入字符串做SHA-256哈希 / Hash helper for concatenated strings."""
        return hashlib.sha256(item.encode()).hexdigest()

    def build_tree(self, nodes: List[MerkleNode]) -> MerkleNode:
        """递归构建Merkle树 / Recursively build the Merkle tree from leaves upward."""
        if not nodes:
            return MerkleNode("")
        while len(nodes) > 1:
            # 维持偶数节点，树高 = ceil(log₂ n)
            if len(nodes) % 2 == 1:
                nodes = nodes + [nodes[-1]]
            new_level: List[MerkleNode] = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1]
                # 父节点哈希 = H(left || right)
                parent_hash = self.hash_item(left.hash + right.hash)
                new_level.append(MerkleNode(parent_hash, left, right))
            nodes = new_level
        return nodes[0]

    def get_proof(self, index: int) -> List[Tuple[str, str]]:
        """生成给定叶子的Merkle证明 / Produce an authentication path for a leaf index."""
        proof: List[Tuple[str, str]] = []
        idx = index
        level = [MerkleNode(h) for h in self.leaves]
        while len(level) > 1:
            # 每层重建父节点，保持完整二叉结构
            if len(level) % 2 == 1:
                level = level + [level[-1]]
            new_level: List[MerkleNode] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1]
                parent_hash = self.hash_item(left.hash + right.hash)
                new_level.append(MerkleNode(parent_hash, left, right))
            sibling_idx = idx ^ 1
            if sibling_idx < len(level) and sibling_idx != idx:
                position = 'left' if idx % 2 else 'right'
                # 记录兄弟节点哈希及其相对位置（左/右）
                proof.append((level[sibling_idx].hash, position))
            idx //= 2
            level = new_level
        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Tuple[str, str]], root_hash: str) -> bool:
        """验证Merkle路径是否通向根哈希 / Verify a leaf against the Merkle root."""
        computed_hash = leaf_hash
        for sibling_hash, position in proof:
            # 根据兄弟节点位置决定拼接顺序
            if position == 'left':
                computed_hash = MerkleTree.hash_item(sibling_hash + computed_hash)
            else:
                computed_hash = MerkleTree.hash_item(computed_hash + sibling_hash)
        return computed_hash == root_hash
