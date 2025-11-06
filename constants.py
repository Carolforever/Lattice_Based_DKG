"""Shared constants for the distributed V3S protocol.

使用大素数以保证Shamir秘密共享的安全性。
"""

PRIME: int = 2**255 - 19  # 2^255 - 19，大素数保证Shamir秘密共享的安全性
