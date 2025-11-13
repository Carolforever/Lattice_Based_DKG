"""Cryptographically secure pseudo-random number generation utilities."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from typing import Optional, Union


class SecureRandom:
    """HKDF-based byte stream wrapped with high level helpers."""

    def __init__(self, label: Union[str, bytes] = b"v3s-secure-rng", reseed_after_blocks: int = 255) -> None:
        if isinstance(label, str):
            label_bytes = label.encode()
        else:
            label_bytes = label

        if not label_bytes:
            raise ValueError("Label must not be empty")

        self._label = label_bytes
        self._hash_len = hashlib.sha256().digest_size
        self._reseed_after_blocks = max(1, reseed_after_blocks)
        self._buffer = bytearray()
        self._block_index = 0
        self._prev_block = b""
        self._prk = b""
        self._reseed()

    def _reseed(self) -> None:
        ikm = secrets.token_bytes(self._hash_len)
        salt = secrets.token_bytes(self._hash_len)
        self._prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        self._block_index = 0
        self._prev_block = b""
        self._buffer.clear()

    def _generate_block(self) -> None:
        if self._block_index >= self._reseed_after_blocks:
            self._reseed()

        self._block_index += 1
        counter = self._block_index.to_bytes(4, "big")
        block = hmac.new(self._prk, self._prev_block + self._label + counter, hashlib.sha256).digest()
        self._prev_block = block
        self._buffer.extend(block)

    def next_bytes(self, length: int) -> bytes:
        if length <= 0:
            return b""

        while len(self._buffer) < length:
            self._generate_block()

        result = bytes(self._buffer[:length])
        del self._buffer[:length]
        return result

    def randbits(self, bits: int) -> int:
        if bits <= 0:
            raise ValueError("Number of bits must be positive")
        byte_length = (bits + 7) // 8
        random_bytes = self.next_bytes(byte_length)
        value = int.from_bytes(random_bytes, "big")
        value &= (1 << bits) - 1
        return value

    def randbelow(self, upper: int) -> int:
        if upper <= 0:
            raise ValueError("Upper bound must be positive")
        bit_length = upper.bit_length()
        while True:
            candidate = self.randbits(bit_length)
            if candidate < upper:
                return candidate

    def randint(self, a: int, b: int) -> int:
        if a > b:
            raise ValueError("Lower bound cannot exceed upper bound")
        return a + self.randbelow(b - a + 1)

    def random_unit_interval(self) -> float:
        # Generate a double-precision fraction in (0, 1)
        while True:
            value = self.randbelow(1 << 53)
            if value != 0:
                return value / float(1 << 53)

    def gauss(self, mu: float = 0.0, sigma: float = 1.0) -> float:
        if sigma <= 0:
            raise ValueError("Sigma must be positive for Gaussian sampling")
        u1 = self.random_unit_interval()
        u2 = self.random_unit_interval()
        mag = math.sqrt(-2.0 * math.log(u1))
        z0 = mag * math.cos(2.0 * math.pi * u2)
        return mu + sigma * z0

    def gaussian_int_unbounded(self, mu: float, sigma: float) -> int:
        """Draw a single integer from a discrete Gaussian without clamping."""
        return int(round(self.gauss(mu, sigma)))

    def gaussian_int(self, mu: float, sigma: float, minimum: int, maximum: int) -> int:
        value = int(self.gauss(mu, sigma))
        if value < minimum:
            return minimum
        if value > maximum:
            return maximum
        return value

    def decimal_salt(self, bits: int) -> str:
        return str(self.randbits(bits))

    def bounded_vector(self, length: int, mu: float, sigma: float, minimum: int, maximum: int) -> list[int]:
        if length < 0:
            raise ValueError("Vector length cannot be negative")
        return [self.gaussian_int(mu, sigma, minimum, maximum) for _ in range(length)]

    def gaussian_vector(self, length: int, mu: float, sigma: float) -> list[int]:
        if length < 0:
            raise ValueError("Vector length cannot be negative")
        return [self.gaussian_int_unbounded(mu, sigma) for _ in range(length)]

    def token_hex(self, num_bytes: int) -> str:
        if num_bytes < 0:
            raise ValueError("Number of bytes cannot be negative")
        return self.next_bytes(num_bytes).hex()

    def derive_child(self, label: Optional[Union[str, bytes]] = None) -> "SecureRandom":
        child_label = label if label is not None else self._label + b":child"
        return SecureRandom(child_label)


def get_default_rng(label: Union[str, bytes] = b"v3s-secure-rng") -> SecureRandom:
    return SecureRandom(label)
