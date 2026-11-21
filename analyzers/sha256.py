"""
Independent SHA-256 Cryptographic Hash Implementation
Designed for Cryptography and Network Security (CNS) verification in MailTrust.
Implements the Secure Hash Standard (FIPS PUB 180-4) completely from mathematical principles.
"""

import math
import struct
from typing import List, Union


def _generate_primes(count: int) -> List[int]:
    """Generate the first `count` prime numbers from scratch."""
    primes: List[int] = []
    candidate = 2
    while len(primes) < count:
        is_prime = True
        limit = math.isqrt(candidate)
        for divisor in range(2, limit + 1):
            if candidate % divisor == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(candidate)
        candidate += 1
    return primes


# FIPS 180-4 constants derived from prime numbers
# Round constants K (first 32 bits of the fractional parts of cube roots of first 64 primes)
_PRIMES_64 = _generate_primes(64)
_ROUND_CONSTANTS: List[int] = [
    int((p ** (1.0 / 3.0) - int(p ** (1.0 / 3.0))) * (1 << 32)) & 0xFFFFFFFF
    for p in _PRIMES_64
]

# Initial hash values H (first 32 bits of fractional parts of square roots of first 8 primes)
_INITIAL_H: List[int] = [
    int((p ** 0.5 - int(p ** 0.5)) * (1 << 32)) & 0xFFFFFFFF
    for p in _PRIMES_64[:8]
]


def _rotr(val: int, shift: int) -> int:
    """Right rotation on 32-bit integer."""
    return ((val >> shift) | (val << (32 - shift))) & 0xFFFFFFFF


class SHA256:
    """
    Pure Python FIPS 180-4 SHA-256 Hash implementation.
    Exposes standard hashlib-compatible streaming interface.
    """

    name: str = "sha256"
    digest_size: int = 32
    block_size: int = 64

    def __init__(self, data: Union[bytes, bytearray, memoryview, str, None] = None):
        # 8 32-bit state words
        self._h: List[int] = list(_INITIAL_H)
        self._buffer = bytearray()
        self._total_bytes: int = 0

        if data is not None:
            self.update(data)

    def update(self, data: Union[bytes, bytearray, memoryview, str]) -> None:
        """Process incoming byte chunk."""
        if isinstance(data, str):
            chunk_bytes = data.encode("utf-8")
        else:
            chunk_bytes = bytes(data)

        self._buffer.extend(chunk_bytes)
        self._total_bytes += len(chunk_bytes)

        # Process complete 64-byte blocks
        while len(self._buffer) >= 64:
            block = self._buffer[:64]
            self._buffer = self._buffer[64:]
            self._transform(block)

    def _transform(self, block: bytes) -> None:
        """Run 64 compression rounds on a 512-bit (64-byte) block."""
        # Unpack 16 32-bit big-endian words
        words = list(struct.unpack(">16I", block)) + [0] * 48

        # Message schedule expansion (W16 .. W63)
        for t in range(16, 64):
            w_t15 = words[t - 15]
            w_t2 = words[t - 2]
            sigma_0 = _rotr(w_t15, 7) ^ _rotr(w_t15, 18) ^ (w_t15 >> 3)
            sigma_1 = _rotr(w_t2, 17) ^ _rotr(w_t2, 19) ^ (w_t2 >> 10)
            words[t] = (words[t - 16] + sigma_0 + words[t - 7] + sigma_1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self._h

        # 64 compression rounds
        for t in range(64):
            sum_1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            choice = (e & f) ^ ((~e) & g)
            temp_1 = (h + sum_1 + choice + _ROUND_CONSTANTS[t] + words[t]) & 0xFFFFFFFF

            sum_0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp_2 = (sum_0 + majority) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp_1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp_1 + temp_2) & 0xFFFFFFFF

        # Compute intermediate hash values
        self._h[0] = (self._h[0] + a) & 0xFFFFFFFF
        self._h[1] = (self._h[1] + b) & 0xFFFFFFFF
        self._h[2] = (self._h[2] + c) & 0xFFFFFFFF
        self._h[3] = (self._h[3] + d) & 0xFFFFFFFF
        self._h[4] = (self._h[4] + e) & 0xFFFFFFFF
        self._h[5] = (self._h[5] + f) & 0xFFFFFFFF
        self._h[6] = (self._h[6] + g) & 0xFFFFFFFF
        self._h[7] = (self._h[7] + h) & 0xFFFFFFFF

    def copy(self) -> "SHA256":
        """Clone current hash state for branch calculations."""
        clone = SHA256()
        clone._h = list(self._h)
        clone._buffer = bytearray(self._buffer)
        clone._total_bytes = self._total_bytes
        return clone

    def digest(self) -> bytes:
        """Finalize and return 32-byte binary digest."""
        temp = self.copy()

        # FIPS 180-4 Padding:
        # Append '1' bit (0x80 byte)
        temp._buffer.append(0x80)

        # Pad with 0x00 bytes until buffer length % 64 == 56
        while len(temp._buffer) % 64 != 56:
            temp._buffer.append(0x00)

        # Append 64-bit big-endian representation of original bit-length
        orig_bit_len = temp._total_bytes * 8
        temp._buffer.extend(struct.pack(">Q", orig_bit_len))

        # Process the final 1 or 2 blocks
        while len(temp._buffer) >= 64:
            block = temp._buffer[:64]
            temp._buffer = temp._buffer[64:]
            temp._transform(block)

        return struct.pack(">8I", *temp._h)

    def hexdigest(self) -> str:
        """Return 64-character lowercase hexadecimal digest string."""
        return self.digest().hex()


def custom_sha256(data: Union[bytes, bytearray, memoryview, str, None] = None) -> SHA256:
    """Factory function matching hashlib.sha256 interface."""
    return SHA256(data)


def sha256_bytes(data: bytes) -> bytes:
    """Convenience helper to compute SHA-256 binary digest directly."""
    return custom_sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Convenience helper to compute SHA-256 hexadecimal digest directly."""
    return custom_sha256(data).hexdigest()
