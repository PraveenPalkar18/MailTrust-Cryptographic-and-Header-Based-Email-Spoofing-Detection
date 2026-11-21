"""
Unit tests for from-scratch SHA-256 implementation.
Verifies against standard NIST FIPS 180-4 test vectors and hashlib parity.
"""

import hashlib
import pytest
from analyzers.sha256 import custom_sha256, sha256_bytes, sha256_hex


def test_nist_empty_string():
    """Verify SHA-256 digest of empty string."""
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_hex(b"") == expected
    assert custom_sha256().hexdigest() == expected


def test_nist_abc():
    """Verify standard NIST test vector 'abc'."""
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_hex(b"abc") == expected


def test_nist_multi_block():
    """Verify standard NIST multi-block test vector."""
    msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    assert sha256_hex(msg) == expected


def test_streaming_updates():
    """Verify that multiple .update() calls produce identical result to one update."""
    h1 = custom_sha256()
    h1.update(b"Cryptography ")
    h1.update(b"and Network ")
    h1.update(b"Security")

    h2 = custom_sha256(b"Cryptography and Network Security")
    assert h1.hexdigest() == h2.hexdigest()
    assert h1.digest() == hashlib.sha256(b"Cryptography and Network Security").digest()


def test_state_copy():
    """Verify that .copy() clones state independently."""
    base = custom_sha256(b"Initial payload prefix. ")
    fork1 = base.copy()
    fork2 = base.copy()

    fork1.update(b"Branch A")
    fork2.update(b"Branch B")

    assert fork1.hexdigest() != fork2.hexdigest()
    assert fork1.hexdigest() == hashlib.sha256(b"Initial payload prefix. Branch A").hexdigest()
    assert fork2.hexdigest() == hashlib.sha256(b"Initial payload prefix. Branch B").hexdigest()


def test_binary_payloads_random_parity():
    """Compare from-scratch SHA-256 output across diverse byte lengths with hashlib."""
    for length in [1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 512, 1024, 4096]:
        payload = bytes((i * 37) % 256 for i in range(length))
        assert custom_sha256(payload).digest() == hashlib.sha256(payload).digest()
        assert custom_sha256(payload).hexdigest() == hashlib.sha256(payload).hexdigest()
