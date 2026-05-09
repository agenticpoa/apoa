"""Tests for key generation and JWT signing/verification."""

from apoa import generate_key_pair, SigningOptions
from apoa.crypto import sign_token, verify_token, decode_header
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey


class TestGenerateKeyPair:
    def test_ed25519_default(self):
        private, public = generate_key_pair()
        assert isinstance(private, Ed25519PrivateKey)
        assert isinstance(public, Ed25519PublicKey)

    def test_ed25519_explicit(self):
        private, public = generate_key_pair("EdDSA")
        assert isinstance(private, Ed25519PrivateKey)

    def test_es256(self):
        private, public = generate_key_pair("ES256")
        assert isinstance(private, EllipticCurvePrivateKey)
        assert isinstance(public, EllipticCurvePublicKey)


class TestSignAndVerify:
    def test_ed25519_round_trip(self, ed25519_keys):
        private, public = ed25519_keys
        payload = {"sub": "test", "data": "hello"}
        raw = sign_token(payload, SigningOptions(private_key=private))
        decoded = verify_token(raw, public)
        assert decoded["sub"] == "test"
        assert decoded["data"] == "hello"

    def test_es256_round_trip(self, es256_keys):
        private, public = es256_keys
        payload = {"sub": "test256"}
        raw = sign_token(payload, SigningOptions(private_key=private, algorithm="ES256"))
        decoded = verify_token(raw, public)
        assert decoded["sub"] == "test256"

    def test_kid_in_header(self, ed25519_keys):
        private, public = ed25519_keys
        raw = sign_token({"sub": "test"}, SigningOptions(private_key=private, kid="key-123"))
        header = decode_header(raw)
        assert header["kid"] == "key-123"
        assert header["alg"] == "EdDSA"

    def test_wrong_key_fails(self, ed25519_keys):
        private, _ = ed25519_keys
        _, wrong_public = generate_key_pair()
        raw = sign_token({"sub": "test"}, SigningOptions(private_key=private))
        import pytest
        with pytest.raises(Exception):
            verify_token(raw, wrong_public)
