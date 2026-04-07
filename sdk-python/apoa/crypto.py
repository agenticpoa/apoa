"""Key generation, JWT signing, and verification. Ed25519 (EdDSA) and ES256."""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key as generate_ec_private_key,
)

from .types import SigningOptions


def generate_key_pair(
    algorithm: str = "EdDSA",
) -> tuple[Any, Any]:
    """Generate a key pair for token signing.

    Returns (private_key, public_key).
    """
    if algorithm == "ES256":
        private_key = generate_ec_private_key(SECP256R1())
        return private_key, private_key.public_key()

    # Default: EdDSA (Ed25519)
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign_token(payload: dict[str, Any], options: SigningOptions) -> str:
    """Sign a payload as a compact JWS (JWT)."""
    alg = "ES256" if options.algorithm == "ES256" else "EdDSA"
    headers: dict[str, str] = {"alg": alg}
    if options.kid:
        headers["kid"] = options.kid

    return jwt.encode(payload, options.private_key, algorithm=alg, headers=headers)


def verify_token(raw_jwt: str, public_key: Any) -> dict[str, Any]:
    """Verify a JWT signature and return the decoded payload."""
    # PyJWT needs to know which algorithms to accept
    return jwt.decode(
        raw_jwt,
        public_key,
        algorithms=["EdDSA", "ES256"],
        options={"verify_exp": False, "verify_aud": False},
    )


def decode_header(raw_jwt: str) -> dict[str, Any]:
    """Decode a JWT header without verifying the signature."""
    return jwt.get_unverified_header(raw_jwt)
