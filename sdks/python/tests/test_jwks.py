"""Tests for JWKS publish + resolve helpers."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

from apoa import (
    APOADefinition,
    Agent,
    Principal,
    ServiceAuthorization,
    SigningOptions,
    ValidationOptions,
    build_jwks,
    create_jwks_resolver,
    create_token,
    generate_key_pair,
    public_key_to_jwk,
    validate_token,
)


class TestPublicKeyToJWK:
    def test_ed25519_export(self):
        _, public_key = generate_key_pair()
        jwk = public_key_to_jwk(public_key, "rotation-1")
        assert jwk["kid"] == "rotation-1"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "EdDSA"
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert isinstance(jwk["x"], str)

    def test_es256_export(self):
        ec_priv = generate_private_key(SECP256R1())
        jwk = public_key_to_jwk(ec_priv.public_key(), "p256-key")
        assert jwk["alg"] == "ES256"
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"

    def test_explicit_alg_and_use(self):
        _, public_key = generate_key_pair()
        jwk = public_key_to_jwk(public_key, "k", use="sig", alg="EdDSA")
        assert jwk["alg"] == "EdDSA"
        assert jwk["use"] == "sig"

    def test_unsupported_key_type_raises(self):
        with pytest.raises(ValueError, match="unsupported public key type"):
            public_key_to_jwk(object(), "k")


class TestBuildJWKS:
    def test_wraps_keys_in_envelope(self):
        _, public_key = generate_key_pair()
        jwk = public_key_to_jwk(public_key, "a")
        jwks = build_jwks([jwk])
        assert isinstance(jwks["keys"], list)
        assert len(jwks["keys"]) == 1
        assert jwks["keys"][0]["kid"] == "a"


class TestCreateJWKSResolver:
    def test_resolves_matching_kid_and_validates_token(self):
        private_key, public_key = generate_key_pair()
        jwks = build_jwks([public_key_to_jwk(public_key, "rotation-1")])

        fetch_count = {"n": 0}

        def fake_get(url):
            fetch_count["n"] += 1
            return json.dumps(jwks).encode()

        resolver = create_jwks_resolver(
            "https://example.invalid/.well-known/jwks.json",
            http_get=fake_get,
        )

        resolved = resolver.resolve("rotation-1")
        assert resolved is not None
        assert fetch_count["n"] == 1

        token = create_token(
            APOADefinition(
                principal=Principal(id="did:apoa:alice"),
                agent=Agent(id="did:apoa:agent"),
                services=[ServiceAuthorization(service="svc.com", scopes=["read"])],
                expires="2099-01-01",
            ),
            SigningOptions(private_key=private_key, kid="rotation-1"),
        )

        result = validate_token(token.raw, ValidationOptions(key_resolver=resolver))
        assert result.valid is True

    def test_returns_none_for_unknown_kid(self):
        _, public_key = generate_key_pair()
        jwks = build_jwks([public_key_to_jwk(public_key, "known")])

        def fake_get(url):
            return json.dumps(jwks).encode()

        resolver = create_jwks_resolver(
            "https://example.invalid/jwks.json",
            http_get=fake_get,
        )
        assert resolver.resolve("does-not-exist") is None

    def test_caches_jwks_within_window(self):
        _, public_key = generate_key_pair()
        jwks = build_jwks([public_key_to_jwk(public_key, "cached")])

        fetch_count = {"n": 0}

        def fake_get(url):
            fetch_count["n"] += 1
            return json.dumps(jwks).encode()

        resolver = create_jwks_resolver(
            "https://example.invalid/jwks.json",
            cache_max_age=60.0,
            http_get=fake_get,
        )

        resolver.resolve("cached")
        resolver.resolve("cached")
        resolver.resolve("cached")
        assert fetch_count["n"] == 1

    def test_propagates_first_fetch_failure(self):
        def fake_get(url):
            raise RuntimeError("upstream down")

        resolver = create_jwks_resolver(
            "https://example.invalid/jwks.json",
            http_get=fake_get,
        )

        with pytest.raises(RuntimeError, match="upstream down"):
            resolver.resolve("any")

    def test_uses_cached_jwks_when_refresh_fails_within_cooldown(self):
        _, public_key = generate_key_pair()
        jwks = build_jwks([public_key_to_jwk(public_key, "cached")])

        call = {"i": 0}

        def fake_get(url):
            call["i"] += 1
            if call["i"] == 1:
                return json.dumps(jwks).encode()
            raise RuntimeError("transient")

        resolver = create_jwks_resolver(
            "https://example.invalid/jwks.json",
            cache_max_age=0.0,  # force refresh on every resolve
            cooldown=3600.0,    # but allow stale-while-failing
            http_get=fake_get,
        )

        # First resolve: populates the cache.
        assert resolver.resolve("cached") is not None
        # Second resolve: refresh fails, falls back to cached value.
        assert resolver.resolve("cached") is not None
        assert call["i"] == 2
