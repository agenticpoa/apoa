"""Tests for token creation, validation, and parsing."""

import json

import pytest
from apoa import (
    APOADefinition,
    Agent,
    Principal,
    ServiceAuthorization,
    SigningOptions,
    ValidationOptions,
    create_token,
    parse_definition,
    validate_token,
)
from apoa.errors import DefinitionValidationError, MetadataValidationError


class TestCreateToken:
    def test_creates_valid_token(self, basic_definition, signing_options):
        token = create_token(basic_definition, signing_options)
        assert token.jti is not None
        assert token.issuer == "did:apoa:alice"
        assert token.audience == ["nationwidemortgage.com"]
        assert token.raw.count(".") == 2  # compact JWS
        assert token.definition.principal.id == "did:apoa:alice"

    def test_es256_signing(self, basic_definition, es256_keys):
        token = create_token(basic_definition, SigningOptions(private_key=es256_keys[0], algorithm="ES256"))
        assert token.raw.count(".") == 2

    def test_metadata_too_many_keys(self, signing_options):
        defn = APOADefinition(
            principal=Principal(id="did:apoa:x"),
            agent=Agent(id="did:apoa:y"),
            services=[ServiceAuthorization(service="s.com", scopes=["read"])],
            expires="2026-12-31T00:00:00Z",
            metadata={f"key_{i}": f"val_{i}" for i in range(21)},
        )
        with pytest.raises(MetadataValidationError, match="max 20"):
            create_token(defn, signing_options)

    def test_metadata_too_large(self, signing_options):
        defn = APOADefinition(
            principal=Principal(id="did:apoa:x"),
            agent=Agent(id="did:apoa:y"),
            services=[ServiceAuthorization(service="s.com", scopes=["read"])],
            expires="2026-12-31T00:00:00Z",
            metadata={"big": "x" * 1024},
        )
        with pytest.raises(MetadataValidationError, match="max 1024"):
            create_token(defn, signing_options)


class TestValidateToken:
    def test_valid_token_passes(self, basic_token, ed25519_keys):
        result = validate_token(basic_token.raw, ValidationOptions(public_key=ed25519_keys[1]))
        assert result.valid is True
        assert result.token is not None
        assert result.token.jti == basic_token.jti

    def test_wrong_key_fails(self, basic_token):
        from apoa import generate_key_pair
        _, wrong_pub = generate_key_pair()
        result = validate_token(basic_token.raw, ValidationOptions(public_key=wrong_pub))
        assert result.valid is False
        assert any("Signature verification failed" in e for e in result.errors)

    def test_expired_token(self, signing_options):
        defn = APOADefinition(
            principal=Principal(id="did:apoa:x"),
            agent=Agent(id="did:apoa:y"),
            services=[ServiceAuthorization(service="s.com", scopes=["read"])],
            expires="2020-01-01T00:00:00Z",
        )
        token = create_token(defn, signing_options)
        from apoa import generate_key_pair
        _, pub = generate_key_pair()
        # Use the matching public key
        from apoa.crypto import generate_key_pair as gkp
        result = validate_token(token.raw, ValidationOptions(public_key=signing_options.private_key.public_key()))
        assert result.valid is False
        assert any("expired" in e.lower() for e in result.errors)

    def test_no_key_fails(self, basic_token):
        result = validate_token(basic_token.raw, ValidationOptions())
        assert result.valid is False
        assert any("No key provided" in e for e in result.errors)

    def test_size_warning(self, basic_token, ed25519_keys):
        # basic_token is small, should not warn
        result = validate_token(basic_token.raw, ValidationOptions(public_key=ed25519_keys[1]))
        if result.warnings:
            assert not any("4KB" in w for w in result.warnings)

    def test_round_trip_definition(self, basic_token, ed25519_keys):
        result = validate_token(basic_token.raw, ValidationOptions(public_key=ed25519_keys[1]))
        assert result.token is not None
        t = result.token
        assert t.definition.principal.id == "did:apoa:alice"
        assert t.definition.agent.name == "HomeBot Pro"
        assert t.definition.services[0].service == "nationwidemortgage.com"
        assert t.definition.services[0].constraints == {"signing": False, "data_export": False}
        assert t.definition.agent_provider is not None
        assert t.definition.agent_provider.name == "HomeBot Inc."
        assert t.definition.legal is not None
        assert t.definition.legal.jurisdiction == "US-CA"


class TestParseDefinition:
    def test_valid_json(self):
        raw = json.dumps({
            "principal": {"id": "did:apoa:alice"},
            "agent": {"id": "did:apoa:bot"},
            "services": [{"service": "test.com", "scopes": ["read"]}],
            "expires": "2026-12-31",
        })
        defn = parse_definition(raw)
        assert defn.principal.id == "did:apoa:alice"
        assert defn.services[0].scopes == ["read"]

    def test_missing_principal(self):
        raw = json.dumps({
            "agent": {"id": "did:apoa:bot"},
            "services": [{"service": "test.com", "scopes": ["read"]}],
            "expires": "2026-12-31",
        })
        with pytest.raises(DefinitionValidationError) as exc_info:
            parse_definition(raw)
        assert any("principal" in e for e in exc_info.value.errors)

    def test_missing_services(self):
        raw = json.dumps({
            "principal": {"id": "did:apoa:alice"},
            "agent": {"id": "did:apoa:bot"},
            "expires": "2026-12-31",
        })
        with pytest.raises(DefinitionValidationError) as exc_info:
            parse_definition(raw)
        assert any("services" in e for e in exc_info.value.errors)

    def test_invalid_json(self):
        with pytest.raises(DefinitionValidationError, match="Invalid JSON"):
            parse_definition("not json at all")

    def test_browser_mode_requires_config(self):
        raw = json.dumps({
            "principal": {"id": "did:apoa:alice"},
            "agent": {"id": "did:apoa:bot"},
            "services": [{"service": "test.com", "scopes": ["read"], "accessMode": "browser"}],
            "expires": "2026-12-31",
        })
        with pytest.raises(DefinitionValidationError) as exc_info:
            parse_definition(raw)
        assert any("browserConfig" in e for e in exc_info.value.errors)

    def test_legal_jurisdiction_validation(self):
        raw = json.dumps({
            "principal": {"id": "did:apoa:alice"},
            "agent": {"id": "did:apoa:bot"},
            "services": [{"service": "test.com", "scopes": ["read"]}],
            "expires": "2026-12-31",
            "legal": {"model": "provider-as-agent", "jurisdiction": "invalid"},
        })
        with pytest.raises(DefinitionValidationError) as exc_info:
            parse_definition(raw)
        assert any("ISO 3166" in e for e in exc_info.value.errors)

    def test_valid_legal_framework(self):
        raw = json.dumps({
            "principal": {"id": "did:apoa:alice"},
            "agent": {"id": "did:apoa:bot"},
            "services": [{"service": "test.com", "scopes": ["read"]}],
            "expires": "2026-12-31",
            "legal": {"model": "provider-as-agent", "jurisdiction": "US-CA", "legalBasis": ["UETA-14"]},
        })
        defn = parse_definition(raw)
        assert defn.legal is not None
        assert defn.legal.jurisdiction == "US-CA"
