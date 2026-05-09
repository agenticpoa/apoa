"""Cross-SDK compatibility test: verify tokens from the TS SDK round-trip through Python."""

import json
from pathlib import Path

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from apoa import validate_token, ValidationOptions
from apoa.token import _payload_to_token


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "ts_token.json"


@pytest.fixture
def ts_fixture():
    if not FIXTURE_PATH.exists():
        pytest.skip("TS fixture not generated. Run: npx tsx tests/generate_ts_fixture.mjs")
    return json.loads(FIXTURE_PATH.read_text())


@pytest.fixture
def ts_public_key(ts_fixture):
    """Reconstruct Ed25519 public key from JWK."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from base64 import urlsafe_b64decode

    jwk = ts_fixture["publicKeyJwk"]
    # OKP key: x is the public key bytes
    x_bytes = urlsafe_b64decode(jwk["x"] + "==")
    return Ed25519PublicKey.from_public_bytes(x_bytes)


class TestCrossSDKCompatibility:
    def test_ts_token_validates_in_python(self, ts_fixture, ts_public_key):
        """A token created by the TS SDK should validate in the Python SDK."""
        result = validate_token(ts_fixture["jwt"], ValidationOptions(public_key=ts_public_key))
        assert result.valid is True, f"Validation failed: {result.errors}"
        assert result.token is not None

    def test_principal_round_trips(self, ts_fixture, ts_public_key):
        result = validate_token(ts_fixture["jwt"], ValidationOptions(public_key=ts_public_key))
        expected = ts_fixture["expected"]
        assert result.token.definition.principal.id == expected["principalId"]

    def test_agent_round_trips(self, ts_fixture, ts_public_key):
        result = validate_token(ts_fixture["jwt"], ValidationOptions(public_key=ts_public_key))
        expected = ts_fixture["expected"]
        assert result.token.definition.agent.name == expected["agentName"]

    def test_services_round_trip(self, ts_fixture, ts_public_key):
        result = validate_token(ts_fixture["jwt"], ValidationOptions(public_key=ts_public_key))
        expected = ts_fixture["expected"]
        service_names = [s.service for s in result.token.definition.services]
        assert service_names == expected["services"]

    def test_agent_provider_round_trips(self, ts_fixture, ts_public_key):
        result = validate_token(ts_fixture["jwt"], ValidationOptions(public_key=ts_public_key))
        expected = ts_fixture["expected"]
        assert result.token.definition.agent_provider is not None
        assert result.token.definition.agent_provider.name == expected["agentProviderName"]

    def test_legal_framework_round_trips(self, ts_fixture, ts_public_key):
        result = validate_token(ts_fixture["jwt"], ValidationOptions(public_key=ts_public_key))
        expected = ts_fixture["expected"]
        assert result.token.definition.legal is not None
        assert result.token.definition.legal.jurisdiction == expected["jurisdiction"]

    def test_constraints_round_trip(self, ts_fixture, ts_public_key):
        result = validate_token(ts_fixture["jwt"], ValidationOptions(public_key=ts_public_key))
        expected = ts_fixture["expected"]
        mortgage_svc = next(s for s in result.token.definition.services if s.service == "nationwidemortgage.com")
        assert mortgage_svc.constraints["signing"] == expected["constraintSigning"]

    def test_browser_config_round_trips(self, ts_fixture, ts_public_key):
        result = validate_token(ts_fixture["jwt"], ValidationOptions(public_key=ts_public_key))
        expected = ts_fixture["expected"]
        mortgage_svc = next(s for s in result.token.definition.services if s.service == "nationwidemortgage.com")
        assert mortgage_svc.browser_config is not None
        assert mortgage_svc.browser_config.credential_vault_ref == expected["browserConfigVaultRef"]
        assert mortgage_svc.browser_config.max_session_duration == 1800
        assert mortgage_svc.browser_config.capture_screenshots is True

    def test_rules_round_trip(self, ts_fixture, ts_public_key):
        result = validate_token(ts_fixture["jwt"], ValidationOptions(public_key=ts_public_key))
        rules = result.token.definition.rules
        assert rules is not None
        assert len(rules) == 2
        rule_ids = [r.id for r in rules]
        assert "no-signing" in rule_ids
        assert "deadline-alert" in rule_ids

    def test_metadata_round_trips(self, ts_fixture, ts_public_key):
        result = validate_token(ts_fixture["jwt"], ValidationOptions(public_key=ts_public_key))
        assert result.token.definition.metadata is not None
        assert result.token.definition.metadata["source"] == "ts-sdk-fixture"
        assert result.token.definition.metadata["version"] == 1
