"""Tests for the application-facing APOA facade."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from apoa import (
    APOA,
    APOADefinition,
    Agent,
    Principal,
    ServiceAuthorization,
    generate_key_pair,
)


class TestAPOA:
    def test_creates_simple_grant_from_string_inputs(self):
        private_key, _ = generate_key_pair()
        apoa = APOA(private_key=private_key)

        before = datetime.now(timezone.utc)
        token = apoa.tokens.create_grant(
            principal="did:apoa:you",
            agent="did:apoa:agent",
            service="mychart.com",
            scopes=["appointments:read"],
            constraints={"signing": False},
            expires_in="30d",
        )

        assert token.definition.principal == Principal(id="did:apoa:you")
        assert token.definition.agent == Agent(id="did:apoa:agent")
        assert token.definition.services == [
            ServiceAuthorization(
                service="mychart.com",
                scopes=["appointments:read"],
                constraints={"signing": False},
            )
        ]
        assert token.definition.expires > before

    def test_authorizes_through_application_namespace(self):
        private_key, _ = generate_key_pair()
        apoa = APOA(private_key=private_key)

        token = apoa.tokens.create_grant(
            principal="did:apoa:you",
            agent=Agent(id="did:apoa:agent", name="My Agent"),
            service="mychart.com",
            scopes=["appointments:read"],
            expires_in="1h",
        )

        allowed = apoa.authorizations.check(token, "mychart.com", "appointments:read")
        denied = apoa.authorizations.check(token, "mychart.com", "messages:send")

        assert allowed.authorized is True
        assert denied.authorized is False

    def test_validates_tokens_through_application_namespace(self):
        private_key, public_key = generate_key_pair()
        apoa = APOA(private_key=private_key)

        token = apoa.tokens.create_grant(
            principal="did:apoa:you",
            agent="did:apoa:agent",
            service="mychart.com",
            scopes=["appointments:read"],
            expires_in="1h",
        )

        result = apoa.tokens.validate(token.raw, public_key=public_key)

        assert result.valid is True
        assert result.token is not None
        assert result.token.jti == token.jti

    def test_keeps_canonical_token_creation_available(self):
        private_key, _ = generate_key_pair()
        apoa = APOA(private_key=private_key)
        definition = APOADefinition(
            principal=Principal(id="did:apoa:you"),
            agent=Agent(id="did:apoa:agent"),
            services=[ServiceAuthorization(service="mychart.com", scopes=["appointments:read"])],
            expires="2099-09-01",
        )

        token = apoa.tokens.create(definition)

        assert token.definition == definition

    def test_accepts_advanced_multi_service_grant_input(self):
        private_key, _ = generate_key_pair()
        apoa = APOA(private_key=private_key)

        token = apoa.tokens.create_grant(
            principal=Principal(id="did:apoa:you", name="You"),
            agent=Agent(id="did:apoa:agent", name="Agent"),
            services=[
                ServiceAuthorization(service="mychart.com", scopes=["appointments:read"]),
                ServiceAuthorization(service="docusign.com", scopes=["documents:read"]),
            ],
            expires="2099-09-01",
            metadata={"source": "test"},
        )

        assert len(token.definition.services) == 2
        assert token.definition.metadata == {"source": "test"}

    def test_throws_helpful_error_for_missing_private_keys(self):
        apoa = APOA()

        with pytest.raises(ValueError, match="APOA needs a private key to create tokens"):
            apoa.tokens.create_grant(
                principal="did:apoa:you",
                agent="did:apoa:agent",
                service="mychart.com",
                scopes=["appointments:read"],
                expires_in="1h",
            )

    def test_throws_helpful_error_for_invalid_grant_input(self):
        private_key, _ = generate_key_pair()
        apoa = APOA(private_key=private_key)

        with pytest.raises(ValueError, match="scopes must be a non-empty list"):
            apoa.tokens.create_grant(
                principal="did:apoa:you",
                agent="did:apoa:agent",
                service="mychart.com",
                expires_in="1h",
            )

    def test_rejects_ambiguous_duration_strings(self):
        private_key, _ = generate_key_pair()
        apoa = APOA(private_key=private_key)

        with pytest.raises(ValueError, match="expires_in must use a clear duration"):
            apoa.tokens.create_grant(
                principal="did:apoa:you",
                agent="did:apoa:agent",
                service="mychart.com",
                scopes=["appointments:read"],
                expires_in="1mo",
            )
