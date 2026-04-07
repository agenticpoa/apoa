"""Tests for the APOAClient facade."""

from apoa import (
    APOADefinition,
    Agent,
    DelegationDefinition,
    Principal,
    Rule,
    ServiceAuthorization,
    create_client,
    generate_key_pair,
)


class TestClient:
    def test_full_workflow(self):
        """End-to-end: create client, generate keys, create token, authorize, audit."""
        keys = generate_key_pair()
        client = create_client(default_private_key=keys[0])

        # Create token
        defn = APOADefinition(
            principal=Principal(id="did:apoa:juan"),
            agent=Agent(id="did:apoa:founder-agent"),
            services=[ServiceAuthorization(
                service="safe-agreement",
                scopes=["offer:submit", "offer:accept", "document:sign"],
                constraints={"signing": False},
            )],
            rules=[Rule(id="no-mfn", description="Do not agree to MFN clause", enforcement="hard")],
            expires="2026-12-31T00:00:00Z",
        )
        token = client.create_token(defn)
        assert token.jti is not None
        assert token.issuer == "did:apoa:juan"

        # Authorize -- should pass
        result = client.authorize(token, "safe-agreement", "offer:submit")
        assert result.authorized is True

        # Authorize -- scope denied
        result = client.authorize(token, "safe-agreement", "payments:send")
        assert result.authorized is False

        # Revoke
        client.revoke(token.jti, "did:apoa:juan", "changed my mind")
        assert client.is_revoked(token.jti) is True

        # Authorize after revocation
        result = client.authorize(token, "safe-agreement", "offer:submit")
        assert result.authorized is False
        assert result.checks["revoked"] is True

    def test_audit_trail(self):
        keys = generate_key_pair()
        client = create_client(default_private_key=keys[0])

        defn = APOADefinition(
            principal=Principal(id="did:apoa:alice"),
            agent=Agent(id="did:apoa:bot"),
            services=[ServiceAuthorization(service="test.com", scopes=["*"])],
            expires="2026-12-31T00:00:00Z",
        )
        token = client.create_token(defn)

        client.log_action(token.jti, "read", "test.com", "allowed")
        client.log_action(token.jti, "write", "test.com", "allowed")

        trail = client.get_audit_trail(token.jti)
        assert len(trail) == 2

    def test_validate_token(self):
        keys = generate_key_pair()
        client = create_client(default_private_key=keys[0])

        from apoa import ValidationOptions

        defn = APOADefinition(
            principal=Principal(id="did:apoa:alice"),
            agent=Agent(id="did:apoa:bot"),
            services=[ServiceAuthorization(service="test.com", scopes=["read"])],
            expires="2026-12-31T00:00:00Z",
        )
        token = client.create_token(defn)

        # Validate with explicit public key
        result = client.validate_token(token.raw, ValidationOptions(public_key=keys[1]))
        assert result.valid is True
        assert result.token is not None

    def test_delegation_via_client(self):
        keys = generate_key_pair()
        client = create_client(default_private_key=keys[0])

        defn = APOADefinition(
            principal=Principal(id="did:apoa:alice"),
            agent=Agent(id="did:apoa:agent1"),
            services=[ServiceAuthorization(service="test.com", scopes=["read", "write"])],
            expires="2026-12-31T00:00:00Z",
            delegatable=True,
            max_delegation_depth=2,
        )
        parent = client.create_token(defn)

        child = client.delegate(
            parent,
            DelegationDefinition(
                agent=Agent(id="did:apoa:sub-agent"),
                services=[ServiceAuthorization(service="test.com", scopes=["read"])],
            ),
        )
        assert child.parent_token == parent.jti

        result = client.verify_chain([parent, child])
        assert result.valid is True

    def test_generate_key_pair(self):
        client = create_client()
        priv, pub = client.generate_key_pair()
        assert priv is not None
        assert pub is not None

    def test_cascade_revoke(self):
        keys = generate_key_pair()
        client = create_client(default_private_key=keys[0])

        client.cascade_revoke("parent-1", ["child-1", "child-2"], "did:apoa:alice", "cleanup")
        assert client.is_revoked("parent-1") is True
        assert client.is_revoked("child-1") is True
        assert client.is_revoked("child-2") is True
