"""Tests for the full authorization flow."""

from apoa import authorize, MemoryRevocationStore, MemoryAuditStore


class TestAuthorize:
    def test_allowed_action(self, basic_token):
        result = authorize(basic_token, "nationwidemortgage.com", "rate_lock:read")
        assert result.authorized is True
        assert result.checks["scope_allowed"] is True

    def test_scope_denied(self, basic_token):
        result = authorize(basic_token, "nationwidemortgage.com", "payments:send")
        assert result.authorized is False
        assert result.checks.get("scope_allowed") is False

    def test_constraint_blocks_action(self, basic_token):
        # "signing:submit" should be blocked because constraint "signing" is false
        result = authorize(basic_token, "nationwidemortgage.com", "signing:submit")
        # First it passes scope (not in scopes), so it fails at scope check
        # Let's use a token that has the scope but constraint blocks it
        from apoa import APOADefinition, Agent, Principal, ServiceAuthorization, SigningOptions, create_token, generate_key_pair

        keys = generate_key_pair()
        defn = APOADefinition(
            principal=Principal(id="did:apoa:x"),
            agent=Agent(id="did:apoa:y"),
            services=[ServiceAuthorization(
                service="test.com",
                scopes=["signing:*"],
                constraints={"signing": False},
            )],
            expires="2026-12-31T00:00:00Z",
        )
        token = create_token(defn, SigningOptions(private_key=keys[0]))
        result = authorize(token, "test.com", "signing:submit")
        assert result.authorized is False
        assert result.checks.get("constraints_passed") is False

    def test_hard_rule_blocks(self, basic_token):
        # basic_token has rule "no-signing" -- should block any action containing "signing"
        # But the action must pass scope check first
        from apoa import APOADefinition, Agent, Principal, Rule, ServiceAuthorization, SigningOptions, create_token, generate_key_pair

        keys = generate_key_pair()
        defn = APOADefinition(
            principal=Principal(id="did:apoa:x"),
            agent=Agent(id="did:apoa:y"),
            services=[ServiceAuthorization(service="test.com", scopes=["*"])],
            rules=[Rule(id="no-messaging", description="No messaging", enforcement="hard")],
            expires="2026-12-31T00:00:00Z",
        )
        token = create_token(defn, SigningOptions(private_key=keys[0]))
        result = authorize(token, "test.com", "messaging:send")
        assert result.authorized is False
        assert result.checks.get("rules_passed") is False
        assert "no-messaging" in (result.reason or "")

    def test_hard_rule_does_not_block_unrelated(self):
        from apoa import APOADefinition, Agent, Principal, Rule, ServiceAuthorization, SigningOptions, create_token, generate_key_pair

        keys = generate_key_pair()
        defn = APOADefinition(
            principal=Principal(id="did:apoa:x"),
            agent=Agent(id="did:apoa:y"),
            services=[ServiceAuthorization(service="test.com", scopes=["*"])],
            rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
            expires="2026-12-31T00:00:00Z",
        )
        token = create_token(defn, SigningOptions(private_key=keys[0]))
        result = authorize(token, "test.com", "appointments:read")
        assert result.authorized is True

    def test_soft_rule_allows_with_violations(self):
        from apoa import APOADefinition, Agent, Principal, Rule, ServiceAuthorization, SigningOptions, create_token, generate_key_pair

        violations_received = []
        keys = generate_key_pair()
        defn = APOADefinition(
            principal=Principal(id="did:apoa:x"),
            agent=Agent(id="did:apoa:y"),
            services=[ServiceAuthorization(service="test.com", scopes=["*"])],
            rules=[Rule(
                id="alert-deadline",
                description="Alert on deadline",
                enforcement="soft",
                on_violation=lambda v: violations_received.append(v),
            )],
            expires="2026-12-31T00:00:00Z",
        )
        token = create_token(defn, SigningOptions(private_key=keys[0]))
        result = authorize(token, "test.com", "read")
        assert result.authorized is True
        assert result.violations is not None
        assert len(result.violations) == 1
        assert result.violations[0].rule_id == "alert-deadline"
        assert len(violations_received) == 1

    def test_revoked_token_denied(self, basic_token):
        store = MemoryRevocationStore()
        from apoa import revoke
        revoke(basic_token.jti, "did:apoa:alice", "testing", store)
        result = authorize(basic_token, "nationwidemortgage.com", "rate_lock:read", revocation_store=store)
        assert result.authorized is False
        assert result.checks["revoked"] is True

    def test_audit_logging(self):
        from apoa import APOADefinition, Agent, Principal, Rule, ServiceAuthorization, SigningOptions, create_token, generate_key_pair

        keys = generate_key_pair()
        audit = MemoryAuditStore()
        defn = APOADefinition(
            principal=Principal(id="did:apoa:x"),
            agent=Agent(id="did:apoa:y"),
            services=[ServiceAuthorization(service="test.com", scopes=["*"])],
            rules=[Rule(id="soft-rule", description="test", enforcement="soft")],
            expires="2026-12-31T00:00:00Z",
        )
        token = create_token(defn, SigningOptions(private_key=keys[0]))
        authorize(token, "test.com", "read", audit_store=audit)
        entries = audit.query(token.jti)
        assert len(entries) == 1
        assert entries[0].result == "escalated"
