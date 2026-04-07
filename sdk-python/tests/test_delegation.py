"""Tests for delegation chains and attenuation."""

import pytest
from apoa import (
    APOADefinition,
    Agent,
    DelegationDefinition,
    MemoryRevocationStore,
    Principal,
    Rule,
    ServiceAuthorization,
    SigningOptions,
    create_token,
    delegate,
    generate_key_pair,
    revoke,
    verify_chain,
)
from apoa.errors import AttenuationViolationError


@pytest.fixture
def delegatable_token():
    keys = generate_key_pair()
    defn = APOADefinition(
        principal=Principal(id="did:apoa:alice"),
        agent=Agent(id="did:apoa:agent1"),
        services=[
            ServiceAuthorization(
                service="test.com",
                scopes=["read", "write", "admin:*"],
                constraints={"signing": False},
            ),
        ],
        rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
        expires="2026-12-31T00:00:00Z",
        delegatable=True,
        max_delegation_depth=3,
    )
    return create_token(defn, SigningOptions(private_key=keys[0])), keys


class TestDelegate:
    def test_valid_delegation(self, delegatable_token):
        parent, keys = delegatable_token
        child = delegate(
            parent,
            DelegationDefinition(
                agent=Agent(id="did:apoa:sub-agent"),
                services=[ServiceAuthorization(service="test.com", scopes=["read"])],
                rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
            ),
            SigningOptions(private_key=keys[0]),
        )
        assert child.parent_token == parent.jti
        assert child.definition.principal.id == "did:apoa:alice"  # inherited
        assert child.definition.agent.id == "did:apoa:sub-agent"
        assert child.definition.services[0].scopes == ["read"]

    def test_scope_must_be_subset(self, delegatable_token):
        parent, keys = delegatable_token
        with pytest.raises(AttenuationViolationError, match="not covered"):
            delegate(
                parent,
                DelegationDefinition(
                    agent=Agent(id="did:apoa:sub"),
                    services=[ServiceAuthorization(service="test.com", scopes=["read", "delete"])],
                    rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
                ),
                SigningOptions(private_key=keys[0]),
            )

    def test_cannot_add_new_service(self, delegatable_token):
        parent, keys = delegatable_token
        with pytest.raises(AttenuationViolationError, match="not in parent"):
            delegate(
                parent,
                DelegationDefinition(
                    agent=Agent(id="did:apoa:sub"),
                    services=[ServiceAuthorization(service="other.com", scopes=["read"])],
                    rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
                ),
                SigningOptions(private_key=keys[0]),
            )

    def test_cannot_relax_constraint(self, delegatable_token):
        parent, keys = delegatable_token
        with pytest.raises(AttenuationViolationError, match="relaxes constraint"):
            delegate(
                parent,
                DelegationDefinition(
                    agent=Agent(id="did:apoa:sub"),
                    services=[ServiceAuthorization(service="test.com", scopes=["read"], constraints={"signing": True})],
                    rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
                ),
                SigningOptions(private_key=keys[0]),
            )

    def test_cannot_remove_rules(self, delegatable_token):
        parent, keys = delegatable_token
        with pytest.raises(AttenuationViolationError, match="removes parent rule"):
            delegate(
                parent,
                DelegationDefinition(
                    agent=Agent(id="did:apoa:sub"),
                    services=[ServiceAuthorization(service="test.com", scopes=["read"])],
                    # Missing "no-signing" rule from parent
                ),
                SigningOptions(private_key=keys[0]),
            )

    def test_can_add_extra_rules(self, delegatable_token):
        parent, keys = delegatable_token
        child = delegate(
            parent,
            DelegationDefinition(
                agent=Agent(id="did:apoa:sub"),
                services=[ServiceAuthorization(service="test.com", scopes=["read"])],
                rules=[
                    Rule(id="no-signing", description="No signing", enforcement="hard"),
                    Rule(id="extra-rule", description="Extra", enforcement="soft"),
                ],
            ),
            SigningOptions(private_key=keys[0]),
        )
        rule_ids = [r.id for r in child.definition.rules]
        assert "no-signing" in rule_ids
        assert "extra-rule" in rule_ids

    def test_non_delegatable_token_fails(self, signing_options):
        defn = APOADefinition(
            principal=Principal(id="did:apoa:alice"),
            agent=Agent(id="did:apoa:agent1"),
            services=[ServiceAuthorization(service="test.com", scopes=["read"])],
            expires="2026-12-31T00:00:00Z",
            delegatable=False,
        )
        parent = create_token(defn, signing_options)
        with pytest.raises(AttenuationViolationError, match="does not allow delegation"):
            delegate(
                parent,
                DelegationDefinition(
                    agent=Agent(id="did:apoa:sub"),
                    services=[ServiceAuthorization(service="test.com", scopes=["read"])],
                ),
                signing_options,
            )

    def test_depth_tracking(self, delegatable_token):
        parent, keys = delegatable_token
        opts = SigningOptions(private_key=keys[0])
        child_def = DelegationDefinition(
            agent=Agent(id="did:apoa:sub1"),
            services=[ServiceAuthorization(service="test.com", scopes=["read"])],
            rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
        )

        child1 = delegate(parent, child_def, opts)
        assert child1.definition.metadata["_delegationDepth"] == 1

        child_def2 = DelegationDefinition(
            agent=Agent(id="did:apoa:sub2"),
            services=[ServiceAuthorization(service="test.com", scopes=["read"])],
            rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
        )
        child2 = delegate(child1, child_def2, opts)
        assert child2.definition.metadata["_delegationDepth"] == 2


class TestVerifyChain:
    def test_valid_chain(self, delegatable_token):
        parent, keys = delegatable_token
        opts = SigningOptions(private_key=keys[0])
        child = delegate(
            parent,
            DelegationDefinition(
                agent=Agent(id="did:apoa:sub"),
                services=[ServiceAuthorization(service="test.com", scopes=["read"])],
                rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
            ),
            opts,
        )
        result = verify_chain([parent, child])
        assert result.valid is True
        assert result.depth == 1

    def test_empty_chain(self):
        result = verify_chain([])
        assert result.valid is False
        assert "empty" in result.errors[0].lower()

    def test_single_token_chain(self, basic_token):
        result = verify_chain([basic_token])
        assert result.valid is True
        assert result.depth == 0

    def test_revoked_in_chain(self, delegatable_token):
        parent, keys = delegatable_token
        opts = SigningOptions(private_key=keys[0])
        child = delegate(
            parent,
            DelegationDefinition(
                agent=Agent(id="did:apoa:sub"),
                services=[ServiceAuthorization(service="test.com", scopes=["read"])],
                rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
            ),
            opts,
        )
        store = MemoryRevocationStore()
        revoke(parent.jti, "did:apoa:alice", "testing", store)
        result = verify_chain([parent, child], revocation_store=store)
        assert result.valid is False
        assert any("revoked" in e for e in result.errors)
