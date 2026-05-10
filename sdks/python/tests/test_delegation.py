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

    def test_child_inherits_omitted_false_constraint(self, delegatable_token):
        # Regression: previously _verify_attenuation only rejected child=True
        # and silently accepted child=undefined. delegate() now inherits the
        # parent's `signing: False` into the child even when the input omits
        # constraints, so the child token's authorize() still enforces it.
        parent, keys = delegatable_token
        child = delegate(
            parent,
            DelegationDefinition(
                agent=Agent(id="did:apoa:sub"),
                services=[ServiceAuthorization(service="test.com", scopes=["read"])],  # no constraints
                rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
            ),
            SigningOptions(private_key=keys[0]),
        )
        child_constraints = child.definition.services[0].constraints or {}
        assert child_constraints.get("signing") is False

    def test_child_inherits_parent_rules_when_omitted(self, delegatable_token):
        # delegate() merges parent rules into the child so they cannot be
        # silently dropped by a delegating agent. The child token is signed
        # with the merged rule set even when the input omits them.
        parent, keys = delegatable_token
        child = delegate(
            parent,
            DelegationDefinition(
                agent=Agent(id="did:apoa:sub"),
                services=[ServiceAuthorization(service="test.com", scopes=["read"])],
                # Intentionally omits "no-signing" — delegate() must inherit it
            ),
            SigningOptions(private_key=keys[0]),
        )
        rule_ids = {r.id for r in (child.definition.rules or [])}
        assert "no-signing" in rule_ids

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

    def test_chain_fails_when_child_relaxes_constraint(self, delegatable_token):
        # Forge a child that flips a parent False constraint to True,
        # bypassing delegate()'s inheritance — same shape as a malicious token.
        parent, keys = delegatable_token
        opts = SigningOptions(private_key=keys[0])
        flipped_child_def = APOADefinition(
            principal=parent.definition.principal,
            agent=Agent(id="did:apoa:relaxed-child"),
            services=[
                ServiceAuthorization(
                    service="test.com",
                    scopes=["read"],
                    constraints={"signing": True},
                )
            ],
            rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
            expires=parent.definition.expires,
        )
        flipped_child = create_token(flipped_child_def, opts, parent_token_id=parent.jti)
        result = verify_chain([parent, flipped_child])
        assert result.valid is False
        assert any("constraint 'signing'" in e for e in result.errors)

    def test_chain_fails_when_child_omits_constraint(self, delegatable_token):
        # Parent has signing: False; child omits it entirely. Without the
        # constraint check in verify_chain, the child's authorize() would
        # skip the signing check — silent privilege escalation.
        parent, keys = delegatable_token
        opts = SigningOptions(private_key=keys[0])
        omitted_child_def = APOADefinition(
            principal=parent.definition.principal,
            agent=Agent(id="did:apoa:omitted-child"),
            services=[
                ServiceAuthorization(service="test.com", scopes=["read"])
                # No constraints at all
            ],
            rules=[Rule(id="no-signing", description="No signing", enforcement="hard")],
            expires=parent.definition.expires,
        )
        omitted_child = create_token(omitted_child_def, opts, parent_token_id=parent.jti)
        result = verify_chain([parent, omitted_child])
        assert result.valid is False
        assert any("constraint 'signing'" in e for e in result.errors)
