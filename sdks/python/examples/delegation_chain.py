"""Delegation: HomeBot delegates a narrower token to a sub-agent, then cascade-revokes."""

from apoa import (
    APOADefinition,
    Agent,
    DelegationDefinition,
    Principal,
    ServiceAuthorization,
    create_client,
    generate_key_pair,
)


def main() -> None:
    private_key, _ = generate_key_pair()
    apoa = create_client(default_private_key=private_key)

    # Step 1: Create the root token (HomeBot has broad access)
    root_token = apoa.create_token(
        APOADefinition(
            principal=Principal(id="did:apoa:jane", name="Jane Doe"),
            agent=Agent(id="did:apoa:homebot", name="HomeBot Pro"),
            services=[
                ServiceAuthorization(
                    service="mychart.com",
                    scopes=["appointments:read", "appointments:write", "prescriptions:read"],
                ),
                ServiceAuthorization(
                    service="stripe.com",
                    scopes=["charges:read", "balance:read", "invoices:read"],
                ),
            ],
            expires="2099-09-01",
            delegatable=True,
            max_delegation_depth=2,
        ),
    )

    print(f"Root token: {root_token.jti}")
    print(f"  Agent: {root_token.definition.agent.name}")
    print(f"  Services: {', '.join(root_token.audience or [])}")

    # Step 2: Delegate to a specialized sub-agent (narrower scope)
    child_token = apoa.delegate(
        root_token,
        DelegationDefinition(
            agent=Agent(id="did:apoa:appointment-bot", name="AppointmentBot"),
            services=[
                ServiceAuthorization(
                    service="mychart.com",
                    scopes=["appointments:read"],  # subset of parent
                ),
            ],
            expires="2098-06-01",  # before parent
        ),
    )

    print(f"\nChild token: {child_token.jti}")
    print(f"  Agent: {child_token.definition.agent.name}")
    print(f"  Parent: {child_token.parent_token}")
    print(f"  Principal: {child_token.definition.principal.name} (inherited)")

    # Step 3: Verify the chain
    chain = apoa.verify_chain([root_token, child_token])
    print(f"\nChain verification: {'VALID' if chain.valid else 'INVALID'}")
    print(f"  Depth: {chain.depth}")
    print(f"  Root: {chain.root.definition.agent.name}")
    print(f"  Leaf: {chain.leaf.definition.agent.name}")

    # Step 4: Use the child token
    scope_check = apoa.check_scope(child_token, "mychart.com", "appointments:read")
    print(f"\nChild scope check (appointments:read): {'ALLOWED' if scope_check.allowed else 'DENIED'}")

    expand_check = apoa.check_scope(child_token, "mychart.com", "appointments:write")
    print(f"Child scope check (appointments:write): {'ALLOWED' if expand_check.allowed else 'DENIED'}")

    cross_check = apoa.check_scope(child_token, "stripe.com", "charges:read")
    print(f"Child scope check (stripe charges:read): {'ALLOWED' if cross_check.allowed else 'DENIED'}")

    # Step 5: Cascade revoke -- kill the parent, kill the children
    print("\n--- Cascade Revocation ---")
    record = apoa.cascade_revoke(
        root_token.jti,
        [child_token.jti],
        revoked_by="did:apoa:jane",
        reason="No longer needed",
    )

    print(f"Revoked parent: {record.token_id}")
    print(f"Cascaded to: {', '.join(record.cascaded)}")
    print(f"Parent revoked: {apoa.is_revoked(root_token.jti)}")
    print(f"Child revoked: {apoa.is_revoked(child_token.jti)}")

    # Chain is now invalid
    post_chain = apoa.verify_chain([root_token, child_token])
    print(f"\nPost-revoke chain: {'VALID' if post_chain.valid else 'INVALID'}")
    print(f"Errors: {'; '.join(post_chain.errors)}")


if __name__ == "__main__":
    main()
