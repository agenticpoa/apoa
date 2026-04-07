"""
APOA Python SDK -- Interactive Demo

Scenario: Jane is buying a home. She authorizes her AI agent (HomeBot Pro)
to monitor four services on her behalf -- with strict boundaries.
"""

from apoa import (
    APOADefinition,
    Agent,
    AgentProvider,
    BrowserSessionConfig,
    DelegationDefinition,
    LegalFramework,
    Principal,
    Rule,
    ServiceAuthorization,
    create_client,
)


def main():
    # --- Step 1: Create a client and generate keys ---
    print("=" * 60)
    print("STEP 1: Setup")
    print("=" * 60)

    from apoa import generate_key_pair, SigningOptions
    private_key, public_key = generate_key_pair()
    client = create_client(default_private_key=private_key)
    print(f"Generated Ed25519 key pair")
    print(f"Client created with MemoryRevocationStore + MemoryAuditStore\n")

    # --- Step 2: Create a token ---
    print("=" * 60)
    print("STEP 2: Create Token")
    print("=" * 60)

    token = client.create_token(
        APOADefinition(
            principal=Principal(id="did:apoa:jane", name="Jane Doe"),
            agent=Agent(id="did:apoa:homebot", name="HomeBot Pro"),
            agent_provider=AgentProvider(name="HomeBot Inc.", contact="support@homebot.ai"),
            services=[
                ServiceAuthorization(
                    service="nationwidemortgage.com",
                    scopes=["rate_lock:read", "documents:read", "timeline:read"],
                    constraints={"signing": False, "data_export": False},
                    access_mode="browser",
                    browser_config=BrowserSessionConfig(
                        allowed_urls=["https://portal.nationwidemortgage.com/*"],
                        credential_vault_ref="1password://vault/mortgage-portal",
                        max_session_duration=1800,
                        capture_screenshots=True,
                    ),
                ),
                ServiceAuthorization(
                    service="docusign.com",
                    scopes=["documents:read", "documents:flag_for_review"],
                    constraints={"signing": False},
                    access_mode="api",
                ),
            ],
            rules=[
                Rule(id="no-signing", description="Never sign, submit, or commit to anything", enforcement="hard"),
                Rule(id="deadline-alert", description="Alert if any deadline is within 48 hours", enforcement="soft"),
            ],
            expires="2026-09-01T00:00:00Z",
            legal=LegalFramework(model="provider-as-agent", jurisdiction="US-CA", legal_basis=["UETA-14", "E-SIGN"]),
            delegatable=True,
            max_delegation_depth=2,
        ),
    )

    print(f"Token ID:    {token.jti}")
    print(f"Issuer:      {token.issuer}")
    print(f"Agent:       {token.definition.agent.name}")
    print(f"Services:    {[s.service for s in token.definition.services]}")
    print(f"JWT size:    {len(token.raw)} bytes")
    print(f"JWT preview: {token.raw[:80]}...\n")

    # --- Step 3: Authorization checks ---
    print("=" * 60)
    print("STEP 3: Authorization Checks")
    print("=" * 60)

    checks = [
        ("nationwidemortgage.com", "rate_lock:read",    "Check rate lock status"),
        ("nationwidemortgage.com", "documents:read",    "Read mortgage documents"),
        ("nationwidemortgage.com", "documents:sign",    "Sign a document"),
        ("nationwidemortgage.com", "signing:submit",    "Submit a signing"),
        ("docusign.com",           "documents:read",    "Read DocuSign documents"),
        ("docusign.com",           "documents:sign",    "Sign via DocuSign"),
        ("docusign.com",           "payments:send",     "Send a payment"),
        ("redfin.com",             "saved_searches:read","Access Redfin"),
    ]

    for service, action, description in checks:
        result = client.authorize(token, service, action)
        status = "ALLOWED" if result.authorized else "DENIED"
        reason = result.reason or "authorized"
        soft = f" (+ {len(result.violations)} soft violation(s))" if result.violations else ""
        print(f"  [{status:7s}] {description:30s} | {service}:{action}")
        if not result.authorized:
            print(f"            Reason: {reason}")
        if result.violations:
            for v in result.violations:
                print(f"            Soft violation: {v.rule_id} -- {v.details}")
    print()

    # --- Step 4: Constraint checking ---
    print("=" * 60)
    print("STEP 4: Direct Constraint Checks")
    print("=" * 60)

    for service, constraint in [
        ("nationwidemortgage.com", "signing"),
        ("nationwidemortgage.com", "data_export"),
        ("nationwidemortgage.com", "messaging"),
        ("docusign.com", "signing"),
    ]:
        result = client.check_constraint(token, service, constraint)
        status = "ALLOWED" if result.allowed else "DENIED"
        print(f"  [{status:7s}] {service} / {constraint:15s} | {result.reason}")
    print()

    # --- Step 5: Delegation ---
    print("=" * 60)
    print("STEP 5: Delegation (HomeBot Pro -> DocReviewer)")
    print("=" * 60)

    child_token = client.delegate(
        token,
        DelegationDefinition(
            agent=Agent(id="did:apoa:docreviewer", name="DocReviewer"),
            services=[
                ServiceAuthorization(service="docusign.com", scopes=["documents:read"]),
            ],
            rules=[
                Rule(id="no-signing", description="Never sign anything", enforcement="hard"),
                Rule(id="deadline-alert", description="Alert if deadline within 48 hours", enforcement="soft"),
            ],
        ),
    )

    print(f"Child token ID: {child_token.jti}")
    print(f"Parent token:   {child_token.parent_token}")
    print(f"Principal:      {child_token.definition.principal.name} (inherited)")
    print(f"Agent:          {child_token.definition.agent.name}")
    print(f"Scopes:         {child_token.definition.services[0].scopes}")
    print(f"Depth:          {child_token.definition.metadata.get('_delegationDepth')}")

    # Verify the chain
    chain_result = client.verify_chain([token, child_token])
    print(f"Chain valid:    {chain_result.valid}")
    print(f"Chain depth:    {chain_result.depth}\n")

    # --- Step 6: Revocation ---
    print("=" * 60)
    print("STEP 6: Revocation")
    print("=" * 60)

    # First, show it works before revocation
    pre = client.authorize(token, "nationwidemortgage.com", "rate_lock:read")
    print(f"Before revoke:  rate_lock:read = {'ALLOWED' if pre.authorized else 'DENIED'}")

    # Revoke with cascade
    client.cascade_revoke(token.jti, [child_token.jti], "did:apoa:jane", "home purchase complete")

    post = client.authorize(token, "nationwidemortgage.com", "rate_lock:read")
    child_post = client.authorize(child_token, "docusign.com", "documents:read")
    print(f"After revoke:   rate_lock:read = {'ALLOWED' if post.authorized else 'DENIED'}")
    print(f"Child revoked:  documents:read = {'ALLOWED' if child_post.authorized else 'DENIED'}")
    print(f"Revoked?        parent={client.is_revoked(token.jti)}, child={client.is_revoked(child_token.jti)}\n")

    # --- Step 7: Audit trail ---
    print("=" * 60)
    print("STEP 7: Audit Trail")
    print("=" * 60)

    # The authorize calls logged soft violations to the audit store
    trail = client.get_audit_trail(token.jti)
    print(f"Entries for token {token.jti[:8]}...:")
    for entry in trail:
        print(f"  {entry.timestamp.strftime('%H:%M:%S')} | {entry.action:25s} | {entry.result:10s} | {entry.service}")

    # --- Step 8: Validate from raw JWT ---
    print(f"\n{'=' * 60}")
    print("STEP 8: Validate from Raw JWT")
    print("=" * 60)

    from apoa import ValidationOptions
    # Simulate receiving a JWT string and validating it
    validation = client.validate_token(token.raw, ValidationOptions(public_key=public_key))
    print(f"Valid:     {validation.valid}")
    if not validation.valid:
        print(f"Errors:    {validation.errors}")
    if validation.warnings:
        print(f"Warnings:  {validation.warnings}")
    # Note: token is revoked, so validation will show that
    for error in validation.errors:
        print(f"  Error: {error}")

    print(f"\n{'=' * 60}")
    print("Done. The SDK handles all of this in ~150 lines of user code.")
    print("=" * 60)


if __name__ == "__main__":
    main()
