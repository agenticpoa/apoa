"""Healthcare monitoring: multi-service token, scope + constraint checks, audit trail."""

from apoa import (
    APOADefinition,
    Agent,
    AgentProvider,
    Principal,
    Rule,
    ServiceAuthorization,
    create_client,
    generate_key_pair,
)


def main() -> None:
    private_key, _ = generate_key_pair()
    apoa = create_client(default_private_key=private_key)

    # Create a multi-service healthcare monitoring token
    token = apoa.create_token(
        APOADefinition(
            principal=Principal(id="did:apoa:juan", name="Juan Figuera"),
            agent=Agent(id="did:apoa:healthbot", name="HealthBot Pro"),
            agent_provider=AgentProvider(name="HealthBot Inc."),
            services=[
                ServiceAuthorization(
                    service="mychart.com",
                    scopes=["appointments:read", "prescriptions:refill_status:read", "lab_results:read"],
                    constraints={"signing": False, "data_export": False},
                ),
                ServiceAuthorization(
                    service="aetna.com",
                    scopes=["claims:read", "benefits:read", "coverage:read"],
                    constraints={"data_export": False},
                ),
                ServiceAuthorization(
                    service="cvs.com",
                    scopes=["prescriptions:status:read", "prescriptions:refill:request"],
                    constraints={"payment": False},
                ),
            ],
            rules=[
                Rule(id="no-messaging", description="Never respond to messages on my behalf", enforcement="hard"),
                Rule(id="notify-refill", description="Alert me when requesting any refill", enforcement="soft"),
            ],
            expires="2026-09-01",
            revocable=True,
        ),
    )

    print(f"Token created: {token.jti}")
    print(f"Issuer: {token.issuer}")
    print(f"Audience: {', '.join(token.audience or [])}")

    # Check various scopes
    print("\n--- Scope Checks ---")
    print("mychart appointments:read ->", apoa.check_scope(token, "mychart.com", "appointments:read"))
    print("mychart messages:send ->", apoa.check_scope(token, "mychart.com", "messages:send"))
    print("aetna claims:read ->", apoa.check_scope(token, "aetna.com", "claims:read"))
    print("cvs prescriptions:status:read ->", apoa.check_scope(token, "cvs.com", "prescriptions:status:read"))

    # Check constraints
    print("\n--- Constraint Checks ---")
    print("mychart signing ->", apoa.check_constraint(token, "mychart.com", "signing"))
    print("cvs payment ->", apoa.check_constraint(token, "cvs.com", "payment"))

    # Log actions
    apoa.log_action(token.jti, "appointments:read", "mychart.com", "allowed", appointmentCount=3)
    apoa.log_action(token.jti, "claims:read", "aetna.com", "allowed", claimsReturned=12)
    apoa.log_action(
        token.jti,
        "prescriptions:refill:request",
        "cvs.com",
        "allowed",
        medication="Lisinopril",
        pharmacy="CVS #4521",
    )

    # Query audit trail
    print("\n--- Audit Trail ---")
    trail = apoa.get_audit_trail(token.jti)
    for entry in trail:
        print(f"  [{entry.service}] {entry.action} -> {entry.result}")

    # Query by service
    aetna_trail = apoa.get_audit_trail_by_service("aetna.com")
    print(f"\nAetna audit entries: {len(aetna_trail)}")


if __name__ == "__main__":
    main()
