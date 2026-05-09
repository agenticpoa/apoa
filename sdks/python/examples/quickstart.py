"""Minimal example: create a token, check what the agent can and can't do."""

from apoa import (
    APOADefinition,
    Agent,
    Principal,
    ServiceAuthorization,
    SigningOptions,
    check_scope,
    create_token,
    generate_key_pair,
)


def main() -> None:
    private_key, _ = generate_key_pair()

    token = create_token(
        APOADefinition(
            principal=Principal(id="did:apoa:you"),
            agent=Agent(id="did:apoa:your-agent", name="My Agent"),
            services=[
                ServiceAuthorization(
                    service="mychart.com",
                    scopes=["appointments:read", "prescriptions:read"],
                    constraints={"signing": False, "data_export": False},
                ),
            ],
            expires="2026-09-01",
        ),
        SigningOptions(private_key=private_key),
    )

    # Can the agent read appointments? Yes.
    allowed = check_scope(token, "mychart.com", "appointments:read")
    print("appointments:read ->", allowed)

    # Can the agent send messages? Absolutely not.
    denied = check_scope(token, "mychart.com", "messages:send")
    print("messages:send ->", denied)


if __name__ == "__main__":
    main()
