"""Minimal example: create a token, check what the agent can and can't do."""

from apoa import (
    APOA,
    Agent,
    generate_key_pair,
)


def main() -> None:
    private_key, public_key = generate_key_pair()
    apoa = APOA(private_key=private_key)

    token = apoa.tokens.create_grant(
        principal="did:apoa:you",
        agent=Agent(id="did:apoa:your-agent", name="My Agent"),
        service="mychart.com",
        scopes=["appointments:read", "prescriptions:read"],
        constraints={"signing": False, "data_export": False},
        expires_in="30d",
    )

    validation = apoa.tokens.validate(token.raw, public_key=public_key)
    print("token valid ->", validation.valid)

    # Can the agent read appointments? Yes.
    allowed = apoa.authorizations.check(token, "mychart.com", "appointments:read")
    print("appointments:read ->", allowed)

    # Can the agent send messages? Absolutely not.
    denied = apoa.authorizations.check(token, "mychart.com", "messages:send")
    print("messages:send ->", denied)


if __name__ == "__main__":
    main()
