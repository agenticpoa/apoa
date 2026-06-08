from apoa import APOA, generate_key_pair


def main() -> None:
    private_key, public_key = generate_key_pair()
    apoa = APOA(private_key=private_key)

    token = apoa.tokens.create_grant(
        principal="did:apoa:alex",
        agent="did:apoa:docs-assistant",
        service="knowledge-base",
        scopes=["articles:search", "articles:summarize"],
        expires_in="24h",
    )

    validation = apoa.tokens.validate(token.raw, public_key=public_key)
    allowed = apoa.authorizations.check(token, "knowledge-base", "articles:summarize")
    denied = apoa.authorizations.check(token, "knowledge-base", "articles:delete")

    print(
        {
            "valid": validation.valid,
            "summarize": allowed.authorized,
            "delete": denied.authorized,
            "denied_reason": denied.reason,
        }
    )


if __name__ == "__main__":
    main()

