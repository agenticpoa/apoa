"""Flagship example: 4 services, mixed access modes, legal framework, hard/soft rules,
browser configs, and cross-service audit trail."""

from apoa import (
    APIAccessConfig,
    APOADefinition,
    Agent,
    AgentProvider,
    AuditEntryInput,
    BrowserSessionConfig,
    LegalFramework,
    Principal,
    Rule,
    ServiceAuthorization,
    create_client,
    generate_key_pair,
)


def main() -> None:
    private_key, _ = generate_key_pair()
    apoa = create_client(default_private_key=private_key)

    token = apoa.create_token(
        APOADefinition(
            principal=Principal(id="did:apoa:jane", name="Jane Doe"),
            agent=Agent(id="did:apoa:homebot", name="HomeBot Pro"),
            agent_provider=AgentProvider(
                name="HomeBot Inc.",
                id="did:apoa:provider:homebot",
                contact="legal@homebot.ai",
            ),
            services=[
                # Browser mode: mortgage lender portal
                ServiceAuthorization(
                    service="nationwidemortgage.com",
                    scopes=["rate_lock:read", "documents:read", "timeline:read"],
                    constraints={"signing": False, "data_export": False},
                    access_mode="browser",
                    browser_config=BrowserSessionConfig(
                        allowed_urls=[
                            "https://portal.nationwidemortgage.com/application/*",
                            "https://portal.nationwidemortgage.com/documents/*",
                        ],
                        credential_vault_ref="1password://vault/mortgage-portal",
                        allow_form_interaction=False,
                        max_session_duration=1800,
                        capture_screenshots=True,
                        blocked_actions=[
                            "click:*sign*",
                            "click:*submit*",
                            "click:*approve*",
                            "navigate:*/settings/*",
                        ],
                    ),
                ),
                # Browser mode: title company
                ServiceAuthorization(
                    service="titlecompany.com",
                    scopes=["title_search:read", "closing_status:read"],
                    constraints={"signing": False},
                    access_mode="browser",
                    browser_config=BrowserSessionConfig(
                        allowed_urls=["https://portal.titlecompany.com/*"],
                        credential_vault_ref="1password://vault/title-company",
                        allow_form_interaction=False,
                        max_session_duration=900,
                    ),
                ),
                # Browser mode: DocuSign
                ServiceAuthorization(
                    service="docusign.com",
                    scopes=["documents:read", "documents:flag_for_review"],
                    constraints={"signing": False},
                    access_mode="browser",
                    browser_config=BrowserSessionConfig(
                        allowed_urls=["https://app.docusign.com/documents/*"],
                        credential_vault_ref="1password://vault/docusign",
                        allow_form_interaction=False,
                        blocked_actions=["click:*sign*", "click:*decline*"],
                    ),
                ),
                # API mode: Redfin
                ServiceAuthorization(
                    service="api.redfin.com",
                    scopes=["listings:read", "offers:read", "market_data:read"],
                    access_mode="api",
                    api_config=APIAccessConfig(oauth_scopes=["read_only"]),
                ),
            ],
            rules=[
                Rule(id="no-signing", description="Never sign, submit, or commit to anything", enforcement="hard"),
                Rule(id="deadline-alert", description="Alert me if any deadline is within 48 hours", enforcement="soft"),
            ],
            legal=LegalFramework(
                model="provider-as-agent",
                jurisdiction="US-CA",
                legal_basis=["UETA-14", "E-SIGN"],
                paired_legal_instrument=False,
            ),
            expires="2026-06-15",
        ),
    )

    print(f"Home purchase token created: {token.jti}")
    print(f"Services: {', '.join(token.audience or [])}")
    legal = token.definition.legal
    if legal:
        print(f"Legal: {legal.model} ({legal.jurisdiction})")

    # Scope checks across services
    print("\n--- Cross-Service Scope Checks ---")
    checks = [
        ("nationwidemortgage.com", "rate_lock:read"),
        ("nationwidemortgage.com", "rate_lock:write"),
        ("titlecompany.com", "title_search:read"),
        ("docusign.com", "documents:read"),
        ("docusign.com", "documents:sign"),
        ("api.redfin.com", "listings:read"),
        ("api.redfin.com", "offers:submit"),
    ]

    for service, action in checks:
        result = apoa.check_scope(token, service, action)
        mark = "OK" if result.allowed else "X "
        print(f"  [{mark}] {service} {action} ({result.reason})")

    # Simulate browser-mode audit entries
    print("\n--- Simulating Agent Actions ---")

    apoa.log_action(
        token.jti,
        AuditEntryInput(
            action="rate_lock:read",
            service="nationwidemortgage.com",
            result="allowed",
            url="https://portal.nationwidemortgage.com/application/rate-lock",
            access_mode="browser",
            screenshot_ref="s3://homebot-audit/jane/mortgage/rate-lock-001.png",
            details={"rate": "6.25%", "locked_until": "2026-04-15"},
        ),
    )

    apoa.log_action(
        token.jti,
        AuditEntryInput(
            action="documents:read",
            service="docusign.com",
            result="allowed",
            url="https://app.docusign.com/documents/closing-disclosure",
            access_mode="browser",
            details={"documentType": "Closing Disclosure", "pages": 5},
        ),
    )

    apoa.log_action(
        token.jti,
        AuditEntryInput(
            action="listings:read",
            service="api.redfin.com",
            result="allowed",
            access_mode="api",
            details={"listingsReturned": 42, "zipCode": "94110"},
        ),
    )

    # Cross-service audit trail
    print("\n--- Cross-Service Audit Trail ---")
    trail = apoa.get_audit_trail(token.jti)
    for entry in trail:
        mode = entry.access_mode or "unknown"
        url_part = f" @ {entry.url}" if entry.url else ""
        print(f"  [{mode}] {entry.service} -> {entry.action}{url_part}")

    # Service-specific trail
    mortgage_trail = apoa.get_audit_trail_by_service("nationwidemortgage.com")
    print(f"\nMortgage audit entries: {len(mortgage_trail)}")
    if mortgage_trail:
        first = mortgage_trail[0]
        print(f"  Access mode: {first.access_mode}")
        print(f"  URL: {first.url}")
        print(f"  Screenshot: {first.screenshot_ref}")


if __name__ == "__main__":
    main()
