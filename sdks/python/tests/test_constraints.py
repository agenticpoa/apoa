"""Tests for constraint checking."""

from apoa import check_constraint


class TestCheckConstraint:
    def test_false_constraint_denied(self, basic_token):
        result = check_constraint(basic_token, "nationwidemortgage.com", "signing")
        assert result.allowed is False
        assert "false" in result.reason

    def test_undefined_constraint_allowed(self, basic_token):
        result = check_constraint(basic_token, "nationwidemortgage.com", "messaging")
        assert result.allowed is True
        assert "not defined" in result.reason

    def test_unknown_service(self, basic_token):
        result = check_constraint(basic_token, "unknown.com", "signing")
        assert result.allowed is False
        assert "not found" in result.reason

    def test_no_constraints_on_service(self, multi_service_token):
        result = check_constraint(multi_service_token, "service-a.com", "anything")
        assert result.allowed is True
        assert "no constraints" in result.reason

    def test_truthy_constraint_allowed(self, signing_options):
        from apoa import APOADefinition, Agent, Principal, ServiceAuthorization, create_token

        defn = APOADefinition(
            principal=Principal(id="did:apoa:x"),
            agent=Agent(id="did:apoa:y"),
            services=[
                ServiceAuthorization(
                    service="test.com",
                    scopes=["read"],
                    constraints={"signing": True, "max_amount": 1000},
                )
            ],
            expires="2026-12-31T00:00:00Z",
        )
        token = create_token(defn, signing_options)
        assert check_constraint(token, "test.com", "signing").allowed is True
        assert check_constraint(token, "test.com", "max_amount").allowed is True
