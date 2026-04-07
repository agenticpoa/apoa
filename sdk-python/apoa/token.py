"""Token creation, signing, validation, and parsing."""

from __future__ import annotations

import json
import math
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .crypto import decode_header, sign_token, verify_token
from .errors import DefinitionValidationError, MetadataValidationError
from .types import (
    APOADefinition,
    APOAToken,
    AgentProvider,
    APIAccessConfig,
    Agent,
    BrowserSessionConfig,
    LegalFramework,
    Principal,
    Rule,
    ServiceAuthorization,
    SigningOptions,
    ValidationOptions,
    ValidationResult,
)
from .utils import is_before_not_before, is_expired, _to_datetime


# --- camelCase <-> snake_case mapping for JWT payload round-trip ---

_SNAKE_TO_CAMEL: dict[str, str] = {
    "not_before": "notBefore",
    "agent_provider": "agentProvider",
    "max_delegation_depth": "maxDelegationDepth",
    "access_mode": "accessMode",
    "browser_config": "browserConfig",
    "api_config": "apiConfig",
    "allowed_urls": "allowedUrls",
    "credential_vault_ref": "credentialVaultRef",
    "allow_form_interaction": "allowFormInteraction",
    "allow_navigation": "allowNavigation",
    "max_session_duration": "maxSessionDuration",
    "capture_screenshots": "captureScreenshots",
    "blocked_actions": "blockedActions",
    "authorization_server": "authorizationServer",
    "oauth_scopes": "oauthScopes",
    "use_dpop": "useDPoP",
    "legal_basis": "legalBasis",
    "paired_legal_instrument": "pairedLegalInstrument",
    "on_violation": "onViolation",
    "parent_token": "parentToken",
    "issued_at": "issuedAt",
    "token_id": "tokenId",
    "revoked_at": "revokedAt",
    "revoked_by": "revokedBy",
    "rule_id": "ruleId",
    "screenshot_ref": "screenshotRef",
    "from_time": "from",
    "to_time": "to",
}

_CAMEL_TO_SNAKE: dict[str, str] = {v: k for k, v in _SNAKE_TO_CAMEL.items()}


def _to_camel(key: str) -> str:
    return _SNAKE_TO_CAMEL.get(key, key)


def _to_snake(key: str) -> str:
    return _CAMEL_TO_SNAKE.get(key, key)


# --- Serialization: Python dataclasses -> JWT payload (camelCase) ---


def _serialize_browser_config(bc: BrowserSessionConfig) -> dict[str, Any]:
    d: dict[str, Any] = {
        "allowedUrls": bc.allowed_urls,
        "credentialVaultRef": bc.credential_vault_ref,
    }
    if bc.allow_form_interaction is not None:
        d["allowFormInteraction"] = bc.allow_form_interaction
    if bc.allow_navigation is not None:
        d["allowNavigation"] = bc.allow_navigation
    if bc.max_session_duration is not None:
        d["maxSessionDuration"] = bc.max_session_duration
    if bc.capture_screenshots is not None:
        d["captureScreenshots"] = bc.capture_screenshots
    if bc.blocked_actions is not None:
        d["blockedActions"] = bc.blocked_actions
    return d


def _serialize_api_config(ac: APIAccessConfig) -> dict[str, Any]:
    d: dict[str, Any] = {}
    if ac.authorization_server is not None:
        d["authorizationServer"] = ac.authorization_server
    if ac.oauth_scopes is not None:
        d["oauthScopes"] = ac.oauth_scopes
    if ac.use_dpop is not None:
        d["useDPoP"] = ac.use_dpop
    return d


def _serialize_service(svc: ServiceAuthorization) -> dict[str, Any]:
    d: dict[str, Any] = {"service": svc.service, "scopes": svc.scopes}
    if svc.constraints is not None:
        d["constraints"] = svc.constraints
    if svc.access_mode is not None:
        d["accessMode"] = svc.access_mode
    if svc.browser_config is not None:
        d["browserConfig"] = _serialize_browser_config(svc.browser_config)
    if svc.api_config is not None:
        d["apiConfig"] = _serialize_api_config(svc.api_config)
    return d


def _serialize_rule(rule: Rule) -> dict[str, Any]:
    # Strip on_violation -- not serializable
    return {"id": rule.id, "description": rule.description, "enforcement": rule.enforcement}


def _serialize_definition(defn: APOADefinition) -> dict[str, Any]:
    d: dict[str, Any] = {
        "principal": {"id": defn.principal.id},
        "agent": {"id": defn.agent.id},
        "services": [_serialize_service(s) for s in defn.services],
        "expires": defn.expires if isinstance(defn.expires, str) else defn.expires.isoformat(),
    }
    if defn.principal.name:
        d["principal"]["name"] = defn.principal.name
    if defn.agent.name:
        d["agent"]["name"] = defn.agent.name
    if defn.agent.provider:
        d["agent"]["provider"] = defn.agent.provider
    if defn.agent_provider:
        ap: dict[str, Any] = {"name": defn.agent_provider.name}
        if defn.agent_provider.id:
            ap["id"] = defn.agent_provider.id
        if defn.agent_provider.contact:
            ap["contact"] = defn.agent_provider.contact
        d["agentProvider"] = ap
    if defn.rules:
        d["rules"] = [_serialize_rule(r) for r in defn.rules]
    if defn.not_before is not None:
        d["notBefore"] = defn.not_before if isinstance(defn.not_before, str) else defn.not_before.isoformat()
    if not defn.revocable:
        d["revocable"] = False
    if defn.delegatable:
        d["delegatable"] = True
    if defn.max_delegation_depth is not None:
        d["maxDelegationDepth"] = defn.max_delegation_depth
    if defn.metadata:
        d["metadata"] = defn.metadata
    if defn.legal:
        lg: dict[str, Any] = {"model": defn.legal.model}
        if defn.legal.jurisdiction:
            lg["jurisdiction"] = defn.legal.jurisdiction
        if defn.legal.legal_basis:
            lg["legalBasis"] = defn.legal.legal_basis
        if defn.legal.paired_legal_instrument is not None:
            lg["pairedLegalInstrument"] = defn.legal.paired_legal_instrument
        d["legal"] = lg
    return d


# --- Deserialization: JWT payload (camelCase) -> Python dataclasses ---


def _deserialize_browser_config(d: dict[str, Any]) -> BrowserSessionConfig:
    return BrowserSessionConfig(
        allowed_urls=d["allowedUrls"],
        credential_vault_ref=d["credentialVaultRef"],
        allow_form_interaction=d.get("allowFormInteraction"),
        allow_navigation=d.get("allowNavigation"),
        max_session_duration=d.get("maxSessionDuration"),
        capture_screenshots=d.get("captureScreenshots"),
        blocked_actions=d.get("blockedActions"),
    )


def _deserialize_api_config(d: dict[str, Any]) -> APIAccessConfig:
    return APIAccessConfig(
        authorization_server=d.get("authorizationServer"),
        oauth_scopes=d.get("oauthScopes"),
        use_dpop=d.get("useDPoP"),
    )


def _deserialize_service(d: dict[str, Any]) -> ServiceAuthorization:
    bc = _deserialize_browser_config(d["browserConfig"]) if d.get("browserConfig") else None
    ac = _deserialize_api_config(d["apiConfig"]) if d.get("apiConfig") else None
    return ServiceAuthorization(
        service=d["service"],
        scopes=d["scopes"],
        constraints=d.get("constraints"),
        access_mode=d.get("accessMode"),
        browser_config=bc,
        api_config=ac,
    )


def _deserialize_rule(d: dict[str, Any]) -> Rule:
    return Rule(id=d["id"], description=d["description"], enforcement=d["enforcement"])


def _deserialize_definition(d: dict[str, Any]) -> APOADefinition:
    principal = Principal(id=d["principal"]["id"], name=d["principal"].get("name"))
    agent = Agent(id=d["agent"]["id"], name=d["agent"].get("name"), provider=d["agent"].get("provider"))

    agent_provider = None
    if ap := d.get("agentProvider"):
        agent_provider = AgentProvider(name=ap["name"], id=ap.get("id"), contact=ap.get("contact"))

    legal = None
    if lg := d.get("legal"):
        legal = LegalFramework(
            model=lg["model"],
            jurisdiction=lg.get("jurisdiction"),
            legal_basis=lg.get("legalBasis"),
            paired_legal_instrument=lg.get("pairedLegalInstrument"),
        )

    rules = [_deserialize_rule(r) for r in d["rules"]] if d.get("rules") else None

    return APOADefinition(
        principal=principal,
        agent=agent,
        services=[_deserialize_service(s) for s in d["services"]],
        expires=d["expires"],
        agent_provider=agent_provider,
        rules=rules,
        not_before=d.get("notBefore"),
        revocable=d.get("revocable", True),
        delegatable=d.get("delegatable", False),
        max_delegation_depth=d.get("maxDelegationDepth"),
        metadata=d.get("metadata"),
        legal=legal,
    )


# --- Validation ---


_ISO_3166_PATTERN = re.compile(r"^[A-Z]{2}(-[A-Z0-9]{1,3})?$")


def _validate_definition_data(obj: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Validate a raw dict as an APOA definition. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    # Required: principal
    if not obj.get("principal") or not isinstance(obj["principal"], dict):
        errors.append("missing required field 'principal'")
    else:
        if not obj["principal"].get("id") or not isinstance(obj["principal"]["id"], str):
            errors.append("'principal.id' must be a non-empty string")

    # Required: agent
    if not obj.get("agent") or not isinstance(obj["agent"], dict):
        errors.append("missing required field 'agent'")
    else:
        if not obj["agent"].get("id") or not isinstance(obj["agent"]["id"], str):
            errors.append("'agent.id' must be a non-empty string")

    # Required: services
    if not obj.get("services") or not isinstance(obj["services"], list) or len(obj["services"]) == 0:
        errors.append("'services' must be a non-empty array")
    else:
        for i, svc in enumerate(obj["services"]):
            if not isinstance(svc, dict):
                errors.append(f"services[{i}] must be an object")
                continue
            if not svc.get("service") or not isinstance(svc["service"], str):
                errors.append(f"services[{i}].service must be a non-empty string")
            if not svc.get("scopes") or not isinstance(svc["scopes"], list) or len(svc["scopes"]) == 0:
                errors.append(f"services[{i}].scopes must be a non-empty array")

            # Browser mode validation
            access_mode = svc.get("accessMode")
            if access_mode == "browser":
                bc = svc.get("browserConfig")
                if not bc or not isinstance(bc, dict):
                    errors.append(
                        f"services[{i}] has accessMode 'browser' but no browserConfig. "
                        "Browser-based access requires explicit URL restrictions and a credential vault reference."
                    )
                else:
                    if not bc.get("allowedUrls") or not isinstance(bc["allowedUrls"], list) or len(bc["allowedUrls"]) == 0:
                        errors.append(f"services[{i}].browserConfig.allowedUrls must be a non-empty array")
                    if not bc.get("credentialVaultRef") or not isinstance(bc["credentialVaultRef"], str):
                        errors.append(f"services[{i}].browserConfig.credentialVaultRef must be a non-empty string")
                    msd = bc.get("maxSessionDuration")
                    if msd is not None and (not isinstance(msd, (int, float)) or msd > 86400):
                        errors.append(f"services[{i}].browserConfig.maxSessionDuration must be <= 86400 seconds")

            if access_mode == "api" and svc.get("browserConfig"):
                warnings.append(f"services[{i}] has accessMode 'api' but browserConfig is present (will be ignored)")

    # Required: expires
    if obj.get("expires") is None:
        errors.append("missing required field 'expires'")

    # Metadata
    metadata = obj.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, dict):
            errors.append("'metadata' must be a plain object")
        else:
            keys = list(metadata.keys())
            if len(keys) > 20:
                errors.append(f"metadata has {len(keys)} keys (max 20)")
            serialized = json.dumps(metadata)
            if len(serialized) > 1024:
                errors.append(f"metadata serialized size is {len(serialized)} bytes (max 1024)")
            for key in keys:
                val = metadata[key]
                if val is not None and not isinstance(val, (str, int, float, bool)):
                    errors.append(f"metadata['{key}'] has invalid type '{type(val).__name__}' (must be str | int | float | bool | None)")

    # AgentProvider
    ap = obj.get("agentProvider")
    if ap is not None:
        if not isinstance(ap, dict):
            errors.append("'agentProvider' must be an object")
        elif not ap.get("name") or not isinstance(ap["name"], str):
            errors.append("'agentProvider.name' is required and must be a non-empty string")

    # Legal framework
    legal = obj.get("legal")
    if legal is not None:
        if not isinstance(legal, dict):
            errors.append("'legal' must be an object")
        else:
            if legal.get("model") != "provider-as-agent":
                errors.append("'legal.model' must be 'provider-as-agent'")
            jurisdiction = legal.get("jurisdiction")
            if jurisdiction is not None:
                if not isinstance(jurisdiction, str):
                    errors.append("'legal.jurisdiction' must be a string")
                elif not _ISO_3166_PATTERN.match(jurisdiction):
                    errors.append(
                        f"'legal.jurisdiction' must be ISO 3166 format (e.g., \"US\", \"US-CA\", \"GB\"), got '{jurisdiction}'"
                    )

    return errors, warnings


def _validate_metadata(metadata: dict[str, Any]) -> None:
    """Validate token metadata constraints. Raises MetadataValidationError."""
    keys = list(metadata.keys())
    if len(keys) > 20:
        raise MetadataValidationError(f"Metadata has {len(keys)} keys (max 20)")
    serialized = json.dumps(metadata)
    if len(serialized) > 1024:
        raise MetadataValidationError(f"Metadata serialized size is {len(serialized)} bytes (max 1024)")
    for key in keys:
        val = metadata[key]
        if val is not None and not isinstance(val, (str, int, float, bool)):
            raise MetadataValidationError(f"Metadata key '{key}' has invalid type '{type(val).__name__}'", key)


# --- Public API ---


def create_token(definition: APOADefinition, options: SigningOptions) -> APOAToken:
    """Create a signed APOA token from a definition."""
    # Validate metadata
    if definition.metadata:
        _validate_metadata(definition.metadata)

    jti = str(uuid.uuid4())
    issued_at = datetime.now(timezone.utc)
    issuer = definition.principal.id
    audience = [s.service for s in definition.services]

    # Build JWT payload
    expires_dt = _to_datetime(definition.expires)
    payload: dict[str, Any] = {
        "jti": jti,
        "iss": issuer,
        "aud": audience,
        "iat": math.floor(issued_at.timestamp()),
        "exp": math.floor(expires_dt.timestamp()),
        "definition": _serialize_definition(definition),
    }

    if definition.not_before is not None:
        nb_dt = _to_datetime(definition.not_before)
        payload["nbf"] = math.floor(nb_dt.timestamp())

    raw = sign_token(payload, options)

    # Size checks
    size_bytes = len(raw.encode("utf-8"))
    if size_bytes > 8192:
        raise MetadataValidationError(
            f"Token size is {size_bytes} bytes (max 8192). Issue multiple tokens for large authorization surfaces."
        )

    return APOAToken(
        jti=jti,
        definition=definition,
        issued_at=issued_at,
        signature=raw.split(".")[2],
        issuer=issuer,
        audience=audience,
        raw=raw,
    )


def validate_token(
    token: str | APOAToken,
    options: ValidationOptions,
) -> ValidationResult:
    """Validate a token -- check signature, expiration, structure, revocation."""
    errors: list[str] = []
    warnings: list[str] = []
    parsed_token: APOAToken | None = None

    raw_jwt = token if isinstance(token, str) else token.raw

    # --- Key resolution ---
    public_key = None
    if options.public_key:
        public_key = options.public_key
    elif options.key_resolver:
        try:
            header = decode_header(raw_jwt)
            kid = header.get("kid")
            if kid:
                resolved = options.key_resolver.resolve(kid)
                if resolved:
                    public_key = resolved
                else:
                    errors.append(f"Key resolver returned null for kid '{kid}'")
            else:
                errors.append("Token has no kid in header and keyResolver requires one")
        except Exception:
            errors.append("Failed to decode token header for key resolution")
    elif options.public_key_resolver:
        try:
            import jwt as pyjwt

            payload_raw = pyjwt.decode(raw_jwt, options={"verify_signature": False, "verify_exp": False, "verify_aud": False})
            issuer = payload_raw.get("iss")
            if issuer:
                public_key = options.public_key_resolver(issuer)
            else:
                errors.append("Token has no issuer (iss) claim for publicKeyResolver")
        except Exception:
            errors.append("Failed to decode token for issuer-based key resolution")
    else:
        errors.append("No key provided: supply public_key, key_resolver, or public_key_resolver")

    # --- Signature verification ---
    payload: dict[str, Any] | None = None
    if public_key:
        try:
            payload = verify_token(raw_jwt, public_key)
        except Exception:
            errors.append("Signature verification failed")

    # If we couldn't verify, try to decode payload for structural checks
    if payload is None:
        try:
            import jwt as pyjwt

            payload = pyjwt.decode(raw_jwt, options={"verify_signature": False, "verify_exp": False, "verify_aud": False})
        except Exception:
            pass

    if payload is None:
        return ValidationResult(valid=False, errors=errors if errors else ["Unable to decode token"], warnings=warnings or None)

    # --- Build APOAToken from payload ---
    try:
        parsed_token = _payload_to_token(payload, raw_jwt)
    except Exception:
        errors.append("Token payload has invalid structure")

    # --- Temporal checks ---
    if payload.get("exp") is not None:
        expires_date = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        if is_expired(expires_date, options.clock_skew):
            errors.append(f"Token expired at {expires_date.isoformat()}")
    else:
        errors.append("Token has no expiration (exp) claim")

    if payload.get("nbf") is not None:
        nb_date = datetime.fromtimestamp(payload["nbf"], tz=timezone.utc)
        if is_before_not_before(nb_date, options.clock_skew):
            errors.append(f"Token not valid before {nb_date.isoformat()}")

    # --- Revocation check ---
    check_rev = options.check_revocation is not False
    if check_rev and options.revocation_store and payload.get("jti"):
        record = options.revocation_store.check(payload["jti"])
        if record:
            errors.append(f"Token has been revoked (at {record.revoked_at.isoformat()} by {record.revoked_by})")

    # --- Size warning ---
    size_bytes = len(raw_jwt.encode("utf-8"))
    if size_bytes > 4096:
        warnings.append(f"Token size is {size_bytes} bytes (exceeds 4KB recommended limit)")

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        token=parsed_token,
        warnings=warnings if warnings else None,
    )


def parse_definition(input_str: str, format: str = "json") -> APOADefinition:
    """Parse a JSON string into an APOADefinition. Validates all fields."""
    detected = format if format != "json" else ("json" if input_str.lstrip().startswith("{") else "json")

    if detected != "json":
        raise DefinitionValidationError(
            "YAML parsing is not supported. Use JSON format.",
            ["YAML parsing is not supported. Use JSON format."],
        )

    try:
        raw = json.loads(input_str)
    except json.JSONDecodeError as e:
        raise DefinitionValidationError(f"Invalid JSON: {e}", [f"Invalid JSON: {e}"])

    errors, warnings = _validate_definition_data(raw)
    if errors:
        err = DefinitionValidationError(f"Invalid definition: {len(errors)} problem(s) found", errors, warnings)
        raise err

    return _deserialize_definition(raw)


# --- Internal helpers ---


def _payload_to_token(payload: dict[str, Any], raw: str) -> APOAToken:
    """Reconstruct an APOAToken from a decoded JWT payload."""
    defn_raw = payload.get("definition")
    if not defn_raw:
        raise ValueError("Missing definition in payload")

    definition = _deserialize_definition(defn_raw)

    return APOAToken(
        jti=payload["jti"],
        definition=definition,
        issued_at=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
        signature=raw.split(".")[2],
        issuer=payload["iss"],
        audience=payload.get("aud"),
        parent_token=defn_raw.get("parentToken"),
        raw=raw,
    )
