/** Base error class for all APOA errors. */
export class APOAError extends Error {
  code: string;

  constructor(message: string, code: string) {
    super(message);
    this.code = code;
    this.name = 'APOAError';
  }
}

/** Thrown when a token has expired. */
export class TokenExpiredError extends APOAError {
  expiredAt: Date;

  constructor(message: string, expiredAt: Date) {
    super(message, 'TOKEN_EXPIRED');
    this.expiredAt = expiredAt;
    this.name = 'TokenExpiredError';
  }
}

/** Thrown when an action is outside the token's authorized scopes. */
export class ScopeViolationError extends APOAError {
  requestedScope: string;
  availableScopes: string[];

  constructor(message: string, requestedScope: string, availableScopes: string[]) {
    super(message, 'SCOPE_VIOLATION');
    this.requestedScope = requestedScope;
    this.availableScopes = availableScopes;
    this.name = 'ScopeViolationError';
  }
}

/** Thrown when a delegated token tries to exceed parent permissions. */
export class AttenuationViolationError extends APOAError {
  parentScope: string[];
  requestedScope: string[];

  constructor(message: string, parentScope: string[], requestedScope: string[]) {
    super(message, 'ATTENUATION_VIOLATION');
    this.parentScope = parentScope;
    this.requestedScope = requestedScope;
    this.name = 'AttenuationViolationError';
  }
}

/** Thrown when trying to use a revoked token. */
export class RevocationError extends APOAError {
  revokedAt: Date;
  revokedBy: string;

  constructor(message: string, revokedAt: Date, revokedBy: string) {
    super(message, 'TOKEN_REVOKED');
    this.revokedAt = revokedAt;
    this.revokedBy = revokedBy;
    this.name = 'RevocationError';
  }
}

/** Thrown when delegation chain verification fails. */
export class ChainVerificationError extends APOAError {
  failedAt: number;
  reason: string;

  constructor(message: string, failedAt: number, reason: string) {
    super(message, 'CHAIN_INVALID');
    this.failedAt = failedAt;
    this.reason = reason;
    this.name = 'ChainVerificationError';
  }
}

/** Thrown when token metadata fails validation. */
export class MetadataValidationError extends APOAError {
  field?: string;

  constructor(message: string, field?: string) {
    super(message, 'METADATA_INVALID');
    this.field = field;
    this.name = 'MetadataValidationError';
  }
}

/** Thrown when a hard rule is violated. */
export class RuleEnforcementError extends APOAError {
  ruleId: string;
  enforcement: 'hard' = 'hard' as const;

  constructor(message: string, ruleId: string) {
    super(message, 'RULE_VIOLATED');
    this.ruleId = ruleId;
    this.name = 'RuleEnforcementError';
  }
}

/** Thrown when a definition fails validation. */
export class DefinitionValidationError extends APOAError {
  errors: string[];

  constructor(message: string, errors: string[]) {
    super(message, 'DEFINITION_INVALID');
    this.errors = errors;
    this.name = 'DefinitionValidationError';
  }
}
