// Phase 0: Types and errors
export type {
  Principal,
  Agent,
  ConstraintValue,
  ConstraintMap,
  AccessMode,
  BrowserSessionConfig,
  APIAccessConfig,
  AgentProvider,
  LegalFramework,
  ServiceAuthorization,
  OnRuleViolation,
  Rule,
  RuleViolation,
  MetadataValue,
  TokenMetadata,
  APOADefinition,
  APOAToken,
  AuditDetailValue,
  AuditEntry,
  ScopeCheckResult,
  RevocationRecord,
  RevocationOptions,
  AuditQueryOptions,
  ChainVerificationResult,
  DelegationChain,
  DelegationDefinition,
  SigningOptions,
  ValidationOptions,
  ValidationResult,
  KeyResolver,
  AuthorizeOptions,
  AuthorizationResult,
  RevocationStore,
  AuditStore,
  APOAClientOptions,
  APOAClient,
} from './types.js';

export {
  APOAError,
  TokenExpiredError,
  ScopeViolationError,
  AttenuationViolationError,
  RevocationError,
  ChainVerificationError,
  MetadataValidationError,
  RuleEnforcementError,
  DefinitionValidationError,
} from './utils/errors.js';

// Phase 1: Utilities
export { generateKeyPair, sign, verify } from './utils/crypto.js';
export { isExpired, isBeforeNotBefore } from './utils/time.js';
export { parseScope, matchScope } from './scope/patterns.js';
export { MemoryRevocationStore } from './revocation/store.js';
export { MemoryAuditStore } from './audit/store.js';

// Phase 2: Core functional modules
export { checkScope, checkConstraint, authorize } from './scope/check.js';
export { parseDefinition } from './token/parse.js';
export { revoke, isRevoked } from './revocation/revoke.js';
export { logAction } from './audit/log.js';
export { getAuditTrail, getAuditTrailByService } from './audit/trail.js';

// Phase 3: Token lifecycle
export { createToken } from './token/create.js';
export { signToken, decodeHeader, verifySignature } from './token/sign.js';
export { validateToken } from './token/validate.js';
export { cascadeRevoke } from './revocation/cascade.js';

// Phase 4: Delegation
export { verifyAttenuation } from './scope/attenuate.js';
export { delegate } from './delegation/chain.js';
export { verifyChain } from './delegation/verify.js';

// Phase 6: Client
export { createClient } from './client.js';
