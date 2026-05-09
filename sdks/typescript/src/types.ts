/** The human granting authority. */
export interface Principal {
  id: string;
  name?: string;
}

/** The AI agent receiving authority. */
export interface Agent {
  id: string;
  name?: string;
  provider?: string;
}

/** Allowed constraint value types. */
export type ConstraintValue = boolean | number | string | string[];

/** A map of constraint names to their values. */
export type ConstraintMap = Record<string, ConstraintValue>;

/** How the agent accesses the service. */
export type AccessMode = 'api' | 'browser';

/** Configuration for browser-based access via secure credential injection. */
export interface BrowserSessionConfig {
  allowedUrls: string[];
  credentialVaultRef: string;
  allowFormInteraction?: boolean;
  allowNavigation?: boolean;
  maxSessionDuration?: number;
  captureScreenshots?: boolean;
  blockedActions?: string[];
}

/** Configuration for API-based access. */
export interface APIAccessConfig {
  authorizationServer?: string;
  oauthScopes?: string[];
  useDPoP?: boolean;
}

/** The organization operating the AI agent. */
export interface AgentProvider {
  name: string;
  id?: string;
  contact?: string;
}

/** The legal model under which this authorization operates. */
export interface LegalFramework {
  model: 'provider-as-agent';
  jurisdiction?: string;
  legalBasis?: string[];
  pairedLegalInstrument?: boolean;
}

/** A service the agent is authorized to access. */
export interface ServiceAuthorization {
  service: string;
  scopes: string[];
  constraints?: ConstraintMap;
  accessMode?: AccessMode;
  browserConfig?: BrowserSessionConfig;
  apiConfig?: APIAccessConfig;
}

/** Called when a soft rule is violated. */
export type OnRuleViolation = (violation: RuleViolation) => void | Promise<void>;

/** Rules that govern agent behavior. */
export interface Rule {
  id: string;
  description: string;
  enforcement: 'hard' | 'soft';
  onViolation?: OnRuleViolation;
}

/** Logged when a soft rule is violated. */
export interface RuleViolation {
  ruleId: string;
  tokenId: string;
  action: string;
  service: string;
  timestamp: Date;
  details?: string;
}

/** Metadata values are JSON-serializable primitives only. */
export type MetadataValue = string | number | boolean | null;

/** Token metadata — flat key-value pairs. Max 20 keys, max 1KB serialized. */
export type TokenMetadata = Record<string, MetadataValue>;

/** The full APOA authorization definition. */
export interface APOADefinition {
  principal: Principal;
  agent: Agent;
  agentProvider?: AgentProvider;
  services: ServiceAuthorization[];
  rules?: Rule[];
  notBefore?: Date | string;
  expires: Date | string;
  revocable?: boolean;
  delegatable?: boolean;
  maxDelegationDepth?: number;
  metadata?: TokenMetadata;
  legal?: LegalFramework;
}

/** A signed, issued APOA token. */
export interface APOAToken {
  jti: string;
  definition: APOADefinition;
  issuedAt: Date;
  signature: string;
  issuer: string;
  audience?: string[];
  parentToken?: string;
  raw: string;
}

/** Audit detail values — serializable primitives only. */
export type AuditDetailValue = string | number | boolean | null;

/** What gets logged every time the agent does something. */
export interface AuditEntry {
  tokenId: string;
  timestamp: Date;
  action: string;
  service: string;
  result: 'allowed' | 'denied' | 'escalated';
  details?: Record<string, AuditDetailValue>;
  url?: string;
  screenshotRef?: string;
  accessMode?: AccessMode;
}

/** Scope check result. */
export interface ScopeCheckResult {
  allowed: boolean;
  reason: string;
  matchedScope?: string;
  constraint?: string;
}

/** Revocation record. */
export interface RevocationRecord {
  tokenId: string;
  revokedAt: Date;
  revokedBy: string;
  reason?: string;
  cascaded: string[];
}

/** Options for revoking a token. */
export interface RevocationOptions {
  revokedBy: string;
  reason?: string;
  cascade?: boolean;
}

/** Options for querying audit trails. */
export interface AuditQueryOptions {
  from?: Date;
  to?: Date;
  action?: string;
  service?: string;
  result?: 'allowed' | 'denied' | 'escalated';
  limit?: number;
  offset?: number;
}

/** Result of verifying a delegation chain. */
export interface ChainVerificationResult {
  valid: boolean;
  depth: number;
  errors: string[];
  failedAt?: number;
  root: APOAToken;
  leaf: APOAToken;
}

/** An ordered list of tokens from root to leaf. */
export type DelegationChain = APOAToken[];

/** Definition for creating a delegated token. */
export interface DelegationDefinition {
  agent: Agent;
  services: ServiceAuthorization[];
  rules?: Rule[];
  expires?: Date | string;
  metadata?: TokenMetadata;
}

/** Options for signing tokens. */
export interface SigningOptions {
  privateKey: CryptoKey;
  algorithm?: 'EdDSA' | 'ES256';
  kid?: string;
}

/** Options for validating tokens. */
export interface ValidationOptions {
  publicKey?: CryptoKey;
  keyResolver?: KeyResolver;
  publicKeyResolver?: (issuer: string) => Promise<CryptoKey>;
  checkRevocation?: boolean;
  revocationStore?: RevocationStore;
  clockSkew?: number;
}

/** Result of token validation. */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  token?: APOAToken;
  warnings?: string[];
}

/** Resolves a public key by its Key ID. */
export interface KeyResolver {
  resolve(kid: string): Promise<CryptoKey | null>;
}

/** Options for the authorize() function. */
export interface AuthorizeOptions {
  revocationStore?: RevocationStore;
  auditStore?: AuditStore;
  context?: Record<string, ConstraintValue>;
}

/** Result of an authorization check. */
export interface AuthorizationResult {
  authorized: boolean;
  reason?: string;
  checks: {
    revoked: boolean;
    scopeAllowed?: boolean;
    constraintsPassed?: boolean;
    rulesPassed?: boolean;
  };
  violations?: RuleViolation[];
}

/** Revocation store interface. */
export interface RevocationStore {
  add(record: RevocationRecord): Promise<void>;
  check(tokenId: string): Promise<RevocationRecord | null>;
  list(principalId: string): Promise<RevocationRecord[]>;
}

/** Audit store interface. */
export interface AuditStore {
  append(entry: AuditEntry): Promise<void>;
  query(tokenId: string, options?: AuditQueryOptions): Promise<AuditEntry[]>;
  queryByService(service: string, options?: AuditQueryOptions): Promise<AuditEntry[]>;
}

/** Options for creating a client. */
export interface APOAClientOptions {
  revocationStore?: RevocationStore;
  auditStore?: AuditStore;
  keyResolver?: KeyResolver;
  defaultSigningOptions?: Partial<SigningOptions>;
}

/** The configured APOA client. */
export interface APOAClient {
  createToken(definition: APOADefinition, options?: SigningOptions): Promise<APOAToken>;
  parseDefinition(input: string, format?: 'yaml' | 'json'): APOADefinition;
  validateToken(token: string | APOAToken, options?: Omit<ValidationOptions, 'revocationStore'>): Promise<ValidationResult>;
  generateKeyPair(algorithm?: 'EdDSA' | 'ES256'): Promise<CryptoKeyPair>;
  checkScope(token: APOAToken, service: string, action: string): ScopeCheckResult;
  checkConstraint(token: APOAToken, service: string, constraint: string): ScopeCheckResult;
  authorize(token: APOAToken, service: string, action: string, options?: Omit<AuthorizeOptions, 'revocationStore' | 'auditStore'>): Promise<AuthorizationResult>;
  delegate(parentToken: APOAToken, childDef: DelegationDefinition, options?: SigningOptions): Promise<APOAToken>;
  verifyChain(chain: DelegationChain): Promise<ChainVerificationResult>;
  revoke(tokenId: string, options: RevocationOptions): Promise<RevocationRecord>;
  isRevoked(tokenId: string): Promise<boolean>;
  logAction(tokenId: string, entry: Omit<AuditEntry, 'tokenId' | 'timestamp'>): Promise<void>;
  getAuditTrail(tokenId: string, options?: AuditQueryOptions): Promise<AuditEntry[]>;
  getAuditTrailByService(service: string, options?: AuditQueryOptions): Promise<AuditEntry[]>;
}
