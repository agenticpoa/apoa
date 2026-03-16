import type {
  APOAClient,
  APOAClientOptions,
  APOADefinition,
  APOAToken,
  AuditEntry,
  AuditQueryOptions,
  AuthorizeOptions,
  AuthorizationResult,
  ChainVerificationResult,
  DelegationChain,
  DelegationDefinition,
  RevocationOptions,
  RevocationRecord,
  ScopeCheckResult,
  SigningOptions,
  ValidationOptions,
  ValidationResult,
} from './types.js';
import { MemoryRevocationStore } from './revocation/store.js';
import { MemoryAuditStore } from './audit/store.js';
import { createToken } from './token/create.js';
import { validateToken } from './token/validate.js';
import { parseDefinition } from './token/parse.js';
import { generateKeyPair } from './utils/crypto.js';
import { checkScope, checkConstraint, authorize } from './scope/check.js';
import { delegate } from './delegation/chain.js';
import { verifyChain } from './delegation/verify.js';
import { revoke, isRevoked } from './revocation/revoke.js';
import { logAction } from './audit/log.js';
import { getAuditTrail, getAuditTrailByService } from './audit/trail.js';

/**
 * Create a configured APOA client.
 * Wires up RevocationStore and AuditStore so methods don't need explicit store params.
 * Defaults to MemoryRevocationStore + MemoryAuditStore for zero-config dev/testing.
 */
export function createClient(options?: APOAClientOptions): APOAClient {
  const revocationStore = options?.revocationStore ?? new MemoryRevocationStore();
  const auditStore = options?.auditStore ?? new MemoryAuditStore();
  const keyResolver = options?.keyResolver;
  const defaultSigningOptions = options?.defaultSigningOptions;

  function mergeSigningOptions(opts?: SigningOptions): SigningOptions {
    if (!opts && !defaultSigningOptions?.privateKey) {
      throw new Error('No signing options provided and no defaultSigningOptions.privateKey configured');
    }
    return {
      ...defaultSigningOptions,
      ...opts,
    } as SigningOptions;
  }

  return {
    async createToken(
      definition: APOADefinition,
      opts?: SigningOptions
    ): Promise<APOAToken> {
      return createToken(definition, mergeSigningOptions(opts));
    },

    parseDefinition(
      input: string,
      format?: 'yaml' | 'json'
    ): APOADefinition {
      return parseDefinition(input, format);
    },

    async validateToken(
      token: string | APOAToken,
      opts?: Omit<ValidationOptions, 'revocationStore'>
    ): Promise<ValidationResult> {
      return validateToken(token, {
        ...opts,
        keyResolver: opts?.keyResolver ?? keyResolver,
        revocationStore,
        checkRevocation: opts?.checkRevocation ?? true,
      });
    },

    async generateKeyPair(
      algorithm?: 'EdDSA' | 'ES256'
    ): Promise<CryptoKeyPair> {
      return generateKeyPair(algorithm);
    },

    checkScope(
      token: APOAToken,
      service: string,
      action: string
    ): ScopeCheckResult {
      return checkScope(token, service, action);
    },

    checkConstraint(
      token: APOAToken,
      service: string,
      constraint: string
    ): ScopeCheckResult {
      return checkConstraint(token, service, constraint);
    },

    async authorize(
      token: APOAToken,
      service: string,
      action: string,
      opts?: Omit<AuthorizeOptions, 'revocationStore' | 'auditStore'>
    ): Promise<AuthorizationResult> {
      return authorize(token, service, action, {
        ...opts,
        revocationStore,
        auditStore,
      });
    },

    async delegate(
      parentToken: APOAToken,
      childDef: DelegationDefinition,
      opts?: SigningOptions
    ): Promise<APOAToken> {
      return delegate(parentToken, childDef, mergeSigningOptions(opts));
    },

    async verifyChain(
      chain: DelegationChain
    ): Promise<ChainVerificationResult> {
      return verifyChain(chain, revocationStore);
    },

    async revoke(
      tokenId: string,
      opts: RevocationOptions
    ): Promise<RevocationRecord> {
      return revoke(tokenId, opts, revocationStore);
    },

    async isRevoked(tokenId: string): Promise<boolean> {
      return isRevoked(tokenId, revocationStore);
    },

    async logAction(
      tokenId: string,
      entry: Omit<AuditEntry, 'tokenId' | 'timestamp'>
    ): Promise<void> {
      return logAction(tokenId, entry, auditStore);
    },

    async getAuditTrail(
      tokenId: string,
      opts?: AuditQueryOptions
    ): Promise<AuditEntry[]> {
      return getAuditTrail(tokenId, opts, auditStore);
    },

    async getAuditTrailByService(
      service: string,
      opts?: AuditQueryOptions
    ): Promise<AuditEntry[]> {
      return getAuditTrailByService(service, opts, auditStore);
    },
  };
}
