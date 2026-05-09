import type {
  ChainVerificationResult,
  DelegationChain,
  RevocationStore,
} from '../types.js';
import { isExpired } from '../utils/time.js';
import { matchScope } from '../scope/patterns.js';

/**
 * Verify a full delegation chain.
 *
 * - Verifies every link attenuates the previous one (scopes are subsets)
 * - Checks expiration of every token (if any parent expired, chain is invalid)
 * - If RevocationStore provided, checks revocation of every token
 * - Reports all errors found, plus failedAt index
 *
 * IMPORTANT: This function checks structural integrity (attenuation, expiry,
 * revocation, parentToken links) but does NOT verify cryptographic signatures.
 * Each token in the chain MUST be validated via validateToken() before passing
 * to verifyChain(). Passing unvalidated APOAToken objects defeats chain security.
 */
export async function verifyChain(
  chain: DelegationChain,
  store?: RevocationStore
): Promise<ChainVerificationResult> {
  const errors: string[] = [];
  let failedAt: number | undefined;

  if (chain.length === 0) {
    return {
      valid: false,
      depth: 0,
      errors: ['Chain is empty'],
      root: undefined as any,
      leaf: undefined as any,
    };
  }

  if (chain.length === 1) {
    // Single token — just check expiration and revocation
    const token = chain[0];
    await checkTokenValidity(token, 0, errors, store);
    return {
      valid: errors.length === 0,
      depth: 0,
      errors,
      failedAt: errors.length > 0 ? 0 : undefined,
      root: token,
      leaf: token,
    };
  }

  // Check each token in the chain
  for (let i = 0; i < chain.length; i++) {
    const token = chain[i];
    const errorsBefore = errors.length;

    // Check expiration
    await checkTokenValidity(token, i, errors, store);

    // Check attenuation against parent (skip root at index 0)
    if (i > 0) {
      const parent = chain[i - 1];
      checkAttenuation(parent, token, i, errors);

      // Check parentToken reference
      if (token.parentToken !== parent.jti) {
        errors.push(
          `Chain link ${i}: parentToken '${token.parentToken}' does not match parent jti '${parent.jti}'`
        );
      }
    }

    // Track first failure
    if (failedAt === undefined && errors.length > errorsBefore) {
      failedAt = i;
    }
  }

  return {
    valid: errors.length === 0,
    depth: chain.length - 1,
    errors,
    failedAt,
    root: chain[0],
    leaf: chain[chain.length - 1],
  };
}

/**
 * Check a single token's validity (expiration and revocation).
 */
async function checkTokenValidity(
  token: { jti: string; definition: { expires: Date | string } },
  index: number,
  errors: string[],
  store?: RevocationStore
): Promise<void> {
  // Expiration check (no clock skew for chain verification — strict)
  if (isExpired(token.definition.expires, 0)) {
    errors.push(`Chain link ${index}: token '${token.jti}' has expired`);
  }

  // Revocation check
  if (store) {
    const record = await store.check(token.jti);
    if (record) {
      errors.push(
        `Chain link ${index}: token '${token.jti}' has been revoked`
      );
    }
  }
}

/**
 * Verify that a child token's scopes are a subset of the parent's.
 */
function checkAttenuation(
  parent: { definition: { services: { service: string; scopes: string[] }[]; expires: Date | string } },
  child: { definition: { services: { service: string; scopes: string[] }[]; expires: Date | string } },
  index: number,
  errors: string[]
): void {
  // Check each child service
  for (const childService of child.definition.services) {
    const parentService = parent.definition.services.find(
      (s) => s.service === childService.service
    );

    if (!parentService) {
      errors.push(
        `Chain link ${index}: service '${childService.service}' not in parent token`
      );
      continue;
    }

    // Check each child scope is covered by a parent scope
    for (const childScope of childService.scopes) {
      const covered = parentService.scopes.some((ps) =>
        matchScope(ps, childScope)
      );
      if (!covered) {
        errors.push(
          `Chain link ${index}: scope '${childScope}' on '${childService.service}' not covered by parent`
        );
      }
    }
  }

  // Check child expiration <= parent expiration
  const childExp = child.definition.expires instanceof Date
    ? child.definition.expires.getTime()
    : new Date(child.definition.expires as string).getTime();
  const parentExp = parent.definition.expires instanceof Date
    ? parent.definition.expires.getTime()
    : new Date(parent.definition.expires as string).getTime();

  if (childExp > parentExp) {
    errors.push(
      `Chain link ${index}: child expiration exceeds parent expiration`
    );
  }
}
