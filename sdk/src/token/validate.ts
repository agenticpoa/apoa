import type {
  APOAToken,
  ValidationOptions,
  ValidationResult,
} from '../types.js';
import { isExpired, isBeforeNotBefore } from '../utils/time.js';
import { decodeHeader, verifySignature } from './sign.js';

/**
 * Validate a token — check signature, expiration, structure, revocation.
 * Returns a detailed result with all errors found.
 *
 * Accepts either a raw JWT string or an APOAToken object.
 * When given a string, decodes and verifies the signature.
 * When given an APOAToken, uses the .raw field for signature verification.
 */
export async function validateToken(
  token: string | APOAToken,
  options: ValidationOptions
): Promise<ValidationResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  let parsedToken: APOAToken | undefined;

  const rawJwt = typeof token === 'string' ? token : token.raw;

  // --- Key resolution ---
  let publicKey: CryptoKey | undefined;

  if (options.publicKey) {
    publicKey = options.publicKey;
  } else if (options.keyResolver) {
    try {
      const header = decodeHeader(rawJwt);
      const kid = header.kid as string | undefined;
      if (kid) {
        const resolved = await options.keyResolver.resolve(kid);
        if (resolved) {
          publicKey = resolved;
        } else {
          errors.push(`Key resolver returned null for kid '${kid}'`);
        }
      } else {
        errors.push('Token has no kid in header and keyResolver requires one');
      }
    } catch {
      errors.push('Failed to decode token header for key resolution');
    }
  } else if (options.publicKeyResolver) {
    // Need issuer from the payload — decode without verification first
    try {
      const header = decodeHeader(rawJwt);
      // Decode payload without verification to get issuer
      const payloadB64 = rawJwt.split('.')[1];
      if (payloadB64) {
        const payloadJson = new TextDecoder().decode(
          base64urlDecode(payloadB64)
        );
        const payload = JSON.parse(payloadJson);
        const issuer = payload.iss as string | undefined;
        if (issuer) {
          publicKey = await options.publicKeyResolver(issuer);
        } else {
          errors.push('Token has no issuer (iss) claim for publicKeyResolver');
        }
      }
    } catch {
      errors.push('Failed to decode token for issuer-based key resolution');
    }
  } else {
    errors.push(
      'No key provided: supply publicKey, keyResolver, or publicKeyResolver'
    );
  }

  // --- Signature verification ---
  let payload: Record<string, unknown> | undefined;
  let signatureVerified = false;

  if (publicKey) {
    try {
      payload = await verifySignature(rawJwt, publicKey);
      signatureVerified = true;
    } catch {
      errors.push('Signature verification failed');
    }
  }

  // If we couldn't verify, decode payload for structural checks only.
  // result.token will NOT be populated (prevents operating on forged data).
  if (!payload) {
    try {
      const payloadB64 = rawJwt.split('.')[1];
      if (payloadB64) {
        payload = JSON.parse(
          new TextDecoder().decode(base64urlDecode(payloadB64))
        );
      }
    } catch {
      // Can't even decode the payload — nothing more to check
    }
  }

  if (!payload) {
    return { valid: false, errors: errors.length > 0 ? errors : ['Unable to decode token'], warnings };
  }

  // --- Build APOAToken from payload (only if signature was verified) ---
  if (signatureVerified) {
    try {
      parsedToken = payloadToToken(payload, rawJwt);
    } catch {
      errors.push('Token payload has invalid structure');
    }
  }

  // --- Temporal checks ---
  const clockSkew = options.clockSkew;

  if (payload.exp !== undefined) {
    const expiresDate = new Date((payload.exp as number) * 1000);
    if (isExpired(expiresDate, clockSkew)) {
      errors.push(`Token expired at ${expiresDate.toISOString()}`);
    }
  } else {
    errors.push('Token has no expiration (exp) claim');
  }

  if (payload.nbf !== undefined) {
    const notBeforeDate = new Date((payload.nbf as number) * 1000);
    if (isBeforeNotBefore(notBeforeDate, clockSkew)) {
      errors.push(`Token not valid before ${notBeforeDate.toISOString()}`);
    }
  }

  // --- Revocation check ---
  const checkRevocation = options.checkRevocation !== false;
  if (checkRevocation && options.revocationStore && payload.jti) {
    const revRecord = await options.revocationStore.check(
      payload.jti as string
    );
    if (revRecord) {
      errors.push(
        `Token has been revoked (at ${revRecord.revokedAt.toISOString()} by ${revRecord.revokedBy})`
      );
    }
  }

  // --- Size warning ---
  const sizeBytes = new TextEncoder().encode(rawJwt).length;
  if (sizeBytes > 4096) {
    warnings.push(`Token size is ${sizeBytes} bytes (exceeds 4KB recommended limit)`);
  }

  return {
    valid: errors.length === 0,
    errors,
    token: parsedToken,
    warnings: warnings.length > 0 ? warnings : undefined,
  };
}

/**
 * Reconstruct an APOAToken from a decoded JWT payload.
 */
function payloadToToken(
  payload: Record<string, unknown>,
  raw: string
): APOAToken {
  const definition = payload.definition as Record<string, unknown>;
  if (!definition) throw new Error('Missing definition in payload');

  return {
    jti: payload.jti as string,
    definition: definition as unknown as APOAToken['definition'],
    issuedAt: new Date((payload.iat as number) * 1000),
    signature: raw.split('.')[2],
    issuer: payload.iss as string,
    audience: payload.aud as string[] | undefined,
    parentToken: (definition.parentToken as string) ?? undefined,
    raw,
  };
}

function base64urlDecode(input: string): Uint8Array {
  // Pad if needed
  const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
