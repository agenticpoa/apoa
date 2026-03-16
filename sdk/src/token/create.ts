import type { APOADefinition, APOAToken, SigningOptions } from '../types.js';
import { MetadataValidationError } from '../utils/errors.js';
import { signToken } from './sign.js';

/**
 * Create an APOA token from a definition.
 * Generates a UUID for jti, validates metadata, derives audience,
 * warns at 4KB, rejects above 8KB.
 */
export async function createToken(
  definition: APOADefinition,
  options: SigningOptions
): Promise<APOAToken> {
  // Validate metadata if present
  if (definition.metadata) {
    validateMetadata(definition.metadata);
  }

  const jti = crypto.randomUUID();
  const issuedAt = new Date();
  const issuer = definition.principal.id;
  const audience = definition.services.map((s) => s.service);

  // Build the payload that gets signed
  const payload: Record<string, unknown> = {
    jti,
    iss: issuer,
    aud: audience,
    iat: Math.floor(issuedAt.getTime() / 1000),
    exp: Math.floor(
      (typeof definition.expires === 'string'
        ? new Date(definition.expires)
        : definition.expires
      ).getTime() / 1000
    ),
    definition: serializeDefinition(definition),
  };

  if (definition.notBefore) {
    payload.nbf = Math.floor(
      (typeof definition.notBefore === 'string'
        ? new Date(definition.notBefore)
        : definition.notBefore
      ).getTime() / 1000
    );
  }

  // Sign the token
  const raw = await signToken(payload, options);

  // Size checks
  const sizeBytes = new TextEncoder().encode(raw).length;
  if (sizeBytes > 8192) {
    throw new MetadataValidationError(
      `Token size is ${sizeBytes} bytes (max 8192). Issue multiple tokens for large authorization surfaces.`
    );
  }

  const token: APOAToken = {
    jti,
    definition,
    issuedAt,
    signature: raw.split('.')[2],
    issuer,
    audience,
    raw,
  };

  return token;
}

function validateMetadata(metadata: Record<string, unknown>): void {
  const keys = Object.keys(metadata);
  if (keys.length > 20) {
    throw new MetadataValidationError(
      `Metadata has ${keys.length} keys (max 20)`
    );
  }

  const serialized = JSON.stringify(metadata);
  if (serialized.length > 1024) {
    throw new MetadataValidationError(
      `Metadata serialized size is ${serialized.length} bytes (max 1024)`
    );
  }

  for (const key of keys) {
    const value = metadata[key];
    if (
      value !== null &&
      typeof value !== 'string' &&
      typeof value !== 'number' &&
      typeof value !== 'boolean'
    ) {
      throw new MetadataValidationError(
        `Metadata key '${key}' has invalid type '${typeof value}'`,
        key
      );
    }
  }
}

/**
 * Serialize a definition for inclusion in the JWT payload.
 * Converts Date objects to ISO strings for JSON compatibility.
 */
function serializeDefinition(
  def: APOADefinition
): Record<string, unknown> {
  return {
    ...def,
    expires:
      def.expires instanceof Date
        ? def.expires.toISOString()
        : def.expires,
    notBefore:
      def.notBefore instanceof Date
        ? def.notBefore.toISOString()
        : def.notBefore,
    // Strip non-serializable onViolation callbacks from rules
    rules: def.rules?.map(({ onViolation: _, ...rest }) => rest),
  };
}
