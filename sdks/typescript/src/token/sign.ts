import * as jose from 'jose';
import type { SigningOptions } from '../types.js';

/**
 * Sign an APOA token payload as a compact JWS.
 * Embeds `kid` in the JWT header when provided.
 * Supports EdDSA (default) and ES256.
 */
export async function signToken(
  payload: Record<string, unknown>,
  options: SigningOptions
): Promise<string> {
  const alg = options.algorithm === 'ES256' ? 'ES256' : 'EdDSA';

  const header: jose.CompactJWSHeaderParameters = { alg };
  if (options.kid) {
    header.kid = options.kid;
  }

  const jws = await new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify(payload))
  )
    .setProtectedHeader(header)
    .sign(options.privateKey);

  return jws;
}

/**
 * Decode a compact JWS protected header without verifying the signature.
 * Used to extract `kid` and `alg` for key resolution.
 */
export function decodeHeader(
  token: string
): Record<string, unknown> {
  const [headerB64] = token.split('.');
  if (!headerB64) throw new Error('Invalid JWS: missing header');
  return JSON.parse(
    new TextDecoder().decode(jose.base64url.decode(headerB64))
  );
}

/**
 * Verify a compact JWS and return the decoded payload.
 */
export async function verifySignature(
  token: string,
  key: CryptoKey
): Promise<Record<string, unknown>> {
  const { payload } = await jose.compactVerify(token, key);
  return JSON.parse(new TextDecoder().decode(payload));
}
