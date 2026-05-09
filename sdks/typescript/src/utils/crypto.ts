import * as jose from 'jose';
import type { SigningOptions } from '../types.js';

/**
 * Generate an Ed25519 or ES256 key pair for signing and verifying tokens.
 */
export async function generateKeyPair(
  algorithm: 'EdDSA' | 'ES256' = 'EdDSA'
): Promise<CryptoKeyPair> {
  const alg = algorithm === 'EdDSA' ? 'EdDSA' : 'ES256';
  const { publicKey, privateKey } = await jose.generateKeyPair(alg, {
    extractable: true,
  });
  return { publicKey, privateKey } as CryptoKeyPair;
}

/**
 * Sign a payload, producing a compact JWS string.
 */
export async function sign(
  payload: Record<string, unknown>,
  options: SigningOptions
): Promise<string> {
  const alg = options.algorithm === 'ES256' ? 'ES256' : 'EdDSA';
  const header: Record<string, unknown> = { alg };
  if (options.kid) {
    header.kid = options.kid;
  }

  const jws = await new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify(payload))
  )
    .setProtectedHeader(header as jose.CompactJWSHeaderParameters)
    .sign(options.privateKey);

  return jws;
}

/**
 * Verify a compact JWS string and return the decoded payload.
 */
export async function verify(
  token: string,
  key: CryptoKey
): Promise<Record<string, unknown>> {
  const { payload } = await jose.compactVerify(token, key);
  return JSON.parse(new TextDecoder().decode(payload));
}
