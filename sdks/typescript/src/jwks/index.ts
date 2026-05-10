import * as jose from 'jose';
import type { KeyResolver } from '../types.js';

/** A JSON Web Key as defined by RFC 7517. */
export interface JWK {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  kid: string;
  use?: 'sig' | 'enc';
  alg?: string;
  [key: string]: unknown;
}

/** A JSON Web Key Set as defined by RFC 7517 §5. */
export interface JWKS {
  keys: JWK[];
}

export interface PublicKeyToJWKOptions {
  kid: string;
  use?: 'sig' | 'enc';
  alg?: 'EdDSA' | 'ES256';
}

/**
 * Convert a public CryptoKey into a JWK. The `kid` is required so callers
 * can match keys against the `kid` header on signed tokens. `alg` defaults
 * to the algorithm implied by the key type (`EdDSA` for Ed25519, `ES256`
 * for P-256).
 */
export async function publicKeyToJWK(
  publicKey: CryptoKey,
  options: PublicKeyToJWKOptions
): Promise<JWK> {
  const exported = await jose.exportJWK(publicKey);
  const alg = options.alg ?? defaultAlgorithm(exported);
  return {
    ...(exported as Record<string, unknown>),
    kid: options.kid,
    use: options.use ?? 'sig',
    alg,
  } as JWK;
}

/** Wrap an array of JWKs in the JWKS envelope. */
export function buildJWKS(keys: JWK[]): JWKS {
  return { keys };
}

export interface JWKSResolverOptions {
  /** How long a fetched JWKS is cached in memory before refetch. Default 1 hour. */
  cacheMaxAgeMs?: number;
  /** How long a fetched JWKS is reused if a refetch fails. Default 24 hours. */
  cooldownMs?: number;
  /** Custom fetch implementation; defaults to the global fetch. */
  fetch?: typeof fetch;
}

/**
 * Create a KeyResolver backed by a remote JWKS endpoint. The resolver fetches
 * `url`, caches the response, and returns the matching public key for a
 * given `kid` claim. Used in conjunction with `validateToken`'s `keyResolver`
 * option so a relying party can verify tokens signed by keys it discovers
 * at runtime.
 */
export function createJWKSResolver(
  url: string,
  options: JWKSResolverOptions = {}
): KeyResolver {
  const cacheMaxAgeMs = options.cacheMaxAgeMs ?? 60 * 60 * 1000;
  const cooldownMs = options.cooldownMs ?? 24 * 60 * 60 * 1000;
  const fetchImpl = options.fetch ?? fetch;

  let cache: { fetchedAt: number; jwks: JWKS } | null = null;
  let inflight: Promise<JWKS> | null = null;

  async function fetchJWKS(): Promise<JWKS> {
    const response = await fetchImpl(url, {
      headers: { accept: 'application/jwk-set+json, application/json' },
    });
    if (!response.ok) {
      throw new Error(`JWKS fetch failed: ${response.status} ${response.statusText}`);
    }
    const body = (await response.json()) as JWKS;
    if (!body || !Array.isArray(body.keys)) {
      throw new Error('JWKS response did not contain a `keys` array');
    }
    return body;
  }

  async function getJWKS(): Promise<JWKS> {
    const now = Date.now();
    if (cache && now - cache.fetchedAt < cacheMaxAgeMs) {
      return cache.jwks;
    }
    if (inflight) {
      return inflight;
    }
    inflight = fetchJWKS()
      .then((jwks) => {
        cache = { fetchedAt: Date.now(), jwks };
        return jwks;
      })
      .catch((err) => {
        if (cache && now - cache.fetchedAt < cooldownMs) {
          return cache.jwks;
        }
        throw err;
      })
      .finally(() => {
        inflight = null;
      });
    return inflight;
  }

  return {
    async resolve(kid: string): Promise<CryptoKey | null> {
      const jwks = await getJWKS();
      const match = jwks.keys.find((k) => k.kid === kid);
      if (!match) return null;
      const key = await jose.importJWK(match as jose.JWK, match.alg);
      return key as CryptoKey;
    },
  };
}

function defaultAlgorithm(jwk: jose.JWK): string {
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') return 'ES256';
  return jwk.alg ?? 'EdDSA';
}
