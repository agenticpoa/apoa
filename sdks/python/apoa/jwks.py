"""JWKS publish and resolve helpers.

Provides utilities for publishing public keys at a discovery endpoint
(``/.well-known/jwks.json``) and for resolving keys by ``kid`` against a
remote JWKS endpoint at validation time.
"""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Any, Callable, Literal

import jwt

JWK = dict[str, Any]
JWKS = dict[str, list[JWK]]


def public_key_to_jwk(
    public_key: Any,
    kid: str,
    *,
    use: Literal["sig", "enc"] = "sig",
    alg: str | None = None,
) -> JWK:
    """Convert a public key (Ed25519 or P-256) into a JWK with ``kid``,
    ``use``, and ``alg`` populated. ``alg`` defaults to ``EdDSA`` for
    Ed25519 and ``ES256`` for P-256.
    """
    type_name = type(public_key).__name__

    if "Ed25519" in type_name:
        jwk = jwt.algorithms.OKPAlgorithm.to_jwk(public_key, as_dict=True)
        default_alg = "EdDSA"
    elif "EllipticCurve" in type_name or "EC" in type_name:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(public_key, as_dict=True)
        default_alg = "ES256"
    else:
        raise ValueError(f"unsupported public key type: {type_name}")

    return {
        **jwk,
        "kid": kid,
        "use": use,
        "alg": alg or default_alg,
    }


def build_jwks(keys: list[JWK]) -> JWKS:
    """Wrap an iterable of JWKs in the JWKS envelope (``{"keys": [...]}``)."""
    return {"keys": list(keys)}


class JWKSResolver:
    """Caches a remote JWKS and resolves public keys by ``kid``.

    Compatible with the ``key_resolver`` option on ``ValidationOptions``.

    By default the resolver rejects non-``https://`` URLs because APOA
    mandates TLS 1.3+ for all communication (SPEC §13.2). For local
    development against a non-HTTPS endpoint, pass ``allow_insecure=True``
    or supply a custom ``http_get`` callable.
    """

    def __init__(
        self,
        url: str,
        *,
        cache_max_age: float = 3600.0,
        cooldown: float = 86400.0,
        http_get: Callable[[str], bytes] | None = None,
        allow_insecure: bool = False,
    ) -> None:
        if http_get is None and not allow_insecure and not url.startswith("https://"):
            raise ValueError(
                f"JWKS URL must use https:// (got: {url!r}). "
                "Pass allow_insecure=True or a custom http_get for local development."
            )
        self.url = url
        self.cache_max_age = cache_max_age
        self.cooldown = cooldown
        self._http_get = http_get or _default_http_get
        self._cache: tuple[float, JWKS] | None = None

    def resolve(self, kid: str) -> Any | None:
        jwks = self._get_jwks()
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                alg = key.get("alg")
                # APOA only specifies EdDSA and ES256 (SPEC §4.1, §13.2).
                # Reject any other alg to prevent algorithm-confusion attacks
                # if a JWKS host serves a wider key set.
                if alg == "EdDSA":
                    return jwt.algorithms.OKPAlgorithm.from_jwk(key)
                if alg == "ES256":
                    return jwt.algorithms.ECAlgorithm.from_jwk(key)
                if alg is None:
                    # Some publishers omit alg; infer from kty + crv.
                    kty = key.get("kty")
                    crv = key.get("crv")
                    if kty == "OKP" and crv == "Ed25519":
                        return jwt.algorithms.OKPAlgorithm.from_jwk(key)
                    if kty == "EC" and crv == "P-256":
                        return jwt.algorithms.ECAlgorithm.from_jwk(key)
                raise ValueError(
                    f"unsupported JWK alg='{alg}' kty='{key.get('kty')}' crv='{key.get('crv')}'; "
                    "APOA accepts only EdDSA (Ed25519) and ES256 (P-256)"
                )
        return None

    def _get_jwks(self) -> JWKS:
        now = time.monotonic()
        if self._cache and now - self._cache[0] < self.cache_max_age:
            return self._cache[1]
        try:
            raw = self._http_get(self.url)
            parsed = json.loads(raw)
            if not isinstance(parsed, dict) or not isinstance(parsed.get("keys"), list):
                raise ValueError("JWKS response did not contain a `keys` array")
            self._cache = (now, parsed)
            return parsed
        except Exception:
            if self._cache and now - self._cache[0] < self.cooldown:
                return self._cache[1]
            raise


def create_jwks_resolver(
    url: str,
    *,
    cache_max_age: float = 3600.0,
    cooldown: float = 86400.0,
    http_get: Callable[[str], bytes] | None = None,
    allow_insecure: bool = False,
) -> JWKSResolver:
    """Create a ``JWKSResolver`` for the given JWKS URL.

    The resolver fetches and caches the JWKS for ``cache_max_age`` seconds
    (default 1 hour). If a refresh fails and the prior fetch is younger
    than ``cooldown`` seconds (default 24 hours), the cached value is
    returned instead of raising.

    ``http_get`` lets callers supply a custom HTTP fetcher (useful in tests
    or behind a corporate proxy). It must accept a URL string and return
    raw response bytes.

    Non-``https://`` URLs are rejected unless ``allow_insecure=True`` or a
    custom ``http_get`` is supplied; APOA mandates TLS for all communication.
    """
    return JWKSResolver(
        url,
        cache_max_age=cache_max_age,
        cooldown=cooldown,
        http_get=http_get,
        allow_insecure=allow_insecure,
    )


def _default_http_get(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/jwk-set+json, application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(
                f"JWKS fetch failed: {response.status} {response.reason}"
            )
        return response.read()
