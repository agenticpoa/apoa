"""Revocation store and cascade revocation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from .types import RevocationRecord


class RevocationStore(Protocol):
    def add(self, record: RevocationRecord) -> None: ...
    def check(self, token_id: str) -> RevocationRecord | None: ...
    def list(self, principal_id: str) -> list[RevocationRecord]: ...


class MemoryRevocationStore:
    """In-memory revocation store for dev/testing."""

    def __init__(self) -> None:
        self._records: dict[str, RevocationRecord] = {}
        self._by_principal: dict[str, list[RevocationRecord]] = {}

    def add(self, record: RevocationRecord) -> None:
        self._records[record.token_id] = record
        self._by_principal.setdefault(record.revoked_by, []).append(record)

    def check(self, token_id: str) -> RevocationRecord | None:
        return self._records.get(token_id)

    def list(self, principal_id: str) -> list[RevocationRecord]:
        return self._by_principal.get(principal_id, [])


def revoke(
    token_id: str,
    revoked_by: str,
    reason: str | None = None,
    store: RevocationStore | None = None,
) -> RevocationRecord:
    """Revoke a single token."""
    if store is None:
        raise ValueError("revocation store is required")

    record = RevocationRecord(
        token_id=token_id,
        revoked_at=datetime.now(timezone.utc),
        revoked_by=revoked_by,
        reason=reason,
        cascaded=[],
    )
    store.add(record)
    return record


def is_revoked(token_id: str, store: RevocationStore) -> bool:
    """Check if a token has been revoked."""
    return store.check(token_id) is not None


def cascade_revoke(
    parent_token_id: str,
    child_token_ids: list[str],
    revoked_by: str,
    reason: str | None = None,
    store: RevocationStore | None = None,
) -> RevocationRecord:
    """Cascade revoke: revoke a parent token and all child tokens."""
    if store is None:
        raise ValueError("revocation store is required")

    revoked_at = datetime.now(timezone.utc)

    # Revoke all children
    for child_id in child_token_ids:
        child_record = RevocationRecord(
            token_id=child_id,
            revoked_at=revoked_at,
            revoked_by=revoked_by,
            reason=f"Cascade: {reason}" if reason else f"Cascade revocation from parent {parent_token_id}",
            cascaded=[],
        )
        store.add(child_record)

    # Revoke parent
    parent_record = RevocationRecord(
        token_id=parent_token_id,
        revoked_at=revoked_at,
        revoked_by=revoked_by,
        reason=reason,
        cascaded=child_token_ids,
    )
    store.add(parent_record)
    return parent_record
