"""Tests for revocation and cascade revocation."""

from apoa import MemoryRevocationStore, cascade_revoke, is_revoked, revoke


class TestRevocation:
    def test_revoke_token(self):
        store = MemoryRevocationStore()
        record = revoke("token-1", "did:apoa:alice", "no longer needed", store)
        assert record.token_id == "token-1"
        assert record.revoked_by == "did:apoa:alice"
        assert record.reason == "no longer needed"

    def test_is_revoked(self):
        store = MemoryRevocationStore()
        assert is_revoked("token-1", store) is False
        revoke("token-1", "did:apoa:alice", store=store)
        assert is_revoked("token-1", store) is True

    def test_list_by_principal(self):
        store = MemoryRevocationStore()
        revoke("token-1", "did:apoa:alice", store=store)
        revoke("token-2", "did:apoa:alice", store=store)
        revoke("token-3", "did:apoa:bob", store=store)
        assert len(store.list("did:apoa:alice")) == 2
        assert len(store.list("did:apoa:bob")) == 1
        assert len(store.list("did:apoa:nobody")) == 0


class TestCascadeRevoke:
    def test_cascade_revokes_all(self):
        store = MemoryRevocationStore()
        record = cascade_revoke(
            "parent-1",
            ["child-1", "child-2", "child-3"],
            "did:apoa:alice",
            "revoking everything",
            store,
        )
        assert record.token_id == "parent-1"
        assert record.cascaded == ["child-1", "child-2", "child-3"]
        assert is_revoked("parent-1", store) is True
        assert is_revoked("child-1", store) is True
        assert is_revoked("child-2", store) is True
        assert is_revoked("child-3", store) is True

    def test_cascade_child_reason(self):
        store = MemoryRevocationStore()
        cascade_revoke("parent-1", ["child-1"], "did:apoa:alice", "security", store)
        child_record = store.check("child-1")
        assert child_record is not None
        assert "Cascade" in child_record.reason
