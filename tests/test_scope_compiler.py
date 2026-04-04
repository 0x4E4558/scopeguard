"""
tests/test_scope_compiler.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for the scope compilation pipeline (Phases 4-8, 10).

Tests verify:
  - ScopeArtifact structure and required fields
  - Determinism: identical inputs → identical outputs
  - scope_hash correctness
  - Token payload and HMAC signature
  - operator_id derivation
  - Capability → module mapping integration
  - Fail-closed behaviour on missing required fields
"""

import copy
import hashlib
import hmac
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from tests.conftest import load_fixture
from nex.canonicalize import canonical_json, canonical_json_bytes
from nex.scope_compiler import (
    ScopeArtifact,
    ScopeCompilationError,
    compile_scope,
    COMPILER_VERSION,
    SCOPE_SCHEMA_VERSION,
)
from nex.scope_token import verify_scope_token

# Fixed test key and timestamp for determinism assertions
_TEST_KEY = b"test-hmac-key-fixed-for-determinism"
_TEST_TS = datetime(2026, 1, 15, 9, 0, 0)


@pytest.fixture
def mcb_engagement():
    return load_fixture("mcb")


# ─── compile_scope returns a complete ScopeArtifact ──────────────────────────

class TestScopeArtifactStructure:
    def test_returns_scope_artifact(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert isinstance(art, ScopeArtifact)

    def test_scope_id_is_uuid_string(self, mcb_engagement):
        import uuid
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        # Should parse as UUID without raising
        parsed = uuid.UUID(art.scope_id)
        assert str(parsed) == art.scope_id

    def test_scope_hash_is_sha256_hex(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert len(art.scope_hash) == 64
        assert all(c in "0123456789abcdef" for c in art.scope_hash)

    def test_operator_id_is_sha256_hex(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert len(art.operator_id) == 64
        assert all(c in "0123456789abcdef" for c in art.operator_id)

    def test_scope_contains_required_top_level_keys(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        required_keys = {
            "scope_id", "schema_version", "engagement_id", "operator_id",
            "authorized_targets", "authorized_modules", "constraints",
            "authorization_basis", "scope_hash",
        }
        assert required_keys.issubset(set(art.scope.keys()))

    def test_scope_schema_version(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art.scope["schema_version"] == SCOPE_SCHEMA_VERSION

    def test_scope_hash_matches_embedded_field(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art.scope["scope_hash"] == art.scope_hash

    def test_scope_id_matches_embedded_field(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art.scope["scope_id"] == art.scope_id

    def test_operator_id_matches_embedded_field(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art.scope["operator_id"] == art.operator_id

    def test_nex_modules_is_sorted_list(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art.nex_modules == sorted(art.nex_modules)

    def test_authorized_targets_sorted_by_cidr(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        cidrs = [t["cidr"] for t in art.scope["authorized_targets"]]
        assert cidrs == sorted(cidrs)


# ─── Scope hash integrity ──────────────────────────────────────────────────────

class TestScopeHashIntegrity:
    def test_scope_hash_verifiable(self, mcb_engagement):
        """scope_hash must equal SHA-256 of the canonical scope WITHOUT scope_hash."""
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        scope_without_hash = {k: v for k, v in art.scope.items() if k != "scope_hash"}
        expected = hashlib.sha256(canonical_json_bytes(scope_without_hash)).hexdigest()
        assert art.scope_hash == expected

    def test_different_engagement_different_hash(self, mcb_engagement):
        eng2 = copy.deepcopy(mcb_engagement)
        eng2.identity.engagement_id = "DIFFERENT-001"
        art1 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        art2 = compile_scope(eng2, _TEST_TS, _TEST_KEY)
        assert art1.scope_hash != art2.scope_hash


# ─── Determinism ──────────────────────────────────────────────────────────────

class TestDeterminism:
    def test_identical_inputs_identical_scope_hash(self, mcb_engagement):
        art1 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        art2 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art1.scope_hash == art2.scope_hash

    def test_identical_inputs_identical_scope_id(self, mcb_engagement):
        art1 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        art2 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art1.scope_id == art2.scope_id

    def test_identical_inputs_identical_operator_id(self, mcb_engagement):
        art1 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        art2 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art1.operator_id == art2.operator_id

    def test_identical_inputs_identical_token_signature(self, mcb_engagement):
        art1 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        art2 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art1.token["signature"] == art2.token["signature"]

    def test_different_timestamp_different_token_signature(self, mcb_engagement):
        """Timestamp is part of the token payload, so it affects the signature."""
        ts2 = datetime(2026, 2, 1, 12, 0, 0)
        art1 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        art2 = compile_scope(mcb_engagement, ts2, _TEST_KEY)
        assert art1.token["signature"] != art2.token["signature"]

    def test_different_timestamp_same_scope_hash(self, mcb_engagement):
        """Timestamp does NOT affect scope_hash — only the token."""
        ts2 = datetime(2026, 2, 1, 12, 0, 0)
        art1 = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        art2 = compile_scope(mcb_engagement, ts2, _TEST_KEY)
        assert art1.scope_hash == art2.scope_hash


# ─── Scope token ──────────────────────────────────────────────────────────────

class TestScopeToken:
    def test_token_envelope_structure(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert "algorithm" in art.token
        assert "payload" in art.token
        assert "signature" in art.token
        assert art.token["algorithm"] == "HMAC-SHA256"

    def test_token_payload_has_required_fields(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        payload = art.token["payload"]
        required = {
            "scope_id", "operator_id", "engagement_id",
            "nex_modules", "authorized_cidrs", "constraints",
            "scope_hash", "issued_at", "expires_at",
        }
        assert required.issubset(set(payload.keys()))

    def test_token_signature_valid(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert verify_scope_token(art.token, _TEST_KEY)

    def test_token_invalid_with_wrong_key(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert not verify_scope_token(art.token, b"wrong-key")

    def test_token_scope_hash_matches_artifact(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art.token["payload"]["scope_hash"] == art.scope_hash

    def test_token_issued_at_matches_timestamp(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art.token["payload"]["issued_at"] == _TEST_TS.isoformat()

    def test_token_nex_modules_is_sorted(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        modules = art.token["payload"]["nex_modules"]
        assert modules == sorted(modules)

    def test_token_authorized_cidrs_is_sorted(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        cidrs = art.token["payload"]["authorized_cidrs"]
        assert cidrs == sorted(cidrs)


# ─── Audit record ─────────────────────────────────────────────────────────────

class TestAuditRecord:
    def test_audit_has_required_keys(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        required = {
            "audit_schema_version", "scope_id", "scope_hash", "operator_id",
            "generated_at", "inputs", "mapping_decisions", "generation_context",
        }
        assert required.issubset(set(art.audit.keys()))

    def test_audit_scope_hash_matches_artifact(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        assert art.audit["scope_hash"] == art.scope_hash

    def test_audit_generation_context_has_versions(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        ctx = art.audit["generation_context"]
        assert "compiler_version" in ctx
        assert "taxonomy_version" in ctx
        assert ctx["compiler_version"] == COMPILER_VERSION

    def test_audit_mapping_decisions_present(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        md = art.audit["mapping_decisions"]
        assert "capabilities_granted" in md
        assert "modules_authorized" in md
        assert "category_capability_map" in md


# ─── Authorization basis ──────────────────────────────────────────────────────

class TestAuthorizationBasis:
    def test_document_status_present(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        basis = art.scope["authorization_basis"]
        assert "document_status" in basis

    def test_all_signatures_present_field_is_bool(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        basis = art.scope["authorization_basis"]
        assert isinstance(basis["all_signatures_present"], bool)

    def test_crypto_signature_fields_present(self, mcb_engagement):
        art = compile_scope(mcb_engagement, _TEST_TS, _TEST_KEY)
        basis = art.scope["authorization_basis"]
        assert "authorization_crypto_signed" in basis
        assert "all_cryptographic_signatures_present" in basis
        assert isinstance(basis["authorization_crypto_signed"], bool)
        assert isinstance(basis["all_cryptographic_signatures_present"], bool)


# ─── Fail-closed on missing required fields ───────────────────────────────────

class TestFailClosed:
    def test_empty_engagement_id_raises(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.identity.engagement_id = ""
        with pytest.raises(ScopeCompilationError):
            compile_scope(eng, _TEST_TS, _TEST_KEY)

    def test_empty_testing_firm_raises(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.identity.testing_firm_legal_name = ""
        with pytest.raises(ScopeCompilationError):
            compile_scope(eng, _TEST_TS, _TEST_KEY)

    def test_empty_prepared_by_raises(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.identity.prepared_by = ""
        with pytest.raises(ScopeCompilationError):
            compile_scope(eng, _TEST_TS, _TEST_KEY)

    def test_empty_secret_key_raises(self, mcb_engagement):
        with pytest.raises(ValueError):
            compile_scope(mcb_engagement, _TEST_TS, b"")

    def test_non_datetime_timestamp_raises(self, mcb_engagement):
        with pytest.raises(TypeError):
            compile_scope(mcb_engagement, "2026-01-01", _TEST_KEY)


# ─── Canonical JSON ───────────────────────────────────────────────────────────

class TestCanonicalJson:
    def test_sorted_keys(self):
        obj = {"z": 1, "a": 2, "m": 3}
        result = canonical_json(obj)
        assert result == '{"a":2,"m":3,"z":1}'

    def test_no_whitespace(self):
        obj = {"key": "value"}
        result = canonical_json(obj)
        assert " " not in result

    def test_nested_sorted_keys(self):
        obj = {"outer": {"z": 1, "a": 2}}
        result = canonical_json(obj)
        assert result == '{"outer":{"a":2,"z":1}}'

    def test_date_serialized_as_iso(self):
        from datetime import date
        obj = {"d": date(2026, 1, 15)}
        result = canonical_json(obj)
        assert '"2026-01-15"' in result

    def test_datetime_serialized_as_iso(self):
        obj = {"dt": datetime(2026, 1, 15, 9, 0, 0)}
        result = canonical_json(obj)
        assert '"2026-01-15T09:00:00"' in result

    def test_identical_inputs_identical_output(self):
        obj = {"b": [3, 1, 2], "a": {"z": "x", "y": "w"}}
        assert canonical_json(obj) == canonical_json(obj)
