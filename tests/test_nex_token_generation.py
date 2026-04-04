import hashlib
import hmac
import ipaddress
import json
import secrets
from datetime import date, datetime, timedelta

import pytest

from nex.models import (
    AuthorizationStatus,
    Classification,
    Contact,
    CredentialUsePolicy,
    DataGovernance,
    DeliveryMethod,
    DocumentStatus,
    Engagement,
    EngagementIdentity,
    EngagementPeriod,
    EngagementType,
    EncryptionStandard,
    NetworkAsset,
    Technique,
    TechniqueCategory,
)
from nex.token_generator import (
    ALGORITHM_LITERAL,
    ScopeTokenGenerator,
    generate_token_json,
    validate_token_with_reason,
)


@pytest.fixture
def test_hmac_key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture
def minimal_engagement() -> Engagement:
    identity = EngagementIdentity(
        engagement_id="TEST-2026-001",
        sow_reference="SOW-2026-001",
        client_org_legal_name="Test Client LLC",
        testing_firm_legal_name="Red Team Inc",
        engagement_type=EngagementType.EXTERNAL_ONLY,
        classification=Classification.CONFIDENTIAL,
        document_version="1.0",
        document_status=DocumentStatus.DRAFT,
        prepared_by="Test Preparer",
        prepared_date=date.today(),
        schema_version="2.0",
    )

    now = datetime.now()
    period = EngagementPeriod(
        authorized_start_date=now,
        authorized_end_date=now + timedelta(days=30),
        active_testing_days=["Monday", "Tuesday", "Wednesday"],
        active_testing_hours_start="09:00 EST",
        active_testing_hours_end="17:00 EST",
        report_draft_due=date.today() + timedelta(days=35),
        report_final_due=date.today() + timedelta(days=40),
    )

    tester_contact = Contact(
        role="team_member",
        full_name="Test Operator",
        title="Security Tester",
        organization="Red Team Inc",
        phone_primary="+1-555-0100",
        email="test.operator@redteam.com",
        authorized_source_ips=["10.0.0.0/24"],
    )

    client_contact = Contact(
        role="primary_contact",
        full_name="Client Representative",
        title="Security Manager",
        organization="Test Client LLC",
        phone_primary="+1-555-0200",
        email="security@testclient.com",
    )

    asset = NetworkAsset(
        asset_name="Production Network",
        cidr_notation="192.168.0.0/16",
        subnet_mask="255.255.0.0",
        description="Main production environment",
        delivery_method=DeliveryMethod.NETWORK_DISCOVERABLE,
    )

    technique = Technique(
        technique_id="RECON-001",
        category=TechniqueCategory.RECONNAISSANCE,
        technique_name="Passive Reconnaissance",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        maintenance_window_required=False,
        notification_required=False,
        prohibited=False,
    )

    data_gov = DataGovernance(
        credential_reporting_window_hours=24,
        credential_use_policy=CredentialUsePolicy.MINIMAL_DEMONSTRATION,
        pii_handling_policy="encrypt and delete",
        evidence_encryption_standard=EncryptionStandard.AES_256,
        evidence_retention_days=30,
        evidence_deletion_confirmation=True,
        data_transfer_method="encrypted channel",
        third_party_disclosure_prohibited=True,
        cloud_storage_prohibited=True,
        personal_device_prohibited=True,
        hash_retention_policy="retain indefinitely",
    )

    return Engagement(
        identity=identity,
        period=period,
        contacts=[tester_contact, client_contact],
        in_scope_assets=[asset],
        techniques=[technique],
        data_governance=data_gov,
    )


def test_envelope_contract_shape(minimal_engagement, test_hmac_key):
    token = ScopeTokenGenerator(
        engagement=minimal_engagement,
        operator_id="op-123",
        hmac_key=test_hmac_key,
        ttl_seconds=3600,
        scope_id="scope-compat-001",
    ).generate()

    assert set(token.keys()) == {"algorithm", "schema_version", "payload", "signature"}
    assert token["algorithm"] == ALGORITHM_LITERAL
    assert token["schema_version"] == "1.0"
    assert isinstance(token["signature"], str) and len(token["signature"]) == 64

    payload = token["payload"]
    assert "scope_id" in payload
    assert "operator_id" in payload
    assert "nex_modules" in payload
    assert "allowed_targets" in payload
    assert "issued_at" in payload
    assert "expires_at" in payload


def test_signature_is_hmac_sha256_over_canonical_payload(minimal_engagement, test_hmac_key):
    token = ScopeTokenGenerator(
        engagement=minimal_engagement,
        operator_id="op-123",
        hmac_key=test_hmac_key,
        scope_id="scope-compat-001",
    ).generate()

    canonical = json.dumps(token["payload"], sort_keys=True, separators=(",", ":"))
    expected = hmac.new(test_hmac_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    assert token["signature"] == expected


def test_expires_at_iso8601_z(minimal_engagement, test_hmac_key):
    token = ScopeTokenGenerator(
        engagement=minimal_engagement,
        operator_id="op-123",
        hmac_key=test_hmac_key,
    ).generate()

    expires_at = token["payload"]["expires_at"]
    assert expires_at.endswith("Z")


def test_validate_with_reason_ok(minimal_engagement, test_hmac_key):
    token = ScopeTokenGenerator(
        engagement=minimal_engagement,
        operator_id="op-123",
        hmac_key=test_hmac_key,
        scope_id="scope-compat-001",
    ).generate()

    cidr = token["payload"].get("authorized_cidrs", ["10.0.0.0/24"])[0]
    target_ip = str(next(ipaddress.ip_network(cidr, strict=False).hosts()))

    ok, reason = validate_token_with_reason(
        token,
        hmac_key=test_hmac_key,
        target=target_ip,
        operator_id="op-123",
        nex_module_ids=token["payload"]["nex_modules"][:1],
    )
    assert ok is True
    assert reason == "ok"


def test_validate_with_reason_bad_signature(minimal_engagement, test_hmac_key):
    token = ScopeTokenGenerator(
        engagement=minimal_engagement,
        operator_id="op-123",
        hmac_key=test_hmac_key,
    ).generate()
    token["signature"] = "0" * 64

    ok, reason = validate_token_with_reason(
        token,
        hmac_key=test_hmac_key,
        target="10.0.0.1",
        operator_id="op-123",
        nex_module_ids=token["payload"]["nex_modules"][:1],
    )
    assert ok is False
    assert reason == "nex_bad_signature"


def test_validate_with_reason_module_not_allowed(minimal_engagement, test_hmac_key):
    token = ScopeTokenGenerator(
        engagement=minimal_engagement,
        operator_id="op-123",
        hmac_key=test_hmac_key,
    ).generate()

    ok, reason = validate_token_with_reason(
        token,
        hmac_key=test_hmac_key,
        target="10.0.0.1",
        operator_id="op-123",
        nex_module_ids=["nex.invalid.module@1.0"],
    )
    assert ok is False
    assert reason == "nex_module_not_allowed"


def test_validate_with_reason_operator_mismatch(minimal_engagement, test_hmac_key):
    token = ScopeTokenGenerator(
        engagement=minimal_engagement,
        operator_id="op-123",
        hmac_key=test_hmac_key,
    ).generate()

    ok, reason = validate_token_with_reason(
        token,
        hmac_key=test_hmac_key,
        target="10.0.0.1",
        operator_id="op-other",
        nex_module_ids=token["payload"]["nex_modules"][:1],
    )
    assert ok is False
    assert reason == "nex_operator_mismatch"


def test_validate_with_reason_bad_expires_at(minimal_engagement, test_hmac_key):
    token = ScopeTokenGenerator(
        engagement=minimal_engagement,
        operator_id="op-123",
        hmac_key=test_hmac_key,
    ).generate()
    token["payload"]["expires_at"] = "not-a-date"

    canonical = json.dumps(token["payload"], sort_keys=True, separators=(",", ":"))
    token["signature"] = hmac.new(test_hmac_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    ok, reason = validate_token_with_reason(
        token,
        hmac_key=test_hmac_key,
        target="10.0.0.1",
        operator_id="op-123",
        nex_module_ids=token["payload"]["nex_modules"][:1],
    )
    assert ok is False
    assert reason == "nex_bad_expires_at"


def test_rejects_unknown_nex_module_ids_from_mapping(minimal_engagement, test_hmac_key, monkeypatch):
    monkeypatch.setattr(
        "nex.token_generator.nex_allowlist_by_technique_class",
        lambda: {"RECON": ["nex.unknown.capability@1.0"], "ENUMERATION": []},
    )
    monkeypatch.setattr(
        "nex.token_generator.known_nex_module_ids",
        lambda: {"nex.recon.dns_enum@1.0"},
    )

    with pytest.raises(ValueError, match="Unknown NEX module IDs"):
        ScopeTokenGenerator(
            engagement=minimal_engagement,
            operator_id="op-123",
            hmac_key=test_hmac_key,
        ).generate()


def test_strict_d3fend_blocks_empty_mapping(minimal_engagement, test_hmac_key, monkeypatch):
    monkeypatch.setenv("NEX_COMPLIANCE_STRICT", "1")
    monkeypatch.setattr(
        "nex.token_generator.capability_to_d3fend_ids",
        lambda: {},
    )

    with pytest.raises(ValueError, match="Strict D3FEND mode"):
        ScopeTokenGenerator(
            engagement=minimal_engagement,
            operator_id="op-123",
            hmac_key=test_hmac_key,
        ).generate()


def test_generate_token_json_is_runnable(minimal_engagement, test_hmac_key):
    raw = generate_token_json(
        engagement=minimal_engagement,
        operator_id="op-123",
        hmac_key=test_hmac_key,
        pretty=False,
    )
    parsed = json.loads(raw)
    assert parsed["algorithm"] == ALGORITHM_LITERAL
