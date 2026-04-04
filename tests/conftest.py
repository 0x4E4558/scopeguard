"""
conftest.py
~~~~~~~~~~~
Pytest fixtures and the fixture loader.
The loader hydrates raw JSON engagement records into Engagement model objects.
This is the primitive intake path — Layer 1 in the full app will be the form UI;
here JSON lets us test the validation engine in isolation.
"""

import json
from datetime import date, datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import pytest
    _pytest_available = True
except ImportError:
    _pytest_available = False
    # Define a no-op fixture decorator so the file is importable without pytest
    class _FakeFixture:
        def __call__(self, fn):
            return fn
    class _FakePytest:
        fixture = _FakeFixture()
    pytest = _FakePytest()  # type: ignore

from scopeguard.models import (
    Engagement, EngagementIdentity, EngagementPeriod, Contact, BlackoutDate,
    NetworkAsset, OutOfScopeAsset, PhysicalLocation, Technique, MaintenanceWindow,
    DataGovernance, SocialEngineering,
    EngagementType, Classification, DocumentStatus, RegulatoryBasis,
    AuthorizationStatus, TechniqueCategory, DeliveryMethod, CredentialUsePolicy,
    EncryptionStandard, UsbPayloadType,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _parse_date(s):
    if s is None:
        return None
    if isinstance(s, date):
        return s
    return date.fromisoformat(s[:10])


def _parse_datetime(s):
    if s is None:
        return None
    if isinstance(s, datetime):
        return s
    # Handle timezone offset strings like "2026-04-07T08:00:00-04:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return datetime.fromisoformat(s[:19])


def load_fixture(name: str) -> Engagement:
    """Load a JSON fixture file and hydrate it into an Engagement object."""
    path = FIXTURES_DIR / f"{name}.json"
    with path.open() as fh:
        data = json.load(fh)

    # ── Identity ──────────────────────────────────────────────────────────────
    id_data = data["identity"]
    regulatory_basis = [
        RegulatoryBasis(r) for r in id_data.get("regulatory_basis", [])
    ]
    identity = EngagementIdentity(
        engagement_id=id_data["engagement_id"],
        sow_reference=id_data["sow_reference"],
        client_org_legal_name=id_data["client_org_legal_name"],
        testing_firm_legal_name=id_data["testing_firm_legal_name"],
        engagement_type=EngagementType(id_data["engagement_type"]),
        classification=Classification(id_data["classification"]),
        document_version=id_data["document_version"],
        document_status=DocumentStatus(id_data["document_status"]),
        prepared_by=id_data["prepared_by"],
        prepared_date=_parse_date(id_data["prepared_date"]),
        schema_version=id_data["schema_version"],
        msa_reference=id_data.get("msa_reference"),
        regulatory_basis=regulatory_basis,
        client_signatory_name=id_data.get("client_signatory_name"),
        client_signatory_date=_parse_date(id_data.get("client_signatory_date")),
        tester_lead_signatory_name=id_data.get("tester_lead_signatory_name"),
        tester_lead_signatory_date=_parse_date(id_data.get("tester_lead_signatory_date")),
        tester_principal_signatory_name=id_data.get("tester_principal_signatory_name"),
        tester_principal_signatory_date=_parse_date(id_data.get("tester_principal_signatory_date")),
        client_signatory_signature=id_data.get("client_signatory_signature"),
        client_signatory_public_key=id_data.get("client_signatory_public_key"),
        tester_lead_signatory_signature=id_data.get("tester_lead_signatory_signature"),
        tester_lead_signatory_public_key=id_data.get("tester_lead_signatory_public_key"),
        tester_principal_signatory_signature=id_data.get("tester_principal_signatory_signature"),
        tester_principal_signatory_public_key=id_data.get("tester_principal_signatory_public_key"),
        document_creator_signature=id_data.get("document_creator_signature"),
        document_creator_public_key=id_data.get("document_creator_public_key"),
    )

    # ── Period ────────────────────────────────────────────────────────────────
    p_data = data["period"]
    blackouts = [
        BlackoutDate(date=_parse_date(bd["date"]), reason=bd["reason"])
        for bd in p_data.get("blackout_dates", [])
    ]
    period = EngagementPeriod(
        authorized_start_date=_parse_datetime(p_data["authorized_start_date"]),
        authorized_end_date=_parse_datetime(p_data["authorized_end_date"]),
        active_testing_days=p_data["active_testing_days"],
        active_testing_hours_start=p_data["active_testing_hours_start"],
        active_testing_hours_end=p_data["active_testing_hours_end"],
        report_draft_due=_parse_date(p_data["report_draft_due"]),
        report_final_due=_parse_date(p_data["report_final_due"]),
        retest_included=p_data.get("retest_included", False),
        blackout_dates=blackouts,
        retest_window_start=_parse_date(p_data.get("retest_window_start")),
        retest_window_end=_parse_date(p_data.get("retest_window_end")),
    )

    # ── Contacts ──────────────────────────────────────────────────────────────
    contacts = [
        Contact(
            role=c["role"],
            full_name=c["full_name"],
            title=c["title"],
            organization=c["organization"],
            phone_primary=c["phone_primary"],
            email=c["email"],
            phone_mobile=c.get("phone_mobile"),
            certifications=c.get("certifications", []),
            authorized_source_ips=c.get("authorized_source_ips", []),
        )
        for c in data.get("contacts", [])
    ]

    # ── In-scope assets ───────────────────────────────────────────────────────
    in_scope = [
        NetworkAsset(
            asset_name=a["asset_name"],
            cidr_notation=a["cidr_notation"],
            subnet_mask=a["subnet_mask"],
            description=a["description"],
            delivery_method=DeliveryMethod(a["delivery_method"]),
            vlan_range_start=a.get("vlan_range_start"),
            vlan_range_end=a.get("vlan_range_end"),
            vlan_count_stated=a.get("vlan_count_stated"),
            delivery_confirmed=a.get("delivery_confirmed", False),
            delivery_confirmed_date=_parse_date(a.get("delivery_confirmed_date")),
            confirmed_address=a.get("confirmed_address"),
        )
        for a in data.get("in_scope_assets", [])
        if "asset_name" in a  # skip pure comment/documentation entries
    ]

    # ── Out-of-scope assets ───────────────────────────────────────────────────
    out_of_scope = [
        OutOfScopeAsset(
            asset_name=a["asset_name"],
            cidr_notation=a["cidr_notation"],
            subnet_mask=a["subnet_mask"],
            description=a["description"],
            delivery_method=DeliveryMethod(a["delivery_method"]),
            vlan_range_start=a.get("vlan_range_start"),
            vlan_range_end=a.get("vlan_range_end"),
            vlan_count_stated=a.get("vlan_count_stated"),
            delivery_confirmed=a.get("delivery_confirmed", False),
            exclusion_reason=a.get("exclusion_reason", ""),
            third_party_operated=a.get("third_party_operated", False),
            third_party_name=a.get("third_party_name"),
            regulatory_exclusion=a.get("regulatory_exclusion", False),
        )
        for a in data.get("out_of_scope_assets", [])
    ]

    # ── Physical locations ────────────────────────────────────────────────────
    locations = [
        PhysicalLocation(
            location_name=loc["location_name"],
            address_full=loc["address_full"],
            authorized_activities=loc["authorized_activities"],
            pre_notification_required=loc["pre_notification_required"],
            facility_third_party=loc["facility_third_party"],
            pre_notification_hours=loc.get("pre_notification_hours"),
            pre_notification_contact_ref=loc.get("pre_notification_contact_ref"),
            facility_security_contact=loc.get("facility_security_contact"),
            facility_notified=loc.get("facility_notified"),
        )
        for loc in data.get("physical_locations", [])
    ]

    # ── Techniques ────────────────────────────────────────────────────────────
    techniques = [
        Technique(
            technique_id=t["technique_id"],
            category=TechniqueCategory(t["category"]),
            technique_name=t["technique_name"],
            authorization_status=AuthorizationStatus(t["authorization_status"]),
            maintenance_window_required=t.get("maintenance_window_required", False),
            notification_required=t.get("notification_required", False),
            prohibited=t.get("prohibited", False),
            conditions=t.get("conditions"),
            approval_workflow=t.get("approval_workflow"),
            maintenance_window_ref=t.get("maintenance_window_ref"),
            notification_lead_time_hours=t.get("notification_lead_time_hours"),
            notification_recipient_ref=t.get("notification_recipient_ref"),
            scope_limitation=t.get("scope_limitation"),
        )
        for t in data.get("techniques", [])
        if "technique_id" in t  # skip pure comment/documentation entries
    ]

    # ── Maintenance windows ───────────────────────────────────────────────────
    windows = [
        MaintenanceWindow(
            window_id=mw["window_id"],
            date=_parse_date(mw["date"]),
            start_time=mw["start_time"],
            end_time=mw["end_time"],
            pre_notification_hours=mw["pre_notification_hours"],
            notification_recipient_ref=mw["notification_recipient_ref"],
            authorized_activity_refs=mw["authorized_activity_refs"],
            cancellation_notice_hours=mw["cancellation_notice_hours"],
            required_staffing_client_refs=mw["required_staffing_client_refs"],
            required_staffing_tester_refs=mw["required_staffing_tester_refs"],
        )
        for mw in data.get("maintenance_windows", [])
    ]

    # ── Data governance ───────────────────────────────────────────────────────
    dg_data = data.get("data_governance")
    data_governance = None
    if dg_data:
        data_governance = DataGovernance(
            credential_reporting_window_hours=dg_data["credential_reporting_window_hours"],
            credential_use_policy=CredentialUsePolicy(dg_data["credential_use_policy"]),
            pii_handling_policy=dg_data["pii_handling_policy"],
            evidence_encryption_standard=EncryptionStandard(dg_data["evidence_encryption_standard"]),
            evidence_retention_days=dg_data["evidence_retention_days"],
            evidence_deletion_confirmation=dg_data["evidence_deletion_confirmation"],
            data_transfer_method=dg_data["data_transfer_method"],
            third_party_disclosure_prohibited=dg_data["third_party_disclosure_prohibited"],
            cloud_storage_prohibited=dg_data["cloud_storage_prohibited"],
            personal_device_prohibited=dg_data["personal_device_prohibited"],
            hash_retention_policy=dg_data["hash_retention_policy"],
            evidence_encryption_justification=dg_data.get("evidence_encryption_justification"),
            cloud_storage_justification=dg_data.get("cloud_storage_justification"),
        )

    # ── Social engineering ────────────────────────────────────────────────────
    se_data = data.get("social_engineering")
    social_engineering = None
    if se_data:
        usb_payload_raw = se_data.get("usb_payload_type")
        social_engineering = SocialEngineering(
            phishing_authorized=se_data["phishing_authorized"],
            vishing_authorized=se_data["vishing_authorized"],
            smishing_authorized=se_data["smishing_authorized"],
            impersonation_authorized=se_data["impersonation_authorized"],
            usb_drop_authorized=se_data["usb_drop_authorized"],
            excluded_se_targets=se_data.get("excluded_se_targets", []),
            phishing_target_list_due_date=_parse_date(se_data.get("phishing_target_list_due_date")),
            phishing_target_departments=se_data.get("phishing_target_departments", []),
            phishing_target_max_count=se_data.get("phishing_target_max_count"),
            pretext_approval_required=se_data.get("pretext_approval_required"),
            pretext_approver_ref=se_data.get("pretext_approver_ref"),
            vishing_targets=se_data.get("vishing_targets"),
            caller_id_spoofing_authorized=se_data.get("caller_id_spoofing_authorized"),
            approved_pretexts=se_data.get("approved_pretexts", []),
            usb_payload_type=UsbPayloadType(usb_payload_raw) if usb_payload_raw else None,
            usb_executable_authorization=se_data.get("usb_executable_authorization"),
            usb_recovery_window_hours=se_data.get("usb_recovery_window_hours"),
            usb_location_refs=se_data.get("usb_location_refs", []),
        )

    return Engagement(
        identity=identity,
        period=period,
        contacts=contacts,
        in_scope_assets=in_scope,
        out_of_scope_assets=out_of_scope,
        physical_locations=locations,
        techniques=techniques,
        maintenance_windows=windows,
        data_governance=data_governance,
        social_engineering=social_engineering,
    )


@pytest.fixture
def mcb_engagement():
    """The canonical valid MCB engagement. Should produce zero BLOCK findings."""
    return load_fixture("mcb")


@pytest.fixture
def nexus_bad_engagement():
    """Deliberately broken Nexus Plaza document. Should produce multiple BLOCK findings."""
    return load_fixture("nexus_bad")
