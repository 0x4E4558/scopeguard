"""
app.hydrator
~~~~~~~~~~~~
Converts the saved JSON engagement data (from SQLite) into a fully hydrated
Engagement model object suitable for passing to the Validator.

This is the bridge between the storage layer (flat JSON blobs per section)
and the validation engine (typed Engagement dataclass).
"""

from __future__ import annotations
import sys
from pathlib import Path
from datetime import date, datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests.conftest import load_fixture
from scopeguard.models import (
    Engagement, EngagementIdentity, EngagementPeriod, Contact, BlackoutDate,
    NetworkAsset, OutOfScopeAsset, PhysicalLocation, Technique, MaintenanceWindow,
    DataGovernance, SocialEngineering,
    EngagementType, Classification, DocumentStatus, RegulatoryBasis,
    AuthorizationStatus, TechniqueCategory, DeliveryMethod, CredentialUsePolicy,
    EncryptionStandard, UsbPayloadType,
)


def _d(s) -> date | None:
    if not s:
        return None
    if isinstance(s, date):
        return s
    return date.fromisoformat(str(s)[:10])


def _dt(s) -> datetime | None:
    if not s:
        return None
    if isinstance(s, datetime):
        return s
    try:
        return datetime.fromisoformat(str(s))
    except ValueError:
        return datetime.fromisoformat(str(s)[:19])


def _make_technique(t: dict):
    """Build a Technique, carrying ATT&CK / NIST / PTES fields as dynamic attrs."""
    tech = Technique(
        technique_id=t.get("technique_id", ""),
        category=TechniqueCategory(t["category"])
            if t.get("category") else TechniqueCategory.RECONNAISSANCE,
        technique_name=t.get("technique_name", ""),
        authorization_status=AuthorizationStatus(t["authorization_status"])
            if t.get("authorization_status") else AuthorizationStatus.NOT_AUTHORIZED,
        maintenance_window_required=bool(t.get("maintenance_window_required", False)),
        notification_required=bool(t.get("notification_required", False)),
        prohibited=bool(t.get("prohibited", False)),
        conditions=t.get("conditions"),
        approval_workflow=t.get("approval_workflow"),
        maintenance_window_ref=t.get("maintenance_window_ref"),
        notification_lead_time_hours=t.get("notification_lead_time_hours"),
        notification_recipient_ref=t.get("notification_recipient_ref"),
        scope_limitation=t.get("scope_limitation"),
    )
    # Carry framework reference fields as dynamic attributes
    tech.mitre_tactic_id    = t.get("mitre_tactic_id", "")
    tech.mitre_technique_id = t.get("mitre_technique_id", "")
    tech.nist_800_115_phase = t.get("nist_800_115_phase", "")
    tech.ptes_phase         = t.get("ptes_phase", "")
    return tech


def hydrate(data: dict) -> Engagement:
    """
    Build an Engagement from the section-keyed dict stored in SQLite.
    Missing sections produce empty/default sub-objects so partial engagements
    can still be validated (and will produce MISSING findings).
    """
    id_data = data.get("identity", {})
    p_data  = data.get("period", {})

    # ── Identity ──────────────────────────────────────────────────────────────
    identity = EngagementIdentity(
        engagement_id=id_data.get("engagement_id", ""),
        sow_reference=id_data.get("sow_reference", ""),
        client_org_legal_name=id_data.get("client_org_legal_name", ""),
        testing_firm_legal_name=id_data.get("testing_firm_legal_name", ""),
        engagement_type=EngagementType(id_data["engagement_type"])
            if id_data.get("engagement_type") else EngagementType.FULL_SCOPE,
        classification=Classification(id_data["classification"])
            if id_data.get("classification") else Classification.CONFIDENTIAL,
        document_version=id_data.get("document_version", "1.0"),
        document_status=DocumentStatus(id_data["document_status"])
            if id_data.get("document_status") else DocumentStatus.DRAFT,
        prepared_by=id_data.get("prepared_by", ""),
        prepared_date=_d(id_data.get("prepared_date")) or date.today(),
        schema_version="1.0",
        msa_reference=id_data.get("msa_reference"),
        regulatory_basis=[
            RegulatoryBasis(r) for r in id_data.get("regulatory_basis", [])
            if r
        ],
        client_signatory_name=id_data.get("client_signatory_name"),
        client_signatory_date=_d(id_data.get("client_signatory_date")),
        tester_lead_signatory_name=id_data.get("tester_lead_signatory_name"),
        tester_lead_signatory_date=_d(id_data.get("tester_lead_signatory_date")),
        tester_principal_signatory_name=id_data.get("tester_principal_signatory_name"),
        tester_principal_signatory_date=_d(id_data.get("tester_principal_signatory_date")),
    )

    # ── Period ────────────────────────────────────────────────────────────────
    blackouts = [
        BlackoutDate(date=_d(bd["date"]), reason=bd.get("reason", ""))
        for bd in p_data.get("blackout_dates", [])
        if bd.get("date")
    ]
    # Provide safe defaults so date math validators don't crash on empty data
    start_default = datetime(2026, 1, 1, 8, 0)
    end_default   = datetime(2026, 12, 31, 17, 0)

    period = EngagementPeriod(
        authorized_start_date=_dt(p_data.get("authorized_start_date")) or start_default,
        authorized_end_date=_dt(p_data.get("authorized_end_date")) or end_default,
        active_testing_days=p_data.get("active_testing_days") or ["Mon"],
        active_testing_hours_start=p_data.get("active_testing_hours_start", "08:00 ET"),
        active_testing_hours_end=p_data.get("active_testing_hours_end", "18:00 ET"),
        report_draft_due=_d(p_data.get("report_draft_due")) or date(2026, 12, 1),
        report_final_due=_d(p_data.get("report_final_due")) or date(2026, 12, 15),
        retest_included=bool(p_data.get("retest_included", False)),
        blackout_dates=blackouts,
        retest_window_start=_d(p_data.get("retest_window_start")),
        retest_window_end=_d(p_data.get("retest_window_end")),
    )

    # ── Contacts ──────────────────────────────────────────────────────────────
    contacts = [
        Contact(
            role=c.get("role", ""),
            full_name=c.get("full_name", ""),
            title=c.get("title", ""),
            organization=c.get("organization", ""),
            phone_primary=c.get("phone_primary", ""),
            email=c.get("email", ""),
            phone_mobile=c.get("phone_mobile"),
            certifications=c.get("certifications", []),
            authorized_source_ips=c.get("authorized_source_ips", []),
        )
        for c in data.get("contacts", [])
        if c.get("role") and c.get("full_name")
    ]

    # ── In-scope assets ───────────────────────────────────────────────────────
    in_scope = [
        NetworkAsset(
            asset_name=a.get("asset_name", ""),
            cidr_notation=a.get("cidr_notation", "0.0.0.0/0"),
            subnet_mask=a.get("subnet_mask", "0.0.0.0"),
            description=a.get("description", ""),
            delivery_method=DeliveryMethod(a["delivery_method"])
                if a.get("delivery_method") else DeliveryMethod.NETWORK_DISCOVERABLE,
            vlan_range_start=a.get("vlan_range_start"),
            vlan_range_end=a.get("vlan_range_end"),
            vlan_count_stated=a.get("vlan_count_stated"),
            delivery_confirmed=bool(a.get("delivery_confirmed", False)),
            delivery_confirmed_date=_d(a.get("delivery_confirmed_date")),
            confirmed_address=a.get("confirmed_address"),
        )
        for a in data.get("in_scope_assets", [])
        if a.get("asset_name")
    ]

    # ── Out-of-scope assets ───────────────────────────────────────────────────
    out_of_scope = [
        OutOfScopeAsset(
            asset_name=a.get("asset_name", ""),
            cidr_notation=a.get("cidr_notation", "0.0.0.0/0"),
            subnet_mask=a.get("subnet_mask", "0.0.0.0"),
            description=a.get("description", ""),
            delivery_method=DeliveryMethod(a["delivery_method"])
                if a.get("delivery_method") else DeliveryMethod.NETWORK_DISCOVERABLE,
            exclusion_reason=a.get("exclusion_reason", ""),
            third_party_operated=bool(a.get("third_party_operated", False)),
            third_party_name=a.get("third_party_name"),
            regulatory_exclusion=bool(a.get("regulatory_exclusion", False)),
        )
        for a in data.get("out_of_scope_assets", [])
        if a.get("asset_name")
    ]

    # ── Physical locations ────────────────────────────────────────────────────
    locations = [
        PhysicalLocation(
            location_name=loc.get("location_name", ""),
            address_full=loc.get("address_full", ""),
            authorized_activities=loc.get("authorized_activities", []),
            pre_notification_required=bool(loc.get("pre_notification_required", False)),
            facility_third_party=bool(loc.get("facility_third_party", False)),
            pre_notification_hours=loc.get("pre_notification_hours"),
            pre_notification_contact_ref=loc.get("pre_notification_contact_ref"),
            facility_security_contact=loc.get("facility_security_contact"),
            facility_notified=loc.get("facility_notified"),
        )
        for loc in data.get("physical_locations", [])
        if loc.get("location_name")
    ]

    # ── Techniques ────────────────────────────────────────────────────────────
    techniques = [
        _make_technique(t)
        for t in data.get("techniques", [])
        if t.get("technique_id")
    ]

    # ── Maintenance windows ───────────────────────────────────────────────────
    windows = [
        MaintenanceWindow(
            window_id=mw.get("window_id", ""),
            date=_d(mw.get("date")) or date.today(),
            start_time=mw.get("start_time", "02:00 ET"),
            end_time=mw.get("end_time", "06:00 ET"),
            pre_notification_hours=mw.get("pre_notification_hours", 4),
            notification_recipient_ref=mw.get("notification_recipient_ref", ""),
            authorized_activity_refs=mw.get("authorized_activity_refs", []),
            cancellation_notice_hours=mw.get("cancellation_notice_hours", 2),
            required_staffing_client_refs=mw.get("required_staffing_client_refs", []),
            required_staffing_tester_refs=mw.get("required_staffing_tester_refs", []),
        )
        for mw in data.get("maintenance_windows", [])
        if mw.get("window_id")
    ]

    # ── Data governance ───────────────────────────────────────────────────────
    dg = data.get("data_governance")
    data_governance = None
    if dg:
        data_governance = DataGovernance(
            credential_reporting_window_hours=int(dg.get("credential_reporting_window_hours", 4)),
            credential_use_policy=CredentialUsePolicy(dg["credential_use_policy"])
                if dg.get("credential_use_policy") else CredentialUsePolicy.MINIMAL_DEMONSTRATION,
            pii_handling_policy=dg.get("pii_handling_policy", ""),
            evidence_encryption_standard=EncryptionStandard(dg["evidence_encryption_standard"])
                if dg.get("evidence_encryption_standard") else EncryptionStandard.AES_256,
            evidence_retention_days=int(dg.get("evidence_retention_days", 30)),
            evidence_deletion_confirmation=bool(dg.get("evidence_deletion_confirmation", True)),
            data_transfer_method=dg.get("data_transfer_method", ""),
            third_party_disclosure_prohibited=bool(dg.get("third_party_disclosure_prohibited", True)),
            cloud_storage_prohibited=bool(dg.get("cloud_storage_prohibited", True)),
            personal_device_prohibited=bool(dg.get("personal_device_prohibited", True)),
            hash_retention_policy=dg.get("hash_retention_policy", ""),
            evidence_encryption_justification=dg.get("evidence_encryption_justification"),
            cloud_storage_justification=dg.get("cloud_storage_justification"),
        )

    # ── Social engineering ────────────────────────────────────────────────────
    se = data.get("social_engineering")
    social_engineering = None
    if se:
        upt = se.get("usb_payload_type")
        social_engineering = SocialEngineering(
            phishing_authorized=bool(se.get("phishing_authorized", False)),
            vishing_authorized=bool(se.get("vishing_authorized", False)),
            smishing_authorized=bool(se.get("smishing_authorized", False)),
            impersonation_authorized=bool(se.get("impersonation_authorized", False)),
            usb_drop_authorized=bool(se.get("usb_drop_authorized", False)),
            excluded_se_targets=se.get("excluded_se_targets", []),
            phishing_target_list_due_date=_d(se.get("phishing_target_list_due_date")),
            phishing_target_departments=se.get("phishing_target_departments", []),
            phishing_target_max_count=se.get("phishing_target_max_count"),
            pretext_approval_required=se.get("pretext_approval_required"),
            pretext_approver_ref=se.get("pretext_approver_ref"),
            vishing_targets=se.get("vishing_targets"),
            caller_id_spoofing_authorized=se.get("caller_id_spoofing_authorized"),
            approved_pretexts=se.get("approved_pretexts", []),
            usb_payload_type=UsbPayloadType(upt) if upt else None,
            usb_executable_authorization=se.get("usb_executable_authorization"),
            usb_recovery_window_hours=se.get("usb_recovery_window_hours"),
            usb_location_refs=se.get("usb_location_refs", []),
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
