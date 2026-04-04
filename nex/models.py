"""
nex.models
~~~~~~~~~~~~~~~~~
Python dataclasses for all 8 schema groups.
These are the structured data objects that flow through the validation engine.
Layer 1 (intake) populates these; Layer 2 (validator) reads them; Layer 3 (output) renders them.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Optional
from enum import Enum


# ─── Enums ────────────────────────────────────────────────────────────────────

class EngagementType(str, Enum):
    EXTERNAL_ONLY = "external_only"
    INTERNAL_ONLY = "internal_only"
    WEB_APP = "web_app"
    FULL_SCOPE = "full_scope"
    RED_TEAM = "red_team"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"

    def includes_social_engineering(self) -> bool:
        return self in (self.FULL_SCOPE, self.RED_TEAM)

    def includes_physical(self) -> bool:
        return self in (self.FULL_SCOPE, self.RED_TEAM)


class Classification(str, Enum):
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    INTERNAL = "internal"
    PUBLIC = "public"


class DocumentStatus(str, Enum):
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    PENDING_SIGNATURE = "pending_signature"
    EXECUTED = "executed"


class RegulatoryBasis(str, Enum):
    GLBA = "GLBA"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    SOX = "SOX"
    FISMA = "FISMA"
    STATE_LAW = "state_law"
    INTERNAL_POLICY = "internal_policy"
    OTHER = "other"


class AuthorizationStatus(str, Enum):
    AUTHORIZED = "authorized"
    NOT_AUTHORIZED = "not_authorized"
    CONDITIONAL = "conditional"


class TechniqueCategory(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    VULN_SCANNING = "vuln_scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    DOS = "dos"
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL = "physical"


class DeliveryMethod(str, Enum):
    NETWORK_DISCOVERABLE = "network_discoverable"
    CLIENT_PROVISIONED = "client_provisioned"
    PHYSICAL_ACCESS = "physical_access"


class CredentialUsePolicy(str, Enum):
    REPORT_ONLY = "report_only"
    MINIMAL_DEMONSTRATION = "minimal_demonstration"
    FULL_USE_WITH_APPROVAL = "full_use_with_approval"


class EncryptionStandard(str, Enum):
    AES_256 = "AES-256"
    AES_128 = "AES-128"
    OTHER = "other"


class UsbPayloadType(str, Enum):
    INERT_TRACKING = "inert_tracking"
    EXECUTABLE = "executable"


# ─── Group 1: Engagement Identity ─────────────────────────────────────────────

@dataclass
class EngagementIdentity:
    engagement_id: str
    sow_reference: str
    client_org_legal_name: str
    testing_firm_legal_name: str
    engagement_type: EngagementType
    classification: Classification
    document_version: str
    document_status: DocumentStatus
    prepared_by: str
    prepared_date: date
    schema_version: str
    msa_reference: Optional[str] = None
    regulatory_basis: list[RegulatoryBasis] = field(default_factory=list)

    # Signature fields — populated when document_status == EXECUTED
    client_signatory_name: Optional[str] = None
    client_signatory_title: Optional[str] = None
    client_signatory_date: Optional[date] = None
    client_legal_review_name: Optional[str] = None
    client_legal_review_date: Optional[date] = None
    tester_lead_signatory_name: Optional[str] = None
    tester_lead_signatory_date: Optional[date] = None
    tester_principal_signatory_name: Optional[str] = None
    tester_principal_signatory_date: Optional[date] = None

    # Cryptographic signatures are required for an executed engagement.
    # Each signer must provide both a detached signature and a public key.
    client_signatory_signature: Optional[str] = None
    client_signatory_public_key: Optional[str] = None
    tester_lead_signatory_signature: Optional[str] = None
    tester_lead_signatory_public_key: Optional[str] = None
    tester_principal_signatory_signature: Optional[str] = None
    tester_principal_signatory_public_key: Optional[str] = None
    document_creator_signature: Optional[str] = None
    document_creator_public_key: Optional[str] = None

    def all_signatures_present(self) -> bool:
        return all([
            self.client_signatory_name, self.client_signatory_date,
            self.tester_lead_signatory_name, self.tester_lead_signatory_date,
            self.tester_principal_signatory_name, self.tester_principal_signatory_date,
        ])

    def all_cryptographic_signatures_present(self) -> bool:
        return all([
            self.client_signatory_signature,
            self.client_signatory_public_key,
            self.tester_lead_signatory_signature,
            self.tester_lead_signatory_public_key,
            self.tester_principal_signatory_signature,
            self.tester_principal_signatory_public_key,
            self.document_creator_signature,
            self.document_creator_public_key,
        ])


# ─── Group 2: Engagement Period ───────────────────────────────────────────────

@dataclass
class BlackoutDate:
    date: date
    reason: str


@dataclass
class EngagementPeriod:
    authorized_start_date: datetime       # with timezone
    authorized_end_date: datetime         # with timezone
    active_testing_days: list[str]        # ["Mon", "Tue", ...]
    active_testing_hours_start: str       # "HH:MM TZ"
    active_testing_hours_end: str         # "HH:MM TZ"
    report_draft_due: date
    report_final_due: date
    retest_included: bool = False
    blackout_dates: list[BlackoutDate] = field(default_factory=list)
    retest_window_start: Optional[date] = None
    retest_window_end: Optional[date] = None


# ─── Group 3: Contacts ────────────────────────────────────────────────────────

@dataclass
class Contact:
    role: str
    full_name: str
    title: str
    organization: str
    phone_primary: str
    email: str
    phone_mobile: Optional[str] = None
    certifications: list[str] = field(default_factory=list)
    authorized_source_ips: list[str] = field(default_factory=list)   # validated IPs/CIDRs

    def is_tester(self) -> bool:
        return self.role in ("engagement_lead", "team_member")

    def conducts_network_testing(self) -> bool:
        return self.is_tester() and bool(self.authorized_source_ips)


# ─── Group 4: Assets ──────────────────────────────────────────────────────────

@dataclass
class NetworkAsset:
    asset_name: str
    cidr_notation: str
    subnet_mask: str
    description: str
    delivery_method: DeliveryMethod
    vlan_range_start: Optional[int] = None
    vlan_range_end: Optional[int] = None
    vlan_count_stated: Optional[int] = None
    vlan_id: Optional[int] = None
    delivery_confirmed: bool = False
    delivery_confirmed_date: Optional[date] = None
    confirmed_address: Optional[str] = None
    # v2 device detail fields
    device_type: Optional[list] = None          # multiselect — list of type strings
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os_platform: Optional[str] = None
    network_segment: Optional[str] = None
    client_asset_list_acknowledged: bool = False
    undisclosed_device_disclaimer: bool = False

    def vlan_count_computed(self) -> Optional[int]:
        if self.vlan_range_start is not None and self.vlan_range_end is not None:
            return self.vlan_range_end - self.vlan_range_start + 1
        return None


@dataclass
class OutOfScopeAsset(NetworkAsset):
    exclusion_reason: str = ""
    third_party_operated: bool = False
    third_party_name: Optional[str] = None
    regulatory_exclusion: bool = False
    # v2 third-party contact fields
    third_party_contact_name: Optional[str] = None
    third_party_contact_phone: Optional[str] = None
    third_party_contact_email: Optional[str] = None


@dataclass
class PhysicalLocation:
    location_name: str
    address_full: str
    authorized_activities: list[str]
    pre_notification_required: bool
    facility_third_party: bool
    location_type: Optional[str] = None          # office, branch, data_center, soc, etc.
    pre_notification_hours: Optional[int] = None
    pre_notification_contact_ref: Optional[str] = None   # contact role reference
    facility_security_contact: Optional[str] = None
    facility_notified: Optional[bool] = None


# ─── Group 5: Techniques ──────────────────────────────────────────────────────

@dataclass
class Technique:
    technique_id: str
    category: TechniqueCategory
    technique_name: str
    authorization_status: AuthorizationStatus
    maintenance_window_required: bool
    notification_required: bool
    prohibited: bool
    conditions: Optional[str] = None
    approval_workflow: Optional[str] = None
    maintenance_window_ref: Optional[str] = None   # window_id
    notification_lead_time_hours: Optional[int] = None
    notification_recipient_ref: Optional[str] = None   # contact role
    scope_limitation: Optional[str] = None


# ─── Group 6: Maintenance Windows ─────────────────────────────────────────────

@dataclass
class MaintenanceWindow:
    window_id: str
    date: date
    start_time: str    # "HH:MM TZ"
    end_time: str      # "HH:MM TZ"
    pre_notification_hours: int
    notification_recipient_ref: str    # contact role
    authorized_activity_refs: list[str]   # technique_ids
    cancellation_notice_hours: int
    required_staffing_client_refs: list[str]   # contact roles
    required_staffing_tester_refs: list[str]   # contact roles
    duration_hours: Optional[float] = None     # derived


# ─── Group 7: Data Governance ─────────────────────────────────────────────────

@dataclass
class DataGovernance:
    credential_reporting_window_hours: int
    credential_use_policy: CredentialUsePolicy
    pii_handling_policy: str
    evidence_encryption_standard: EncryptionStandard
    evidence_retention_days: int
    evidence_deletion_confirmation: bool
    data_transfer_method: str
    third_party_disclosure_prohibited: bool
    cloud_storage_prohibited: bool
    personal_device_prohibited: bool
    hash_retention_policy: str
    evidence_encryption_justification: Optional[str] = None
    cloud_storage_justification: Optional[str] = None


# ─── Group 8: Social Engineering ──────────────────────────────────────────────

@dataclass
class SocialEngineering:
    phishing_authorized: bool
    vishing_authorized: bool
    smishing_authorized: bool
    impersonation_authorized: bool
    usb_drop_authorized: bool
    excluded_se_targets: list[str]    # required even if empty

    # Phishing sub-fields
    phishing_target_list_due_date: Optional[date] = None
    phishing_target_departments: list[str] = field(default_factory=list)
    phishing_target_max_count: Optional[int] = None
    pretext_approval_required: Optional[bool] = None
    pretext_approver_ref: Optional[str] = None   # contact role

    # Vishing sub-fields
    vishing_targets: Optional[str] = None
    caller_id_spoofing_authorized: Optional[bool] = None

    # Impersonation sub-fields
    approved_pretexts: list[str] = field(default_factory=list)

    # USB sub-fields
    usb_payload_type: Optional[UsbPayloadType] = None
    usb_executable_authorization: Optional[str] = None
    usb_recovery_window_hours: Optional[int] = None
    usb_location_refs: list[str] = field(default_factory=list)   # location names


# ─── Top-level Engagement ─────────────────────────────────────────────────────

@dataclass
class Engagement:
    """
    Complete engagement data object.
    Populated by Layer 1 (intake), validated by Layer 2, rendered by Layer 3.
    """
    identity: EngagementIdentity
    period: EngagementPeriod
    contacts: list[Contact] = field(default_factory=list)
    in_scope_assets: list[NetworkAsset] = field(default_factory=list)
    out_of_scope_assets: list[OutOfScopeAsset] = field(default_factory=list)
    physical_locations: list[PhysicalLocation] = field(default_factory=list)
    techniques: list[Technique] = field(default_factory=list)
    maintenance_windows: list[MaintenanceWindow] = field(default_factory=list)
    data_governance: Optional[DataGovernance] = None
    social_engineering: Optional[SocialEngineering] = None

    def contact_by_role(self, role: str) -> Optional[Contact]:
        for c in self.contacts:
            if c.role == role:
                return c
        return None

    def contacts_by_role(self, role: str) -> list[Contact]:
        return [c for c in self.contacts if c.role == role]

    def technique_by_id(self, tid: str) -> Optional[Technique]:
        for t in self.techniques:
            if t.technique_id == tid:
                return t
        return None

    def window_by_id(self, wid: str) -> Optional[MaintenanceWindow]:
        for w in self.maintenance_windows:
            if w.window_id == wid:
                return w
        return None

    def all_in_scope_cidrs(self) -> list[str]:
        return [a.cidr_notation for a in self.in_scope_assets]

    def all_out_of_scope_cidrs(self) -> list[str]:
        return [a.cidr_notation for a in self.out_of_scope_assets]

    def tester_source_ips(self) -> list[str]:
        ips = []
        for c in self.contacts:
            ips.extend(c.authorized_source_ips)
        return list(set(ips))
