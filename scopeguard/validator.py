"""
scopeguard.validator
~~~~~~~~~~~~~~~~~~~~
Validation engine — Layer 2.
Operates on a complete Engagement data object produced by Layer 1.
Performs both field-level (VAL-*) and cross-reference (XRF-*) validation.
Produces a FindingList. Never touches the input form directly.

Rule IDs and severity levels match the specification exactly.
"""

from __future__ import annotations
import ipaddress
import re
from datetime import date, datetime, timezone
from typing import Optional

from .models import (
    Engagement, EngagementType, DocumentStatus, AuthorizationStatus,
    DeliveryMethod, EncryptionStandard, UsbPayloadType, NetworkAsset,
    OutOfScopeAsset, Technique
)
from .finding import Finding, FindingList, Severity

# RFC 5322-ish email pattern (practical, not exhaustive)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

# Vague condition phrases to reject
_VAGUE_PHRASES = [
    "only if necessary",
    "if absolutely necessary",
    "if needed",
    "at discretion",
    "as appropriate",
    "if required",
    "when needed",
]


def _is_vague(text: str) -> bool:
    low = text.lower()
    return any(phrase in low for phrase in _VAGUE_PHRASES)


def _valid_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _valid_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return _valid_cidr(value)


def _cidr_and_mask_agree(cidr: str, mask: str) -> bool:
    """Return True if the CIDR prefix and subnet mask describe the same network."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return str(net.netmask) == mask
    except ValueError:
        return False  # invalid CIDR — caught by VAL-001


def _cidr_is_subnet_of(child: str, parent: str) -> bool:
    """Return True if child network is a subnet of (or equal to) parent network."""
    try:
        c = ipaddress.ip_network(child, strict=False)
        p = ipaddress.ip_network(parent, strict=False)
        return c.subnet_of(p)
    except (ValueError, TypeError):
        return False


def _same_supernet_16(cidr_a: str, cidr_b: str) -> bool:
    """Return True if both CIDRs share a /16 or larger supernet."""
    try:
        a = ipaddress.ip_network(cidr_a, strict=False)
        b = ipaddress.ip_network(cidr_b, strict=False)
        return a.supernet(new_prefix=16) == b.supernet(new_prefix=16)
    except (ValueError, TypeError):
        return False


def _valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email))


def _looks_like_pem_public_key(value: str) -> bool:
    v = (value or "").strip()
    return (
        "-----BEGIN PUBLIC KEY-----" in v
        and "-----END PUBLIC KEY-----" in v
    )


def _looks_like_detached_signature(value: str) -> bool:
    v = (value or "").strip()
    if not v:
        return False
    # Accept hex signatures (e.g. raw ECDSA/EdDSA output encoded as hex)
    if len(v) >= 64 and len(v) % 2 == 0 and _HEX_RE.fullmatch(v):
        return True
    # Accept base64 signatures (typical detached signature transport)
    if len(v) >= 32 and _B64_RE.fullmatch(v):
        return True
    return False


def _within_period(d: date, start: datetime, end: datetime) -> bool:
    start_date = start.date() if isinstance(start, datetime) else start
    end_date = end.date() if isinstance(end, datetime) else end
    return start_date <= d <= end_date


class Validator:
    """
    Runs all VAL and XRF rules against a complete Engagement object.
    Call validate() to get a FindingList.
    """

    def __init__(self, engagement: Engagement) -> None:
        self.e = engagement
        self.findings = FindingList()

    def validate(self) -> FindingList:
        self._run_val_rules()
        self._run_xrf_rules()
        return self.findings

    def _add(self, rule_id: str, severity: Severity, description: str,
             resolution: str, field_path: Optional[str] = None,
             related_fields: Optional[list[str]] = None) -> None:
        self.findings.add(Finding(
            rule_id=rule_id,
            severity=severity,
            description=description,
            resolution=resolution,
            field_path=field_path,
            related_fields=related_fields or [],
        ))

    # ──────────────────────────────────────────────────────────────────────────
    # Field-level validation rules (VAL-001 through VAL-020)
    # ──────────────────────────────────────────────────────────────────────────

    def _run_val_rules(self) -> None:
        self._val_network_assets()
        self._val_dates()
        self._val_contacts()
        self._val_techniques()
        self._val_data_governance()
        self._val_social_engineering()
        self._val_document_status()
        self._val_assets_delivery()
        self._val_physical_locations()

    def _val_network_assets(self) -> None:
        all_assets: list[NetworkAsset] = (
            list(self.e.in_scope_assets) + list(self.e.out_of_scope_assets)
        )
        for asset in all_assets:
            scope = "in_scope" if asset in self.e.in_scope_assets else "out_of_scope"
            prefix = f"{scope}_assets[{asset.asset_name}]"

            # VAL-001: CIDR notation validity
            if not _valid_cidr(asset.cidr_notation):
                self._add(
                    "VAL-001", Severity.BLOCK,
                    f"'{asset.cidr_notation}' is not a valid CIDR network address.",
                    "Correct the CIDR notation. Python ipaddress.ip_network() is used for validation.",
                    field_path=f"{prefix}.cidr_notation",
                )

            # VAL-002: CIDR and subnet mask agreement
            elif not _cidr_and_mask_agree(asset.cidr_notation, asset.subnet_mask):
                self._add(
                    "VAL-002", Severity.BLOCK,
                    f"Subnet mask '{asset.subnet_mask}' does not agree with "
                    f"CIDR prefix '{asset.cidr_notation}'.",
                    "Provide either the correct subnet mask or the correct CIDR — "
                    "both must describe the same network.",
                    field_path=f"{prefix}.subnet_mask",
                    related_fields=[f"{prefix}.cidr_notation"],
                )

            # VAL-003: VLAN count consistency
            if (asset.vlan_count_stated is not None and
                    asset.vlan_count_computed() is not None):
                if asset.vlan_count_stated != asset.vlan_count_computed():
                    self._add(
                        "VAL-003", Severity.BLOCK,
                        f"Stated VLAN count ({asset.vlan_count_stated}) does not match "
                        f"computed count from range "
                        f"({asset.vlan_range_start}–{asset.vlan_range_end} = "
                        f"{asset.vlan_count_computed()}).",
                        "Correct either the VLAN range endpoints or the stated count.",
                        field_path=f"{prefix}.vlan_count_stated",
                        related_fields=[
                            f"{prefix}.vlan_range_start",
                            f"{prefix}.vlan_range_end",
                        ],
                    )

    def _val_dates(self) -> None:
        p = self.e.period
        ident = self.e.identity

        # VAL-004: end date after start date
        if p.authorized_end_date <= p.authorized_start_date:
            self._add(
                "VAL-004", Severity.BLOCK,
                "authorized_end_date is not after authorized_start_date.",
                "End date must be after start date.",
                field_path="period.authorized_end_date",
                related_fields=["period.authorized_start_date"],
            )

        # VAL-005: testing hours end after start
        # Comparison done as string HH:MM for simplicity; full impl parses timezone-aware times
        if p.active_testing_hours_end <= p.active_testing_hours_start:
            self._add(
                "VAL-005", Severity.BLOCK,
                "active_testing_hours_end is not after active_testing_hours_start.",
                "End time must be after start time.",
                field_path="period.active_testing_hours_end",
                related_fields=["period.active_testing_hours_start"],
            )

        # VAL-006: final report after draft
        if p.report_final_due <= p.report_draft_due:
            self._add(
                "VAL-006", Severity.BLOCK,
                "report_final_due is not after report_draft_due.",
                "Final report must be due after the draft.",
                field_path="period.report_final_due",
                related_fields=["period.report_draft_due"],
            )

        # XRF-007 (date cross-reference): retest window before end date
        if p.retest_window_start is not None:
            end_date = (p.authorized_end_date.date()
                        if isinstance(p.authorized_end_date, datetime)
                        else p.authorized_end_date)
            if p.retest_window_start <= end_date:
                self._add(
                    "XRF-007", Severity.BLOCK,
                    "retest_window_start is not after authorized_end_date.",
                    "The retest window must begin after the primary engagement ends.",
                    field_path="period.retest_window_start",
                    related_fields=["period.authorized_end_date"],
                )

        # XRF-008: blackout dates within engagement period
        for bd in p.blackout_dates:
            if not _within_period(bd.date, p.authorized_start_date, p.authorized_end_date):
                self._add(
                    "XRF-008", Severity.BLOCK,
                    f"Blackout date {bd.date} falls outside the engagement period "
                    f"({p.authorized_start_date.date()} – {p.authorized_end_date.date()}).",
                    "Blackout dates must be within the authorized engagement period.",
                    field_path="period.blackout_dates",
                )

    def _val_contacts(self) -> None:
        for contact in self.e.contacts:
            path = f"contacts[{contact.role}:{contact.full_name}]"

            # VAL-022: full_name must not be an IP address or CIDR
            if _valid_ip_or_cidr((contact.full_name or "").strip()):
                self._add(
                    "VAL-022", Severity.BLOCK,
                    f"Contact full_name '{contact.full_name}' (role: {contact.role}) "
                    f"appears to be an IP address or CIDR, not a person's name.",
                    "Enter the person's full legal name in the full_name field. "
                    "Tester source IP addresses must be entered in the "
                    "authorized_source_ips field on the engagement_lead or team_member contact record.",
                    field_path=f"{path}.full_name",
                )

            # VAL-007: tester source IP validity
            for ip in contact.authorized_source_ips:
                if not _valid_ip_or_cidr(ip):
                    self._add(
                        "VAL-007", Severity.BLOCK,
                        f"Tester source IP '{ip}' (contact: {contact.full_name}) "
                        f"is not a valid IP address or CIDR.",
                        "Provide a valid IPv4 or IPv6 address or CIDR range.",
                        field_path=f"{path}.authorized_source_ips",
                    )

            # VAL-008: email format
            if not _valid_email(contact.email):
                self._add(
                    "VAL-008", Severity.BLOCK,
                    f"Email '{contact.email}' (contact: {contact.full_name}) "
                    f"does not match RFC 5322 format.",
                    "Provide a valid email address.",
                    field_path=f"{path}.email",
                )

        # VAL-015: required contact roles present
        self._check_required_roles()

    def _check_required_roles(self) -> None:
        et = self.e.identity.engagement_type
        present_roles = {c.role for c in self.e.contacts}

        always_required = [
            "authorizing_executive",
            "primary_technical_contact",
            "emergency_halt_authority",
            "engagement_lead",
        ]
        full_scope_required = [
            "business_continuity_contact",
            "soc_duty_contact",
        ]
        physical_required = ["physical_security_manager"]
        se_required = ["legal_counsel"]

        for role in always_required:
            if role not in present_roles:
                self._add(
                    "VAL-015", Severity.MISSING,
                    f"Required contact role '{role}' has no entry.",
                    f"Provide contact information for the {role} role.",
                    field_path=f"contacts[{role}]",
                )

        if et in (EngagementType.FULL_SCOPE, EngagementType.RED_TEAM):
            for role in full_scope_required:
                if role not in present_roles:
                    self._add(
                        "VAL-015", Severity.MISSING,
                        f"Required contact role '{role}' has no entry "
                        f"(required for {et.value} engagements).",
                        f"Provide contact information for the {role} role.",
                        field_path=f"contacts[{role}]",
                    )

        if self.e.physical_locations:
            for role in physical_required:
                if role not in present_roles:
                    self._add(
                        "VAL-015", Severity.MISSING,
                        f"Physical locations are in scope but required contact role "
                        f"'{role}' has no entry.",
                        f"Provide contact information for the {role} role.",
                        field_path=f"contacts[{role}]",
                    )

        if self.e.social_engineering is not None:
            for role in se_required:
                if role not in present_roles:
                    self._add(
                        "VAL-015", Severity.MISSING,
                        f"Social engineering is in scope but required contact role "
                        f"'{role}' has no entry.",
                        f"Provide contact information for the {role} role.",
                        field_path=f"contacts[{role}]",
                    )

    def _val_techniques(self) -> None:
        for tech in self.e.techniques:
            path = f"techniques[{tech.technique_id}]"

            # VAL-009: conditional techniques must have approval_workflow
            if tech.authorization_status == AuthorizationStatus.CONDITIONAL:
                if not tech.approval_workflow:
                    self._add(
                        "VAL-009", Severity.BLOCK,
                        f"Technique '{tech.technique_name}' ({tech.technique_id}) is "
                        f"CONDITIONAL but has no approval_workflow defined.",
                        "Define who approves, by what method, and how it is documented. "
                        "Vague language ('if necessary') is not accepted.",
                        field_path=f"{path}.approval_workflow",
                    )
                if tech.conditions and _is_vague(tech.conditions):
                    self._add(
                        "VAL-009", Severity.BLOCK,
                        f"Technique '{tech.technique_name}' ({tech.technique_id}) has "
                        f"vague condition text: '{tech.conditions}'.",
                        "Conditions must be specific and actionable. Replace with "
                        "explicit, unambiguous language.",
                        field_path=f"{path}.conditions",
                    )

            # VAL-010: maintenance-window-required technique must reference a window
            if tech.maintenance_window_required:
                window_ref = tech.maintenance_window_ref
                has_window = bool(window_ref) and any(
                    mw.window_id == window_ref for mw in self.e.maintenance_windows
                )
                if not has_window:
                    self._add(
                        "VAL-010", Severity.BLOCK,
                        f"Technique '{tech.technique_name}' ({tech.technique_id}) requires "
                        f"a maintenance window but no valid window is referenced.",
                        "Define at least one maintenance window and reference it before authorizing this technique.",
                        field_path=f"{path}.maintenance_window_ref",
                    )

    def _val_data_governance(self) -> None:
        dg = self.e.data_governance
        if dg is None:
            return

        # VAL-011: credential reporting window
        if dg.credential_reporting_window_hours > 4:
            self._add(
                "VAL-011", Severity.BLOCK,
                f"credential_reporting_window_hours is {dg.credential_reporting_window_hours}; "
                f"industry standard maximum is 4 hours.",
                "Reduce to 4 hours or fewer. If a longer window is required, "
                "obtain explicit client agreement in writing and document the justification.",
                field_path="data_governance.credential_reporting_window_hours",
            )

        # VAL-012: third-party disclosure prohibition
        if not dg.third_party_disclosure_prohibited:
            self._add(
                "VAL-012", Severity.BLOCK,
                "third_party_disclosure_prohibited is false.",
                "This field must be true. Third-party disclosure prohibition is a "
                "non-negotiable requirement.",
                field_path="data_governance.third_party_disclosure_prohibited",
            )

    def _val_social_engineering(self) -> None:
        se = self.e.social_engineering
        if se is None:
            return

        # VAL-013: executable USB payload requires written authorization
        if (se.usb_payload_type == UsbPayloadType.EXECUTABLE and
                not se.usb_executable_authorization):
            self._add(
                "VAL-013", Severity.BLOCK,
                "USB payload type is 'executable' but no separate written authorization "
                "reference is provided.",
                "Executable payloads require a separate authorization field with "
                "client signature.",
                field_path="social_engineering.usb_executable_authorization",
            )

        # VAL-018: excluded_se_targets must be explicitly set
        if se.excluded_se_targets is None:
            self._add(
                "VAL-018", Severity.MISSING,
                "excluded_se_targets is absent — no explicit decision about SE target "
                "exclusions has been recorded.",
                "Explicitly define who is excluded from social engineering. "
                "An empty list is valid but must be deliberately set.",
                field_path="social_engineering.excluded_se_targets",
            )

        # VAL-019: when phishing is authorized, demand all required phishing fields
        if se.phishing_authorized:
            if se.phishing_target_departments and not se.phishing_target_list_due_date:
                self._add(
                    "VAL-019", Severity.MISSING,
                    "Phishing target departments are defined but the target list delivery date is missing.",
                    "Enter the date the client will deliver the phishing target list. "
                    "This is required before testing can proceed once phishing targets are specified.",
                    field_path="social_engineering.phishing_target_list_due_date",
                )
            if se.phishing_target_departments is not None and not se.phishing_target_departments:
                self._add(
                    "VAL-019b", Severity.MISSING,
                    "Phishing is authorized — target departments must be specified.",
                    "List the departments or groups that are in scope for phishing simulation.",
                    field_path="social_engineering.phishing_target_departments",
                )

        # VAL-019c: vishing required fields
        if se.vishing_authorized and not se.vishing_targets:
            self._add(
                "VAL-019c", Severity.MISSING,
                "Vishing is authorized — target scope must be specified.",
                "Describe who may be called (e.g. 'Inbound call center only', 'Helpdesk extension 1000-1099').",
                field_path="social_engineering.vishing_targets",
            )

        # VAL-019d: impersonation required fields
        if se.impersonation_authorized and not se.approved_pretexts:
            self._add(
                "VAL-019d", Severity.MISSING,
                "Impersonation is authorized — approved pretexts must be defined.",
                "List the specific scenarios the testing team is authorized to use "
                "(e.g. 'IT support technician', 'HVAC contractor').",
                field_path="social_engineering.approved_pretexts",
            )

        # VAL-019e: USB drop required fields
        if se.usb_drop_authorized and not se.usb_payload_type:
            self._add(
                "VAL-019e", Severity.MISSING,
                "USB drop is authorized — payload type must be specified.",
                "Select the payload type: inert/tracking only, macro-enabled document, or executable.",
                field_path="social_engineering.usb_payload_type",
            )

    def _val_document_status(self) -> None:
        # VAL-014: executed status requires all signature fields
        if self.e.identity.document_status == DocumentStatus.EXECUTED:
            if (
                not self.e.identity.all_signatures_present()
                or not self.e.identity.all_cryptographic_signatures_present()
            ):
                self._add(
                    "VAL-014", Severity.BLOCK,
                    "document_status is 'executed' but one or more required human "
                    "or cryptographic signatures are missing.",
                    "All required signatory names/dates and signer cryptographic "
                    "signature + public-key fields must be populated before status can "
                    "be set to 'executed'.",
                    field_path="identity.document_status",
                )
            else:
                identity = self.e.identity
                crypto_fields = [
                    ("identity.client_signatory_signature", identity.client_signatory_signature, "signature"),
                    ("identity.client_signatory_public_key", identity.client_signatory_public_key, "public_key"),
                    ("identity.tester_lead_signatory_signature", identity.tester_lead_signatory_signature, "signature"),
                    ("identity.tester_lead_signatory_public_key", identity.tester_lead_signatory_public_key, "public_key"),
                    ("identity.tester_principal_signatory_signature", identity.tester_principal_signatory_signature, "signature"),
                    ("identity.tester_principal_signatory_public_key", identity.tester_principal_signatory_public_key, "public_key"),
                    ("identity.document_creator_signature", identity.document_creator_signature, "signature"),
                    ("identity.document_creator_public_key", identity.document_creator_public_key, "public_key"),
                ]
                for field_path, value, ftype in crypto_fields:
                    if ftype == "public_key":
                        ok = _looks_like_pem_public_key(value or "")
                        expected = "PEM-formatted public key"
                    else:
                        ok = _looks_like_detached_signature(value or "")
                        expected = "detached signature (hex or base64)"
                    if not ok:
                        self._add(
                            "VAL-014", Severity.BLOCK,
                            f"{field_path} is not a valid {expected}.",
                            "Provide a cryptographically valid signer artifact in the expected format.",
                            field_path=field_path,
                        )

    def _val_assets_delivery(self) -> None:
        # VAL-016: client-provisioned asset with no confirmed delivery
        for asset in self.e.in_scope_assets:
            if asset.delivery_method == DeliveryMethod.CLIENT_PROVISIONED:
                if not asset.delivery_confirmed:
                    self._add(
                        "VAL-016", Severity.MISSING,
                        f"In-scope asset '{asset.asset_name}' is client-provisioned "
                        f"but has no confirmed delivery date or address.",
                        "Asset cannot be tested until client confirms delivery with "
                        "IP address or hostname.",
                        field_path=f"in_scope_assets[{asset.asset_name}].delivery_confirmed",
                    )

    def _val_physical_locations(self) -> None:
        et = self.e.identity.engagement_type

        # VAL-017: physical testing in scope but no locations defined
        if et.includes_physical() and not self.e.physical_locations:
            self._add(
                "VAL-017", Severity.MISSING,
                f"Engagement type '{et.value}' includes physical testing but "
                f"no physical locations are defined.",
                "Define at least one authorized physical location.",
                field_path="physical_locations",
            )

        # VAL-020: maintenance windows with no authorized activities
        for mw in self.e.maintenance_windows:
            if not mw.authorized_activity_refs:
                self._add(
                    "VAL-020", Severity.MISSING,
                    f"Maintenance window {mw.window_id} has no authorized activities.",
                    "Each maintenance window must reference at least one technique "
                    "that requires it.",
                    field_path=f"maintenance_windows[{mw.window_id}].authorized_activity_refs",
                )

        # VAL-021: physical location sub-fields required when parent fields are set
        for loc in self.e.physical_locations:
            loc_name = getattr(loc, 'location_name', 'unknown')
            path = f"physical_locations[{loc_name}]"

            if getattr(loc, 'pre_notification_required', False):
                if not getattr(loc, 'pre_notification_hours', None):
                    self._add(
                        "VAL-021", Severity.MISSING,
                        f"Location '{loc_name}' requires pre-notification "
                        f"but lead time hours are not specified.",
                        "Enter the required advance notice period in hours — this is "
                        "needed for the Physical Security Manager notification protocol.",
                        field_path=f"{path}.pre_notification_hours",
                    )
                if not getattr(loc, 'pre_notification_contact_ref', None):
                    self._add(
                        "VAL-021b", Severity.MISSING,
                        f"Location '{loc_name}' requires pre-notification "
                        f"but the notification contact role is not specified.",
                        "Enter the contact role who must receive advance notice "
                        "(typically physical_security_manager).",
                        field_path=f"{path}.pre_notification_contact",
                    )

            if getattr(loc, 'facility_third_party', False):
                if not getattr(loc, 'facility_security_contact', None):
                    self._add(
                        "VAL-021c", Severity.MISSING,
                        f"Location '{loc_name}' is third-party operated but "
                        f"facility security contact is not defined.",
                        "Provide the name/contact of the facility's security point of "
                        "contact. Required before physical testing at this location.",
                        field_path=f"{path}.facility_security_contact",
                    )

    # ──────────────────────────────────────────────────────────────────────────
    # Cross-reference validation rules (XRF-001 through XRF-016)
    # ──────────────────────────────────────────────────────────────────────────

    def _run_xrf_rules(self) -> None:
        self._xrf_cidr_overlap()
        self._xrf_technique_references()
        self._xrf_notification_references()
        self._xrf_physical_contacts()
        self._xrf_se_contacts()
        self._xrf_facility_notification()
        self._xrf_tester_ips_for_network_techniques()
        self._xrf_regulatory_notes()

    def _xrf_cidr_overlap(self) -> None:
        in_cidrs = self.e.all_in_scope_cidrs()
        out_cidrs = self.e.all_out_of_scope_cidrs()

        # XRF-001: same CIDR in both lists
        overlap = set(in_cidrs) & set(out_cidrs)
        for cidr in overlap:
            self._add(
                "XRF-001", Severity.BLOCK,
                f"CIDR '{cidr}' appears in both the in-scope and out-of-scope asset lists.",
                "Remove the address from one list or explicitly document the overlap "
                "with a written resolution.",
                field_path="in_scope_assets / out_of_scope_assets",
            )

        # XRF-002: in-scope CIDR is subnet of an out-of-scope CIDR
        for in_cidr in in_cidrs:
            for out_cidr in out_cidrs:
                if in_cidr != out_cidr and _cidr_is_subnet_of(in_cidr, out_cidr):
                    self._add(
                        "XRF-002", Severity.BLOCK,
                        f"In-scope CIDR '{in_cidr}' is a subnet of out-of-scope "
                        f"CIDR '{out_cidr}'. This creates an implicit conflict.",
                        "The more specific range should be explicitly listed in the "
                        "in-scope list with a note that it is carved out of the exclusion.",
                        related_fields=[in_cidr, out_cidr],
                    )

        # XRF-003: out-of-scope CIDR is subnet of an in-scope CIDR
        for out_cidr in out_cidrs:
            for in_cidr in in_cidrs:
                if out_cidr != in_cidr and _cidr_is_subnet_of(out_cidr, in_cidr):
                    self._add(
                        "XRF-003", Severity.BLOCK,
                        f"Out-of-scope CIDR '{out_cidr}' is a subnet of in-scope "
                        f"CIDR '{in_cidr}'.",
                        "Confirm whether the subnet is intentionally excluded. "
                        "If so, document it explicitly as a carve-out.",
                        related_fields=[out_cidr, in_cidr],
                    )

        # XRF-013: NOTE — overlapping /16 supernets between in-scope and out-of-scope
        noted_pairs: set[tuple[str, str]] = set()
        for in_cidr in in_cidrs:
            for out_cidr in out_cidrs:
                pair = tuple(sorted([in_cidr, out_cidr]))
                if pair not in noted_pairs and _same_supernet_16(in_cidr, out_cidr):
                    # Only note if not already flagged as a BLOCK above
                    if not (_cidr_is_subnet_of(in_cidr, out_cidr) or
                            _cidr_is_subnet_of(out_cidr, in_cidr) or
                            in_cidr == out_cidr):
                        self._add(
                            "XRF-013", Severity.NOTE,
                            f"In-scope CIDR '{in_cidr}' and out-of-scope CIDR "
                            f"'{out_cidr}' share the same /16 supernet.",
                            "Confirm that network isolation between these segments is "
                            "sufficient to prevent accidental contact.",
                            related_fields=[in_cidr, out_cidr],
                        )
                        noted_pairs.add(pair)  # type: ignore[arg-type]

    def _xrf_technique_references(self) -> None:
        window_ids = {mw.window_id for mw in self.e.maintenance_windows}

        for tech in self.e.techniques:
            path = f"techniques[{tech.technique_id}]"

            # XRF-004: technique references non-existent maintenance window
            if tech.maintenance_window_ref and tech.maintenance_window_ref not in window_ids:
                self._add(
                    "XRF-004", Severity.BLOCK,
                    f"Technique '{tech.technique_name}' ({tech.technique_id}) references "
                    f"maintenance window '{tech.maintenance_window_ref}' which does not exist.",
                    "Create the referenced maintenance window before authorizing this technique.",
                    field_path=f"{path}.maintenance_window_ref",
                )

        # XRF-005: maintenance window dates outside engagement period
        # When retest is included, windows may fall within the retest window too
        for mw in self.e.maintenance_windows:
            p = self.e.period
            end = p.authorized_end_date
            if p.retest_included and p.retest_window_end:
                # Convert retest_window_end (date) to a comparable datetime
                retest_end_dt = datetime.combine(p.retest_window_end,
                                                  datetime.max.time())
                if isinstance(end, datetime):
                    from datetime import timezone
                    # Use the later of engagement end and retest window end
                    retest_end_aware = retest_end_dt.replace(tzinfo=end.tzinfo)
                    effective_end = max(end, retest_end_aware)
                else:
                    effective_end = p.retest_window_end
            else:
                effective_end = end

            if not _within_period(mw.date, p.authorized_start_date, effective_end):
                self._add(
                    "XRF-005", Severity.BLOCK,
                    f"Maintenance window {mw.window_id} date ({mw.date}) falls outside "
                    f"the authorized engagement period.",
                    "Maintenance windows must fall within the engagement start and end dates.",
                    field_path=f"maintenance_windows[{mw.window_id}].date",
                )

    def _xrf_notification_references(self) -> None:
        contact_roles = {c.role for c in self.e.contacts}

        # XRF-006: notification_recipient references non-existent contact
        for tech in self.e.techniques:
            if (tech.notification_required and tech.notification_recipient_ref and
                    tech.notification_recipient_ref not in contact_roles):
                self._add(
                    "XRF-006", Severity.BLOCK,
                    f"Technique '{tech.technique_name}' notification_recipient "
                    f"'{tech.notification_recipient_ref}' does not match any defined contact role.",
                    "The referenced contact must be defined in the contacts section.",
                    field_path=f"techniques[{tech.technique_id}].notification_recipient_ref",
                )

        # XRF-012: notification_required technique with no lead time
        for tech in self.e.techniques:
            if tech.notification_required and tech.notification_lead_time_hours is None:
                self._add(
                    "XRF-012", Severity.CLARIFY,
                    f"Technique '{tech.technique_name}' ({tech.technique_id}) requires "
                    f"notification but no notification_lead_time_hours is defined.",
                    "Define how much advance notice is required for this technique.",
                    field_path=f"techniques[{tech.technique_id}].notification_lead_time_hours",
                )

    def _xrf_physical_contacts(self) -> None:
        contact_roles = {c.role for c in self.e.contacts}

        # XRF-009: physical location in scope but no physical_security_manager contact
        if self.e.physical_locations and "physical_security_manager" not in contact_roles:
            self._add(
                "XRF-009", Severity.CLARIFY,
                "Physical locations are in scope but physical_security_manager contact "
                "is not defined.",
                "Define the physical security manager contact — required for "
                "pre-notification of physical testing.",
                field_path="contacts[physical_security_manager]",
            )

    def _xrf_se_contacts(self) -> None:
        if self.e.social_engineering is None:
            return
        contact_roles = {c.role for c in self.e.contacts}

        # XRF-010: SE in scope but no legal_counsel contact
        if "legal_counsel" not in contact_roles:
            self._add(
                "XRF-010", Severity.CLARIFY,
                "Social engineering is in scope but Attorney of Record contact is not defined.",
                "An Attorney of Record is required when social engineering pretexts require legal approval.",
                field_path="contacts[legal_counsel]",
            )

    def _xrf_facility_notification(self) -> None:
        # XRF-011: third-party facility not notified
        for loc in self.e.physical_locations:
            if loc.facility_third_party and loc.facility_notified is False:
                self._add(
                    "XRF-011", Severity.CLARIFY,
                    f"Physical location '{loc.location_name}' is a third-party facility "
                    f"but facility_notified is false.",
                    "The third-party facility operator must be notified before testing. "
                    "Confirm notification and date.",
                    field_path=f"physical_locations[{loc.location_name}].facility_notified",
                )

    def _xrf_tester_ips_for_network_techniques(self) -> None:
        # XRF-014: network testing authorized but no tester source IPs defined
        has_network_techniques = any(
            t.authorization_status != "not_authorized"
            for t in self.e.techniques
            if t.category.value in ("reconnaissance", "vuln_scanning", "exploitation",
                                    "post_exploitation", "dos")
        )
        if has_network_techniques and not self.e.tester_source_ips():
            self._add(
                "XRF-014", Severity.NOTE,
                "Network testing techniques are authorized but no tester source IPs "
                "are defined in any contact record.",
                "Define authorized source IP addresses so the client SOC can whitelist "
                "testing traffic.",
                field_path="contacts[*].authorized_source_ips",
            )

    def _xrf_regulatory_notes(self) -> None:
        reg = self.e.identity.regulatory_basis
        identity_path = "identity.regulatory_basis"

        # XRF-015: potential HIPAA exposure not addressed
        # Triggered for healthcare-adjacent clients (heuristic: if GLBA present,
        # check whether HIPAA is also present — bank with health-related services)
        # Full implementation would check client industry; here we flag if
        # HIPAA is absent and engagement type could reach sensitive systems
        if (self.e.identity.engagement_type in
                (EngagementType.FULL_SCOPE, EngagementType.RED_TEAM) and
                "HIPAA" not in [r.value for r in reg]):
            self._add(
                "XRF-015", Severity.NOTE,
                "Full-scope engagement does not list HIPAA in regulatory_basis.",
                "If any in-scope system may contain protected health information, "
                "HIPAA must be addressed explicitly.",
                field_path=identity_path,
            )

        # XRF-016: PCI-DSS listed but no CDE assets identified or excluded.
        # Only fire when the user has actually started defining assets — if
        # neither the in-scope nor out-of-scope section has any entries yet,
        # the asset sections haven't been filled and this check is premature.
        if "PCI-DSS" in [r.value for r in reg]:
            has_any_assets = self.e.in_scope_assets or self.e.out_of_scope_assets
            if has_any_assets:
                cde_keywords = {"card", "cardholder", "pci", "cde", "payment", "processing"}

                def _has_cde(assets):
                    for a in assets:
                        text = ((a.asset_name or "") + " " +
                                (getattr(a, "description", "") or "")).lower()
                        if any(kw in text for kw in cde_keywords):
                            return True
                    return False

                if not _has_cde(self.e.in_scope_assets) and not _has_cde(self.e.out_of_scope_assets):
                    self._add(
                        "XRF-016", Severity.NOTE,
                        "PCI-DSS is listed in regulatory_basis but no cardholder data "
                        "environment (CDE) assets are identified or explicitly excluded.",
                        "Add CDE assets to the in-scope or out-of-scope asset list, or note "
                        "'CDE' / 'PCI' in an asset name or description to confirm scope is addressed.",
                        field_path=identity_path,
                    )
