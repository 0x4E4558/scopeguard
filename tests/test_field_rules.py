"""
tests/test_field_rules.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for field-level validation rules VAL-001 through VAL-020.

Test philosophy:
  - Each test targets exactly one rule.
  - Tests are named test_<rule_id>_<scenario>.
  - Positive tests (valid data, rule should NOT fire) verify no false positives.
  - Negative tests (invalid data, rule SHOULD fire) verify detection.
  - Fixture mutations create minimally-broken versions of the MCB engagement.
"""

import copy
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from scopeguard.validator import Validator
from scopeguard.models import (
    NetworkAsset, OutOfScopeAsset, DeliveryMethod,
    DocumentStatus, AuthorizationStatus, TechniqueCategory,
    Technique, DataGovernance, CredentialUsePolicy, EncryptionStandard,
    SocialEngineering, UsbPayloadType,
)
from scopeguard.finding import Severity
from tests.conftest import load_fixture


def validate(engagement):
    return Validator(engagement).validate()


def has_rule(findings, rule_id):
    return any(f.rule_id == rule_id for f in findings)


def count_rule(findings, rule_id):
    return sum(1 for f in findings if f.rule_id == rule_id)


# ─── VAL-001: CIDR notation validity ─────────────────────────────────────────

class TestVAL001:
    def test_valid_cidrs_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-001"), \
            "VAL-001 fired on valid MCB CIDRs"

    def test_invalid_cidr_triggers(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.in_scope_assets[0].cidr_notation = "999.999.999.999/33"
        findings = validate(eng)
        assert has_rule(findings, "VAL-001")

    def test_host_bits_set_no_trigger(self, mcb_engagement):
        """ipaddress.ip_network with strict=False accepts host bits set."""
        eng = copy.deepcopy(mcb_engagement)
        eng.in_scope_assets[0].cidr_notation = "10.10.0.1/22"  # host bit set — still valid CIDR
        findings = validate(eng)
        # VAL-001 should not fire; VAL-002 may fire since mask changes
        val001_findings = [f for f in findings if f.rule_id == "VAL-001"]
        assert not val001_findings


# ─── VAL-002: Subnet mask agrees with CIDR ───────────────────────────────────

class TestVAL002:
    def test_all_mcb_masks_agree(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-002"), \
            "VAL-002 fired on MCB engagement — all masks should agree"

    def test_nexus_mismatch_detected(self, nexus_bad_engagement):
        """The Nexus fixture has /21 with 255.255.255.0 — should detect."""
        findings = validate(nexus_bad_engagement)
        assert has_rule(findings, "VAL-002"), \
            "VAL-002 did not detect the /21 vs 255.255.255.0 mismatch in Nexus fixture"

    def test_specific_mismatch(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.in_scope_assets[0].cidr_notation = "10.10.0.0/22"
        eng.in_scope_assets[0].subnet_mask = "255.255.255.0"  # /22 → should be 255.255.252.0
        findings = validate(eng)
        assert has_rule(findings, "VAL-002")
        blocker = next(f for f in findings if f.rule_id == "VAL-002")
        assert blocker.severity == Severity.BLOCK

    def test_field_path_identifies_asset(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.in_scope_assets[0].subnet_mask = "255.255.255.0"
        findings = validate(eng)
        val002 = [f for f in findings if f.rule_id == "VAL-002"]
        assert val002
        assert "subnet_mask" in val002[0].field_path


# ─── VAL-003: VLAN count consistency ─────────────────────────────────────────

class TestVAL003:
    def test_correct_vlan_counts_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-003")

    def test_nexus_vlan_count_error_detected(self, nexus_bad_engagement):
        """Nexus fixture has range 10-12 but states 5."""
        findings = validate(nexus_bad_engagement)
        assert has_rule(findings, "VAL-003")

    def test_vlan_count_off_by_one(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        # Core Banking: range 10-13 = 4, but say 3
        asset = next(a for a in eng.in_scope_assets if "Core Banking" in a.asset_name)
        asset.vlan_count_stated = 3
        findings = validate(eng)
        assert has_rule(findings, "VAL-003")

    def test_no_vlan_count_stated_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        # If vlan_count_stated is None, VAL-003 should not fire
        asset = eng.in_scope_assets[0]
        asset.vlan_count_stated = None
        findings = validate(eng)
        assert not has_rule(findings, "VAL-003")


# ─── VAL-004: End date after start date ──────────────────────────────────────

class TestVAL004:
    def test_valid_dates_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-004")

    def test_end_before_start_detected(self, mcb_engagement):
        from datetime import datetime, timezone, timedelta
        eng = copy.deepcopy(mcb_engagement)
        eng.period.authorized_end_date = eng.period.authorized_start_date - timedelta(days=1)
        findings = validate(eng)
        assert has_rule(findings, "VAL-004")
        assert any(f.severity == Severity.BLOCK for f in findings if f.rule_id == "VAL-004")

    def test_same_start_end_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.period.authorized_end_date = eng.period.authorized_start_date
        findings = validate(eng)
        assert has_rule(findings, "VAL-004")


# ─── VAL-005: Testing hours end after start ──────────────────────────────────

class TestVAL005:
    def test_valid_hours_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-005")

    def test_end_before_start_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.period.active_testing_hours_end = "05:00 ET"
        eng.period.active_testing_hours_start = "22:00 ET"
        findings = validate(eng)
        assert has_rule(findings, "VAL-005")


# ─── VAL-006: Final report after draft ───────────────────────────────────────

class TestVAL006:
    def test_valid_report_dates_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-006")

    def test_final_before_draft_detected(self, mcb_engagement):
        from datetime import date
        eng = copy.deepcopy(mcb_engagement)
        eng.period.report_final_due = date(2026, 4, 30)
        eng.period.report_draft_due = date(2026, 5, 2)
        findings = validate(eng)
        assert has_rule(findings, "VAL-006")


# ─── VAL-007: Tester source IP validity ──────────────────────────────────────

class TestVAL007:
    def test_valid_ips_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-007")

    def test_invalid_ip_detected(self, nexus_bad_engagement):
        findings = validate(nexus_bad_engagement)
        assert has_rule(findings, "VAL-007")

    def test_valid_cidr_range_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.contacts[7].authorized_source_ips = ["198.51.100.0/24"]
        findings = validate(eng)
        assert not has_rule(findings, "VAL-007")

    def test_hostname_rejected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.contacts[7].authorized_source_ips = ["attacker.example.com"]
        findings = validate(eng)
        assert has_rule(findings, "VAL-007")


# ─── VAL-008: Email format ────────────────────────────────────────────────────

class TestVAL008:
    def test_valid_emails_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-008")

    def test_invalid_email_detected(self, nexus_bad_engagement):
        findings = validate(nexus_bad_engagement)
        assert has_rule(findings, "VAL-008")

    def test_missing_at_sign_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.contacts[0].email = "noatsign.example.com"
        findings = validate(eng)
        assert has_rule(findings, "VAL-008")


# ─── VAL-009: Conditional permission must have non-vague approval workflow ───

class TestVAL009:
    def test_valid_conditional_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-009"), \
            "VAL-009 fired on MCB conditional techniques — all should have workflows"

    def test_vague_condition_detected(self, nexus_bad_engagement):
        findings = validate(nexus_bad_engagement)
        assert has_rule(findings, "VAL-009")

    def test_missing_workflow_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        t = next(t for t in eng.techniques if t.authorization_status == AuthorizationStatus.CONDITIONAL)
        t.approval_workflow = None
        findings = validate(eng)
        assert has_rule(findings, "VAL-009")

    def test_vague_phrases_detected(self, mcb_engagement):
        vague_phrases = [
            "only if necessary",
            "if absolutely necessary",
            "at discretion",
            "as appropriate",
        ]
        for phrase in vague_phrases:
            eng = copy.deepcopy(mcb_engagement)
            t = next(t for t in eng.techniques
                     if t.authorization_status == AuthorizationStatus.CONDITIONAL)
            t.conditions = f"Allowed {phrase}."
            findings = validate(eng)
            assert has_rule(findings, "VAL-009"), \
                f"Vague phrase '{phrase}' was not detected"


# ─── VAL-010: Maintenance-window-required technique needs a window defined ───

class TestVAL010:
    def test_valid_technique_with_window_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-010")

    def test_nexus_missing_window_detected(self, nexus_bad_engagement):
        findings = validate(nexus_bad_engagement)
        assert has_rule(findings, "VAL-010")

    def test_window_required_but_not_referenced(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        # Add a technique that requires a window but has no ref
        eng.techniques.append(Technique(
            technique_id="TECH-DOS-999",
            category=TechniqueCategory.DOS,
            technique_name="Test DoS technique",
            authorization_status=AuthorizationStatus.CONDITIONAL,
            conditions="Only during defined maintenance window with 1-hour notice to Client.",
            approval_workflow="Client Technical Contact confirms via email before window starts.",
            maintenance_window_required=True,
            maintenance_window_ref=None,
            notification_required=True,
            notification_lead_time_hours=1,
            notification_recipient_ref="primary_technical_contact",
            prohibited=False,
        ))
        findings = validate(eng)
        assert has_rule(findings, "VAL-010")


# ─── VAL-011: Credential reporting window ≤ 4 hours ─────────────────────────

class TestVAL011:
    def test_valid_4_hour_window_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-011")

    def test_nexus_8_hour_window_detected(self, nexus_bad_engagement):
        findings = validate(nexus_bad_engagement)
        assert has_rule(findings, "VAL-011")

    def test_exactly_4_hours_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.data_governance.credential_reporting_window_hours = 4
        findings = validate(eng)
        assert not has_rule(findings, "VAL-011")

    def test_5_hours_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.data_governance.credential_reporting_window_hours = 5
        findings = validate(eng)
        assert has_rule(findings, "VAL-011")


# ─── VAL-012: third_party_disclosure_prohibited must be true ─────────────────

class TestVAL012:
    def test_true_value_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-012")

    def test_nexus_false_value_detected(self, nexus_bad_engagement):
        findings = validate(nexus_bad_engagement)
        assert has_rule(findings, "VAL-012")
        blocker = next(f for f in findings if f.rule_id == "VAL-012")
        assert blocker.severity == Severity.BLOCK

    def test_setting_false_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.data_governance.third_party_disclosure_prohibited = False
        findings = validate(eng)
        assert has_rule(findings, "VAL-012")


# ─── VAL-013: Executable USB requires written authorization ──────────────────

class TestVAL013:
    def test_inert_payload_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-013")

    def test_executable_without_authorization_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.social_engineering.usb_payload_type = UsbPayloadType.EXECUTABLE
        eng.social_engineering.usb_executable_authorization = None
        findings = validate(eng)
        assert has_rule(findings, "VAL-013")

    def test_executable_with_authorization_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.social_engineering.usb_payload_type = UsbPayloadType.EXECUTABLE
        eng.social_engineering.usb_executable_authorization = "Written authorization signed by CISO on 2026-04-01"
        findings = validate(eng)
        assert not has_rule(findings, "VAL-013")


# ─── VAL-014: Executed status requires all signatures ────────────────────────

class TestVAL014:
    _SIG = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo9PQ=="
    _PK = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestkeymaterial\n"
        "-----END PUBLIC KEY-----"
    )

    def test_pending_status_no_trigger(self, mcb_engagement):
        """MCB is pending_signature — VAL-014 should not fire."""
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-014")

    def test_nexus_executed_without_signatures_detected(self, nexus_bad_engagement):
        """Nexus has status=executed but all signature fields are null."""
        findings = validate(nexus_bad_engagement)
        assert has_rule(findings, "VAL-014")

    def test_fully_signed_no_trigger(self, mcb_engagement):
        from datetime import date
        eng = copy.deepcopy(mcb_engagement)
        eng.identity.document_status = DocumentStatus.EXECUTED
        eng.identity.client_signatory_name = "Sandra K. Whitfield"
        eng.identity.client_signatory_date = date(2026, 4, 1)
        eng.identity.tester_lead_signatory_name = "Marcus T. Holloway"
        eng.identity.tester_lead_signatory_date = date(2026, 4, 1)
        eng.identity.tester_principal_signatory_name = "RSG Director"
        eng.identity.tester_principal_signatory_date = date(2026, 4, 1)
        eng.identity.client_signatory_signature = self._SIG
        eng.identity.client_signatory_public_key = self._PK
        eng.identity.tester_lead_signatory_signature = self._SIG
        eng.identity.tester_lead_signatory_public_key = self._PK
        eng.identity.tester_principal_signatory_signature = self._SIG
        eng.identity.tester_principal_signatory_public_key = self._PK
        eng.identity.document_creator_signature = self._SIG
        eng.identity.document_creator_public_key = self._PK
        findings = validate(eng)
        assert not has_rule(findings, "VAL-014")

    def test_bad_crypto_signature_format_detected(self, mcb_engagement):
        from datetime import date
        eng = copy.deepcopy(mcb_engagement)
        eng.identity.document_status = DocumentStatus.EXECUTED
        eng.identity.client_signatory_name = "Sandra K. Whitfield"
        eng.identity.client_signatory_date = date(2026, 4, 1)
        eng.identity.tester_lead_signatory_name = "Marcus T. Holloway"
        eng.identity.tester_lead_signatory_date = date(2026, 4, 1)
        eng.identity.tester_principal_signatory_name = "RSG Director"
        eng.identity.tester_principal_signatory_date = date(2026, 4, 1)

        eng.identity.client_signatory_signature = "not-a-valid-signature"
        eng.identity.client_signatory_public_key = self._PK
        eng.identity.tester_lead_signatory_signature = self._SIG
        eng.identity.tester_lead_signatory_public_key = self._PK
        eng.identity.tester_principal_signatory_signature = self._SIG
        eng.identity.tester_principal_signatory_public_key = self._PK
        eng.identity.document_creator_signature = self._SIG
        eng.identity.document_creator_public_key = self._PK

        findings = validate(eng)
        assert has_rule(findings, "VAL-014")


# ─── VAL-015: Required contact roles present ─────────────────────────────────

class TestVAL015:
    def test_all_required_roles_present_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-015")

    def test_missing_engagement_lead_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.contacts = [c for c in eng.contacts if c.role != "engagement_lead"]
        findings = validate(eng)
        assert has_rule(findings, "VAL-015")
        missing = [f for f in findings if f.rule_id == "VAL-015"]
        assert any("engagement_lead" in f.field_path for f in missing)

    def test_missing_authorizing_executive_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.contacts = [c for c in eng.contacts if c.role != "authorizing_executive"]
        findings = validate(eng)
        val015 = [f for f in findings if f.rule_id == "VAL-015"]
        assert any("authorizing_executive" in f.field_path for f in val015)

    def test_nexus_missing_required_roles(self, nexus_bad_engagement):
        """Nexus is missing business_continuity_contact, physical_security_manager, etc."""
        findings = validate(nexus_bad_engagement)
        val015 = [f for f in findings if f.rule_id == "VAL-015"]
        assert len(val015) >= 2


# ─── VAL-016: Client-provisioned asset delivery confirmed ────────────────────

class TestVAL016:
    def test_mcb_provisioned_assets_flagged(self, mcb_engagement):
        """MCB has three client_provisioned assets with delivery_confirmed=False."""
        findings = validate(mcb_engagement)
        val016 = [f for f in findings if f.rule_id == "VAL-016"]
        assert len(val016) == 3  # Three TBD assets in MCB fixture

    def test_confirmed_asset_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        from datetime import date
        for asset in eng.in_scope_assets:
            if asset.delivery_method == DeliveryMethod.CLIENT_PROVISIONED:
                asset.delivery_confirmed = True
                asset.delivery_confirmed_date = date(2026, 4, 4)
                asset.confirmed_address = "203.0.113.1"
        findings = validate(eng)
        assert not has_rule(findings, "VAL-016")


# ─── VAL-017: Physical testing in scope requires locations ───────────────────

class TestVAL017:
    def test_locations_defined_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-017")

    def test_full_scope_without_locations_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.physical_locations = []
        findings = validate(eng)
        assert has_rule(findings, "VAL-017")


# ─── VAL-018: excluded_se_targets must be explicitly set ─────────────────────

class TestVAL018:
    def test_explicit_exclusions_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-018")

    def test_none_exclusions_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.social_engineering.excluded_se_targets = None
        findings = validate(eng)
        assert has_rule(findings, "VAL-018")

    def test_empty_list_no_trigger(self, mcb_engagement):
        """Empty list is valid — forces deliberate decision."""
        eng = copy.deepcopy(mcb_engagement)
        eng.social_engineering.excluded_se_targets = []
        findings = validate(eng)
        assert not has_rule(findings, "VAL-018")


# ─── VAL-019: Phishing authorized but no target list delivery date ───────────

class TestVAL019:
    def test_phishing_with_delivery_date_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-019")

    def test_phishing_without_delivery_date_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.social_engineering.phishing_target_list_due_date = None
        findings = validate(eng)
        assert has_rule(findings, "VAL-019")


# ─── VAL-020: Maintenance window with no authorized activities ───────────────

class TestVAL020:
    def test_windows_with_activities_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "VAL-020")

    def test_empty_activities_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.maintenance_windows[0].authorized_activity_refs = []
        findings = validate(eng)
        assert has_rule(findings, "VAL-020")


# ─── Milestone test: MCB fixture produces zero BLOCKs ────────────────────────

class TestMilestone:
    def test_mcb_has_no_blockers(self, mcb_engagement):
        """
        Phase 1 milestone: the MCB fixture (canonical valid engagement) must
        produce zero BLOCK findings.
        """
        findings = validate(mcb_engagement)
        blockers = findings.blockers()
        if blockers:
            for f in blockers:
                print(f"\nUNEXPECTED BLOCKER: {f}")
        assert not blockers, \
            f"MCB fixture produced {len(blockers)} unexpected BLOCK finding(s)"

    def test_nexus_bad_has_multiple_blockers(self, nexus_bad_engagement):
        """
        The Nexus bad fixture must produce BLOCKs for:
        - VAL-002 (CIDR/mask mismatch)
        - VAL-003 (VLAN count error)
        - VAL-010 (missing maintenance window reference)
        - VAL-011 (credential window > 4 hours)
        - VAL-012 (third_party_disclosure not true)
        - VAL-014 (executed without signatures)
        """
        findings = validate(nexus_bad_engagement)
        expected_block_rules = ["VAL-002", "VAL-003", "VAL-010", "VAL-011", "VAL-012", "VAL-014"]
        for rule_id in expected_block_rules:
            assert has_rule(findings, rule_id), \
                f"Expected BLOCK rule {rule_id} was not detected in Nexus bad fixture"
        assert findings.has_blockers()
