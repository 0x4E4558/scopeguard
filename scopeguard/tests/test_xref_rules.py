"""
tests/test_xref_rules.py
~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for cross-reference validation rules XRF-001 through XRF-016.

These rules operate on the complete Engagement object and check relationships
between fields in different sections — the class of errors that field-level
validation cannot catch.
"""

import copy
import sys
from datetime import date, datetime, timedelta
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from scopeguard.validator import Validator
from scopeguard.models import (
    Contact, NetworkAsset, OutOfScopeAsset, PhysicalLocation,
    Technique, MaintenanceWindow, DeliveryMethod, AuthorizationStatus,
    TechniqueCategory,
)
from scopeguard.finding import Severity
from tests.conftest import load_fixture


def validate(engagement):
    return Validator(engagement).validate()


def has_rule(findings, rule_id):
    return any(f.rule_id == rule_id for f in findings)


def findings_for(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# ─── XRF-001: Same CIDR in both in-scope and out-of-scope ────────────────────

class TestXRF001:
    def test_no_overlap_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-001")

    def test_same_cidr_in_both_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        # Add 10.10.0.0/22 (already in-scope) to out-of-scope as well
        eng.out_of_scope_assets.append(OutOfScopeAsset(
            asset_name="Duplicate",
            cidr_notation="10.10.0.0/22",
            subnet_mask="255.255.252.0",
            description="Same CIDR as Core Banking Network",
            delivery_method=DeliveryMethod.NETWORK_DISCOVERABLE,
            exclusion_reason="Test duplicate",
            third_party_operated=False,
            regulatory_exclusion=False,
        ))
        findings = validate(eng)
        assert has_rule(findings, "XRF-001")
        assert findings_for(findings, "XRF-001")[0].severity == Severity.BLOCK

    def test_non_overlapping_cidrs_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.out_of_scope_assets.append(OutOfScopeAsset(
            asset_name="Unrelated",
            cidr_notation="192.0.2.0/24",
            subnet_mask="255.255.255.0",
            description="Completely separate range",
            delivery_method=DeliveryMethod.NETWORK_DISCOVERABLE,
            exclusion_reason="Not needed",
            third_party_operated=False,
            regulatory_exclusion=False,
        ))
        findings = validate(eng)
        assert not has_rule(findings, "XRF-001")


# ─── XRF-002: In-scope CIDR is subnet of out-of-scope CIDR ──────────────────

class TestXRF002:
    def test_no_subnet_relationship_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-002")

    def test_in_scope_subnet_of_out_of_scope_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        # Add 10.10.0.0/16 to out-of-scope; 10.10.0.0/22 is in-scope and is a subnet
        eng.out_of_scope_assets.append(OutOfScopeAsset(
            asset_name="Broad Exclusion",
            cidr_notation="10.10.0.0/16",
            subnet_mask="255.255.0.0",
            description="Broad network exclusion",
            delivery_method=DeliveryMethod.NETWORK_DISCOVERABLE,
            exclusion_reason="Test scenario",
            third_party_operated=False,
            regulatory_exclusion=False,
        ))
        findings = validate(eng)
        assert has_rule(findings, "XRF-002")

    def test_finding_is_block(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.out_of_scope_assets.append(OutOfScopeAsset(
            asset_name="Supernet",
            cidr_notation="10.10.0.0/8",
            subnet_mask="255.0.0.0",
            description="Supernet containing in-scope CIDRs",
            delivery_method=DeliveryMethod.NETWORK_DISCOVERABLE,
            exclusion_reason="Test",
            third_party_operated=False,
            regulatory_exclusion=False,
        ))
        findings = validate(eng)
        xrf002 = findings_for(findings, "XRF-002")
        assert xrf002
        assert all(f.severity == Severity.BLOCK for f in xrf002)


# ─── XRF-003: Out-of-scope CIDR is subnet of in-scope CIDR ──────────────────

class TestXRF003:
    def test_mcb_carve_outs_detected(self, mcb_engagement):
        """
        MCB has Executive VLAN (10.10.4.0/24) out-of-scope while Core Banking
        (10.10.0.0/22) is in-scope. 10.10.4.0/24 IS a subnet of 10.10.0.0/22.
        This should trigger XRF-003.
        """
        eng = copy.deepcopy(mcb_engagement)
        eng.out_of_scope_assets.append(OutOfScopeAsset(
            asset_name="Executive VLAN",
            cidr_notation="10.10.4.0/24",
            subnet_mask="255.255.255.0",
            description="Executive VLAN carved out of Core Banking range",
            delivery_method=DeliveryMethod.NETWORK_DISCOVERABLE,
            exclusion_reason="Excluded by Client request — pending board approval",
            third_party_operated=False,
            regulatory_exclusion=False,
        ))
        findings = validate(eng)
        assert has_rule(findings, "XRF-003")

    def test_no_overlap_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        # MCB fixture out-of-scope CIDRs (172.x, 10.90.x) don't overlap in-scope (10.10-70.x, 192.168.x)
        assert not has_rule(findings, "XRF-003")


# ─── XRF-004: Technique references non-existent maintenance window ───────────

class TestXRF004:
    def test_valid_window_refs_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-004")

    def test_nexus_bad_ref_detected(self, nexus_bad_engagement):
        """Nexus fixture references MW-NONEXISTENT."""
        findings = validate(nexus_bad_engagement)
        assert has_rule(findings, "XRF-004")

    def test_dangling_window_ref_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        t = next(t for t in eng.techniques if t.maintenance_window_ref)
        t.maintenance_window_ref = "MW-DOES-NOT-EXIST"
        findings = validate(eng)
        assert has_rule(findings, "XRF-004")


# ─── XRF-005: Maintenance window date within engagement period ───────────────

class TestXRF005:
    def test_windows_within_period_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-005")

    def test_window_before_start_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.maintenance_windows[0].date = date(2026, 3, 1)  # before April 7 start
        findings = validate(eng)
        assert has_rule(findings, "XRF-005")

    def test_window_after_end_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.maintenance_windows[0].date = date(2026, 6, 1)  # after April 25 end
        findings = validate(eng)
        assert has_rule(findings, "XRF-005")

    def test_window_on_start_date_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.maintenance_windows[0].date = date(2026, 4, 7)  # on start date — valid
        findings = validate(eng)
        assert not has_rule(findings, "XRF-005")


# ─── XRF-006: notification_recipient references non-existent contact ─────────

class TestXRF006:
    def test_valid_refs_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-006")

    def test_dangling_recipient_ref_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        t = next(t for t in eng.techniques if t.notification_required)
        t.notification_recipient_ref = "nonexistent_role"
        findings = validate(eng)
        assert has_rule(findings, "XRF-006")
        assert findings_for(findings, "XRF-006")[0].severity == Severity.BLOCK


# ─── XRF-007: retest_window_start before authorized_end_date ─────────────────

class TestXRF007:
    def test_valid_retest_window_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-007")

    def test_retest_before_end_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        # Set retest start to be during the engagement (before end date)
        eng.period.retest_window_start = date(2026, 4, 20)  # before April 25 end
        findings = validate(eng)
        assert has_rule(findings, "XRF-007")

    def test_no_retest_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.period.retest_included = False
        eng.period.retest_window_start = None
        eng.period.retest_window_end = None
        findings = validate(eng)
        assert not has_rule(findings, "XRF-007")


# ─── XRF-008: Blackout dates within engagement period ────────────────────────

class TestXRF008:
    def test_valid_blackout_no_trigger(self, mcb_engagement):
        """April 15 is within April 7 – April 25."""
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-008")

    def test_blackout_before_start_detected(self, mcb_engagement):
        from scopeguard.models import BlackoutDate
        eng = copy.deepcopy(mcb_engagement)
        eng.period.blackout_dates.append(
            BlackoutDate(date=date(2026, 3, 15), reason="Before engagement start")
        )
        findings = validate(eng)
        assert has_rule(findings, "XRF-008")

    def test_blackout_after_end_detected(self, mcb_engagement):
        from scopeguard.models import BlackoutDate
        eng = copy.deepcopy(mcb_engagement)
        eng.period.blackout_dates.append(
            BlackoutDate(date=date(2026, 5, 1), reason="After engagement end")
        )
        findings = validate(eng)
        assert has_rule(findings, "XRF-008")


# ─── XRF-009: Physical location in scope but no physical_security_manager ────

class TestXRF009:
    def test_manager_defined_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-009")

    def test_missing_manager_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.contacts = [c for c in eng.contacts if c.role != "physical_security_manager"]
        findings = validate(eng)
        # XRF-009 is CLARIFY; VAL-015 is also MISSING — both may fire
        assert has_rule(findings, "XRF-009")
        assert findings_for(findings, "XRF-009")[0].severity == Severity.CLARIFY


# ─── XRF-010: SE in scope but no legal_counsel contact ───────────────────────

class TestXRF010:
    def test_counsel_defined_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-010")

    def test_missing_counsel_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.contacts = [c for c in eng.contacts if c.role != "legal_counsel"]
        findings = validate(eng)
        assert has_rule(findings, "XRF-010")
        assert findings_for(findings, "XRF-010")[0].severity == Severity.CLARIFY


# ─── XRF-011: Third-party facility not notified ──────────────────────────────

class TestXRF011:
    def test_facility_notified_no_trigger(self, mcb_engagement):
        """MCB data center is third-party but facility_notified=False — should trigger."""
        findings = validate(mcb_engagement)
        # MCB fixture has CyrusOne with facility_notified=False — this SHOULD trigger XRF-011
        assert has_rule(findings, "XRF-011")

    def test_facility_notified_true_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        for loc in eng.physical_locations:
            if loc.facility_third_party:
                loc.facility_notified = True
        findings = validate(eng)
        assert not has_rule(findings, "XRF-011")

    def test_non_third_party_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        for loc in eng.physical_locations:
            loc.facility_third_party = False
            loc.facility_notified = None
        findings = validate(eng)
        assert not has_rule(findings, "XRF-011")


# ─── XRF-012: notification_required technique with no lead time ──────────────

class TestXRF012:
    def test_lead_times_defined_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-012")

    def test_missing_lead_time_detected(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        t = next(t for t in eng.techniques if t.notification_required)
        t.notification_lead_time_hours = None
        findings = validate(eng)
        assert has_rule(findings, "XRF-012")
        assert findings_for(findings, "XRF-012")[0].severity == Severity.CLARIFY


# ─── XRF-013: In-scope and out-of-scope on same /16 supernet ─────────────────

class TestXRF013:
    def test_mcb_supernet_overlap_noted(self, mcb_engagement):
        """
        MCB has 10.x.x.x in-scope and 10.90.0.0/22 out-of-scope.
        These share a /8 supernet (not /16 exactly, but the rule checks /16).
        10.10.0.0 and 10.90.0.0 share the same /16? No — /16 of 10.10 is 10.10.0.0/16,
        /16 of 10.90 is 10.90.0.0/16. Different /16s. So no XRF-013 for MCB.
        This test verifies no false positive.
        """
        findings = validate(mcb_engagement)
        # XRF-013 is NOTE severity — check it doesn't fire for unrelated segments
        xrf013 = findings_for(findings, "XRF-013")
        # Any that do fire should be genuinely on the same /16
        import ipaddress
        for f in xrf013:
            cidrs = f.related_fields
            if len(cidrs) == 2:
                try:
                    a = ipaddress.ip_network(cidrs[0], strict=False)
                    b = ipaddress.ip_network(cidrs[1], strict=False)
                    assert a.supernet(new_prefix=16) == b.supernet(new_prefix=16), \
                        f"XRF-013 fired on CIDRs that don't share a /16: {cidrs}"
                except (ValueError, TypeError):
                    pass  # non-IP related_fields from other findings

    def test_same_16_supernet_noted(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        # Add an out-of-scope asset on 10.10.x.x — same /16 as Core Banking (10.10.0.0/22)
        eng.out_of_scope_assets.append(OutOfScopeAsset(
            asset_name="Same /16 Segment",
            cidr_notation="10.10.200.0/24",
            subnet_mask="255.255.255.0",
            description="On same /16 as Core Banking but different /22",
            delivery_method=DeliveryMethod.NETWORK_DISCOVERABLE,
            exclusion_reason="Test scenario",
            third_party_operated=False,
            regulatory_exclusion=False,
        ))
        findings = validate(eng)
        xrf013 = findings_for(findings, "XRF-013")
        # Should have at least one NOTE about the shared /16
        assert xrf013
        assert all(f.severity == Severity.NOTE for f in xrf013)

    def test_xrf013_does_not_fire_when_already_block(self, mcb_engagement):
        """XRF-013 should not fire for pairs already caught by XRF-002/003."""
        eng = copy.deepcopy(mcb_engagement)
        # 10.10.0.0/8 is a supernet of 10.10.0.0/22 — XRF-002 catches this
        # XRF-013 should not also fire for the same pair
        eng.out_of_scope_assets.append(OutOfScopeAsset(
            asset_name="Supernet",
            cidr_notation="10.10.0.0/8",
            subnet_mask="255.0.0.0",
            description="Supernet",
            delivery_method=DeliveryMethod.NETWORK_DISCOVERABLE,
            exclusion_reason="Test",
            third_party_operated=False,
            regulatory_exclusion=False,
        ))
        findings = validate(eng)
        # XRF-002 should fire; XRF-013 should NOT fire for the same pair
        assert has_rule(findings, "XRF-002")
        xrf013 = findings_for(findings, "XRF-013")
        # Check no XRF-013 finding has the same pair as an XRF-002 finding
        xrf002_pairs = {
            tuple(sorted(f.related_fields)) for f in findings_for(findings, "XRF-002")
        }
        for f in xrf013:
            if f.related_fields:
                pair = tuple(sorted(f.related_fields))
                assert pair not in xrf002_pairs, \
                    "XRF-013 fired for a pair already caught by XRF-002"


# ─── XRF-014: Network techniques authorized but no tester source IPs ─────────

class TestXRF014:
    def test_ips_defined_no_trigger(self, mcb_engagement):
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-014")

    def test_no_ips_with_network_techniques_noted(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        for c in eng.contacts:
            c.authorized_source_ips = []
        findings = validate(eng)
        assert has_rule(findings, "XRF-014")
        assert findings_for(findings, "XRF-014")[0].severity == Severity.NOTE


# ─── XRF-015: Full-scope engagement without HIPAA consideration ──────────────

class TestXRF015:
    def test_mcb_gets_hipaa_note(self, mcb_engagement):
        """MCB is full_scope without HIPAA in regulatory_basis — should get NOTE."""
        findings = validate(mcb_engagement)
        assert has_rule(findings, "XRF-015")
        assert findings_for(findings, "XRF-015")[0].severity == Severity.NOTE

    def test_hipaa_listed_no_trigger(self, mcb_engagement):
        from scopeguard.models import RegulatoryBasis
        eng = copy.deepcopy(mcb_engagement)
        eng.identity.regulatory_basis.append(RegulatoryBasis.HIPAA)
        findings = validate(eng)
        assert not has_rule(findings, "XRF-015")

    def test_non_full_scope_no_trigger(self, mcb_engagement):
        from scopeguard.models import EngagementType
        eng = copy.deepcopy(mcb_engagement)
        eng.identity.engagement_type = EngagementType.EXTERNAL_ONLY
        findings = validate(eng)
        assert not has_rule(findings, "XRF-015")


# ─── XRF-016: PCI-DSS listed but no CDE assets identified ───────────────────

class TestXRF016:
    def test_mcb_pci_with_excluded_cde_noted(self, mcb_engagement):
        """
        MCB lists PCI-DSS in regulatory_basis. It has 'Card Processing (FIS)' in
        out_of_scope. The keyword 'card' should be detected — no XRF-016 for MCB.
        """
        findings = validate(mcb_engagement)
        assert not has_rule(findings, "XRF-016")

    def test_pci_without_cde_assets_noted(self, mcb_engagement):
        from scopeguard.models import RegulatoryBasis
        eng = copy.deepcopy(mcb_engagement)
        # Remove CDE-related assets
        eng.out_of_scope_assets = [
            a for a in eng.out_of_scope_assets
            if "card" not in a.asset_name.lower() and "payment" not in a.asset_name.lower()
        ]
        eng.in_scope_assets = [
            a for a in eng.in_scope_assets
            if "card" not in a.asset_name.lower()
        ]
        findings = validate(eng)
        assert has_rule(findings, "XRF-016")
        assert findings_for(findings, "XRF-016")[0].severity == Severity.NOTE

    def test_no_pci_no_trigger(self, mcb_engagement):
        eng = copy.deepcopy(mcb_engagement)
        eng.identity.regulatory_basis = [r for r in eng.identity.regulatory_basis
                                          if r.value != "PCI-DSS"]
        findings = validate(eng)
        assert not has_rule(findings, "XRF-016")


# ─── Combined: Nexus bad fixture catches all spec-documented errors ───────────

class TestNexusMilestone:
    def test_all_spec_errors_detected(self, nexus_bad_engagement):
        """
        Phase 1 milestone (spec Section 7):
        The Nexus Plaza student document errors must all be detected:
          - CIDR/subnet conflict    → VAL-002
          - VLAN count mismatch     → VAL-003
          - Missing maintenance window for DoS technique → VAL-010 + XRF-004
          - Unsigned but 'executed' → VAL-014
        """
        findings = validate(nexus_bad_engagement)
        required = {
            "VAL-002": "CIDR/subnet mismatch",
            "VAL-003": "VLAN count mismatch",
            "VAL-010": "technique needs window but none defined",
            "XRF-004": "technique references non-existent window",
            "VAL-014": "executed status without signatures",
        }
        for rule_id, description in required.items():
            assert has_rule(findings, rule_id), \
                f"Phase 1 milestone failed: {rule_id} ({description}) was not detected"

    def test_all_nexus_block_findings_are_block_severity(self, nexus_bad_engagement):
        findings = validate(nexus_bad_engagement)
        spec_blockers = ["VAL-002", "VAL-003", "VAL-010", "VAL-014", "VAL-011", "VAL-012"]
        for rule_id in spec_blockers:
            rule_findings = findings_for(findings, rule_id)
            assert rule_findings, f"No findings for {rule_id}"
            assert all(f.severity == Severity.BLOCK for f in rule_findings), \
                f"{rule_id} findings are not all BLOCK severity"
