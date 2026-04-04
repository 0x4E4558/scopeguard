"""
scopeguard.nex_contract
~~~~~~~~~~~~~~~~~~~~~~~
Embedded NEX compatibility contract data for ScopeGuard.

The runtime implementation must not depend on external compatibility files.
This module owns the embedded contract tables used by token generation and
validation.
"""

from __future__ import annotations

from typing import Dict, Set

_SCOPEGUARD_ALLOWLIST_BY_TECHNIQUE_CLASS: dict[str, list[str]] = {
    "RECON": ["nex.recon.dns_enum@1.0", "nex.recon.asn_lookup@1.0"],
    "ENUMERATION": ["nex.recon.host_enum@1.0", "nex.recon.service_enum@1.0"],
    "VULNERABILITY_SCAN": ["nex.scan.port_scan@1.0", "nex.scan.vuln_scan@1.0"],
    "WEB_ANALYSIS": ["nex.web.fingerprint@1.0", "nex.web.tech_detect@1.0"],
    "NETWORK_CAPTURE": ["nex.net.packet_capture@1.0"],
    "EXPLOIT": ["nex.exploit.framework@1.0", "nex.exploit.posture_test@1.0"],
    "CREDENTIAL_HARVEST": ["nex.exploit.credential_test@1.0"],
    "LATERAL_MOVEMENT": ["nex.postex.lateral_movement@1.0"],
    "PERSISTENCE": ["nex.postex.persistence@1.0"],
    "EXFILTRATION": ["nex.postex.data_collection@1.0"],
    "DENIAL_OF_SERVICE": ["nex.dos.application_test@1.0"],
    "SOCIAL_ENGINEERING": [
        "nex.se.phishing@1.0",
        "nex.se.smishing@1.0",
        "nex.se.vishing@1.0",
        "nex.se.impersonation@1.0",
        "nex.se.usb_drop@1.0",
    ],
    "PHYSICAL_ACCESS": [
        "nex.physical.entry@1.0",
        "nex.physical.badge_clone@1.0",
        "nex.physical.lock_bypass@1.0",
    ],
}

_MODULE_TO_D3FEND_IDS: dict[str, set[str]] = {
    "nex.recon.dns_enum@1.0": {"d3f:network-service-discovery"},
    "nex.recon.asn_lookup@1.0": {"d3f:network-attribution-analysis"},
    "nex.recon.host_enum@1.0": {"d3f:host-discovery"},
    "nex.recon.service_enum@1.0": {"d3f:service-discovery"},
    "nex.scan.port_scan@1.0": {"d3f:network-port-scanning"},
    "nex.scan.vuln_scan@1.0": {"d3f:vulnerability-assessment"},
    "nex.web.fingerprint@1.0": {"d3f:web-application-fingerprinting"},
    "nex.web.tech_detect@1.0": {"d3f:web-technology-identification"},
    "nex.net.packet_capture@1.0": {"d3f:network-traffic-capture"},
    "nex.exploit.framework@1.0": {"d3f:exploit-execution-monitoring"},
    "nex.exploit.posture_test@1.0": {"d3f:attack-surface-validation"},
    "nex.exploit.credential_test@1.0": {"d3f:credential-abuse-testing"},
    "nex.postex.lateral_movement@1.0": {"d3f:lateral-movement-detection"},
    "nex.postex.persistence@1.0": {"d3f:persistence-mechanism-monitoring"},
    "nex.postex.data_collection@1.0": {"d3f:data-exfiltration-monitoring"},
    "nex.dos.application_test@1.0": {"d3f:service-availability-testing"},
    "nex.se.phishing@1.0": {"d3f:phishing-simulation"},
    "nex.se.smishing@1.0": {"d3f:smishing-simulation"},
    "nex.se.vishing@1.0": {"d3f:vishing-simulation"},
    "nex.se.impersonation@1.0": {"d3f:impersonation-simulation"},
    "nex.se.usb_drop@1.0": {"d3f:removable-media-deception"},
    "nex.physical.entry@1.0": {"d3f:physical-access-testing"},
    "nex.physical.badge_clone@1.0": {"d3f:credential-replica-detection"},
    "nex.physical.lock_bypass@1.0": {"d3f:physical-control-bypass-testing"},
}

_GOVERNANCE_REJECT_REASON_CODES: set[str] = {
    "scopeguard_bad_signature",
    "scopeguard_bad_expires_at",
    "scopeguard_expired",
    "scopeguard_target_out_of_scope",
    "scopeguard_operator_mismatch",
    "scopeguard_module_not_allowed",
    "scopeguard_validation_error",
    "ok",
}

_STRICT_D3FEND_REQUIRED_NON_EMPTY = True


def scopeguard_allowlist_by_technique_class() -> dict[str, list[str]]:
    return {key: list(values) for key, values in _SCOPEGUARD_ALLOWLIST_BY_TECHNIQUE_CLASS.items()}


def known_scopeguard_module_ids() -> set[str]:
    out: set[str] = set()
    for values in _SCOPEGUARD_ALLOWLIST_BY_TECHNIQUE_CLASS.values():
        out.update(values)
    return out


def capability_to_d3fend_ids() -> dict[str, set[str]]:
    return {capability: set(d3fend_ids) for capability, d3fend_ids in _MODULE_TO_D3FEND_IDS.items()}


def strict_d3fend_required_non_empty() -> bool:
    return _STRICT_D3FEND_REQUIRED_NON_EMPTY


def governance_reason_codes() -> set[str]:
    return set(_GOVERNANCE_REJECT_REASON_CODES)
