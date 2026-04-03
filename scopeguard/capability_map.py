"""
scopeguard.capability_map
~~~~~~~~~~~~~~~~~~~~~~~~~
Version-locked capability taxonomy and Nex module identifier mapping.

Design rules:
  - TAXONOMY_VERSION must be incremented whenever any mapping changes.
  - Every Capability must have at least one Nex module entry.
  - Every TechniqueCategory value must appear in CATEGORY_TO_CAPABILITIES.
  - No capability may exist without a defined module mapping (enforced at import time).
  - Mappings are read-only; mutation at runtime is prohibited.
"""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet

# Bump this whenever ANY mapping in this file changes.
TAXONOMY_VERSION = "1.0.0"

# Nex module identifier format: nex.<domain>.<name>@<semver>
# The version suffix must be incremented if module behaviour changes.


class Capability(str, Enum):
    """Authoritative capability taxonomy used across Scopeguard and Nex."""

    RECONNAISSANCE       = "RECONNAISSANCE"
    SCAN_PORTS           = "SCAN_PORTS"
    SCAN_WEB             = "SCAN_WEB"
    ENUMERATION          = "ENUMERATION"
    VULN_SCANNING        = "VULN_SCANNING"
    EXPLOITATION         = "EXPLOITATION"
    POST_EXPLOITATION    = "POST_EXPLOITATION"
    DENIAL_OF_SERVICE    = "DENIAL_OF_SERVICE"
    SOCIAL_ENGINEERING   = "SOCIAL_ENGINEERING"
    PHYSICAL_ACCESS      = "PHYSICAL_ACCESS"


# Maps TechniqueCategory.value → frozenset of Capability values.
# One-to-many: a technique category may grant several capabilities.
# This mapping is version-locked; do not extend without bumping TAXONOMY_VERSION.
CATEGORY_TO_CAPABILITIES: dict[str, FrozenSet[str]] = {
    "reconnaissance":    frozenset({
        Capability.RECONNAISSANCE.value,
        Capability.ENUMERATION.value,
    }),
    "vuln_scanning":     frozenset({
        Capability.SCAN_PORTS.value,
        Capability.SCAN_WEB.value,
        Capability.VULN_SCANNING.value,
    }),
    "exploitation":      frozenset({
        Capability.EXPLOITATION.value,
    }),
    "post_exploitation": frozenset({
        Capability.POST_EXPLOITATION.value,
    }),
    "dos":               frozenset({
        Capability.DENIAL_OF_SERVICE.value,
    }),
    "social_engineering": frozenset({
        Capability.SOCIAL_ENGINEERING.value,
    }),
    "physical":          frozenset({
        Capability.PHYSICAL_ACCESS.value,
    }),
}

# Maps Capability → sorted tuple of Nex module identifiers.
# Module identifiers follow:  nex.<domain>.<name>@<semver>
CAPABILITY_TO_NEX_MODULES: dict[str, tuple[str, ...]] = {
    Capability.RECONNAISSANCE.value: (
        "nex.recon.dns_enum@1.0",
        "nex.recon.host_discovery@1.0",
        "nex.recon.whois@1.0",
    ),
    Capability.SCAN_PORTS.value: (
        "nex.scanner.port_scan@1.0",
        "nex.scanner.service_detect@1.0",
    ),
    Capability.SCAN_WEB.value: (
        "nex.scanner.http_fingerprint@1.0",
        "nex.scanner.web_crawler@1.0",
    ),
    Capability.ENUMERATION.value: (
        "nex.recon.ldap_enum@1.0",
        "nex.recon.smb_enum@1.0",
        "nex.recon.snmp_enum@1.0",
    ),
    Capability.VULN_SCANNING.value: (
        "nex.scanner.cve_check@1.0",
        "nex.scanner.vuln_scan@1.0",
    ),
    Capability.EXPLOITATION.value: (
        "nex.exploit.credential_test@1.0",
        "nex.exploit.framework@1.0",
    ),
    Capability.POST_EXPLOITATION.value: (
        "nex.postex.data_collection@1.0",
        "nex.postex.lateral_movement@1.0",
        "nex.postex.persistence@1.0",
    ),
    Capability.DENIAL_OF_SERVICE.value: (
        "nex.dos.stress_test@1.0",
    ),
    Capability.SOCIAL_ENGINEERING.value: (
        "nex.se.impersonation@1.0",
        "nex.se.phishing@1.0",
        "nex.se.smishing@1.0",
        "nex.se.usb_drop@1.0",
        "nex.se.vishing@1.0",
    ),
    Capability.PHYSICAL_ACCESS.value: (
        "nex.physical.badge_clone@1.0",
        "nex.physical.entry@1.0",
        "nex.physical.lock_bypass@1.0",
    ),
}

# ── Integrity check (runs once at import time) ────────────────────────────────
# Fail closed: every declared Capability must have a module mapping.
_missing = [
    cap.value for cap in Capability
    if cap.value not in CAPABILITY_TO_NEX_MODULES
]
if _missing:
    raise RuntimeError(
        f"capability_map integrity error: missing Nex module mapping for "
        f"capabilities: {_missing}"
    )


# ── Public helpers ─────────────────────────────────────────────────────────────

def categories_to_capabilities(categories: list[str]) -> list[str]:
    """Return a sorted, deduplicated list of capability values for the given
    technique category values.  Unknown categories are silently skipped.
    """
    caps: set[str] = set()
    for cat in categories:
        caps.update(CATEGORY_TO_CAPABILITIES.get(cat, frozenset()))
    return sorted(caps)


def capabilities_to_modules(capabilities: list[str]) -> list[str]:
    """Return a sorted, deduplicated list of Nex module identifiers for the
    given capability values.  Unknown capabilities are silently skipped.
    """
    modules: set[str] = set()
    for cap in capabilities:
        modules.update(CAPABILITY_TO_NEX_MODULES.get(cap, ()))
    return sorted(modules)


def category_capability_matrix(categories: list[str]) -> dict[str, list[str]]:
    """Return a mapping of  category → [capabilities...]  for *categories*.

    Only categories present in CATEGORY_TO_CAPABILITIES are included.
    Keys and values are sorted for deterministic output.
    """
    matrix: dict[str, list[str]] = {}
    for cat in sorted(set(categories)):
        if cat in CATEGORY_TO_CAPABILITIES:
            matrix[cat] = sorted(CATEGORY_TO_CAPABILITIES[cat])
    return matrix
