"""
nex.scope_compiler
~~~~~~~~~~~~~~~~~~~~~~~~~
Phases 4-8, 10 — deterministic scope authority compilation.

Takes a validated Engagement object and produces a complete, cryptographically
bound ScopeArtifact that Nex's PolicyDecisionEngine and ScopeTokenManager can
consume directly.

Outputs (all contained in ScopeArtifact):
  scope          — the canonical scope.json dict  (Phase 4)
  scope_hash     — SHA-256 hex of canonical scope (Phase 5)
  token          — HMAC-signed scope token envelope (Phase 5)
  audit          — full input/decision/mapping audit record (Phase 10)

Determinism invariant:
  Identical Engagement + identical timestamp + identical secret_key
  → bit-for-bit identical ScopeArtifact.

Fail-closed rule:
  If any required field is absent or a mapping is undefined, the compiler
  raises ScopeCompilationError rather than producing a partial artifact.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .canonicalize import canonical_json, canonical_json_bytes
from .capability_map import (
    TAXONOMY_VERSION,
    categories_to_capabilities,
    capabilities_to_modules,
    category_capability_matrix,
)
from .models import Engagement, AuthorizationStatus, DocumentStatus
from .scope_token import generate_scope_token

# ── Constants ─────────────────────────────────────────────────────────────────

# Fixed UUID namespace for deterministic scope_id (UUID v5).
# This constant must never change; changing it would invalidate all existing
# scope_ids.
_SCOPE_ID_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

COMPILER_VERSION = "1.0.0"
SCOPE_SCHEMA_VERSION = "1.0"
AUDIT_SCHEMA_VERSION = "1.0"


class ScopeCompilationError(Exception):
    """Raised when the compiler cannot produce a valid scope artifact."""


# ── Public output type ────────────────────────────────────────────────────────

@dataclass
class ScopeArtifact:
    """All outputs of a single scope compilation run.

    All fields are populated atomically; a partial ScopeArtifact is never
    returned by :func:`compile_scope`.
    """

    scope_id: str
    scope_hash: str
    operator_id: str

    # Full scope.json object (includes scope_hash as a field)
    scope: dict

    # HMAC-signed token envelope
    token: dict

    # Full audit record
    audit: dict

    # Convenience: sorted list of authorized Nex module identifiers
    nex_modules: list[str] = field(default_factory=list)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _require(value: Any, label: str) -> Any:
    """Raise ScopeCompilationError if *value* is falsy."""
    if not value and value != 0:
        raise ScopeCompilationError(
            f"Required field missing or empty: {label!r}. "
            "Scope compilation cannot proceed (fail-closed)."
        )
    return value


def _derive_operator_id(engagement: Engagement) -> str:
    """SHA-256 of canonical identity triple.

    Deterministic and non-reversible.  Used in place of plaintext identifiers
    for all enforcement comparisons.
    """
    parts = "|".join([
        _require(engagement.identity.engagement_id, "identity.engagement_id"),
        _require(engagement.identity.testing_firm_legal_name,
                 "identity.testing_firm_legal_name"),
        _require(engagement.identity.prepared_by, "identity.prepared_by"),
    ])
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


def _derive_scope_id(engagement: Engagement) -> str:
    """UUID v5 derived from (engagement_id, client, testing_firm).

    Deterministic for a given engagement triple; different from random UUIDs.
    """
    seed = "|".join([
        engagement.identity.engagement_id,
        engagement.identity.client_org_legal_name,
        engagement.identity.testing_firm_legal_name,
    ])
    return str(uuid.uuid5(_SCOPE_ID_NAMESPACE, seed))


def _authorized_targets(engagement: Engagement) -> list[dict]:
    """Sorted list of authorized target descriptors derived from in-scope assets."""
    targets = []
    for asset in engagement.in_scope_assets:
        targets.append({
            "asset_name":        asset.asset_name,
            "cidr":              asset.cidr_notation,
            "delivery_method":   (asset.delivery_method.value
                                  if hasattr(asset.delivery_method, "value")
                                  else str(asset.delivery_method)),
            "description":       asset.description,
            "hostname":          asset.hostname or "",
            "ip_address":        asset.ip_address or "",
        })
    # Sort by CIDR for determinism regardless of form entry order
    return sorted(targets, key=lambda t: t["cidr"])


def _out_of_scope_cidrs(engagement: Engagement) -> list[str]:
    return sorted(a.cidr_notation for a in engagement.out_of_scope_assets)


def _authorized_source_ips(engagement: Engagement) -> list[str]:
    ips: set[str] = set()
    for contact in engagement.contacts:
        ips.update(contact.authorized_source_ips)
    return sorted(ips)


def _authorized_modules_block(engagement: Engagement) -> dict:
    """Derive capabilities and Nex module list from authorized techniques."""
    authorized_categories: list[str] = []
    for tech in engagement.techniques:
        status = (tech.authorization_status.value
                  if hasattr(tech.authorization_status, "value")
                  else str(tech.authorization_status))
        if status in ("authorized", "conditional") and not tech.prohibited:
            cat = (tech.category.value
                   if hasattr(tech.category, "value")
                   else str(tech.category))
            authorized_categories.append(cat)

    # Deduplicate before mapping
    unique_categories = sorted(set(authorized_categories))
    capabilities = categories_to_capabilities(unique_categories)
    modules = capabilities_to_modules(capabilities)
    matrix = category_capability_matrix(unique_categories)

    return {
        "taxonomy_version":         TAXONOMY_VERSION,
        "capabilities":             capabilities,
        "category_capability_map":  matrix,
        "nex_modules":              modules,
    }


def _authorization_basis(engagement: Engagement) -> dict:
    """Structured authorization status derived from document identity fields."""
    status = (engagement.identity.document_status.value
              if hasattr(engagement.identity.document_status, "value")
              else str(engagement.identity.document_status))

    reg_basis = sorted(
        r.value if hasattr(r, "value") else str(r)
        for r in engagement.identity.regulatory_basis
    )

    return {
        "document_status":         status,
        "authorization_signed":    engagement.identity.all_signatures_present(),
        "authorization_crypto_signed": engagement.identity.all_cryptographic_signatures_present(),
        "engagement_type":         (engagement.identity.engagement_type.value
                                    if hasattr(engagement.identity.engagement_type, "value")
                                    else str(engagement.identity.engagement_type)),
        "regulatory_basis":        reg_basis,
        "client_signatory_name":   engagement.identity.client_signatory_name or "",
        "tester_lead_signatory":   engagement.identity.tester_lead_signatory_name or "",
        "all_signatures_present":  engagement.identity.all_signatures_present(),
        "all_cryptographic_signatures_present": engagement.identity.all_cryptographic_signatures_present(),
    }


def _constraints_block(engagement: Engagement, authorized_source_ips: list[str],
                        out_of_scope_cidrs: list[str]) -> dict:
    per = engagement.period
    blackouts = sorted(
        {"date": bd.date.isoformat(), "reason": bd.reason}
        for bd in per.blackout_dates
    )

    return {
        "network_access": {
            "authorized_source_ips": authorized_source_ips,
            "out_of_scope_cidrs":    out_of_scope_cidrs,
        },
        "execution_limits": {
            "concurrent_scans_max": None,
        },
        "time_window": {
            "active_days":           sorted(per.active_testing_days),
            "active_hours_end":      per.active_testing_hours_end,
            "active_hours_start":    per.active_testing_hours_start,
            "blackout_dates":        blackouts,
            "end_utc":               (per.authorized_end_date.isoformat()
                                      if per.authorized_end_date else None),
            "start_utc":             (per.authorized_start_date.isoformat()
                                      if per.authorized_start_date else None),
        },
    }


def _data_governance_block(engagement: Engagement) -> dict:
    dg = engagement.data_governance
    if dg is None:
        return {}
    enc = (dg.evidence_encryption_standard.value
           if hasattr(dg.evidence_encryption_standard, "value")
           else str(dg.evidence_encryption_standard))
    cred = (dg.credential_use_policy.value
            if hasattr(dg.credential_use_policy, "value")
            else str(dg.credential_use_policy))
    return {
        "cloud_storage_prohibited":        dg.cloud_storage_prohibited,
        "credential_reporting_window_hours": dg.credential_reporting_window_hours,
        "credential_use_policy":           cred,
        "evidence_encryption_standard":    enc,
        "evidence_retention_days":         dg.evidence_retention_days,
        "personal_device_prohibited":      dg.personal_device_prohibited,
        "pii_handling_policy":             dg.pii_handling_policy,
        "third_party_disclosure_prohibited": dg.third_party_disclosure_prohibited,
    }


# ── Core compilation function ─────────────────────────────────────────────────

def compile_scope(
    engagement: Engagement,
    timestamp: datetime,
    secret_key: bytes,
) -> ScopeArtifact:
    """Compile a validated Engagement into a complete ScopeArtifact.

    Args:
        engagement:  Fully hydrated Engagement object (must have passed
                     validation with no BLOCK findings before calling this).
        timestamp:   Injected UTC datetime used as ``issued_at``.  Must NOT
                     be generated inside this function to preserve determinism.
        secret_key:  HMAC secret key bytes.  Must be injected by the caller.

    Returns:
        A complete ScopeArtifact.  Never returns a partial artifact.

    Raises:
        ScopeCompilationError: If any required field is absent.
        ValueError:            If secret_key is empty.
    """
    if not isinstance(timestamp, datetime):
        raise TypeError("timestamp must be a datetime object")
    if not secret_key:
        raise ValueError("secret_key must not be empty")

    # ── Derive deterministic identifiers ──────────────────────────────────────
    scope_id    = _derive_scope_id(engagement)
    operator_id = _derive_operator_id(engagement)

    # ── Build sub-blocks ──────────────────────────────────────────────────────
    targets             = _authorized_targets(engagement)
    source_ips          = _authorized_source_ips(engagement)
    oos_cidrs           = _out_of_scope_cidrs(engagement)
    modules_block       = _authorized_modules_block(engagement)
    auth_basis          = _authorization_basis(engagement)
    constraints         = _constraints_block(engagement, source_ips, oos_cidrs)
    data_governance     = _data_governance_block(engagement)

    # ── Assemble scope payload (without scope_hash) ───────────────────────────
    scope_payload: dict = {
        "authorized_modules":   modules_block,
        "authorized_targets":   targets,
        "authorization_basis":  auth_basis,
        "constraints":          constraints,
        "data_governance":      data_governance,
        "engagement_id":        engagement.identity.engagement_id,
        "operator_id":          operator_id,
        "schema_version":       SCOPE_SCHEMA_VERSION,
        "scope_id":             scope_id,
    }

    # ── Compute scope_hash over the payload without the hash field ─────────────
    scope_hash = hashlib.sha256(
        canonical_json_bytes(scope_payload)
    ).hexdigest()

    # Add scope_hash into the scope object
    scope_payload["scope_hash"] = scope_hash

    # ── Build token payload ────────────────────────────────────────────────────
    expires_at = constraints["time_window"]["end_utc"]
    token_payload: dict = {
        "authorized_cidrs":       sorted(t["cidr"] for t in targets),
        "constraints": {
            "active_days":           constraints["time_window"]["active_days"],
            "active_hours_end":      constraints["time_window"]["active_hours_end"],
            "active_hours_start":    constraints["time_window"]["active_hours_start"],
            "time_window_end_utc":   expires_at,
            "time_window_start_utc": constraints["time_window"]["start_utc"],
        },
        "engagement_id":          engagement.identity.engagement_id,
        "expires_at":             expires_at,
        "issued_at":              timestamp.isoformat(),
        "nex_modules":            modules_block["nex_modules"],
        "operator_id":            operator_id,
        "scope_hash":             scope_hash,
        "scope_id":               scope_id,
    }

    # ── Sign token ─────────────────────────────────────────────────────────────
    token = generate_scope_token(token_payload, secret_key)

    # ── Build audit record ─────────────────────────────────────────────────────
    audit: dict = {
        "audit_schema_version": AUDIT_SCHEMA_VERSION,
        "generation_context": {
            "canonical_encoding":   "UTF-8",
            "compiler_version":     COMPILER_VERSION,
            "taxonomy_version":     TAXONOMY_VERSION,
        },
        "generated_at": timestamp.isoformat(),
        "inputs": {
            "client_org":              engagement.identity.client_org_legal_name,
            "document_status":         auth_basis["document_status"],
            "engagement_id":           engagement.identity.engagement_id,
            "engagement_type":         auth_basis["engagement_type"],
            "in_scope_assets_count":   len(engagement.in_scope_assets),
            "out_of_scope_assets_count": len(engagement.out_of_scope_assets),
            "physical_locations_count": len(engagement.physical_locations),
            "prepared_by":             engagement.identity.prepared_by,
            "regulatory_basis":        auth_basis["regulatory_basis"],
            "social_engineering_present": engagement.social_engineering is not None,
            "techniques_count":        len(engagement.techniques),
            "testing_firm":            engagement.identity.testing_firm_legal_name,
        },
        "mapping_decisions": {
            "authorized_categories":   sorted(
                set(
                    (t.category.value
                     if hasattr(t.category, "value") else str(t.category))
                    for t in engagement.techniques
                    if not t.prohibited
                )
            ),
            "capabilities_granted":    modules_block["capabilities"],
            "category_capability_map": modules_block["category_capability_map"],
            "modules_authorized":      modules_block["nex_modules"],
        },
        "operator_id":  operator_id,
        "scope_hash":   scope_hash,
        "scope_id":     scope_id,
        "validation_results": {
            "note": "Validation findings must be retrieved from the FindingList "
                    "produced by nex.validator.Validator.validate() and "
                    "attached to the audit record by the caller."
        },
    }

    return ScopeArtifact(
        scope_id=scope_id,
        scope_hash=scope_hash,
        operator_id=operator_id,
        scope=scope_payload,
        token=token,
        audit=audit,
        nex_modules=modules_block["nex_modules"],
    )
