"""
nex.token_generator
~~~~~~~~~~~~~~~~~~~~~~~~~~
Nex-side NEX envelope issuance and compatibility validation.

Implements the embedded compatibility contract used by Nex.
"""

from __future__ import annotations

import hmac
import hashlib
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from .models import Engagement
from .nex_contract import (
    capability_to_d3fend_ids,
    governance_reason_codes,
    known_nex_module_ids,
    nex_allowlist_by_technique_class,
    strict_d3fend_required_non_empty,
)

ALGORITHM_LITERAL = "HMAC-SHA256"
SCHEMA_VERSION = "1.0"

_NEX_REASON_CODES = {
    "nex_bad_signature",
    "nex_bad_expires_at",
    "nex_expired",
    "nex_target_out_of_scope",
    "nex_operator_mismatch",
    "nex_module_not_allowed",
    "nex_validation_error",
    "ok",
}


@dataclass
class TokenPayload:
    scope_id: str
    operator_id: str
    nex_modules: list[str]
    allowed_targets: list[str]
    expires_at: str
    issued_at: str
    authorized_cidrs: Optional[list[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        if not out.get("authorized_cidrs"):
            out.pop("authorized_cidrs", None)
        return out


@dataclass
class ScopeTokenEnvelope:
    algorithm: str
    payload: Dict[str, Any]
    signature: str
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        # Preserve deterministic top-level key order for output stability.
        return {
            "algorithm": self.algorithm,
            "schema_version": self.schema_version,
            "payload": self.payload,
            "signature": self.signature,
        }


class NexEnvelopeValidator:
    """Nex-side validator mirroring NEX nex envelope semantics."""

    def __init__(self, hmac_key: bytes):
        if not hmac_key or len(hmac_key) != 32:
            raise ValueError("hmac_key must be exactly 32 bytes")
        self.hmac_key = hmac_key

    @staticmethod
    def is_nex_envelope(obj: Any) -> bool:
        if not isinstance(obj, dict):
            return False
        return "algorithm" in obj and "payload" in obj and "signature" in obj

    @staticmethod
    def _normalize_target(target: str) -> str:
        raw = (target or "").strip()
        if not raw:
            return ""

        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            host = parsed.hostname or ""
            return host.strip().lower()

        if "://" in raw:
            parsed = urlparse(raw)
            host = parsed.hostname or ""
            return host.strip().lower()

        # Strip port from host:port when possible.
        if raw.count(":") == 1 and "." in raw:
            host, _, maybe_port = raw.partition(":")
            if maybe_port.isdigit():
                return host.strip().lower()

        return raw.lower()

    def validate_with_reason(
        self,
        envelope: Dict[str, Any],
        *,
        target: str,
        operator_id: Optional[str],
        nex_module_ids: list[str],
    ) -> tuple[bool, str]:
        try:
            if not self.is_nex_envelope(envelope):
                return False, "nex_validation_error"

            payload = envelope.get("payload")
            signature = envelope.get("signature")
            if not isinstance(payload, dict) or not isinstance(signature, str):
                return False, "nex_validation_error"

            if not self._verify_signature(payload, signature):
                return False, "nex_bad_signature"

            expires_at_raw = payload.get("expires_at")
            expires_at = self._parse_iso_utc(expires_at_raw)
            if expires_at is None:
                return False, "nex_bad_expires_at"
            if datetime.now(timezone.utc) >= expires_at:
                return False, "nex_expired"

            token_operator = str(payload.get("operator_id", ""))
            if operator_id and token_operator and token_operator != str(operator_id):
                return False, "nex_operator_mismatch"

            token_modules = payload.get("nex_modules", [])
            if not isinstance(token_modules, list):
                return False, "nex_validation_error"
            token_modules_clean = [m for m in token_modules if isinstance(m, str) and m]

            if token_modules_clean and nex_module_ids:
                if not any(req in token_modules_clean for req in nex_module_ids):
                    return False, "nex_module_not_allowed"

            # Nex envelope path: enforce only authorized_cidrs if provided.
            authorized_cidrs = payload.get("authorized_cidrs", [])
            if authorized_cidrs:
                if not isinstance(authorized_cidrs, list):
                    return False, "nex_validation_error"
                normalized_target = self._normalize_target(target)
                try:
                    target_ip = ipaddress.ip_address(normalized_target)
                except ValueError:
                    return False, "nex_target_out_of_scope"

                matched = False
                for cidr in authorized_cidrs:
                    if not isinstance(cidr, str):
                        continue
                    try:
                        if target_ip in ipaddress.ip_network(cidr, strict=False):
                            matched = True
                            break
                    except ValueError:
                        continue
                if not matched:
                    return False, "nex_target_out_of_scope"

            return True, "ok"
        except Exception:
            return False, "nex_validation_error"

    def _verify_signature(self, payload: Dict[str, Any], signature: str) -> bool:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(self.hmac_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        return secrets.compare_digest(expected, signature)

    @staticmethod
    def _parse_iso_utc(value: Any) -> Optional[datetime]:
        if not isinstance(value, str) or not value.strip():
            return None
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)


class ScopeTokenGenerator:
    """Generates NEX-compatible Nex token envelopes."""

    # Nex technique categories -> NEX technique classes.
    NEX_TO_NEX_TECHNIQUE_CLASSES: dict[str, list[str]] = {
        "reconnaissance": ["RECON", "ENUMERATION"],
        "vuln_scanning": ["VULNERABILITY_SCAN", "WEB_ANALYSIS", "NETWORK_CAPTURE"],
        "exploitation": ["EXPLOIT", "CREDENTIAL_HARVEST"],
        "post_exploitation": ["LATERAL_MOVEMENT", "PERSISTENCE", "EXFILTRATION"],
        "dos": ["DENIAL_OF_SERVICE"],
        "social_engineering": ["SOCIAL_ENGINEERING"],
        "physical": ["PHYSICAL_ACCESS"],
    }

    def __init__(
        self,
        engagement: Engagement,
        operator_id: str,
        hmac_key: bytes,
        ttl_seconds: int = 3600,
        scope_id: Optional[str] = None,
    ):
        if engagement is None:
            raise ValueError("engagement cannot be None")
        if not operator_id or not isinstance(operator_id, str):
            raise ValueError("operator_id must be a non-empty string")
        if len(operator_id) > 256:
            raise ValueError("operator_id must be <= 256 characters")
        if not hmac_key or len(hmac_key) != 32:
            raise ValueError("hmac_key must be exactly 32 bytes")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")

        self.engagement = engagement
        self.operator_id = operator_id.strip()
        self.hmac_key = hmac_key
        self.ttl_seconds = ttl_seconds
        self.scope_id = scope_id or secrets.token_hex(16)

    def generate(self) -> Dict[str, Any]:
        payload = self._build_payload()
        signature = self._sign_payload(payload)
        envelope = ScopeTokenEnvelope(
            algorithm=ALGORITHM_LITERAL,
            payload=payload,
            signature=signature,
        )
        out = envelope.to_dict()
        self._validate_emitted_envelope(out)
        return out

    def _build_payload(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=self.ttl_seconds)

        nex_modules = self._derive_nex_modules()
        allowed_targets = self._derive_allowed_targets()
        authorized_cidrs = self._derive_authorized_cidrs()

        payload: Dict[str, Any] = {
            "scope_id": self.scope_id,
            "operator_id": self.operator_id,
            "nex_modules": nex_modules,
            "allowed_targets": allowed_targets,
            "issued_at": self._to_iso_z(now),
            "expires_at": self._to_iso_z(expires),
        }
        if authorized_cidrs:
            payload["authorized_cidrs"] = authorized_cidrs
        return payload

    def _derive_nex_modules(self) -> list[str]:
        allowlist = nex_allowlist_by_technique_class()
        known = known_nex_module_ids()

        technique_classes: set[str] = set()
        for technique in self.engagement.techniques:
            if technique.authorization_status.value != "authorized":
                continue
            category = technique.category.value
            mapped = self.NEX_TO_NEX_TECHNIQUE_CLASSES.get(category)
            if mapped is None:
                raise ValueError(f"No NEX technique class mapping for category '{category}'")
            technique_classes.update(mapped)

        if not technique_classes:
            raise ValueError("No authorized techniques available to derive nex_modules")

        modules: set[str] = set()
        for tclass in sorted(technique_classes):
            for module_id in allowlist.get(tclass, []):
                modules.add(module_id)

        if not modules:
            # Compatibility rule: empty derived allowlist is ignored by NEX gate,
            # but Nex still emits a deterministic empty list only if no
            # mappings exist for selected classes.
            return []

        unknown = [m for m in modules if m not in known]
        if unknown:
            raise ValueError(f"Unknown NEX module IDs derived from manifest mapping: {sorted(unknown)}")

        self._enforce_d3fend_strict_if_required(sorted(modules))
        return sorted(modules)

    def _enforce_d3fend_strict_if_required(self, modules: list[str]) -> None:
        strict_env = str(__import__("os").environ.get("NEX_COMPLIANCE_STRICT", "1")).strip().lower()
        strict_on = strict_env in {"1", "true", "yes", "on"}
        if not strict_on:
            return
        if not strict_d3fend_required_non_empty():
            return

        d3fend_map = capability_to_d3fend_ids()
        empty = [m for m in modules if not d3fend_map.get(m)]
        if empty:
            raise ValueError(
                "Strict D3FEND mode requires non-empty effective_mitre_d3fend_ids for all selected nex_modules: "
                f"{empty}"
            )

    def _derive_allowed_targets(self) -> list[str]:
        values: set[str] = set()
        for asset in self.engagement.in_scope_assets:
            cidr = str(asset.cidr_notation or "").strip()
            if cidr:
                ipaddress.ip_network(cidr, strict=False)
                values.add(cidr)
            host = str(asset.hostname or "").strip().lower()
            if host and self._is_hostname_pattern(host):
                values.add(host)
        if not values:
            raise ValueError("No valid in-scope targets available for allowed_targets")
        return sorted(values)

    def _derive_authorized_cidrs(self) -> list[str]:
        values: set[str] = set()
        for contact in self.engagement.contacts:
            if not contact.is_tester():
                continue
            for item in contact.authorized_source_ips or []:
                values.add(self._normalize_cidr(item))
        return sorted(values)

    def _sign_payload(self, payload: Dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        mac = hmac.new(self.hmac_key, canonical.encode("utf-8"), hashlib.sha256)
        return mac.hexdigest()

    @staticmethod
    def _to_iso_z(dt: datetime) -> str:
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _normalize_cidr(raw: str) -> str:
        value = str(raw or "").strip()
        if not value:
            raise ValueError("Empty CIDR value")
        if "/" not in value:
            ip = ipaddress.ip_address(value)
            value = f"{value}/{'32' if ip.version == 4 else '128'}"
        return str(ipaddress.ip_network(value, strict=False))

    @staticmethod
    def _is_hostname_pattern(value: str) -> bool:
        if not value or len(value) > 253:
            return False
        pattern = r"^(\*\.)?([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$"
        return bool(re.match(pattern, value, re.IGNORECASE))

    def _validate_emitted_envelope(self, envelope: Dict[str, Any]) -> None:
        if envelope.get("algorithm") != ALGORITHM_LITERAL:
            raise ValueError("Envelope algorithm must be HMAC-SHA256")
        payload = envelope.get("payload")
        signature = envelope.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise ValueError("Envelope must contain payload dict and signature string")

        required_fields = {
            "scope_id",
            "operator_id",
            "nex_modules",
            "allowed_targets",
            "expires_at",
            "issued_at",
        }
        missing = sorted(required_fields - set(payload.keys()))
        if missing:
            raise ValueError(f"Token payload missing required fields: {missing}")

        if not isinstance(payload["nex_modules"], list):
            raise ValueError("nex_modules must be list[str]")
        for module_id in payload["nex_modules"]:
            if not isinstance(module_id, str):
                raise ValueError("nex_modules must be list[str]")

        if "authorized_cidrs" in payload and not isinstance(payload["authorized_cidrs"], list):
            raise ValueError("authorized_cidrs must be list[str] when provided")

        validator = NexEnvelopeValidator(self.hmac_key)
        ok, reason = validator.validate_with_reason(
            envelope,
            target="0.0.0.0",
            operator_id=self.operator_id,
            nex_module_ids=[],
        )
        if reason not in _NEX_REASON_CODES:
            raise ValueError(f"Unexpected nex reason code: {reason}")
        if not ok and reason != "nex_target_out_of_scope":
            # We pass a synthetic target that may fail target checks intentionally.
            raise ValueError(f"Generated envelope failed compatibility validation: {reason}")


def generate_token_json(
    engagement: Engagement,
    operator_id: str,
    hmac_key: bytes,
    ttl_seconds: int = 3600,
    pretty: bool = False,
    scope_id: Optional[str] = None,
) -> str:
    envelope = ScopeTokenGenerator(
        engagement=engagement,
        operator_id=operator_id,
        hmac_key=hmac_key,
        ttl_seconds=ttl_seconds,
        scope_id=scope_id,
    ).generate()
    if pretty:
        return json.dumps(envelope, indent=2, sort_keys=True)
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True)


def generate_token_file(
    engagement: Engagement,
    operator_id: str,
    hmac_key: bytes,
    output_path: str,
    ttl_seconds: int = 3600,
    scope_id: Optional[str] = None,
) -> str:
    data = generate_token_json(
        engagement=engagement,
        operator_id=operator_id,
        hmac_key=hmac_key,
        ttl_seconds=ttl_seconds,
        pretty=True,
        scope_id=scope_id,
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(data)
    return output_path


def validate_token_with_reason(
    envelope: Dict[str, Any],
    *,
    hmac_key: bytes,
    target: str,
    operator_id: Optional[str],
    nex_module_ids: list[str],
) -> tuple[bool, str]:
    validator = NexEnvelopeValidator(hmac_key)
    ok, reason = validator.validate_with_reason(
        envelope,
        target=target,
        operator_id=operator_id,
        nex_module_ids=nex_module_ids,
    )
    manifest_codes = governance_reason_codes()
    if reason not in _NEX_REASON_CODES:
        return False, "nex_validation_error"
    if manifest_codes and reason not in manifest_codes:
        return False, "nex_validation_error"
    return ok, reason
