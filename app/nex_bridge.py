"""
nex_bridge
~~~~~~~~~~
Post-generation bridge: compiles a validated Nex Engagement into the
Nex policy bundle that BootPolicy.initialise() reads at session startup.

Workflow (called by nex/app/generator.py after .docx files land on disk):

    1. hash_document(sow_path), hash_document(roe_path)  →  sow_hash, roe_hash
    2. build_roe_constraints(engagement, sow_hash)        →  ROEConstraints
    3. write_policy_bundle(...)                           →  /etc/nex-policy.json

After BootPolicy.initialise() returns a BootSession, the caller must invoke:

    4. post_bootstrap_commit(boot_session, roe, recovery_dir)
                                                          →  RecoveryRecord

Design notes
------------
* This module imports Nex's native classes directly.  It does NOT reimplement
  ScopeToken, ScopeTokenManager, EvidenceLedger, or SessionRecoveryManager —
  doing so would produce an incompatible wire format.
* BootPolicy.initialise() generates a fresh session HMAC key at runtime.
  The bridge therefore cannot pre-issue a ScopeToken for runtime enforcement;
  instead it writes the machine-readable policy bundle from which BootPolicy
  constructs its own ROEConstraints and ScopeTokenManager.  The ScopeToken
  used at module-execution time is issued by BootPolicy's ScopeTokenManager
  and passed via context["scope_token"].
* post_bootstrap_commit() must be called immediately after BootPolicy returns
  so that SessionRecoveryManager has a RecoveryRecord on disk before any
  module runs.  If the process is interrupted between bootstrap and commit, the
  engagement must be restarted from the policy bundle — which remains on disk.
* Standard library only.  All Nex imports are guarded so that Nex's
  test suite can import this module without a full Nex installation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
import warnings
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Optional

# ---------------------------------------------------------------------------
# Nex imports — guarded for environments where nex is not on sys.path
# ---------------------------------------------------------------------------

try:
    from core.policy_engine import ROEConstraints, TechniqueClass
    _NEX_POLICY_AVAILABLE = True
except ImportError:
    try:
        from policy_engine import ROEConstraints, TechniqueClass  # type: ignore
        _NEX_POLICY_AVAILABLE = True
    except ImportError:
        _NEX_POLICY_AVAILABLE = False
        ROEConstraints = None  # type: ignore
        TechniqueClass = None  # type: ignore

try:
    from core.session_recovery import SessionRecoveryManager, RecoveryRecord
    _NEX_RECOVERY_AVAILABLE = True
except ImportError:
    try:
        from session_recovery import SessionRecoveryManager, RecoveryRecord  # type: ignore
        _NEX_RECOVERY_AVAILABLE = True
    except ImportError:
        _NEX_RECOVERY_AVAILABLE = False
        SessionRecoveryManager = None  # type: ignore
        RecoveryRecord = None  # type: ignore

# TYPE_CHECKING-only imports so type checkers can resolve the annotations
# without requiring the packages at runtime.
if TYPE_CHECKING:
    from nex.models import Engagement, Technique, AuthorizationStatus
    from core.boot_policy import BootSession
    from core.operator_identity import OperatorKeyring

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHUNK_SIZE       = 65536          # file-hashing block size in bytes
POLICY_VERSION   = "1.0"
DEFAULT_POLICY_PATH = Path(
    os.environ.get("NEX_POLICY_PATH", "/etc/nex-policy.json")
)
DEFAULT_RECOVERY_DIR = Path(
    os.environ.get("NEX_RECOVERY_DIR", "/var/lib/nex/recovery")
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Technique-ID prefix → TechniqueClass mapping
#
# Source of truth: nex/schema/techniques.yaml (technique_id prefixes)
# mapped to nex/core/policy_engine.py TechniqueClass enum values.
# PE-* ids are resolved individually because the category is split across
# multiple TechniqueClass values.
# ---------------------------------------------------------------------------

# Prefix-level table.  Evaluated first; PE-* handled by exact-id table below.
_PREFIX_MAP = {
    "REC-":  "RECON",
    "VS-":   "VULNERABILITY_SCAN",
    "EXP-":  "EXPLOIT",
    "DOS-":  "EXPLOIT",
    "SE-":   "RECON",
    "PHY-":  "RECON",
}

# Compatibility aliases used by older fixtures and legacy exports.
# These are normalized before prefix matching so we do not silently drop
# authorised techniques when a historical TECH-* identifier is encountered.
_ALIAS_PREFIX_MAP = {
    "TECH-RECON-":  "REC-",
    "TECH-VULN-":   "VS-",
    "TECH-EXPLOIT-": "EXP-",
    "TECH-POST-":   "PE-",
    "TECH-DOS-":    "DOS-",
    "TECH-SE-":     "SE-",
    "TECH-PHYS-":   "PHY-",
}

# Exact technique_id overrides for PE-* (post-exploitation sub-split).
_PE_EXACT_MAP = {
    "PE-001": "LATERAL_MOVEMENT",
    "PE-002": "LATERAL_MOVEMENT",
    "PE-003": "LATERAL_MOVEMENT",
    "PE-004": "LATERAL_MOVEMENT",
    "PE-005": "LATERAL_MOVEMENT",
    "PE-006": "EXPLOIT",
    "PE-007": "EXPLOIT",
    "PE-008": "LATERAL_MOVEMENT",
    "PE-009": "LATERAL_MOVEMENT",
    "PE-010": "PERSISTENCE",
    "PE-011": "CREDENTIAL_HARVEST",
    "PE-012": "CREDENTIAL_HARVEST",
    "PE-013": "LATERAL_MOVEMENT",
    "PE-014": "EXPLOIT",
}


# ---------------------------------------------------------------------------
# Atomic write helper
# ---------------------------------------------------------------------------

def _atomic_json_write(path: Path, obj: dict) -> None:
    """Write *obj* as sorted-key JSON to *path* atomically (temp → fsync → rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def hash_document(path: str | Path) -> str:
    """Return the SHA-256 hex digest of the file at *path*.

    Reads in CHUNK_SIZE-byte blocks so memory usage is bounded regardless of
    document size.

    Raises:
        FileNotFoundError: If *path* does not exist.
        OSError:           If the file cannot be opened or read.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def map_techniques(techniques: List[Any]) -> List[Any]:
    """Map authorised Nex Technique objects to TechniqueClass values.

    Filters to techniques where:
        authorization_status == AuthorizationStatus.AUTHORIZED
        prohibited           == False

    Maps each qualifying technique_id to a TechniqueClass using the prefix
    table defined in this module.  Unrecognised IDs are logged and skipped —
    they do not raise an exception so that unknown future technique IDs do not
    block document generation.

    Returns a deduplicated, sorted list of TechniqueClass instances.

    Raises:
        RuntimeError: If the Nex policy_engine module is not importable.
    """
    if not _NEX_POLICY_AVAILABLE:
        raise RuntimeError(
            "nex/core/policy_engine.py is not importable.  Ensure that the "
            "nex package root is on sys.path before calling map_techniques()."
        )

    result: set[str] = set()

    for tech in techniques:
        # Resolve enum values to strings for comparison.
        auth_status = tech.authorization_status
        auth_str    = auth_status.value if hasattr(auth_status, "value") else str(auth_status)

        if auth_str != "authorized":
            continue
        if tech.prohibited:
            continue

        tid = tech.technique_id

        # Normalise older TECH-* aliases onto the current catalogue prefixes
        # before applying the canonical mapping tables below.
        for alias_prefix, canonical_prefix in _ALIAS_PREFIX_MAP.items():
            if tid.startswith(alias_prefix):
                tid = canonical_prefix + tid[len(alias_prefix):]
                break

        # PE-* exact match first.
        if tid in _PE_EXACT_MAP:
            result.add(_PE_EXACT_MAP[tid])
            continue

        # Prefix match for all other categories.
        matched = False
        for prefix, tc_value in _PREFIX_MAP.items():
            if tid.startswith(prefix):
                result.add(tc_value)
                matched = True
                break

        if not matched:
            log.warning(
                "nex_bridge.map_techniques: technique_id %r matched no known "
                "prefix — skipped.  Add it to _PREFIX_MAP or _PE_EXACT_MAP.",
                tid,
            )

    # Convert string values to TechniqueClass enum members and return sorted.
    technique_classes = []
    for tc_value in sorted(result):
        try:
            technique_classes.append(TechniqueClass(tc_value))
        except ValueError:
            log.warning(
                "nex_bridge.map_techniques: %r is not a valid TechniqueClass "
                "value — skipped.",
                tc_value,
            )

    return technique_classes


def _derive_operator_id(engagement: Any) -> str:
    """Return the operator_id for this engagement.

    Reads from the contact with role 'engagement_lead'.  This is the
    authoritative identity that ROEConstraints.operator_id carries, and the
    value Nex uses to attribute every ledger entry.

    Raises:
        ValueError: If no contact with role 'engagement_lead' exists.
    """
    lead = engagement.contact_by_role("engagement_lead")
    if lead is None:
        raise ValueError(
            "Engagement has no contact with role 'engagement_lead'.  "
            "An engagement lead is required to derive operator_id for the "
            "Nex ROEConstraints.  Add the contact before generating documents."
        )
    return lead.email


def build_roe_constraints(engagement: Any, sow_hash: str) -> Any:
    """Build a Nex ROEConstraints from a validated Nex Engagement.

    This is the native Nex ROEConstraints dataclass from core/policy_engine.py,
    not a local reimplementation.  BootPolicy._build_roe_constraints() reads
    the same fields from the policy bundle and constructs an identical object —
    this function is provided so the caller can verify the constraints before
    writing the bundle, and so post_bootstrap_commit() can pass them directly
    to SessionRecoveryManager.commit_pre_launch().

    Args:
        engagement: Hydrated Engagement object from nex/app/hydrator.py.
        sow_hash:   SHA-256 hex digest of the SOW .docx file, produced by
                    hash_document().

    Returns:
        A fully populated ROEConstraints instance.

    Raises:
        RuntimeError: If nex/core/policy_engine.py is not importable.
        ValueError:   If no engagement_lead contact is present.
    """
    if not _NEX_POLICY_AVAILABLE:
        raise RuntimeError(
            "nex/core/policy_engine.py is not importable.  Ensure that the "
            "nex package root is on sys.path before calling build_roe_constraints()."
        )

    operator_id = _derive_operator_id(engagement)

    allowed_targets = [a.cidr_notation for a in engagement.in_scope_assets]
    restricted_targets = [a.cidr_notation for a in engagement.out_of_scope_assets]
    allowed_techniques = map_techniques(engagement.techniques)

    window_start = int(engagement.period.authorized_start_date.timestamp())
    window_end   = int(engagement.period.authorized_end_date.timestamp())

    return ROEConstraints(
        allowed_targets    = allowed_targets,
        allowed_techniques = allowed_techniques,
        restricted_targets = restricted_targets,
        window_start       = window_start,
        window_end         = window_end,
        operator_id        = operator_id,
        sow_hash           = sow_hash,
        policy_version     = POLICY_VERSION,
    )


def write_policy_bundle(
    engagement:               Any,
    sow_path:                 str | Path,
    roe_path:                 str | Path,
    *,
    path:                     Optional[str | Path] = None,
    runtime_mode:             str = "OFFENSIVE_MODE",
    expected_environment_hash: str = "",
) -> dict:
    """Hash the SOW/ROE documents and write the Nex policy bundle.

    This is the primary entry point called by nex/app/generator.py
    after both .docx files have been written to disk.

    The bundle is written to /etc/nex-policy.json (or the path
    specified by the NEX_POLICY_PATH environment variable, or the *path*
    argument).  BootPolicy.initialise() reads this file via
    _load_policy_bundle() and constructs ROEConstraints, ScopeTokenManager,
    PolicyDecisionEngine, EvidenceLedger, NexHub, and ExecutionGate from it.

    Policy bundle fields consumed by boot_policy._build_roe_constraints():
        runtime_mode              — RuntimeMode value string.
        expected_environment_hash — SHA-256 of /etc/nex-manifest;
                                    pass "" to skip manifest verification.
        tactical_window_start     — Unix epoch int (engagement start).
        tactical_window_end       — Unix epoch int (engagement end).
        allowed_targets           — In-scope CIDR list.
        allowed_techniques        — TechniqueClass value strings (e.g. "RECON").
        restricted_targets        — Out-of-scope CIDR list.
        sow_hash                  — SHA-256 of the SOW .docx file.
        policy_version            — "1.0".

    Args:
        engagement:               Hydrated Engagement from hydrator.py.
        sow_path:                 Path to the SOW .docx file on disk.
        roe_path:                 Path to the ROE .docx file on disk.
        path:                     Override destination path.  Defaults to
                                  DEFAULT_POLICY_PATH.
        runtime_mode:             RuntimeMode string for boot_policy.
                                  Defaults to "OFFENSIVE_MODE".
        expected_environment_hash: SHA-256 hex of /etc/nex-manifest.
                                  Pass "" (default) to skip manifest check.

    Returns:
        The policy bundle dict that was written, for inspection or testing.

    Raises:
        FileNotFoundError: If sow_path or roe_path does not exist.
        ValueError:        If no engagement_lead contact is present.
        OSError:           On write failure.
    """
    sow_hash = hash_document(sow_path)
    roe_hash = hash_document(roe_path)

    operator_id = _derive_operator_id(engagement)

    allowed_targets    = [a.cidr_notation for a in engagement.in_scope_assets]
    restricted_targets = [a.cidr_notation for a in engagement.out_of_scope_assets]
    window_start       = int(engagement.period.authorized_start_date.timestamp())
    window_end         = int(engagement.period.authorized_end_date.timestamp())

    # TechniqueClass values as strings — BootPolicy calls TechniqueClass(raw.upper())
    # on each entry, so these must exactly match TechniqueClass enum values.
    allowed_technique_strs: List[str] = []
    if _NEX_POLICY_AVAILABLE:
        technique_classes = map_techniques(engagement.techniques)
        allowed_technique_strs = [
            tc.value if hasattr(tc, "value") else str(tc)
            for tc in technique_classes
        ]
    else:
        warnings.warn(
            "nex/core/policy_engine.py is not importable; allowed_techniques "
            "will be empty in the policy bundle.  BootPolicy will fall back to "
            "mode defaults.  Add nex to sys.path to populate this field.",
            RuntimeWarning,
            stacklevel=2,
        )

    bundle: dict = {
        # ── Fields read by boot_policy._load_policy_bundle() ──────────────────
        "runtime_mode":              runtime_mode,
        "expected_environment_hash": expected_environment_hash,
        "tactical_window_start":     window_start,
        "tactical_window_end":       window_end,
        "allowed_targets":           sorted(allowed_targets),
        "allowed_techniques":        sorted(allowed_technique_strs),
        "restricted_targets":        sorted(restricted_targets),
        "sow_hash":                  sow_hash,
        "policy_version":            POLICY_VERSION,
        # ── Chain-of-custody metadata (not read by BootPolicy, audit use only) ─
        "engagement_id":             engagement.identity.engagement_id,
        "operator_id":               operator_id,
        "roe_hash":                  roe_hash,
        "generated_at":              int(time.time()),
    }

    target = Path(path) if path else DEFAULT_POLICY_PATH
    _atomic_json_write(target, bundle)
    log.info("nex_bridge: policy bundle written to %s", target)

    return bundle


def post_bootstrap_commit(
    boot_session:     Any,
    roe:              Any,
    recovery_dir:     Optional[str | Path] = None,
    operator_keyring: Optional[Any] = None,
) -> Any:
    """Commit the pre-launch recovery record after BootPolicy.initialise() returns.

    Must be called immediately after BootPolicy.initialise() and before any
    call to NexOrchestrator.run().  This ensures that if the process is
    interrupted during or after session startup, Nex can recover the full
    session state — including the ROE hash, ledger genesis hash, tactical
    window, and consumed scope token IDs — from the encrypted recovery file.

    The RecoveryRecord is encrypted with AES-256-CTR and MAC'd with
    HMAC-SHA256 using key material derived from boot_session.session_key.
    If the process crashes after this call, SessionRecoveryManager.recover()
    can reload the record given the same key material.

    Args:
        boot_session:     BootSession returned by BootPolicy.initialise().
                          Provides hub, ledger, token_manager, and session_key.
        roe:              ROEConstraints built by build_roe_constraints().
                          Must be the same constraints written to the policy
                          bundle — BootPolicy constructs an equivalent object
                          internally, but this call uses the bridge's copy so
                          that the roe_hash in the RecoveryRecord matches the
                          sow_hash embedded in the policy bundle.
        recovery_dir:     Override for the recovery record directory.  Defaults
                          to DEFAULT_RECOVERY_DIR.
        operator_keyring: Optional OperatorKeyring for dual-key record signing.
                          When None, the record is stored unsigned and a
                          UserWarning is issued by SessionRecoveryManager.

    Returns:
        The committed RecoveryRecord.

    Raises:
        RuntimeError:         If nex/core/session_recovery.py is not importable.
        RecoveryCommitError:  If the encrypted file cannot be written to disk.
    """
    if not _NEX_RECOVERY_AVAILABLE:
        raise RuntimeError(
            "nex/core/session_recovery.py is not importable.  Ensure that the "
            "nex package root is on sys.path before calling post_bootstrap_commit()."
        )

    storage_path = str(Path(recovery_dir) if recovery_dir else DEFAULT_RECOVERY_DIR)
    enc_key      = bytearray(boot_session.session_key)

    mgr = SessionRecoveryManager(
        storage_path          = storage_path,
        encryption_key_material = enc_key,
    )

    try:
        record = mgr.commit_pre_launch(
            hub              = boot_session.hub,
            roe              = roe,
            ledger           = boot_session.ledger,
            token_manager    = boot_session.token_manager,
            operator_keyring = operator_keyring,
        )
    finally:
        # Zero our local copy of the key — boot_session.session_key is the
        # authoritative copy; the manager zeroes its own internal buffer
        # via scorch() on shutdown.
        for i in range(len(enc_key)):
            enc_key[i] = 0

    log.info(
        "nex_bridge: pre-launch recovery record committed for session %s",
        boot_session.hub._session_id,
    )
    return record
