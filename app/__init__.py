"""
app/__init__.py  (also serves as app.py entry point)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ScopeGuard Flask application.
Run with: python app.py  (from the scopeguard/ directory)
"""

import os
import sys
import json
import secrets
from pathlib import Path
from datetime import date, datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import (Flask, render_template, request, jsonify, redirect,
                   url_for, abort, send_file)

from app.storage import (
    init_db, create_engagement, load_engagement,
    save_section, update_status, list_engagements, delete_engagement,
    save_scope_artifact, load_latest_scope_artifact,
)
from app.form_builder import get_all_sections, get_section_fields, SECTION_IDS
from app.hydrator import hydrate
from scopeguard.validator import Validator
from scopeguard.finding import Severity
from scopeguard.models import DocumentStatus

app = Flask(__name__, template_folder="templates", static_folder="static")
# Secret key: prefer an environment variable so it stays stable across restarts.
# Falls back to a random key (sessions won't survive restarts, which is fine for
# a local single-user tool).
app.secret_key = os.environ.get("SCOPEGUARD_SECRET_KEY") or secrets.token_hex(32)


def _json_serial(obj):
    if isinstance(obj, (date, datetime)):
        return obj.isoformat()
    raise TypeError(f"Not serializable: {type(obj)}")


def _get_hmac_key() -> bytes:
    """Return the HMAC key for scope token signing.

    Resolution order:
        1. SCOPEGUARD_HMAC_SECRET / NEX_SCOPE_SECRET / SCOPEGUARD_HMAC_KEY
            environment variable (hex-encoded).
      2. data/hmac.key file (hex-encoded, one line).
      3. Development fallback: a deterministic key derived from app.secret_key.
         This is NOT suitable for production; set SCOPEGUARD_HMAC_KEY in prod.
    """
    env_key = (
        os.environ.get("SCOPEGUARD_HMAC_SECRET", "").strip()
        or os.environ.get("NEX_SCOPE_SECRET", "").strip()
        or os.environ.get("SCOPEGUARD_HMAC_KEY", "").strip()
    )
    if env_key:
        return bytes.fromhex(env_key)

    key_file = Path(__file__).parent.parent / "data" / "hmac.key"
    if key_file.exists():
        hex_key = key_file.read_text(encoding="utf-8").strip()
        return bytes.fromhex(hex_key)

    # Development fallback — not for production use
    import hashlib
    return hashlib.sha256(app.secret_key.encode("utf-8")).digest()


def _require_signed_documents(engagement, action_label: str):
    """Reject actions that depend on fully executed SOW/ROE signatures."""
    identity = engagement.identity
    if (
        identity.document_status != DocumentStatus.EXECUTED
        or not identity.all_signatures_present()
        or not identity.all_cryptographic_signatures_present()
    ):
        return jsonify({
            "error": f"{action_label} blocked",
            "message": (
                "The SOW and ROE must be fully signed (human sign-off plus "
                "cryptographic signatures/public keys for required signers) "
                "before this action can proceed."
            ),
        }), 422
    return None


# ─── Home ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    engagements = list_engagements()
    return render_template("index.html", engagements=engagements)


# ─── New engagement ───────────────────────────────────────────────────────────

@app.route("/new", methods=["POST"])
def new_engagement():
    row_id = create_engagement()
    return redirect(url_for("section", eng_id=row_id, section_id="identity"))


# ─── Section intake form ──────────────────────────────────────────────────────

@app.route("/engagement/<eng_id>/section/<section_id>")
def section(eng_id, section_id):
    if section_id not in SECTION_IDS:
        abort(404)
    record = load_engagement(eng_id)
    if record is None:
        abort(404)

    sections   = get_all_sections()
    fields     = get_section_fields(section_id)
    saved_data = record["data"].get(section_id, {})

    # Determine which sections are complete (have saved data)
    completed = {sid for sid in SECTION_IDS if record["data"].get(sid)}

    # Current section index for prev/next navigation
    idx      = SECTION_IDS.index(section_id)
    prev_sid = SECTION_IDS[idx - 1] if idx > 0 else None
    next_sid = SECTION_IDS[idx + 1] if idx < len(SECTION_IDS) - 1 else None

    LIST_SECTIONS = {'contacts', 'in_scope_assets', 'out_of_scope_assets',
                     'physical_locations', 'maintenance_windows'}

    required_roles = []
    if section_id == 'contacts':
        required_roles = _get_required_roles(record['data'])

    highlight_role  = request.args.get('highlight', '')
    highlight_field = request.args.get('field', '')

    # Load technique catalog for the technique matrix section
    technique_catalog = {}
    if section_id == 'techniques':
        import yaml as _yaml
        import pathlib as _pl
        _tfile = _pl.Path(__file__).parent.parent / 'schema' / 'techniques.yaml'
        _tdata = _yaml.safe_load(_tfile.read_text())
        technique_catalog = _tdata.get('catalog', {})

    return render_template(
        "section.html",
        eng_id=eng_id,
        section_id=section_id,
        section_idx=idx,
        sections=sections,
        fields=fields,
        saved_data=saved_data,
        completed=completed,
        prev_sid=prev_sid,
        next_sid=next_sid,
        record=record,
        is_list_section=(section_id in LIST_SECTIONS),
        required_roles=required_roles,
        highlight_role=highlight_role,
        highlight_field=highlight_field,
        technique_catalog=technique_catalog if section_id == 'techniques' else {},
    )


# ─── Save section (AJAX) ─────────────────────────────────────────────────────

@app.route("/engagement/<eng_id>/section/<section_id>/save", methods=["POST"])
def save_section_route(eng_id, section_id):
    if section_id not in SECTION_IDS:
        return jsonify({"error": "unknown section"}), 400

    record = load_engagement(eng_id)
    if record is None:
        return jsonify({"error": "engagement not found"}), 404

    body = request.get_json(force=True, silent=True) or {}
    section_data = body.get("data", {})

    # Guard: technique matrix must arrive as a list of dicts.
    # If it arrives as a plain dict (flat form scrape fired instead of matrix override),
    # that means the matrix JS didn't activate — discard the bad save rather than corrupt the data.
    if section_id == "techniques":
        if isinstance(section_data, dict):
            # Bad format — flat scrape. Return current findings without saving.
            updated = load_engagement(eng_id)
            findings = _run_validation(updated["data"])
            return jsonify({
                "ok": False,
                "error": "technique_format_error",
                "findings": _serialize_findings(findings),
                "block_count": len(findings.blockers()),
            })
        # Filter out any non-dict items defensively
        if isinstance(section_data, list):
            section_data = [t for t in section_data if isinstance(t, dict) and t.get("technique_id")]

    # Normalise array fields to lists.
    # The browser always sends these as JSON arrays, but defensive server-side
    # coercion prevents corruption from any edge-case client behaviour.
    _ARRAY_FIELDS_FLAT = {
        "social_engineering": {"phishing_target_departments", "approved_pretexts",
                               "excluded_se_targets", "usb_location_refs"},
    }
    _ARRAY_FIELDS_CONTACT = {"certifications", "authorized_source_ips"}

    if section_id in _ARRAY_FIELDS_FLAT and isinstance(section_data, dict):
        for field in _ARRAY_FIELDS_FLAT[section_id]:
            val = section_data.get(field)
            if val is None:
                section_data[field] = []
            elif isinstance(val, str):
                section_data[field] = [val] if val else []
            elif not isinstance(val, list):
                section_data[field] = list(val)

    if section_id == "contacts" and isinstance(section_data, list):
        for contact in section_data:
            if not isinstance(contact, dict):
                continue
            for field in _ARRAY_FIELDS_CONTACT:
                val = contact.get(field)
                if val is None:
                    contact[field] = []
                elif isinstance(val, str):
                    contact[field] = [val] if val else []
                elif not isinstance(val, list):
                    contact[field] = list(val)

    save_section(eng_id, section_id, section_data)

    # Run validation on the updated engagement
    updated = load_engagement(eng_id)
    findings = _run_validation(updated["data"])

    # For contacts section, return updated required_roles state
    updated_required_roles = None
    if section_id == 'contacts':
        updated_required_roles = _get_required_roles(updated["data"])

    return jsonify({
        "ok": True,
        "findings": _serialize_findings(findings),
        "block_count": len(findings.blockers()),
        "required_roles": updated_required_roles,
    })


# ─── Validate (full, AJAX) ────────────────────────────────────────────────────

@app.route("/engagement/<eng_id>/validate")
def validate_engagement(eng_id):
    record = load_engagement(eng_id)
    if record is None:
        abort(404)
    findings = _run_validation(record["data"])
    return jsonify({
        "findings": _serialize_findings(findings),
        "counts": findings.count(),
        "has_blockers": findings.has_blockers(),
    })


# ─── Pre-flight report ────────────────────────────────────────────────────────

@app.route("/engagement/<eng_id>/preflight")
def preflight(eng_id):
    record = load_engagement(eng_id)
    if record is None:
        abort(404)

    findings  = _run_validation(record["data"])
    sections  = get_all_sections()
    completed = {sid for sid in SECTION_IDS if record["data"].get(sid)}

    return render_template(
        "preflight.html",
        eng_id=eng_id,
        record=record,
        findings=findings,
        sections=sections,
        completed=completed,
        Severity=Severity,
    )


# ─── Document generation ──────────────────────────────────────────────────────

@app.route("/engagement/<eng_id>/generate/<doc_type>")
def generate_document(eng_id, doc_type):
    if doc_type not in ("sow", "roe"):
        abort(404)

    record = load_engagement(eng_id)
    if record is None:
        abort(404)

    findings = _run_validation(record["data"])
    if findings.has_blockers():
        block_count   = len(findings.blockers())
        return jsonify({
            "error": "Document generation blocked",
            "blockers": block_count,
            "message": (
                "Resolve all BLOCK findings before generating documents."
            ),
        }), 422

    from app.hydrator import hydrate
    from app.generator import generate_sow, generate_roe
    from scopeguard.scope_compiler import compile_scope, ScopeCompilationError
    import io

    try:
        engagement = hydrate(record["data"])
    except Exception as exc:
        app.logger.error("Hydration failed for %s: %s", eng_id, exc, exc_info=True)
        return jsonify({"error": "Document generation failed",
                        "message": "Engagement data could not be processed. "
                                   "Re-save each section and try again."}), 422

    signed_block = _require_signed_documents(engagement, "Document generation")
    if signed_block is not None:
        return signed_block

    eng_id_str = record["data"].get("identity", {}).get("engagement_id", eng_id[:8])

    # Compile scope and embed binding in the document (fail gracefully if
    # compilation is not yet possible for this engagement)
    scope_binding = None
    try:
        timestamp = datetime.now(timezone.utc).replace(tzinfo=None)
        artifact = compile_scope(engagement, timestamp, _get_hmac_key())
        scope_binding = {
            "scope_id":   artifact.scope_id,
            "scope_hash": artifact.scope_hash,
            "operator_id": artifact.operator_id,
        }
        # Persist scope artifact (append-only versioning)
        save_scope_artifact(eng_id, {
            "scope_id":   artifact.scope_id,
            "scope_hash": artifact.scope_hash,
            "operator_id": artifact.operator_id,
            "scope":  artifact.scope,
            "token":  artifact.token,
            "audit":  artifact.audit,
        })
    except (ScopeCompilationError, ValueError, TypeError):
        # Scope compilation is best-effort during document generation;
        # documents are still generated without scope binding if it fails.
        scope_binding = None

    _DOCS_DIR = Path(__file__).parent.parent / "data" / "docs"
    _DOCS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        if doc_type == "sow":
            sow_path = _DOCS_DIR / f"{eng_id}-sow.docx"
            docx_bytes = generate_sow(engagement, scope_binding=scope_binding,
                                      output_path=sow_path)
            filename = f"{eng_id_str}-Scope-of-Work.docx"
        else:
            roe_path = _DOCS_DIR / f"{eng_id}-roe.docx"
            docx_bytes = generate_roe(engagement, scope_binding=scope_binding,
                                      output_path=roe_path)
            filename = f"{eng_id_str}-Rules-of-Engagement.docx"
    except Exception as exc:
        app.logger.error("Document generation failed for %s (%s): %s",
                         eng_id, doc_type, exc, exc_info=True)
        return jsonify({"error": "Document generation failed",
                        "message": "An error occurred while building the document. "
                                   "Check the server log for details."}), 500

    return send_file(
        io.BytesIO(docx_bytes),
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/engagement/<eng_id>/generate/draft/<doc_type>")
def generate_draft_document(eng_id, doc_type):
    """Generate a printable draft document for client review and approval.

    This route bypasses all signature and execution-status gates so that
    documents can be printed and sent to the client at any stage of the
    engagement workflow.  No execution token or scope binding is embedded;
    the document is watermarked as DRAFT — PENDING SIGNATURE.
    """
    if doc_type not in ("sow", "roe"):
        abort(404)

    record = load_engagement(eng_id)
    if record is None:
        abort(404)

    from app.hydrator import hydrate
    from app.generator import generate_sow, generate_roe
    import io as _io

    try:
        engagement = hydrate(record["data"])
    except Exception as exc:
        app.logger.error("Hydration failed for %s: %s", eng_id, exc, exc_info=True)
        return jsonify({"error": "Draft generation failed",
                        "message": "Engagement data could not be processed. "
                                   "Re-save each section and try again."}), 422

    eng_id_str = record["data"].get("identity", {}).get("engagement_id", eng_id[:8])

    try:
        if doc_type == "sow":
            docx_bytes = generate_sow(engagement, draft=True)
            filename = f"{eng_id_str}-Scope-of-Work-DRAFT.docx"
        else:
            docx_bytes = generate_roe(engagement, draft=True)
            filename = f"{eng_id_str}-Rules-of-Engagement-DRAFT.docx"
    except Exception as exc:
        app.logger.error("Draft generation failed for %s (%s): %s",
                         eng_id, doc_type, exc, exc_info=True)
        return jsonify({"error": "Draft generation failed",
                        "message": "An error occurred while building the document. "
                                   "Check the server log for details."}), 500

    return send_file(
        _io.BytesIO(docx_bytes),
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/engagement/<eng_id>/generate/scope-token")
def generate_scope_token_route(eng_id):
    """Generate a NEX-compatible scope token envelope for an engagement."""
    record = load_engagement(eng_id)
    if record is None:
        abort(404)

    findings = _run_validation(record["data"])
    if findings.has_blockers():
        return jsonify({
            "error": "Token generation blocked",
            "blockers": len(findings.blockers()),
            "message": "Resolve all BLOCK findings before generating tokens.",
        }), 422

    env_key = (
        os.environ.get("SCOPEGUARD_HMAC_SECRET", "").strip()
        or os.environ.get("NEX_SCOPE_SECRET", "").strip()
        or os.environ.get("SCOPEGUARD_HMAC_KEY", "").strip()
    )
    if not env_key:
        return jsonify({
            "error": "Token generation blocked",
            "message": (
                "Set SCOPEGUARD_HMAC_SECRET (or NEX_SCOPE_SECRET) before "
                "requesting a scope token."
            ),
        }), 422

    from scopeguard.token_generator import generate_token_json

    try:
        engagement = hydrate(record["data"])
        signed_block = _require_signed_documents(engagement, "Token generation")
        if signed_block is not None:
            return signed_block
        operator = engagement.contact_by_role("engagement_lead")
        token_json = generate_token_json(
            engagement=engagement,
            operator_id=(operator.full_name if operator else engagement.identity.engagement_id),
            hmac_key=bytes.fromhex(env_key),
            scope_id=None,
        )
    except Exception as exc:
        app.logger.error("Scope token generation failed for %s: %s", eng_id, exc, exc_info=True)
        return jsonify({
            "error": "Token generation blocked",
            "message": "Engagement data could not be processed. Re-save each section and try again.",
        }), 422

    return app.response_class(token_json, mimetype="application/json")

# ─── Delete ───────────────────────────────────────────────────────────────────

@app.route("/engagement/<eng_id>/delete", methods=["POST"])
def delete_eng(eng_id):
    delete_engagement(eng_id)
    return redirect(url_for("index"))


# ─── Scope artifact ───────────────────────────────────────────────────────────

@app.route("/engagement/<eng_id>/scope")
def scope_artifact(eng_id):
    """Compile and return the machine-enforceable scope.json for this engagement.

    Validates the engagement, compiles a ScopeArtifact, persists it, and
    returns the canonical scope.json as a downloadable file.
    """
    record = load_engagement(eng_id)
    if record is None:
        abort(404)

    findings = _run_validation(record["data"])
    if findings.has_blockers():
        return jsonify({
            "error": "Scope compilation blocked",
            "blockers": len(findings.blockers()),
            "message": "Resolve all BLOCK findings before compiling scope.",
        }), 422

    from app.hydrator import hydrate
    from scopeguard.scope_compiler import compile_scope, ScopeCompilationError
    from scopeguard.canonicalize import canonical_json
    import io as _io

    try:
        engagement = hydrate(record["data"])
        signed_block = _require_signed_documents(engagement, "Scope compilation")
        if signed_block is not None:
            return signed_block
        timestamp = datetime.now(timezone.utc).replace(tzinfo=None)
        artifact = compile_scope(engagement, timestamp, _get_hmac_key())
    except ScopeCompilationError:
        return jsonify({"error": "Scope compilation error", "detail": "One or more required engagement fields are missing or invalid."}), 422

    save_scope_artifact(eng_id, {
        "scope_id":   artifact.scope_id,
        "scope_hash": artifact.scope_hash,
        "operator_id": artifact.operator_id,
        "scope":  artifact.scope,
        "token":  artifact.token,
        "audit":  artifact.audit,
    })

    eng_id_str = record["data"].get("identity", {}).get("engagement_id", eng_id[:8])
    buf = _io.BytesIO(canonical_json(artifact.scope).encode("utf-8"))
    buf.seek(0)
    return send_file(buf, mimetype="application/json", as_attachment=True,
                     download_name=f"{eng_id_str}-scope.json")


@app.route("/engagement/<eng_id>/nex-export", methods=["POST"])
def nex_export(eng_id):
    """Write the full scope artifact set to the Nex artifact directory layout.

    Writes to the configured Nex artifacts directory (default:
    /var/lib/nex/artifacts, overridable via SCOPEGUARD_NEX_ARTIFACTS_DIR env
    var).  Returns a JSON manifest describing what was written.
    """
    record = load_engagement(eng_id)
    if record is None:
        abort(404)

    findings = _run_validation(record["data"])
    if findings.has_blockers():
        return jsonify({
            "error": "Nex export blocked",
            "blockers": len(findings.blockers()),
            "message": "Resolve all BLOCK findings before exporting to Nex.",
        }), 422

    from app.hydrator import hydrate
    from app.nex_export import export_to_nex
    from scopeguard.scope_compiler import compile_scope, ScopeCompilationError

    try:
        engagement = hydrate(record["data"])
        signed_block = _require_signed_documents(engagement, "Nex export")
        if signed_block is not None:
            return signed_block
        timestamp = datetime.now(timezone.utc).replace(tzinfo=None)
        artifact = compile_scope(engagement, timestamp, _get_hmac_key())
    except ScopeCompilationError:
        return jsonify({"error": "Scope compilation error", "detail": "One or more required engagement fields are missing or invalid."}), 422

    try:
        manifest = export_to_nex(artifact, timestamp)
    except OSError:
        return jsonify({"error": "Nex export failed",
                        "detail": "Unable to write to the Nex artifact directory."}), 500

    # Also persist in DB
    save_scope_artifact(eng_id, {
        "scope_id":   artifact.scope_id,
        "scope_hash": artifact.scope_hash,
        "operator_id": artifact.operator_id,
        "scope":  artifact.scope,
        "token":  artifact.token,
        "audit":  artifact.audit,
    })

    return jsonify(manifest)



# ─── JSON export ──────────────────────────────────────────────────────────────

@app.route("/engagement/<eng_id>/export")
def export_engagement(eng_id):
    """Download the raw engagement data as a JSON file for backup or transfer."""
    record = load_engagement(eng_id)
    if record is None:
        abort(404)

    eng_id_str = record["data"].get("identity", {}).get("engagement_id", eng_id[:8])
    filename = f"{eng_id_str}-engagement.json"

    export_data = {
        "scopeguard_export": True,
        "exported_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "engagement_row_id": eng_id,
        "data": record["data"],
    }
    import io as _io
    buf = _io.BytesIO(json.dumps(export_data, indent=2, default=_json_serial).encode("utf-8"))
    buf.seek(0)
    return send_file(buf, mimetype="application/json", as_attachment=True,
                     download_name=filename)


# ─── JSON import ──────────────────────────────────────────────────────────────

@app.route("/import", methods=["POST"])
def import_engagement():
    """Accept a previously exported JSON file and create a new engagement from it."""
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        payload = json.loads(uploaded.read().decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return jsonify({"error": f"Invalid JSON: {exc}"}), 400

    # Accept either the exported envelope or a bare data dict
    data = payload.get("data", payload) if isinstance(payload, dict) else {}
    if not isinstance(data, dict):
        return jsonify({"error": "Unrecognised format — expected a JSON object"}), 400

    row_id = create_engagement()
    for section_id, section_data in data.items():
        if section_id in SECTION_IDS and isinstance(section_data, (dict, list)):
            save_section(row_id, section_id, section_data)

    return redirect(url_for("section", eng_id=row_id, section_id="identity"))


# ─── Duplicate engagement ─────────────────────────────────────────────────────

@app.route("/engagement/<eng_id>/duplicate", methods=["POST"])
def duplicate_engagement(eng_id):
    """Create a copy of an existing engagement as a new draft."""
    record = load_engagement(eng_id)
    if record is None:
        abort(404)

    new_id = create_engagement()
    for section_id, section_data in record["data"].items():
        if section_id in SECTION_IDS and section_data:
            # Reset execution-specific fields in the identity copy
            if section_id == "identity":
                section_data = dict(section_data)
                section_data.pop("client_signatory_name", None)
                section_data.pop("client_signatory_date", None)
                section_data.pop("tester_lead_signatory_name", None)
                section_data.pop("tester_lead_signatory_date", None)
                section_data.pop("tester_principal_signatory_name", None)
                section_data.pop("tester_principal_signatory_date", None)
                section_data["document_status"] = "draft"
            save_section(new_id, section_id, section_data)

    return redirect(url_for("section", eng_id=new_id, section_id="identity"))

# ─── Helpers ──────────────────────────────────────────────────────────────────

_ROLE_MATRIX = {
    'authorizing_executive': {
        'label': 'Authorizing Executive',
        'description': 'The individual with legal authority to authorize penetration testing of all listed assets. Must sign the SOW. Typically CISO or equivalent.',
        'types': 'all', 'needs_mobile': True,
        'required_fields': ['full_name', 'title', 'phone_primary', 'phone_mobile', 'email'],
    },
    'primary_technical_contact': {
        'label': 'Primary Technical Contact',
        'description': 'Receives daily status reports and critical finding notifications. Delivers pre-engagement assets (IP lists, credentials). Must be reachable during all testing windows.',
        'types': 'all', 'needs_mobile': False,
        'required_fields': ['full_name', 'title', 'phone_primary', 'email'],
    },
    'emergency_halt_authority': {
        'label': 'Emergency Halt Authority',
        'description': 'The single individual who can issue an immediate stop-work order. Mobile number is mandatory — must be reachable at any hour during the engagement.',
        'types': 'all', 'needs_mobile': True,
        'required_fields': ['full_name', 'title', 'phone_primary', 'phone_mobile', 'email'],
    },
    'engagement_lead': {
        'label': 'Engagement Lead (Testing Firm)',
        'description': 'The testing firm\'s responsible point of contact. Accountable for ROE compliance by all team members. Signs the ROE.',
        'types': 'all', 'needs_mobile': True,
        'required_fields': ['full_name', 'title', 'phone_primary', 'phone_mobile', 'email'],
    },
    'business_continuity_contact': {
        'label': 'Business Continuity Contact',
        'description': 'Secondary escalation contact if the Primary Technical Contact and CISO are both unreachable during a critical finding. Required for full-scope engagements.',
        'types': ['full_scope', 'red_team'], 'needs_mobile': False,
        'required_fields': ['full_name', 'title', 'phone_primary', 'email'],
    },
    'soc_duty_contact': {
        'label': 'SOC / Incident Response Desk',
        'description': '24/7 operations contact for alert suppression configuration and incident coordination. Required for full-scope engagements where testing traffic must be whitelisted.',
        'types': ['full_scope', 'red_team'], 'needs_mobile': False,
        'required_fields': ['full_name', 'phone_primary', 'email'],
    },
    'legal_counsel': {
        'label': 'Attorney of Record',
        'description': 'The licensed attorney whose name appears on this engagement as the legal authority for social engineering pretext approval. This attorney bears professional responsibility for reviewing and approving all pretexts before use. Bar number and jurisdiction are required to establish the attorney\'s authority to provide legal approval in this engagement\'s jurisdiction.',
        'types': 'se_only', 'needs_mobile': False,
        'required_fields': ['full_name', 'law_firm', 'bar_number', 'bar_jurisdiction', 'phone_primary', 'email'],
        'attorney': True,
    },
    'physical_security_manager': {
        'label': 'Physical Security Manager',
        'description': 'Facility security contact who receives mandatory 24-hour pre-notification before any physical testing. Must coordinate colocation/third-party facility access.',
        'types': 'physical_only', 'needs_mobile': False,
        'required_fields': ['full_name', 'title', 'phone_primary', 'email'],
    },
}


def _get_required_roles(data):
    eng_type = data.get('identity', {}).get('engagement_type', '')
    has_phys = bool(data.get('physical_locations'))
    has_se   = bool(data.get('social_engineering'))
    filled   = {c.get('role') for c in (data.get('contacts') or []) if c.get('role')}

    result = []
    for role_id, meta in _ROLE_MATRIX.items():
        types = meta['types']
        if types == 'all':
            required = True
        elif types == 'se_only':
            required = has_se
        elif types == 'physical_only':
            required = has_phys
        elif isinstance(types, list):
            required = eng_type in types
        else:
            required = False

        if required:
            result.append({
                'role':         role_id,
                'label':        meta['label'],
                'description':  meta.get('description', ''),
                'filled':       role_id in filled,
                'needs_mobile': meta['needs_mobile'],
                'attorney':     meta.get('attorney', False),
                'required_fields': meta.get('required_fields', []),
            })
    return result


def _run_validation(data: dict):
    try:
        engagement = hydrate(data)
        return Validator(engagement).validate()
    except Exception as e:
        import traceback
        app.logger.warning(f"Validation error: {e}")
        app.logger.debug(traceback.format_exc())
        from scopeguard.finding import FindingList, Finding, Severity
        fl = FindingList()
        fl.add(Finding(
            rule_id="SYS-001",
            severity=Severity.BLOCK,
            description=f"Internal validation error — engagement data could not be processed: {e}",
            resolution="Check the server log for a full traceback. This is usually caused by "
                       "corrupted or partially-saved section data. Re-save each section to recover.",
        ))
        return fl


def _serialize_findings(findings) -> list[dict]:
    return [
        {
            "rule_id":       f.rule_id,
            "severity":      f.severity.value,
            "description":   f.description,
            "resolution":    f.resolution,
            "field_path":    f.field_path,
        }
        for f in findings
    ]


# ─── Entry point ─────────────────────────────────────────────────────────────

def create_app():
    init_db()
    # Fix any engagements where techniques was saved as a flat dict
    try:
        from app.storage import migrate_technique_data
        fixed = migrate_technique_data()
        if fixed:
            import logging
            logging.getLogger(__name__).info(
                f"[startup] Fixed corrupted technique data in {fixed} engagement(s)"
            )
    except Exception:
        pass
    return app

