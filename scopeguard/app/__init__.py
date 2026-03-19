"""
app/__init__.py  (also serves as app.py entry point)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ScopeGuard Flask application.
Run with: python app.py  (from the scopeguard/ directory)
"""

import sys
import json
from pathlib import Path
from datetime import date, datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, request, jsonify, redirect, url_for, abort

from app.storage import init_db, create_engagement, load_engagement, \
    save_section, update_status, list_engagements, delete_engagement
from app.form_builder import get_all_sections, get_section_fields, SECTION_IDS
from app.hydrator import hydrate
from scopeguard.validator import Validator
from scopeguard.finding import Severity

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "scopeguard-local-dev"


def _json_serial(obj):
    if isinstance(obj, (date, datetime)):
        return obj.isoformat()
    raise TypeError(f"Not serializable: {type(obj)}")


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
                     'physical_locations', 'techniques', 'maintenance_windows'}

    required_roles = []
    if section_id == 'contacts':
        required_roles = _get_required_roles(record['data'])

    highlight_role  = request.args.get('highlight', '')
    highlight_field = request.args.get('field', '')

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
        return jsonify({
            "error": "Document generation blocked",
            "blockers": len(findings.blockers()),
            "message": "Resolve all BLOCK findings before generating documents.",
        }), 422

    from app.hydrator import hydrate
    from app.generator import generate_sow, generate_roe
    from flask import send_file
    import io

    engagement = hydrate(record["data"])
    eng_id_str = record["data"].get("identity", {}).get("engagement_id", eng_id[:8])

    if doc_type == "sow":
        docx_bytes = generate_sow(engagement)
        filename = f"{eng_id_str}-Scope-of-Work.docx"
    else:
        docx_bytes = generate_roe(engagement)
        filename = f"{eng_id_str}-Rules-of-Engagement.docx"

    return send_file(
        io.BytesIO(docx_bytes),
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename,
    )


# ─── Delete ───────────────────────────────────────────────────────────────────

@app.route("/engagement/<eng_id>/delete", methods=["POST"])
def delete_eng(eng_id):
    delete_engagement(eng_id)
    return redirect(url_for("index"))


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
        app.logger.warning(f"Validation error (returning empty findings): {e}")
        app.logger.debug(traceback.format_exc())
        from scopeguard.finding import FindingList
        return FindingList()


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
    return app


if __name__ == "__main__":
    init_db()
    print("\n  ScopeGuard running at http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
