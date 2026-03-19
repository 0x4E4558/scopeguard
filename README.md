ScopeGuard
Penetration Test Scope & ROE Builder.

Guides you through building a complete, technically validated, legally defensible Scope of Work and Rules of Engagement document pair — catching every ambiguity, missing field, and inconsistency before anything gets signed.

Install & Run
# 1. Create venv and install dependencies (run once)
bash setup.sh

# 2. Start the app
bash run.sh
Then open http://127.0.0.1:5000 in your browser.

All data is stored locally in ./data/scopeguard.db. Nothing leaves your machine.

Run the test suite
bash run_tests.sh
92 tests covering all 20 field-level (VAL) and 16 cross-reference (XRF) validation rules against the MCB sample engagement and the deliberately-broken Nexus fixture.

Requirements
Python 3.10 or later
No other system dependencies
What ScopeGuard produces
Two .docx files per engagement, downloaded directly from the Pre-flight Report page:

Scope of Work (SOW)

Cover page with classification header and standards alignment notice
Engagement metadata and period tables
Client and testing team contact tables
In-scope and out-of-scope asset tables with CIDR/subnet/VLAN detail
Social engineering scope matrix
Deliverables schedule
Data governance obligations
Full legal section: authorization defense, law enforcement intervention obligation, indemnification, limitation of liability, findings validity disclaimer (point-in-time), confidentiality, governing law
Signature blocks
Rules of Engagement (ROE)

Companion document to the SOW
Communication protocols and 4-hour critical finding notification rule
Technique authorization matrix organized by MITRE ATT&CK tactic, with ATT&CK Technique IDs (T-numbers) in every row
Absolute prohibitions list
Maintenance windows table
Evidence collection standards
Safe harbor clause and law enforcement contact/detention guidance
Appendix A: Framework References (ATT&CK, NIST SP 800-115, PTES, OWASP, CVSS v3.1, CVE/NVD, CWE)
Signature and team acknowledgment tables
Standards alignment
Documents produced by ScopeGuard align with:

Framework	Application
MITRE ATT&CK Enterprise v15	Technique taxonomy, tactic/technique IDs in ROE matrix
NIST SP 800-115	Testing phase classification (Planning/Discovery/Attack/Reporting)
PTES	Engagement phase structure
OWASP Testing Guide v4.2	Web application and API technique references
CVSS v3.1	Finding severity scoring reference
CVE / NVD	Vulnerability identifier references
CWE	Root-cause weakness classification
Legal protections
The generated SOW includes purpose-built legal language for penetration test engagements:

Authorization defense — satisfies the "authorization" element of the CFAA (18 U.S.C. § 1030) and state equivalents, establishing that authorized activities constitute lawful computer access
Law enforcement intervention obligation — client is contractually required to immediately confirm authorization to any detaining authority, provide a certified copy of the agreement to law enforcement on request, and cooperate fully (addresses situations like the Coalfire/Iowa incident, 2019)
Indemnification — client indemnifies the testing firm against criminal and civil claims arising from authorized activities
Limitation of liability — mutual, with carve-outs for gross negligence, willful misconduct, and client's failure to perform its intervention obligations
Findings validity disclaimer — explicit point-in-time limitation; findings reflect the state of systems at time of testing only
Confidentiality — 5-year survival period, indefinite for trade secrets
The ROE includes a safe harbor clause defining the five conditions that constitute authorized access, and specific guidance for personnel who are detained during testing.

How it works
Phase 1 — Validation engine
36 validation rules catch every class of engagement document failure:

Field-level rules (VAL-001 to VAL-020)

CIDR notation validity and subnet mask agreement
VLAN count consistency
Date range logic (end after start, retest after engagement, etc.)
Email format (RFC 5322)
IP address and CIDR range validity
Conditional technique approval workflows — rejects vague language
Credential reporting window (hard max: 4 hours)
Mandatory third-party disclosure prohibition
Signature fields required before executed status
Cross-reference rules (XRF-001 to XRF-016)

CIDR overlap between in-scope and out-of-scope asset lists
Subnet/supernet conflicts
Dangling maintenance window references
Notification recipient references pointing to undefined contacts
Blackout and maintenance window dates outside engagement period
Missing required contacts for the engagement type
PCI-DSS CDE asset identification
HIPAA exposure for full-scope engagements
Phase 2 — Intake form
Flask web UI, runs entirely locally on port 5000
SQLite storage with section-level autosave (600ms debounce)
10 sections covering all 8 schema groups
Collapsible list items with persistent headers showing name, status badge, and key identifiers
Contacts section: Required Contacts panel listing every role required for the engagement type with descriptions, required/optional badges, and one-click Add buttons. "Add All Missing" button scaffolds all unfilled required roles at once.
Role picker: Custom dropdown replacing the plain select for the role field — shows each role with a description, REQUIRED/OPTIONAL badge, ATTORNEY badge where applicable, and client/tester grouping
Legal Credentials section (bar number, jurisdiction, law firm) always visible in contact cards, prominent when role is Attorney/Legal Counsel, subdued otherwise
Pre-flight report with findings grouped by severity (BLOCK/CLARIFY/MISSING/NOTE). Links go directly to the relevant section and field — clicking a contact finding opens the contacts section with the missing role pre-selected; clicking a field finding scrolls to and highlights the specific input
Live findings panel (bottom-right) updates as you type
Phase 3 — Document generation
SOW and ROE generated as .docx from validated engagement data
Download buttons appear on the Pre-flight Report page once all BLOCK findings are resolved
Filenames: [EngagementID]-Scope-of-Work.docx and [EngagementID]-Rules-of-Engagement.docx
Project layout
setup.sh                # Run once to create venv + install deps
run.sh                  # Start the app
run_tests.sh            # Run the validation test suite

app.py                  # Flask entry point

app/
  __init__.py           # Flask routes, required role matrix
  storage.py            # SQLite persistence
  form_builder.py       # Schema YAML -> form field specs
  hydrator.py           # Storage JSON -> Engagement model
  generator.py          # SOW and ROE .docx generation
  legal.py              # Legal protective clauses library
  templates/            # Jinja2 HTML templates
  static/               # CSS (IBM Plex Sans/Mono, dark theme) and JS

scopeguard/             # Validation engine
  models.py             # Engagement dataclasses (8 groups)
  validator.py          # 36 validation rules (VAL + XRF)
  finding.py            # Finding / FindingList / Severity
  schema_loader.py      # YAML schema loader

schema/                 # 8 YAML schema files (one per group)
  engagement.yaml       # Group 1: identity and metadata
  period.yaml           # Group 2: dates and testing windows
  contacts.yaml         # Group 3: contact records and roles
  assets.yaml           # Group 4: in-scope, out-of-scope, physical
  techniques.yaml       # Group 5: authorization matrix (ATT&CK mapped)
  maintenance_windows.yaml  # Group 6: disruptive testing windows
  data_governance.yaml  # Group 7: evidence and data handling
  social_engineering.yaml   # Group 8: SE scope and constraints

tests/
  test_field_rules.py   # VAL-001 through VAL-020 unit tests
  test_xref_rules.py    # XRF-001 through XRF-016 unit tests
  conftest.py           # Fixture loader and pytest helpers
  fixtures/
    mcb.json            # Canonical valid engagement (Meridian Community Bank)
    nexus_bad.json      # Deliberately broken engagement for error detection

data/                   # SQLite DB created here on first run
Disclaimer
Legal clauses in generated documents are drafted as protective commercial contract language for authorized penetration testing engagements. They are not a substitute for qualified legal counsel. Both parties should have documents reviewed by attorneys licensed in the applicable jurisdiction before execution.

ScopeGuard is a pre-engagement document builder. It does not send packets, make network connections, or interact with any external services. All data remains on your machine.

The Attached .docx files are the output from the application.
