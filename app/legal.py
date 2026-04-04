"""
app.legal
~~~~~~~~~
Legal protective clauses for Nex-generated documents.

These clauses are designed to:
1. Establish the signed agreement as a complete authorization defense under
   the Computer Fraud and Abuse Act (18 U.S.C. § 1030) and state equivalents.
2. Protect testing firm personnel from criminal and civil exposure for
   authorized activities (cf. Coalfire/Iowa Judicial Branch incident, 2019).
3. Obligate the client to intervene immediately if law enforcement contact
   occurs during authorized testing.
4. Indemnify the testing firm against third-party claims arising from
   activities the client expressly authorized.
5. Clearly bound the validity of findings to the time of testing.

IMPORTANT: These clauses are drafted as protective commercial contract
language. They are NOT a substitute for qualified legal counsel. Parties
should have these documents reviewed by attorneys licensed in the applicable
jurisdiction before execution.
"""

from __future__ import annotations


# ─── Clause library ───────────────────────────────────────────────────────────
# Each clause is a dict with:
#   title:    Section heading
#   body:     List of paragraph strings (each renders as a separate paragraph)
#   bullets:  Optional list of bullet strings

CLAUSES_SOW: list[dict] = [

    {
        "title": "Authorization and Lawful Access",
        "body": [
            "This Agreement constitutes express written authorization by the Client for the "
            "Testing Team to access, probe, test, and attempt to exploit the systems, networks, "
            "facilities, and personnel defined in Section 3 of this Agreement, during the "
            "authorized testing windows defined in Section 1.3, from the authorized source "
            "addresses defined in Section 2.2.",

            "The parties expressly agree that this authorization satisfies the 'authorization' "
            "element of the Computer Fraud and Abuse Act (18 U.S.C. § 1030), the Electronic "
            "Communications Privacy Act (18 U.S.C. §§ 2510–2523), and all substantially "
            "equivalent state computer crime, unauthorized access, and cybersecurity statutes, "
            "including but not limited to the law of the state(s) in which testing activities "
            "are conducted.",

            "Testing Team personnel acting in good faith within the defined scope, time windows, "
            "and source address restrictions of this Agreement are performing authorized computer "
            "access within the meaning of applicable law. No such activity shall constitute "
            "unauthorized access, unauthorized use, unauthorized interception of communications, "
            "trespass, or any related civil or criminal offense.",

            "The Client represents and warrants that it has legal authority to grant the "
            "authorizations provided herein with respect to all assets, systems, facilities, "
            "and personnel listed in Section 3, including assets hosted, managed, or operated "
            "by third parties on the Client's behalf where such authority exists.",
        ],
    },

    {
        "title": "Law Enforcement Contact and Client Intervention Obligation",
        "body": [
            "The Client acknowledges that authorized penetration testing activities — including "
            "physical security testing, social engineering, network scanning, and system "
            "exploitation — may, if observed by uninformed parties, appear indistinguishable "
            "from malicious activity. The parties have taken the following precautions to "
            "prevent unnecessary law enforcement contact and to protect Testing Team personnel "
            "in the event such contact occurs:",
        ],
        "bullets": [
            "Testing Team personnel conducting physical testing carry a signed authorization "
            "letter (Appendix B) at all times on Client premises. This letter identifies the "
            "bearer as an authorized security tester acting under contract.",

            "The Client's authorized emergency contact (identified in Section 2.1) is "
            "reachable at all times during active testing to verbally confirm authorization "
            "to any law enforcement officer, security officer, or facility personnel who "
            "challenges Testing Team personnel.",

            "The Client's General Counsel or designated legal representative is aware of "
            "this engagement and is prepared to provide written confirmation of authorization "
            "to law enforcement on short notice.",
        ],
        "body2": [
            "CLIENT INTERVENTION OBLIGATION: If any Testing Team personnel are detained, "
            "arrested, charged, or threatened with criminal or civil action by any law "
            "enforcement agency, private security force, or other third party in connection "
            "with activities authorized under this Agreement, the Client shall:",
        ],
        "bullets2": [
            "Immediately and unequivocally confirm the authorization of the relevant activities "
            "to the detaining authority, in writing if requested, within two (2) hours of "
            "notification by the Testing Team or its counsel.",

            "Provide any law enforcement agency, prosecutor, or court with a certified copy "
            "of this Agreement and the authorization letter (Appendix B) upon request.",

            "Cooperate fully with any investigation to establish that the Testing Team "
            "personnel were acting under lawful, written authorization at all relevant times.",

            "Not unreasonably withhold, delay, or qualify confirmation of authorization "
            "once activities have been verified as within scope and time window.",
        ],
        "body3": [
            "The Client's failure to perform the intervention obligations above, where such "
            "failure materially contributes to criminal charges, civil liability, or legal "
            "defense costs incurred by the Testing Team or its personnel, shall constitute "
            "a material breach of this Agreement.",
        ],
    },

    {
        "title": "Indemnification",
        "body": [
            "Client shall indemnify, defend, and hold harmless the Testing Team, its principals, "
            "officers, employees, subcontractors, and agents (collectively, 'Indemnified "
            "Parties') from and against any and all claims, demands, suits, proceedings, "
            "losses, liabilities, damages, costs, and expenses (including reasonable attorneys' "
            "fees) arising out of or relating to:",
        ],
        "bullets": [
            "Any criminal investigation, prosecution, or civil action brought by any third "
            "party — including any government agency, law enforcement body, or private party "
            "— against any Indemnified Party in connection with testing activities that were "
            "authorized under this Agreement and conducted within the defined scope, time "
            "windows, and source address restrictions;",

            "Any claim by a third party (including employees, vendors, customers, or regulators "
            "of the Client) arising from testing activities authorized under this Agreement;",

            "The Client's failure to obtain authorization from third-party asset owners before "
            "including third-party-operated assets within the testing scope;",

            "The Client's failure to perform its intervention obligations under the Law "
            "Enforcement Contact clause above.",
        ],
        "body2": [
            "This indemnification obligation shall survive the termination or expiration of "
            "this Agreement. It does not apply to activities conducted outside the defined "
            "scope, outside the authorized time windows, or from unauthorized source addresses, "
            "nor to activities prohibited under Section 3 of the Rules of Engagement document.",

            "The Testing Team shall promptly notify the Client of any claim for which "
            "indemnification may be sought and shall cooperate reasonably in the defense of "
            "such claim. The Client shall have the right to control the defense of any "
            "indemnified claim, provided that the Testing Team shall have the right to "
            "participate with counsel of its own choosing at its own expense.",
        ],
    },

    {
        "title": "Limitation of Liability",
        "body": [
            "EXCEPT FOR (A) A PARTY'S INDEMNIFICATION OBLIGATIONS, (B) DAMAGES ARISING FROM "
            "A PARTY'S GROSS NEGLIGENCE OR WILLFUL MISCONDUCT, OR (C) THE CLIENT'S FAILURE "
            "TO PERFORM ITS LAW ENFORCEMENT INTERVENTION OBLIGATIONS, IN NO EVENT SHALL EITHER "
            "PARTY BE LIABLE TO THE OTHER FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, "
            "EXEMPLARY, OR PUNITIVE DAMAGES, REGARDLESS OF THE CAUSE OF ACTION OR THE THEORY "
            "OF LIABILITY, EVEN IF SUCH PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH "
            "DAMAGES.",

            "The Testing Team's total aggregate liability to the Client under this Agreement "
            "shall not exceed the total fees paid by the Client to the Testing Team under this "
            "Agreement in the twelve (12) months preceding the event giving rise to the claim. "
            "This limitation does not apply to the Client's indemnification obligations.",
        ],
    },

    {
        "title": "Findings Validity and Scope of Assurance",
        "body": [
            "IMPORTANT — PLEASE READ CAREFULLY:",

            "The findings, vulnerabilities, and security observations documented in any "
            "deliverable produced under this Agreement reflect the security posture of the "
            "tested systems AS OF THE DATE(S) OF TESTING ONLY. Security posture changes "
            "continuously. The Testing Team makes no representation, warranty, or assurance "
            "that:",
        ],
        "bullets": [
            "The tested systems were free of vulnerabilities not discovered during testing. "
            "Penetration testing is a point-in-time sampling exercise, not a comprehensive "
            "audit of all possible vulnerabilities.",

            "The tested systems will remain in the same security state after the completion "
            "of testing. System changes, patch deployments, configuration drift, new software "
            "installation, and user activity can alter the security posture at any time.",

            "Vulnerabilities identified during testing represent the complete universe of "
            "vulnerabilities present in the tested systems. Testing is inherently bounded by "
            "scope, time, methodology, and the state of publicly known attack techniques at "
            "the time of testing.",

            "Remediation of identified findings will result in the tested systems being free "
            "of all security vulnerabilities.",

            "The testing methodology detected all attack paths that a motivated threat actor "
            "might use, including zero-day vulnerabilities, insider threats, or attack "
            "techniques developed after the testing period.",
        ],
        "body2": [
            "The findings in any deliverable under this Agreement SHALL NOT be used as a "
            "representation that the Client's systems are secure, that the Client has met "
            "any specific regulatory or compliance standard, or that no breach has occurred "
            "or will occur. Compliance with any regulatory framework (including but not "
            "limited to PCI-DSS, GLBA, HIPAA, SOX, and FISMA) requires ongoing controls "
            "assessment beyond the scope of penetration testing.",

            "The Testing Team's findings are provided 'as of the date of testing' and the "
            "report should be treated as having a limited shelf life. The Client is advised "
            "to conduct regular, periodic testing to maintain current situational awareness "
            "of its security posture.",
        ],
    },

    {
        "title": "Confidentiality and Non-Disclosure",
        "body": [
            "All deliverables, findings, vulnerability details, network architecture information, "
            "credentials, and other information produced or obtained under this Agreement "
            "('Confidential Information') are strictly confidential. Both parties agree:",
        ],
        "bullets": [
            "To use Confidential Information solely for the purposes of this engagement and "
            "the remediation of identified findings.",

            "Not to disclose Confidential Information to any third party without the prior "
            "written consent of the other party, except as required by law or regulation.",

            "To protect Confidential Information using at least the same degree of care used "
            "to protect their own confidential information, but in no event less than "
            "reasonable care.",

            "The Testing Team shall not publish, present, reference, or disclose any "
            "Client-specific findings, vulnerabilities, network details, or engagement "
            "outcomes — including in anonymized form — without the Client's express written "
            "consent.",

            "This confidentiality obligation survives the termination or expiration of this "
            "Agreement for a period of five (5) years, or indefinitely with respect to "
            "information that constitutes a trade secret under applicable law.",
        ],
    },

    {
        "title": "Governing Law and Dispute Resolution",
        "body": [
            "This Agreement shall be governed by and construed in accordance with the laws "
            "of the state in which the Testing Team's principal place of business is located, "
            "without regard to its conflict-of-law provisions.",

            "Any dispute arising out of or relating to this Agreement shall first be submitted "
            "to good-faith negotiation between the parties' authorized representatives. If "
            "not resolved within thirty (30) days, the dispute shall be submitted to binding "
            "arbitration under the commercial arbitration rules of the American Arbitration "
            "Association, with arbitration to take place in the Testing Team's home jurisdiction. "
            "Each party shall bear its own costs of arbitration.",

            "Nothing in this Agreement prevents either party from seeking injunctive or other "
            "equitable relief from a court of competent jurisdiction where necessary to "
            "prevent irreparable harm.",
        ],
    },

    {
        "title": "Entire Agreement and Severability",
        "body": [
            "This Agreement, together with the accompanying Rules of Engagement document and "
            "any exhibits or appendices attached hereto, constitutes the entire agreement "
            "between the parties with respect to its subject matter and supersedes all prior "
            "negotiations, representations, warranties, and understandings of the parties "
            "with respect thereto.",

            "If any provision of this Agreement is found to be invalid, illegal, or "
            "unenforceable, the remaining provisions shall continue in full force and effect. "
            "The invalid or unenforceable provision shall be modified to the minimum extent "
            "necessary to make it valid and enforceable while preserving the parties' "
            "original intent.",

            "This Agreement may not be amended except by a written instrument signed by "
            "authorized representatives of both parties. No waiver of any provision of this "
            "Agreement shall be effective unless in writing and shall not be construed as a "
            "waiver of any other provision.",
        ],
    },
]


CLAUSES_ROE: list[dict] = [
    {
        "title": "Scope of Authorization — Safe Harbor",
        "body": [
            "Activities conducted by Testing Team personnel that satisfy ALL of the following "
            "conditions constitute authorized access within the meaning of this Agreement "
            "and applicable law. This safe harbor is the primary legal protection for Testing "
            "Team personnel and should be read in conjunction with the indemnification "
            "provisions of the Scope of Work:",
        ],
        "bullets": [
            "The activity targets only assets, systems, networks, or personnel explicitly "
            "listed in Section 3 of the Scope of Work (in-scope assets, physical locations, "
            "or social engineering targets);",

            "The activity is conducted during an authorized testing window as defined in "
            "Section 1.3 of the Scope of Work (or within a defined maintenance window for "
            "activities requiring one);",

            "The activity originates from a source IP address listed in Section 2.2 of the "
            "Scope of Work for network-based activities, or is conducted in person at an "
            "authorized physical location for physical/social engineering activities;",

            "The activity is not listed among the Prohibited Actions in Section 3 of this "
            "document;",

            "For CONDITIONAL techniques: the specified approval workflow has been completed "
            "and documented prior to execution of the technique.",
        ],
        "body2": [
            "Activities falling outside any one of the above conditions are NOT authorized "
            "under this Agreement and do not benefit from the safe harbor or indemnification "
            "provisions of the Scope of Work. The Testing Team is solely responsible for "
            "any activities conducted outside the defined scope.",
        ],
    },

    {
        "title": "Immediate Suspension and Incident Response",
        "body": [
            "The following situations require IMMEDIATE suspension of all testing activity "
            "and notification to the Client emergency contact. Time is critical in these "
            "situations — do not delay to complete a test, document a finding, or clean up "
            "tool artifacts before suspending:",
        ],
        "bullets": [
            "Any Testing Team personnel is contacted, challenged, detained, or threatened "
            "by law enforcement, security personnel, or any other party — STOP immediately, "
            "present the authorization letter, provide the Client emergency contact number, "
            "and request that the detaining party contact the Client CISO directly;",

            "Any testing activity causes unintended impact to production system availability, "
            "data integrity, or business operations;",

            "The Testing Team gains access to any out-of-scope system, network, or data — "
            "even if access was obtained through an in-scope system;",

            "Evidence of an active breach, ongoing criminal activity, or compromise by a "
            "third party is discovered on any Client system;",

            "The Client issues a stop-work order through any channel.",
        ],
        "body2": [
            "Testing Team personnel who are detained should: (1) remain calm and cooperative; "
            "(2) present the physical authorization letter; (3) provide the Client CISO "
            "emergency mobile number and request that law enforcement contact that number; "
            "(4) contact Testing Firm legal counsel; (5) not make substantive statements "
            "about the engagement to law enforcement without counsel present.",

            "The Testing Team shall provide a written incident report to the Client within "
            "two (2) business hours of any suspension event, describing what occurred, "
            "what systems were affected, and what actions the Testing Team took.",
        ],
    },
]


def get_sow_legal_clauses() -> list[dict]:
    """Return all SOW legal clauses."""
    return CLAUSES_SOW


def get_roe_legal_clauses() -> list[dict]:
    """Return all ROE legal clauses."""
    return CLAUSES_ROE
