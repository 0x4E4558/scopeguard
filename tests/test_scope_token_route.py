"""
tests/test_scope_token_route
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Integration tests for the Flask route that generates NEX scope tokens.

These tests ensure token generation is bound to the same preflight validation
gate as document generation and that output matches the strict envelope shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import date

import pytest


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    # Use isolated DB for route tests.
    from app import storage

    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "nex-test.db")
    monkeypatch.setenv(
        "NEX_HMAC_SECRET",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    monkeypatch.setenv("NEX_COMPLIANCE_STRICT", "0")

    from app import create_app

    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def _seed_engagement_from_fixture(fixture_name: str) -> str:
    from app.storage import create_engagement, save_section

    fixture_path = Path(__file__).parent / "fixtures" / f"{fixture_name}.json"
    data = json.loads(fixture_path.read_text())

    row_id = create_engagement()
    for section_id, section_data in data.items():
        save_section(row_id, section_id, section_data)
    return row_id


def _seed_signed_engagement_from_fixture(fixture_name: str) -> str:
    from app.storage import create_engagement, save_section

    fixture_path = Path(__file__).parent / "fixtures" / f"{fixture_name}.json"
    data = json.loads(fixture_path.read_text())

    identity = data["identity"]
    identity.update({
        "document_status": "executed",
        "client_signatory_name": "Client Signatory",
        "client_signatory_date": date.today().isoformat(),
        "tester_lead_signatory_name": "Tester Lead",
        "tester_lead_signatory_date": date.today().isoformat(),
        "tester_principal_signatory_name": "Tester Principal",
        "tester_principal_signatory_date": date.today().isoformat(),
        "client_signatory_signature": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo9PQ==",
        "client_signatory_public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestclientkeymaterial\n-----END PUBLIC KEY-----",
        "tester_lead_signatory_signature": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo9PQ==",
        "tester_lead_signatory_public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestleadkeymaterial\n-----END PUBLIC KEY-----",
        "tester_principal_signatory_signature": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo9PQ==",
        "tester_principal_signatory_public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestprincipalkeymaterial\n-----END PUBLIC KEY-----",
        "document_creator_signature": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo9PQ==",
        "document_creator_public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestcreatorkeymaterial\n-----END PUBLIC KEY-----",
    })

    row_id = create_engagement()
    for section_id, section_data in data.items():
        save_section(row_id, section_id, section_data)
    return row_id


def test_scope_token_route_rejects_when_blocked(app_client):
    from app.storage import create_engagement

    row_id = create_engagement()
    resp = app_client.get(f"/engagement/{row_id}/generate/scope-token")

    assert resp.status_code == 422
    body = resp.get_json()
    assert body["error"] == "Token generation blocked"


def test_scope_token_route_rejects_unsigned_documents(app_client):
    row_id = _seed_engagement_from_fixture("mcb")

    resp = app_client.get(f"/engagement/{row_id}/generate/scope-token")

    assert resp.status_code == 422
    body = resp.get_json()
    assert body["error"] == "Token generation blocked"
    assert "signed" in body["message"].lower()


def test_scope_token_route_returns_strict_envelope(app_client):
    row_id = _seed_signed_engagement_from_fixture("mcb")

    resp = app_client.get(f"/engagement/{row_id}/generate/scope-token")

    assert resp.status_code == 200
    token = json.loads(resp.data.decode("utf-8"))

    assert set(token.keys()) == {"algorithm", "schema_version", "payload", "signature"}
    assert token["algorithm"] == "HMAC-SHA256"
    assert token["schema_version"] == "1.0"
    assert len(token["signature"]) == 64

    payload = token["payload"]
    assert set(payload.keys()).issuperset(
        {
            "scope_id",
            "operator_id",
            "issued_at",
            "expires_at",
            "nex_modules",
            "allowed_targets",
        }
    )

    assert isinstance(payload["scope_id"], str) and len(payload["scope_id"]) >= 32
    assert isinstance(payload["operator_id"], str) and payload["operator_id"]
    assert isinstance(payload["issued_at"], str) and payload["issued_at"].endswith("Z")
    assert isinstance(payload["expires_at"], str) and payload["expires_at"].endswith("Z")
    assert isinstance(payload["nex_modules"], list) and payload["nex_modules"]
    assert isinstance(payload["allowed_targets"], list) and payload["allowed_targets"]
    if "authorized_cidrs" in payload:
        assert isinstance(payload["authorized_cidrs"], list)


def test_document_routes_require_signed_documents(app_client):
    row_id = _seed_engagement_from_fixture("mcb")

    sow_resp = app_client.get(f"/engagement/{row_id}/generate/sow")
    roe_resp = app_client.get(f"/engagement/{row_id}/generate/roe")

    assert sow_resp.status_code == 422
    assert roe_resp.status_code == 422
    assert "signed" in sow_resp.get_json()["message"].lower()
    assert "signed" in roe_resp.get_json()["message"].lower()


def test_scope_token_route_rejects_without_secret(tmp_path, monkeypatch):
    from app import storage

    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "nex-test-no-secret.db")
    monkeypatch.delenv("NEX_HMAC_SECRET", raising=False)
    monkeypatch.delenv("NEX_SCOPE_SECRET", raising=False)

    from app import create_app

    app = create_app()
    app.config["TESTING"] = True

    row_id = _seed_engagement_from_fixture("mcb")
    with app.test_client() as client:
        resp = client.get(f"/engagement/{row_id}/generate/scope-token")

    assert resp.status_code == 422
    body = resp.get_json()
    assert body["error"] == "Token generation blocked"
    assert "NEX_HMAC_SECRET" in body["message"]
