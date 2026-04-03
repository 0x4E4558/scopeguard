"""
tests.test_nex_bridge
~~~~~~~~~~~~~~~~~~~~~
Unit tests for nex_bridge.  Nex native classes are mocked so the suite runs
without a full Nex installation.

Run with:
    python -m pytest tests/
  or
    python -m unittest discover tests/
"""

import hashlib
import json
import os
import tempfile
import unittest
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, List
from unittest.mock import MagicMock, patch

# Add parent directory to path so tests work without installation
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import nex_bridge
from nex_bridge import (
    CHUNK_SIZE,
    DEFAULT_POLICY_PATH,
    DEFAULT_RECOVERY_DIR,
    POLICY_VERSION,
    _atomic_json_write,
    _derive_operator_id,
    _PE_EXACT_MAP,
    _PREFIX_MAP,
    build_roe_constraints,
    hash_document,
    map_techniques,
    post_bootstrap_commit,
    write_policy_bundle,
)


# ---------------------------------------------------------------------------
# Mock Nex classes — stand-ins for core.policy_engine / core.session_recovery
# ---------------------------------------------------------------------------

class _MockTechniqueClass:
    """Minimal stand-in for nex/core/policy_engine.TechniqueClass."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __repr__(self) -> str:
        return f"TechniqueClass({self.value!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _MockTechniqueClass) and self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __lt__(self, other: "_MockTechniqueClass") -> bool:
        return self.value < other.value


@dataclass
class _MockROEConstraints:
    """Minimal stand-in for nex/core/policy_engine.ROEConstraints."""

    allowed_targets: List[str]
    allowed_techniques: list
    restricted_targets: List[str]
    window_start: int
    window_end: int
    operator_id: str
    sow_hash: str
    policy_version: str


@dataclass
class _MockRecoveryRecord:
    """Minimal stand-in for nex/core/session_recovery.RecoveryRecord."""

    session_id: str = "mock-session"


class _MockSessionRecoveryManager:
    """Minimal stand-in for nex/core/session_recovery.SessionRecoveryManager."""

    def __init__(self, storage_path: str, encryption_key_material: bytearray) -> None:
        self.storage_path = storage_path
        self.enc_key = encryption_key_material
        self._commit_calls: list = []

    def commit_pre_launch(self, **kwargs: Any) -> _MockRecoveryRecord:
        self._commit_calls.append(kwargs)
        return _MockRecoveryRecord()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_technique(
    technique_id: str,
    auth: str = "authorized",
    prohibited: bool = False,
) -> Any:
    return SimpleNamespace(
        technique_id=technique_id,
        authorization_status=SimpleNamespace(value=auth),
        prohibited=prohibited,
    )


def _make_engagement(
    *,
    engagement_id: str = "ENG-2026-TEST-001",
    authorized_start: str = "2026-01-01T08:00:00+00:00",
    authorized_end: str = "2026-12-31T17:00:00+00:00",
    cidrs: List[str] = None,
    oos_cidrs: List[str] = None,
    techniques: List[Any] = None,
    lead_email: str = "lead@example.com",
) -> Any:
    """Construct a duck-typed Engagement-like object compatible with nex_bridge."""
    _cidrs = cidrs or ["10.0.0.0/8", "172.16.0.0/12"]
    _oos = oos_cidrs or ["192.168.99.0/24"]
    _techniques = techniques or [
        _make_technique("REC-001"),
        _make_technique("EXP-001"),
        _make_technique("PE-010", prohibited=True),
        _make_technique("DOS-001", auth="conditional"),
    ]
    lead_contact = SimpleNamespace(email=lead_email)

    def contact_by_role(role: str) -> Any:
        return lead_contact if role == "engagement_lead" else None

    return SimpleNamespace(
        identity=SimpleNamespace(engagement_id=engagement_id),
        period=SimpleNamespace(
            authorized_start_date=datetime.fromisoformat(authorized_start),
            authorized_end_date=datetime.fromisoformat(authorized_end),
        ),
        in_scope_assets=[SimpleNamespace(cidr_notation=c) for c in _cidrs],
        out_of_scope_assets=[SimpleNamespace(cidr_notation=c) for c in _oos],
        techniques=_techniques,
        contact_by_role=contact_by_role,
    )


def _tmp_file(content: bytes = b"hello world") -> Path:
    """Write *content* to a temp file and return its Path."""
    fd, path = tempfile.mkstemp(suffix=".docx")
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    return Path(path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestHashDocument(unittest.TestCase):
    def test_known_hash(self):
        content = b"nex-bridge test content"
        expected = hashlib.sha256(content).hexdigest()
        tmp = _tmp_file(content)
        try:
            self.assertEqual(hash_document(tmp), expected)
        finally:
            os.unlink(tmp)

    def test_large_file_chunked(self):
        content = os.urandom(CHUNK_SIZE * 3)
        expected = hashlib.sha256(content).hexdigest()
        tmp = _tmp_file(content)
        try:
            self.assertEqual(hash_document(tmp), expected)
        finally:
            os.unlink(tmp)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            hash_document("/tmp/__nonexistent_nex_bridge_test__.docx")

    def test_accepts_string_path(self):
        content = b"string path test"
        tmp = _tmp_file(content)
        try:
            self.assertEqual(hash_document(str(tmp)), hashlib.sha256(content).hexdigest())
        finally:
            os.unlink(tmp)

    def test_returns_64_char_hex(self):
        tmp = _tmp_file(b"x")
        try:
            result = hash_document(tmp)
            self.assertEqual(len(result), 64)
            int(result, 16)  # must be valid hex
        finally:
            os.unlink(tmp)


class TestAtomicJsonWrite(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_creates_file(self):
        path = Path(self._tmpdir) / "out.json"
        _atomic_json_write(path, {"key": "value"})
        self.assertTrue(path.exists())

    def test_content_is_valid_json(self):
        path = Path(self._tmpdir) / "out.json"
        obj = {"z": 1, "a": 2, "m": [3, 4]}
        _atomic_json_write(path, obj)
        self.assertEqual(json.loads(path.read_bytes()), obj)

    def test_keys_are_sorted(self):
        path = Path(self._tmpdir) / "sorted.json"
        _atomic_json_write(path, {"z": 1, "a": 2, "m": 3})
        raw = path.read_text()
        self.assertLess(raw.index('"a"'), raw.index('"m"'))
        self.assertLess(raw.index('"m"'), raw.index('"z"'))

    def test_creates_parent_directories(self):
        path = Path(self._tmpdir) / "sub" / "dir" / "out.json"
        _atomic_json_write(path, {"x": 1})
        self.assertTrue(path.exists())

    def test_overwrites_existing_file(self):
        path = Path(self._tmpdir) / "overwrite.json"
        _atomic_json_write(path, {"v": 1})
        _atomic_json_write(path, {"v": 2})
        self.assertEqual(json.loads(path.read_bytes())["v"], 2)


class TestDeriveOperatorId(unittest.TestCase):
    def test_returns_lead_email(self):
        eng = _make_engagement(lead_email="alice@example.com")
        self.assertEqual(_derive_operator_id(eng), "alice@example.com")

    def test_missing_lead_raises_value_error(self):
        eng = _make_engagement()
        eng.contact_by_role = lambda role: None
        with self.assertRaises(ValueError):
            _derive_operator_id(eng)


class TestMapTechniques(unittest.TestCase):
    """Patches _NEX_POLICY_AVAILABLE and TechniqueClass for isolation."""

    def _patch(self):
        return patch.multiple(
            "nex_bridge",
            _NEX_POLICY_AVAILABLE=True,
            TechniqueClass=_MockTechniqueClass,
        )

    def test_raises_when_nex_unavailable(self):
        with patch("nex_bridge._NEX_POLICY_AVAILABLE", False):
            with self.assertRaises(RuntimeError):
                map_techniques([])

    def test_authorized_non_prohibited_included(self):
        with self._patch():
            result = map_techniques([_make_technique("REC-001")])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].value, "RECON")

    def test_unauthorized_excluded(self):
        with self._patch():
            result = map_techniques([_make_technique("EXP-001", auth="conditional")])
        self.assertEqual(result, [])

    def test_prohibited_excluded(self):
        with self._patch():
            result = map_techniques([_make_technique("REC-001", prohibited=True)])
        self.assertEqual(result, [])

    def test_pe_exact_map_lateral_movement(self):
        with self._patch():
            result = map_techniques([_make_technique("PE-001")])
        self.assertIn("LATERAL_MOVEMENT", [tc.value for tc in result])

    def test_pe_exact_map_persistence(self):
        with self._patch():
            result = map_techniques([_make_technique("PE-010")])
        self.assertIn("PERSISTENCE", [tc.value for tc in result])

    def test_pe_exact_map_credential_harvest(self):
        with self._patch():
            result = map_techniques([_make_technique("PE-011")])
        self.assertIn("CREDENTIAL_HARVEST", [tc.value for tc in result])

    def test_prefix_map_rec(self):
        with self._patch():
            result = map_techniques([_make_technique("REC-999")])
        self.assertEqual(result[0].value, "RECON")

    def test_prefix_map_vs(self):
        with self._patch():
            result = map_techniques([_make_technique("VS-999")])
        self.assertEqual(result[0].value, "VULNERABILITY_SCAN")

    def test_prefix_map_exp(self):
        with self._patch():
            result = map_techniques([_make_technique("EXP-999")])
        self.assertEqual(result[0].value, "EXPLOIT")

    def test_prefix_map_dos(self):
        with self._patch():
            result = map_techniques([_make_technique("DOS-999")])
        self.assertEqual(result[0].value, "EXPLOIT")

    def test_unknown_id_skipped_without_error(self):
        with self._patch():
            result = map_techniques([_make_technique("UNKNOWN-001")])
        self.assertEqual(result, [])

    def test_duplicate_categories_deduplicated(self):
        with self._patch():
            result = map_techniques([
                _make_technique("REC-001"),
                _make_technique("REC-002"),
            ])
        values = [tc.value for tc in result]
        self.assertEqual(values.count("RECON"), 1)

    def test_returns_sorted_list(self):
        techs = [
            _make_technique("REC-001"),
            _make_technique("EXP-001"),
            _make_technique("VS-001"),
            _make_technique("PE-001"),
        ]
        with self._patch():
            result = map_techniques(techs)
        values = [tc.value for tc in result]
        self.assertEqual(values, sorted(values))

    def test_all_pe_exact_ids_covered(self):
        for tid in _PE_EXACT_MAP:
            with self._patch():
                result = map_techniques([_make_technique(tid)])
            self.assertTrue(len(result) >= 1, f"{tid} produced no TechniqueClass")

    def test_all_prefix_map_prefixes_covered(self):
        samples = {
            "REC-": "REC-001", "VS-": "VS-001", "EXP-": "EXP-001",
            "DOS-": "DOS-001", "SE-": "SE-001", "PHY-": "PHY-001",
        }
        for prefix, tid in samples.items():
            with self._patch():
                result = map_techniques([_make_technique(tid)])
            self.assertTrue(len(result) >= 1, f"Prefix {prefix!r} produced no result")


class TestBuildRoeConstraints(unittest.TestCase):
    def _patch(self):
        return patch.multiple(
            "nex_bridge",
            _NEX_POLICY_AVAILABLE=True,
            ROEConstraints=_MockROEConstraints,
            TechniqueClass=_MockTechniqueClass,
        )

    def setUp(self):
        self.eng = _make_engagement()
        self.sow_hash = "a" * 64

    def test_raises_when_nex_unavailable(self):
        with patch("nex_bridge._NEX_POLICY_AVAILABLE", False):
            with self.assertRaises(RuntimeError):
                build_roe_constraints(self.eng, self.sow_hash)

    def test_returns_roe_constraints_instance(self):
        with self._patch():
            result = build_roe_constraints(self.eng, self.sow_hash)
        self.assertIsInstance(result, _MockROEConstraints)

    def test_allowed_targets_from_in_scope(self):
        with self._patch():
            result = build_roe_constraints(self.eng, self.sow_hash)
        self.assertIn("10.0.0.0/8", result.allowed_targets)
        self.assertIn("172.16.0.0/12", result.allowed_targets)

    def test_restricted_targets_from_out_of_scope(self):
        with self._patch():
            result = build_roe_constraints(self.eng, self.sow_hash)
        self.assertIn("192.168.99.0/24", result.restricted_targets)

    def test_sow_hash_stored(self):
        with self._patch():
            result = build_roe_constraints(self.eng, self.sow_hash)
        self.assertEqual(result.sow_hash, self.sow_hash)

    def test_window_start_is_int_epoch(self):
        with self._patch():
            result = build_roe_constraints(self.eng, self.sow_hash)
        self.assertIsInstance(result.window_start, int)
        self.assertGreater(result.window_start, 0)

    def test_window_end_after_start(self):
        with self._patch():
            result = build_roe_constraints(self.eng, self.sow_hash)
        self.assertGreater(result.window_end, result.window_start)

    def test_operator_id_from_lead_email(self):
        eng = _make_engagement(lead_email="lead@example.com")
        with self._patch():
            result = build_roe_constraints(eng, self.sow_hash)
        self.assertEqual(result.operator_id, "lead@example.com")

    def test_policy_version(self):
        with self._patch():
            result = build_roe_constraints(self.eng, self.sow_hash)
        self.assertEqual(result.policy_version, POLICY_VERSION)

    def test_missing_lead_raises_value_error(self):
        eng = _make_engagement()
        eng.contact_by_role = lambda role: None
        with self._patch():
            with self.assertRaises(ValueError):
                build_roe_constraints(eng, self.sow_hash)

    def test_prohibited_techniques_excluded(self):
        eng = _make_engagement(techniques=[
            _make_technique("REC-001"),
            _make_technique("EXP-001", prohibited=True),
        ])
        with self._patch():
            result = build_roe_constraints(eng, self.sow_hash)
        values = [tc.value for tc in result.allowed_techniques]
        self.assertIn("RECON", values)
        self.assertNotIn("EXPLOIT", values)


class TestWritePolicyBundle(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.policy_path = Path(self._tmpdir) / "policy.json"
        self.sow = _tmp_file(b"SOW document contents")
        self.roe = _tmp_file(b"ROE document contents")
        self.eng = _make_engagement()

    def tearDown(self):
        for p in (self.sow, self.roe):
            try:
                os.unlink(p)
            except OSError:
                pass
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch.multiple(
            "nex_bridge",
            _NEX_POLICY_AVAILABLE=True,
            TechniqueClass=_MockTechniqueClass,
        )

    def _run(self, **kwargs) -> dict:
        kw = {"path": self.policy_path}
        kw.update(kwargs)
        with self._patch():
            return write_policy_bundle(self.eng, self.sow, self.roe, **kw)

    def _load(self) -> dict:
        return json.loads(self.policy_path.read_text())

    def test_creates_file(self):
        self._run()
        self.assertTrue(self.policy_path.exists())

    def test_returns_dict(self):
        self.assertIsInstance(self._run(), dict)

    def test_sow_hash_computed_from_file(self):
        self._run()
        self.assertEqual(
            self._load()["sow_hash"],
            hashlib.sha256(b"SOW document contents").hexdigest(),
        )

    def test_roe_hash_in_bundle(self):
        self._run()
        self.assertEqual(
            self._load()["roe_hash"],
            hashlib.sha256(b"ROE document contents").hexdigest(),
        )

    def test_runtime_mode_default(self):
        self._run()
        self.assertEqual(self._load()["runtime_mode"], "OFFENSIVE_MODE")

    def test_runtime_mode_custom(self):
        self._run(runtime_mode="FORENSIC_MODE")
        self.assertEqual(self._load()["runtime_mode"], "FORENSIC_MODE")

    def test_expected_environment_hash_empty_default(self):
        self._run()
        self.assertEqual(self._load()["expected_environment_hash"], "")

    def test_expected_environment_hash_custom(self):
        self._run(expected_environment_hash="abcd" * 16)
        self.assertEqual(self._load()["expected_environment_hash"], "abcd" * 16)

    def test_tactical_window_start_is_int_epoch(self):
        self._run()
        data = self._load()
        self.assertIsInstance(data["tactical_window_start"], int)
        self.assertGreater(data["tactical_window_start"], 0)

    def test_tactical_window_end_is_int_epoch(self):
        self._run()
        data = self._load()
        self.assertIsInstance(data["tactical_window_end"], int)
        self.assertGreater(data["tactical_window_end"], 0)

    def test_tactical_window_end_after_start(self):
        self._run()
        data = self._load()
        self.assertGreater(data["tactical_window_end"], data["tactical_window_start"])

    def test_allowed_targets_from_in_scope(self):
        self._run()
        data = self._load()
        self.assertIn("10.0.0.0/8", data["allowed_targets"])
        self.assertIn("172.16.0.0/12", data["allowed_targets"])

    def test_restricted_targets_from_out_of_scope(self):
        self._run()
        self.assertIn("192.168.99.0/24", self._load()["restricted_targets"])

    def test_allowed_techniques_uppercase(self):
        self._run()
        techs = self._load()["allowed_techniques"]
        self.assertIsInstance(techs, list)
        self.assertTrue(all(t == t.upper() for t in techs))

    def test_allowed_techniques_sorted(self):
        self._run()
        techs = self._load()["allowed_techniques"]
        self.assertEqual(techs, sorted(techs))

    def test_policy_version_present(self):
        self._run()
        self.assertEqual(self._load()["policy_version"], POLICY_VERSION)

    def test_engagement_id_in_bundle(self):
        self._run()
        self.assertEqual(self._load()["engagement_id"], "ENG-2026-TEST-001")

    def test_operator_id_in_bundle(self):
        self._run()
        self.assertEqual(self._load()["operator_id"], "lead@example.com")

    def test_generated_at_is_int(self):
        self._run()
        self.assertIsInstance(self._load()["generated_at"], int)

    def test_all_boot_policy_keys_present(self):
        self._run()
        data = self._load()
        for key in (
            "runtime_mode", "expected_environment_hash",
            "tactical_window_start", "tactical_window_end",
            "allowed_targets", "allowed_techniques",
            "restricted_targets", "sow_hash", "policy_version",
        ):
            self.assertIn(key, data, f"Missing boot_policy key: {key!r}")

    def test_missing_sow_raises(self):
        with self._patch():
            with self.assertRaises(FileNotFoundError):
                write_policy_bundle(
                    self.eng,
                    "/tmp/__missing_sow__.docx",
                    self.roe,
                    path=self.policy_path,
                )

    def test_missing_roe_raises(self):
        with self._patch():
            with self.assertRaises(FileNotFoundError):
                write_policy_bundle(
                    self.eng,
                    self.sow,
                    "/tmp/__missing_roe__.docx",
                    path=self.policy_path,
                )

    def test_empty_allowed_techniques_and_warning_when_nex_unavailable(self):
        with patch("nex_bridge._NEX_POLICY_AVAILABLE", False):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                write_policy_bundle(self.eng, self.sow, self.roe, path=self.policy_path)
        self.assertEqual(self._load()["allowed_techniques"], [])
        self.assertTrue(
            any(issubclass(w.category, RuntimeWarning) for w in caught),
            "Expected a RuntimeWarning when Nex policy engine is unavailable",
        )

    def test_string_paths_accepted(self):
        with self._patch():
            result = write_policy_bundle(
                self.eng, str(self.sow), str(self.roe), path=self.policy_path
            )
        self.assertIsInstance(result, dict)


class TestPostBootstrapCommit(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.recovery_dir = Path(self._tmpdir) / "recovery"
        self.mock_hub = SimpleNamespace(_session_id="session-xyz")
        self.boot_session = SimpleNamespace(
            hub=self.mock_hub,
            ledger=MagicMock(),
            token_manager=MagicMock(),
            session_key=bytearray(b"\xAA" * 32),
        )
        self.roe = _MockROEConstraints(
            allowed_targets=["10.0.0.0/8"],
            allowed_techniques=[],
            restricted_targets=[],
            window_start=1_000_000,
            window_end=2_000_000,
            operator_id="lead@example.com",
            sow_hash="a" * 64,
            policy_version=POLICY_VERSION,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch.multiple(
            "nex_bridge",
            _NEX_RECOVERY_AVAILABLE=True,
            SessionRecoveryManager=_MockSessionRecoveryManager,
        )

    def test_raises_when_nex_unavailable(self):
        with patch("nex_bridge._NEX_RECOVERY_AVAILABLE", False):
            with self.assertRaises(RuntimeError):
                post_bootstrap_commit(self.boot_session, self.roe)

    def test_returns_recovery_record(self):
        with self._patch():
            record = post_bootstrap_commit(
                self.boot_session, self.roe, recovery_dir=self.recovery_dir
            )
        self.assertIsInstance(record, _MockRecoveryRecord)

    def test_commit_pre_launch_receives_correct_args(self):
        tracker: List[dict] = []

        class _TrackingManager(_MockSessionRecoveryManager):
            def commit_pre_launch(self, **kwargs: Any) -> _MockRecoveryRecord:
                tracker.append(kwargs)
                return _MockRecoveryRecord()

        with patch.multiple(
            "nex_bridge",
            _NEX_RECOVERY_AVAILABLE=True,
            SessionRecoveryManager=_TrackingManager,
        ):
            post_bootstrap_commit(
                self.boot_session, self.roe, recovery_dir=self.recovery_dir
            )

        self.assertEqual(len(tracker), 1)
        call = tracker[0]
        self.assertIs(call["hub"], self.mock_hub)
        self.assertIs(call["roe"], self.roe)
        self.assertIs(call["ledger"], self.boot_session.ledger)
        self.assertIs(call["token_manager"], self.boot_session.token_manager)
        self.assertIsNone(call["operator_keyring"])

    def test_session_key_original_not_zeroed(self):
        original_key = bytearray(b"\xAA" * 32)
        self.boot_session.session_key = original_key
        with self._patch():
            post_bootstrap_commit(
                self.boot_session, self.roe, recovery_dir=self.recovery_dir
            )
        # boot_session.session_key is the authoritative copy — must be unchanged
        self.assertEqual(original_key, bytearray(b"\xAA" * 32))

    def test_default_recovery_dir_used_when_none(self):
        captured: List[str] = []

        class _CapturingManager(_MockSessionRecoveryManager):
            def __init__(self, storage_path: str, encryption_key_material: bytearray) -> None:
                captured.append(storage_path)
                super().__init__(storage_path, encryption_key_material)

        with patch.multiple(
            "nex_bridge",
            _NEX_RECOVERY_AVAILABLE=True,
            SessionRecoveryManager=_CapturingManager,
        ):
            post_bootstrap_commit(self.boot_session, self.roe, recovery_dir=None)

        self.assertEqual(captured[0], str(DEFAULT_RECOVERY_DIR))

    def test_operator_keyring_forwarded(self):
        mock_keyring = MagicMock()
        tracker: List[dict] = []

        class _TrackingManager(_MockSessionRecoveryManager):
            def commit_pre_launch(self, **kwargs: Any) -> _MockRecoveryRecord:
                tracker.append(kwargs)
                return _MockRecoveryRecord()

        with patch.multiple(
            "nex_bridge",
            _NEX_RECOVERY_AVAILABLE=True,
            SessionRecoveryManager=_TrackingManager,
        ):
            post_bootstrap_commit(
                self.boot_session, self.roe,
                recovery_dir=self.recovery_dir,
                operator_keyring=mock_keyring,
            )

        self.assertIs(tracker[0]["operator_keyring"], mock_keyring)


if __name__ == "__main__":
    unittest.main()
