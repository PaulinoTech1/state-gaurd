import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import state_guard as guard


class StateGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "config.json"
        self.path.write_text('{"debug": true, "other": 12}')

    def test_preview_does_not_write(self):
        before = self.path.read_bytes()
        self.assertEqual(guard.remediate(self.path, {"debug": False})[0]["status"], "drift")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(self.path.with_name("config.json.state-guard.bak").exists())

    def test_apply_preserves_unmanaged_keys_and_backup(self):
        before = self.path.read_bytes()
        self.assertEqual(guard.remediate(self.path, {"debug": False}, True)[0]["status"], "pass")
        self.assertEqual(json.loads(self.path.read_bytes()), {"debug": False, "other": 12})
        self.assertEqual(self.path.with_name("config.json.state-guard.bak").read_bytes(), before)
        guard.remediate(self.path, {"debug": False}, True)

    def test_existing_backup_blocks_mutation(self):
        backup = self.path.with_name("config.json.state-guard.bak")
        backup.write_text("recovery")
        before = self.path.read_bytes()
        with self.assertRaises(FileExistsError):
            guard.remediate(self.path, {"debug": False}, True)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(backup.read_text(), "recovery")

    def test_types_and_missing_keys_are_drift(self):
        checks = guard.inspect_config(self.path, {"other": True, "missing": False})[2]
        self.assertTrue(all(c["status"] == "drift" for c in checks))

    def test_invalid_config_and_empty_policy(self):
        self.path.write_text("[]")
        with self.assertRaises(ValueError):
            guard.inspect_config(self.path, {"debug": False})
        self.path.write_text('{"version": 1, "settings": {}}')
        with self.assertRaises(ValueError):
            guard.load_policy(self.path)

    def test_collector_failure_is_unknown(self):
        with patch.object(guard.platform, "system", return_value="Windows"), patch.object(guard, "command", side_effect=OSError):
            self.assertTrue(all(c["status"] == "unknown" for c in guard.endpoint_checks()))

    def test_reports_hide_config_values(self):
        self.path.write_text('{"secret": "private"}')
        self.assertNotIn("private", json.dumps(guard.inspect_config(self.path, {"secret": "expected"})[2]))


if __name__ == "__main__":
    unittest.main()
