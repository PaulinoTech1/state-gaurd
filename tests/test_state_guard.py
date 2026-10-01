import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import codecs
import state_guard as guard
from state_guard_json import decode, render


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

    def test_windows_collectors_include_tamper_and_cloud_protection(self):
        values = ["true", "true", "true", "1"]
        with patch.object(guard.platform, "system", return_value="Windows"), patch.object(guard, "command", side_effect=values) as collector:
            checks = guard.endpoint_checks()
        self.assertEqual([check["check"] for check in checks], [
            "Firewall profiles enabled",
            "Defender real-time protection",
            "Defender tamper protection",
            "Defender cloud-delivered protection",
        ])
        self.assertTrue(all(check["status"] == "pass" for check in checks))
        self.assertIn("Get-MpPreference", collector.call_args_list[-1].args[0][-1])

    def test_linux_collectors_include_dmesg_restriction(self):
        with patch.object(guard.platform, "system", return_value="Linux"), patch.object(guard.Path, "read_text", side_effect=["2", "1", "1"]):
            checks = guard.endpoint_checks()
        self.assertEqual(checks[-1]["check"], "Kernel messages restricted")
        self.assertEqual(checks[-1]["status"], "pass")

    def test_reports_hide_config_values(self):
        self.path.write_text('{"secret": "private"}')
        self.assertNotIn("private", json.dumps(guard.inspect_config(self.path, {"secret": "expected"})[2]))

    def test_render_empty_object_no_edits(self):
        raw = b'{}'
        config = decode(raw)
        # No settings to change; should return identical bytes
        self.assertEqual(render(raw, config, {}), b'{}')
        # Missing keys without opt-in must fail closed
        with self.assertRaisesRegex(ValueError, "allow-reformat"):
            render(raw, config, {"newkey": True})

    def test_render_empty_object_with_reformat(self):
        raw = b'{}'
        config = decode(raw)
        out = render(raw, config, {"newkey": True}, allow_reformat=True)
        self.assertEqual(json.loads(out), {"newkey": True})

    def test_render_bom_whitespace_preserved(self):
        raw = codecs.BOM_UTF8 + b'  { "debug" : true }  '
        config = decode(raw)
        out = render(raw, config, {"debug": False})
        # BOM preserved, whitespace outside edited value preserved
        self.assertTrue(out.startswith(codecs.BOM_UTF8))
        self.assertIn(b'  { "debug" : false }  ', out)

    def test_render_whitespace_only_object(self):
        raw = b'  {\n  }  '
        config = decode(raw)
        self.assertEqual(render(raw, config, {}), raw)

    def test_whitespace_and_comments_fail_closed(self):
        for raw in (b"   \r\n\t", b'{ "debug": true /* comment */ }'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    decode(raw)

    def test_policy_bool_does_not_match_integer_config(self):
        policy = self.path.with_name("policy.json")
        policy.write_text('{"version": 1, "settings": {"enabled": true}}')
        self.path.write_text('{"enabled": 1}')
        settings = guard.load_policy(policy)
        check = guard.inspect_config(self.path, settings)[2][0]
        self.assertEqual(check["status"], "drift")
        self.assertEqual(check["expected_type"], "bool")
        self.assertEqual(check["observed_type"], "int")

    def test_render_does_not_edit_nested_match_for_unchanged_top_level(self):
        raw = b'{"enabled":false,"nested":{"enabled":true}}'
        config = decode(raw)
        self.assertEqual(render(raw, config, {"enabled": False}), raw)


if __name__ == "__main__":
    unittest.main()
