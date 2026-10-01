import codecs
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import state_guard as guard
import state_guard_storage as storage


class RemediationSecurityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "config.json"
        self.path.write_bytes(b'{"debug":true,"unmanaged": "secret"}')
        self.original = self.path.read_bytes()
        self.settings = {"debug": False}

    def apply(self):
        return guard.remediate(self.path, self.settings, True)

    def create_windows_file_with_acl(self, path, sddl):
        pointer = storage.w.LPVOID()
        storage.checked(storage.from_sddl(sddl, 1, storage.ctypes.byref(pointer), None))
        attributes = storage.SecurityAttributes(storage.ctypes.sizeof(storage.SecurityAttributes), pointer, False)
        try:
            handle = storage.create_file(str(path), 0xC0000000, 3, storage.ctypes.byref(attributes), 1, 0x00200000, None)
            if handle == storage.ctypes.c_void_p(-1).value:
                raise storage.ctypes.WinError(storage.ctypes.get_last_error())
            storage.close_handle(handle)
        finally:
            storage.local_free(pointer)

    def test_exact_unmanaged_bytes_with_bom_crlf_and_escaping(self):
        raw = codecs.BOM_UTF8 + b'{\r\n  "debug" : true, "escaped": "\\u00e9", "number": 1.00e2, "nested": {"x": [1,2]}\r\n}\r\n'
        self.path.write_bytes(raw)
        self.apply()
        self.assertEqual(self.path.read_bytes(), raw.replace(b'"debug" : true', b'"debug" : false'))
        self.assertEqual(guard.recovery_paths(self.path)[0].read_bytes(), raw)

    def test_multiple_managed_values_only(self):
        raw = b'{ "debug":true , "second":"old", "nested":{"debug":true}, "third": 123 }'
        self.path.write_bytes(raw)
        guard.remediate(self.path, {"debug": False, "second": "new", "third": 8}, True)
        self.assertEqual(self.path.read_bytes(), b'{ "debug":false , "second":"new", "nested":{"debug":true}, "third": 8 }')

    def test_missing_key_requires_explicit_opt_in(self):
        with self.assertRaisesRegex(ValueError, "allow-reformat"):
            guard.remediate(self.path, {"missing": False}, True)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertFalse(guard.recovery_paths(self.path)[0].exists())
        guard.remediate(self.path, {"missing": False}, True, allow_reformat=True)
        self.assertFalse(json.loads(self.path.read_bytes())["missing"])

    def test_reject_ambiguous_json_before_recovery_creation(self):
        for raw in (b'{"debug":true,"debug":false}', b'{"debug":true,"x":NaN}',
                    b'{"debug":true,"x":1e999}', '{"debug":true}'.encode("utf-16"),
                    b'{"debug":true,"nested":{"a":1,"a":2}}'):
            with self.subTest(raw=raw):
                self.path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    self.apply()
                self.assertEqual(self.path.read_bytes(), raw)
                self.assertFalse(guard.recovery_paths(self.path)[0].exists())

    def test_boolean_policy_version_rejected(self):
        self.path.write_bytes(b'{"version":true,"settings":{"debug":false}}')
        with self.assertRaises(ValueError):
            guard.load_policy(self.path)

    def test_reformat_refuses_numeric_value_loss(self):
        for token in (b"9007199254740993.0", b"1e-400"):
            raw = b'{"debug":true,"unmanaged":' + token + b'}'
            self.path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "numeric precision"):
                guard.remediate(self.path, {"missing": False}, True, allow_reformat=True)
            self.assertEqual(self.path.read_bytes(), raw)
            self.assertFalse(guard.recovery_paths(self.path)[0].exists())

    def test_linux_collectors_pass_and_collection_errors_are_unknown(self):
        with patch.object(guard.platform, "system", return_value="Linux"), patch.object(guard.Path, "read_text", side_effect=["2", "1"]):
            self.assertTrue(all(c["status"] == "pass" for c in guard.endpoint_checks()))
        with patch.object(guard.platform, "system", return_value="Linux"), patch.object(guard.Path, "read_text", side_effect=OSError):
            self.assertTrue(all(c["status"] == "unknown" for c in guard.endpoint_checks()))

    def test_windows_alternate_stream_rejected(self):
        if os.name != "nt":
            self.skipTest("Windows stream check")
        lock = self.path.with_name(self.path.name + ".state-guard.lock")
        lock.write_bytes(b"\0")  # The inherited temporary-directory ACL is intentionally non-private.
        Path(str(self.path) + ":extra").write_bytes(b"unmanaged stream")
        with self.assertRaisesRegex(ValueError, "alternate data streams"):
            self.apply()
        self.assertEqual(Path(str(self.path) + ":extra").read_bytes(), b"unmanaged stream")
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_oversized_config_rejected(self):
        self.path.write_bytes(b" " * (storage.MAX_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "4 MiB"):
            self.apply()

    def test_replacement_failure_never_truncates_original(self):
        with patch.object(storage, "replace_file", side_effect=OSError("injected rename failure")):
            with self.assertRaises(OSError):
                self.apply()
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(guard.recovery_paths(self.path)[0].read_bytes(), self.original)
        self.assertFalse(list(self.path.parent.glob("*.tmp")))
        self.assertEqual(guard.rollback(self.path, True)[0]["status"], "pass")

    def test_backup_failure_blocks_mutation(self):
        with patch.object(guard, "create_private", side_effect=PermissionError("private backup unavailable")):
            with self.assertRaises(PermissionError):
                self.apply()
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertFalse(guard.recovery_paths(self.path)[1].exists())

    def test_staging_flush_failure_blocks_mutation(self):
        original_create = storage.create_private
        def fail_staging(path, raw):
            if str(path).endswith(".tmp"):
                with patch.object(storage.os, "fsync", side_effect=OSError("injected flush failure")):
                    return original_create(path, raw)
            return original_create(path, raw)
        with patch.object(storage, "create_private", side_effect=fail_staging):
            with self.assertRaises(OSError):
                self.apply()
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertFalse(list(self.path.parent.glob("*.tmp")))

    def test_lock_contention_blocks_second_apply(self):
        with storage.operation_lock(self.path):
            with self.assertRaisesRegex(ValueError, "lock"):
                self.apply()
        self.assertEqual(self.path.read_bytes(), self.original)
        self.apply()  # releasing the lock enables a legitimate operation

    def test_windows_snapshot_denies_an_ordinary_writer(self):
        if os.name != "nt":
            self.skipTest("Windows mandatory sharing check")
        with storage.snapshot(self.path):
            with self.assertRaises(PermissionError):
                with self.path.open("wb"):
                    pass
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_change_detected_before_replacement(self):
        raw, info = self.original, self.path.stat()
        newer = b'{"debug":true,"unmanaged":"newer"}'
        self.path.write_bytes(newer)
        with self.assertRaisesRegex(ValueError, "changed"):
            storage.atomic_update(self.path, raw, b'{"debug":false}', info)
        self.assertEqual(self.path.read_bytes(), newer)

    def test_recovery_files_are_private_from_creation(self):
        self.apply()
        for path in (*guard.recovery_paths(self.path), self.path.with_name(self.path.name + ".state-guard.lock")):
            with storage.open_regular(path, private=True):
                pass
            if os.name == "nt":
                self.assertTrue(storage.private_acl(path))
            else:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_windows_runner_acl_is_private(self):
        if os.name != "nt":
            self.skipTest("Windows ACL check")
        candidate = self.path.with_name("runner-default.lock")
        text = f"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{storage.user_sid()})"
        self.create_windows_file_with_acl(candidate, text)
        with storage.open_regular(candidate, private=True):
            pass

    def test_windows_public_acl_reports_rejected_ace(self):
        if os.name != "nt":
            self.skipTest("Windows ACL check")
        candidate = self.path.with_name("public.lock")
        self.create_windows_file_with_acl(candidate, "D:P(A;;FA;;;WD)")
        with self.assertRaisesRegex(ValueError, r"ACEs=.*trustee=S-1-1-0"):
            with storage.open_regular(candidate, private=True):
                pass

    def test_public_recovery_permissions_block_rollback(self):
        self.apply()
        backup = guard.recovery_paths(self.path)[0]
        if os.name == "nt":
            pointer = storage.w.LPVOID()
            storage.checked(storage.from_sddl("D:P(A;;FA;;;WD)", 1, storage.ctypes.byref(pointer), None))
            try:
                storage.checked(storage.set_security(str(backup), 4 | 0x80000000, pointer))
            finally:
                storage.local_free(pointer)
        else:
            backup.chmod(0o644)
        applied = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "permissions"):
            guard.rollback(self.path, True)
        self.assertEqual(self.path.read_bytes(), applied)

    def test_windows_public_directory_does_not_make_public_backups(self):
        if os.name != "nt":
            self.skipTest("Windows ACL inheritance check")
        pointer = storage.w.LPVOID()
        text = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{storage.user_sid()})(A;OICI;GRGX;;;WD)"
        storage.checked(storage.from_sddl(text, 1, storage.ctypes.byref(pointer), None))
        try:
            storage.checked(storage.set_security(str(self.path.parent), 4 | 0x80000000, pointer))
        finally:
            storage.local_free(pointer)
        self.path.unlink()
        self.path.write_bytes(self.original)
        self.apply()
        self.assertTrue(all(storage.private_acl(p) for p in guard.recovery_paths(self.path)))

    def test_rollback_restores_exact_bytes_and_keeps_recovery(self):
        self.apply()
        applied = self.path.read_bytes()
        self.assertEqual(guard.rollback(self.path)[0]["status"], "drift")
        self.assertEqual(self.path.read_bytes(), applied)
        self.assertEqual(guard.rollback(self.path, True)[0]["status"], "pass")
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertTrue(all(p.exists() for p in guard.recovery_paths(self.path)))
        guard.rollback(self.path, True)  # idempotent recovery

    def test_rollback_refuses_newer_changes(self):
        self.apply()
        newer = b'{"debug":false,"unmanaged":"newer"}'
        self.path.write_bytes(newer)
        with self.assertRaisesRegex(ValueError, "newer"):
            guard.rollback(self.path, True)
        self.assertEqual(self.path.read_bytes(), newer)

    def test_rollback_refuses_corrupt_backup(self):
        self.apply()
        backup = guard.recovery_paths(self.path)[0]
        backup.write_bytes(b'{"tampered":true}')
        applied = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            guard.rollback(self.path, True)
        self.assertEqual(self.path.read_bytes(), applied)

    def test_rollback_rename_failure_keeps_current_and_recovery(self):
        self.apply()
        applied = self.path.read_bytes()
        with patch.object(storage, "replace_file", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                guard.rollback(self.path, True)
        self.assertEqual(self.path.read_bytes(), applied)
        self.assertEqual(guard.recovery_paths(self.path)[0].read_bytes(), self.original)

    def test_hard_link_rejected(self):
        alias = self.path.with_name("alias.json")
        os.link(self.path, alias)
        with self.assertRaisesRegex(ValueError, "hard links"):
            self.apply()
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_symlink_path_rejected(self):
        alias = self.path.with_name("alias.json")
        try:
            alias.symlink_to(self.path)
        except OSError:
            self.skipTest("Symlink creation not permitted on this host")
        with self.assertRaisesRegex(ValueError, "Linked paths"):
            guard.remediate(alias, self.settings, True)

    def test_cli_preview_apply_and_rollback_codes(self):
        policy = self.path.with_name("policy.json")
        policy.write_text('{"version":1,"settings":{"debug":false}}')
        base = ["--policy", str(policy), "--config", str(self.path), "--json"]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(guard.main(["remediate", *base]), 1)
            self.assertEqual(guard.main(["remediate", *base, "--apply"]), 0)
            self.assertEqual(guard.main(["rollback", "--config", str(self.path), "--json"]), 1)
            self.assertEqual(guard.main(["rollback", "--config", str(self.path), "--json", "--apply"]), 0)
        self.assertNotIn("secret", output.getvalue())
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_killed_process_before_rename_keeps_original_and_releases_lock(self):
        marker = self.path.with_name("ready")
        script = """
import sys, time
from pathlib import Path
import state_guard, state_guard_storage
def pause(source, target):
    Path(sys.argv[2]).write_text('ready')
    time.sleep(30)
state_guard_storage.replace_file = pause
state_guard.remediate(sys.argv[1], {'debug': False}, True)
"""
        process = subprocess.Popen([sys.executable, "-c", script, str(self.path), str(marker)], cwd=Path(guard.__file__).parent, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 8
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(marker.exists(), "child did not reach staged replacement")
        finally:
            if process.poll() is None:
                process.kill()
            _, error = process.communicate(timeout=5)
        self.assertEqual(error, b"")
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(guard.recovery_paths(self.path)[0].read_bytes(), self.original)
        guard.rollback(self.path, True)

    def test_posix_config_mode_preserved(self):
        if os.name == "nt":
            self.skipTest("POSIX mode check")
        self.path.chmod(0o640)
        self.apply()
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)

    def test_windows_config_security_descriptor_preserved(self):
        if os.name != "nt":
            self.skipTest("Windows ACL check")
        def sddl(path):
            value = storage.w.LPWSTR()
            storage.checked(storage.to_sddl(storage.descriptor(path, 7), 1, 7, storage.ctypes.byref(value), None))
            try:
                return value.value
            finally:
                storage.local_free(storage.ctypes.cast(value, storage.w.HLOCAL))
        before = sddl(self.path)
        self.apply()
        self.assertEqual(sddl(self.path), before)


if __name__ == "__main__":
    unittest.main()
