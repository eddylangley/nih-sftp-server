"""Tests for the attribute-related handlers: SSH_FXP_STAT, SSH_FXP_LSTAT,
SSH_FXP_FSTAT, SSH_FXP_SETSTAT, SSH_FXP_FSETSTAT.

None of these were exercised by the earlier test modules at all - this
file closes that gap.
"""
import os
import pathlib
import stat
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build
import sftp_wire as wire
from testutil import SFTPTestCase, require_working_asan, skip_if_root


@require_working_asan
class StatTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def _stat(self, opcode, path):
        payload = struct.pack(">B", opcode) + struct.pack(">I", 1) + wire.sstr(path)
        return self.session(self.binary).run([wire.pkt(payload)])

    def test_stat_existing_file_returns_attrs(self):
        self.write_file("f.txt", b"contents")
        result = self._stat(wire.SSH_FXP_STAT, "f.txt")
        self.assertFalse(result.crashed, result.stderr_text())
        resp = result.responses[1]
        self.assertEqual(resp[0], wire.SSH_FXP_ATTRS)
        flags = struct.unpack(">I", resp[5:9])[0]
        self.assertTrue(flags & wire.SSH_FILEXFER_ATTR_SIZE)
        self.assertTrue(flags & wire.SSH_FILEXFER_ATTR_PERMISSIONS)
        size = struct.unpack(">Q", resp[9:17])[0]
        self.assertEqual(size, len(b"contents"))

    def test_stat_nonexistent_file_fails(self):
        result = self._stat(wire.SSH_FXP_STAT, "nope.txt")
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_NO_SUCH_FILE)

    def test_lstat_on_symlink_reports_link_not_target(self):
        target = self.write_file("target.txt", b"1234567890")
        link = self.cwd / "link"
        link.symlink_to(target)

        lstat_result = self._stat(wire.SSH_FXP_LSTAT, "link")
        stat_result = self._stat(wire.SSH_FXP_STAT, "link")
        self.assertFalse(lstat_result.crashed, lstat_result.stderr_text())
        self.assertFalse(stat_result.crashed, stat_result.stderr_text())

        lstat_size = struct.unpack(">Q", lstat_result.responses[1][9:17])[0]
        stat_size = struct.unpack(">Q", stat_result.responses[1][9:17])[0]
        # lstat() reports the symlink's own size (the length of the target
        # path string), stat() follows the link and reports target.txt's size.
        self.assertNotEqual(lstat_size, stat_size)
        self.assertEqual(stat_size, 10)

    def test_stat_name_too_long_reports_bad_message(self):
        """Exercises errno_to_sftp's ENAMETOOLONG -> SSH_FX_BAD_MESSAGE mapping."""
        too_long = "x" * 300  # past NAME_MAX (255) on ext4 and most Linux filesystems
        result = self._stat(wire.SSH_FXP_STAT, too_long)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_BAD_MESSAGE)

    @skip_if_root
    def test_stat_permission_denied_directory(self):
        """Exercises errno_to_sftp's EACCES -> SSH_FX_PERMISSION_DENIED
        mapping, and put_status()'s SSH_FX_PERMISSION_DENIED message case.
        Root bypasses DAC permission checks entirely, so this only means
        anything under a non-root user (e.g. in CI).
        """
        blocked_dir = self.cwd / "blocked"
        blocked_dir.mkdir()
        (blocked_dir / "inside.txt").write_bytes(b"secret")
        blocked_dir.chmod(0o000)
        try:
            result = self._stat(wire.SSH_FXP_STAT, "blocked/inside.txt")
            self.assertFalse(result.crashed, result.stderr_text())
            self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_PERMISSION_DENIED)
        finally:
            blocked_dir.chmod(0o755)  # so tempdir cleanup can remove it


@require_working_asan
class FstatTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def test_fstat_on_open_handle_returns_attrs(self):
        self.write_file("f.txt", b"hello")
        session = self.session(self.binary)
        open_payload = struct.pack(">B", wire.SSH_FXP_OPEN) + struct.pack(">I", 1) \
            + wire.sstr("f.txt") + struct.pack(">I", wire.SSH_FXF_READ) + struct.pack(">I", 0)
        fstat_payload_tmpl = struct.pack(">B", wire.SSH_FXP_FSTAT) + struct.pack(">I", 2)

        result = session.run([wire.pkt(open_payload)])
        handle = wire.handle_of(result.responses[1])
        fstat_packet = wire.pkt(fstat_payload_tmpl + wire.sstr(handle))

        result = session.run([wire.pkt(open_payload), fstat_packet])
        self.assertFalse(result.crashed, result.stderr_text())
        resp = result.responses[2]
        self.assertEqual(resp[0], wire.SSH_FXP_ATTRS)
        size = struct.unpack(">Q", resp[9:17])[0]
        self.assertEqual(size, len(b"hello"))

    def test_fstat_on_invalid_handle_fails(self):
        payload = struct.pack(">B", wire.SSH_FXP_FSTAT) + struct.pack(">I", 1) + wire.sstr(b"FF")
        result = self.session(self.binary).run([wire.pkt(payload)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_FAILURE)


@require_working_asan
class SetstatTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def _setstat(self, path, attrs_payload):
        payload = struct.pack(">B", wire.SSH_FXP_SETSTAT) + struct.pack(">I", 1) \
            + wire.sstr(path) + attrs_payload
        return self.session(self.binary).run([wire.pkt(payload)])

    def test_setstat_permissions(self):
        self.write_file("f.txt")
        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_PERMISSIONS) + struct.pack(">I", 0o644)
        result = self._setstat("f.txt", attrs)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)
        mode = stat.S_IMODE(os.stat(self.cwd / "f.txt").st_mode)
        self.assertEqual(mode, 0o644)

    def test_setstat_acmodtime(self):
        self.write_file("f.txt")
        atime, mtime = 1_000_000_000, 1_100_000_000
        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_ACMODTIME) \
            + struct.pack(">I", atime) + struct.pack(">I", mtime)
        result = self._setstat("f.txt", attrs)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)
        st = os.stat(self.cwd / "f.txt")
        self.assertEqual(int(st.st_atime), atime)
        self.assertEqual(int(st.st_mtime), mtime)

    def test_setstat_on_nonexistent_file_fails(self):
        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_PERMISSIONS) + struct.pack(">I", 0o644)
        result = self._setstat("nope.txt", attrs)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_NO_SUCH_FILE)

    def test_setstat_with_extended_attrs_are_skipped_not_applied(self):
        """Exercises get_attrs()'s SSH_FILEXFER_ATTR_EXTENDED discard loop."""
        self.write_file("f.txt")
        SSH_FILEXFER_ATTR_EXTENDED = 0x80000000
        flags = wire.SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_EXTENDED
        attrs = (
            struct.pack(">I", flags)
            + struct.pack(">I", 0o600)
            + struct.pack(">I", 1)  # one extended (type, data) pair
            + wire.sstr("vendor-type") + wire.sstr("vendor-data")
        )
        result = self._setstat("f.txt", attrs)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)
        mode = stat.S_IMODE(os.stat(self.cwd / "f.txt").st_mode)
        self.assertEqual(mode, 0o600)

    @skip_if_root
    def test_setstat_chown_to_unowned_uid_fails(self):
        """Exercises sftp_setstat()'s chown() failure branch: a non-root
        user can't give away a file to an arbitrary uid they don't own
        (EPERM -> SSH_FX_PERMISSION_DENIED).
        """
        self.write_file("f.txt")
        unowned_uid, unowned_gid = 1, 1  # traditionally "daemon" - not us
        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_UIDGID) \
            + struct.pack(">I", unowned_uid) + struct.pack(">I", unowned_gid)
        result = self._setstat("f.txt", attrs)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_PERMISSION_DENIED)


@require_working_asan
class FsetstatTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def test_fsetstat_permissions_on_open_handle(self):
        self.write_file("f.txt")
        session = self.session(self.binary)
        open_pkt = struct.pack(">B", wire.SSH_FXP_OPEN) + struct.pack(">I", 1) \
            + wire.sstr("f.txt") + struct.pack(">I", wire.SSH_FXF_WRITE | wire.SSH_FXF_CREAT) \
            + struct.pack(">I", 0)

        # Learn the handle from a standalone call first (same pattern as
        # test_handles.py's round trip test), then reuse it in a second,
        # single-session batch where it's actually still a live handle.
        probe = session.run([wire.pkt(open_pkt)])
        handle = wire.handle_of(probe.responses[1])
        self.assertIsNotNone(handle)

        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_PERMISSIONS) + struct.pack(">I", 0o640)
        fsetstat_pkt = struct.pack(">B", wire.SSH_FXP_FSETSTAT) + struct.pack(">I", 2) \
            + wire.sstr(handle) + attrs

        result = session.run([wire.pkt(open_pkt), wire.pkt(fsetstat_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_OK)
        mode = stat.S_IMODE(os.stat(self.cwd / "f.txt").st_mode)
        self.assertEqual(mode, 0o640)

    def test_fsetstat_on_invalid_handle_fails(self):
        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_PERMISSIONS) + struct.pack(">I", 0o640)
        payload = struct.pack(">B", wire.SSH_FXP_FSETSTAT) + struct.pack(">I", 1) + wire.sstr(b"FF") + attrs
        result = self.session(self.binary).run([wire.pkt(payload)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_FAILURE)

    @skip_if_root
    def test_fsetstat_chown_to_unowned_uid_fails(self):
        """Exercises sftp_fsetstat()'s fchown() failure branch (EPERM)."""
        self.write_file("f.txt")
        session = self.session(self.binary)
        open_pkt = struct.pack(">B", wire.SSH_FXP_OPEN) + struct.pack(">I", 1) \
            + wire.sstr("f.txt") + struct.pack(">I", wire.SSH_FXF_WRITE | wire.SSH_FXF_CREAT) \
            + struct.pack(">I", 0)
        probe = session.run([wire.pkt(open_pkt)])
        handle = wire.handle_of(probe.responses[1])
        self.assertIsNotNone(handle)

        unowned_uid, unowned_gid = 1, 1
        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_UIDGID) \
            + struct.pack(">I", unowned_uid) + struct.pack(">I", unowned_gid)
        fsetstat_pkt = struct.pack(">B", wire.SSH_FXP_FSETSTAT) + struct.pack(">I", 2) \
            + wire.sstr(handle) + attrs

        result = session.run([wire.pkt(open_pkt), wire.pkt(fsetstat_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_PERMISSION_DENIED)


if __name__ == "__main__":
    unittest.main()
