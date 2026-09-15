"""Tests for SSH_FXP_WRITE, SSH_FXP_REMOVE, SSH_FXP_RENAME.

sftp_write's real body (as opposed to the malformed-packet checks that
already exercised get_data()) had no coverage before this file, and
neither did sftp_rename's success path.
"""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build
import sftp_wire as wire
from testutil import SFTPTestCase, require_working_asan


@require_working_asan
class WriteTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def _open_pkt(self, reqid, path, pflags):
        return struct.pack(">B", wire.SSH_FXP_OPEN) + struct.pack(">I", reqid) \
            + wire.sstr(path) + struct.pack(">I", pflags) + struct.pack(">I", 0)

    def test_write_creates_file_with_correct_content(self):
        session = self.session(self.binary)
        open_pkt = self._open_pkt(1, "out.txt", wire.SSH_FXF_WRITE | wire.SSH_FXF_CREAT)
        probe = session.run([wire.pkt(open_pkt)])
        handle = wire.handle_of(probe.responses[1])
        self.assertIsNotNone(handle)

        write_pkt = struct.pack(">B", wire.SSH_FXP_WRITE) + struct.pack(">I", 2) \
            + wire.sstr(handle) + struct.pack(">Q", 0) + wire.sstr(b"hello world")
        close_pkt = struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", 3) + wire.sstr(handle)

        result = session.run([wire.pkt(open_pkt), wire.pkt(write_pkt), wire.pkt(close_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_OK)
        self.assertEqual(wire.status_of(result.responses[3]), wire.SSH_FX_OK)
        self.assertEqual((self.cwd / "out.txt").read_bytes(), b"hello world")

    def test_write_at_nonzero_offset(self):
        self.write_file("out.txt", b"0123456789")
        session = self.session(self.binary)
        open_pkt = self._open_pkt(1, "out.txt", wire.SSH_FXF_WRITE)
        probe = session.run([wire.pkt(open_pkt)])
        handle = wire.handle_of(probe.responses[1])

        write_pkt = struct.pack(">B", wire.SSH_FXP_WRITE) + struct.pack(">I", 2) \
            + wire.sstr(handle) + struct.pack(">Q", 5) + wire.sstr(b"XXXXX")
        result = session.run([wire.pkt(open_pkt), wire.pkt(write_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_OK)
        self.assertEqual((self.cwd / "out.txt").read_bytes(), b"01234XXXXX")

    def test_write_with_invalid_handle_fails(self):
        write_pkt = struct.pack(">B", wire.SSH_FXP_WRITE) + struct.pack(">I", 1) \
            + wire.sstr(b"FF") + struct.pack(">Q", 0) + wire.sstr(b"data")
        result = self.session(self.binary).run([wire.pkt(write_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_FAILURE)

    def test_open_read_write_flags(self):
        """Exercises pflags_to_unix()'s O_RDWR branch (both READ and WRITE
        flags set), not exercised by the read-only/write-only tests
        elsewhere in the suite.
        """
        self.write_file("rw.txt", b"start")
        session = self.session(self.binary)
        open_pkt = self._open_pkt(1, "rw.txt", wire.SSH_FXF_READ | wire.SSH_FXF_WRITE)
        probe = session.run([wire.pkt(open_pkt)])
        handle = wire.handle_of(probe.responses[1])
        self.assertIsNotNone(handle, "O_RDWR open should succeed")

        write_pkt = struct.pack(">B", wire.SSH_FXP_WRITE) + struct.pack(">I", 2) \
            + wire.sstr(handle) + struct.pack(">Q", 0) + wire.sstr(b"XXXXX")
        result = session.run([wire.pkt(open_pkt), wire.pkt(write_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_OK)

    def test_open_with_trunc_flag_empties_existing_file(self):
        """Exercises pflags_to_unix()'s O_TRUNC branch."""
        self.write_file("trunc.txt", b"old content that should be gone")
        open_pkt = self._open_pkt(
            1, "trunc.txt", wire.SSH_FXF_WRITE | wire.SSH_FXF_CREAT | wire.SSH_FXF_TRUNC,
        )
        result = self.session(self.binary).run([wire.pkt(open_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertIsNotNone(wire.handle_of(result.responses[1]))
        self.assertEqual((self.cwd / "trunc.txt").read_bytes(), b"")

    def test_open_with_excl_flag_fails_if_file_exists(self):
        """Exercises pflags_to_unix()'s O_EXCL branch, both directions:
        succeeds when the file doesn't exist yet, fails (EEXIST) when it
        does.
        """
        open_pkt = self._open_pkt(
            1, "exclusive.txt", wire.SSH_FXF_WRITE | wire.SSH_FXF_CREAT | wire.SSH_FXF_EXCL,
        )
        result = self.session(self.binary).run([wire.pkt(open_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertIsNotNone(wire.handle_of(result.responses[1]), "first EXCL create should succeed")

        result2 = self.session(self.binary).run([wire.pkt(open_pkt)])
        self.assertFalse(result2.crashed, result2.stderr_text())
        self.assertEqual(wire.status_of(result2.responses[1]), wire.SSH_FX_FAILURE,
                          "second EXCL create on the same path should fail (EEXIST)")

    def test_read_past_end_of_file_reports_eof(self):
        """Exercises sftp_read()'s ret==0 -> SSH_FX_EOF branch."""
        self.write_file("short.txt", b"tiny")
        session = self.session(self.binary)
        open_pkt = self._open_pkt(1, "short.txt", wire.SSH_FXF_READ)
        probe = session.run([wire.pkt(open_pkt)])
        handle = wire.handle_of(probe.responses[1])

        read_pkt = struct.pack(">B", wire.SSH_FXP_READ) + struct.pack(">I", 2) \
            + wire.sstr(handle) + struct.pack(">Q", 100) + struct.pack(">I", 10)  # offset past EOF
        result = session.run([wire.pkt(open_pkt), wire.pkt(read_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_EOF)

    def test_write_to_read_only_handle_fails(self):
        """Exercises sftp_write()'s write()-failed branch: writing to a
        handle whose underlying fd was opened read-only fails at the OS
        level with EBADF, distinct from the "invalid handle" case (which
        fails earlier, before ever calling write()).
        """
        self.write_file("readonly.txt", b"original")
        session = self.session(self.binary)
        open_pkt = self._open_pkt(1, "readonly.txt", wire.SSH_FXF_READ)
        probe = session.run([wire.pkt(open_pkt)])
        handle = wire.handle_of(probe.responses[1])
        self.assertIsNotNone(handle)

        write_pkt = struct.pack(">B", wire.SSH_FXP_WRITE) + struct.pack(">I", 2) \
            + wire.sstr(handle) + struct.pack(">Q", 0) + wire.sstr(b"nope")
        result = session.run([wire.pkt(open_pkt), wire.pkt(write_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        # EBADF (writing to a read-only fd) maps to SSH_FX_NO_SUCH_FILE per
        # errno_to_sftp(), not SSH_FX_FAILURE.
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_NO_SUCH_FILE)
        self.assertEqual((self.cwd / "readonly.txt").read_bytes(), b"original")

    def test_read_from_write_only_handle_fails(self):
        """Exercises sftp_read()'s read()-failed branch (EBADF), the
        mirror image of the write-to-read-only-handle case above.
        """
        self.write_file("writeonly.txt", b"data")
        session = self.session(self.binary)
        open_pkt = self._open_pkt(1, "writeonly.txt", wire.SSH_FXF_WRITE)
        probe = session.run([wire.pkt(open_pkt)])
        handle = wire.handle_of(probe.responses[1])
        self.assertIsNotNone(handle)

        read_pkt = struct.pack(">B", wire.SSH_FXP_READ) + struct.pack(">I", 2) \
            + wire.sstr(handle) + struct.pack(">Q", 0) + struct.pack(">I", 10)
        result = session.run([wire.pkt(open_pkt), wire.pkt(read_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        # Same EBADF -> SSH_FX_NO_SUCH_FILE mapping as the write case above.
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_NO_SUCH_FILE)


@require_working_asan
class RemoveTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def test_remove_existing_file(self):
        self.write_file("gone.txt")
        payload = struct.pack(">B", wire.SSH_FXP_REMOVE) + struct.pack(">I", 1) + wire.sstr("gone.txt")
        result = self.session(self.binary).run([wire.pkt(payload)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)
        self.assertFalse((self.cwd / "gone.txt").exists())

    def test_remove_nonexistent_fails(self):
        payload = struct.pack(">B", wire.SSH_FXP_REMOVE) + struct.pack(">I", 1) + wire.sstr("nope.txt")
        result = self.session(self.binary).run([wire.pkt(payload)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_NO_SUCH_FILE)


@require_working_asan
class RenameTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def _rename(self, old, new):
        payload = struct.pack(">B", wire.SSH_FXP_RENAME) + struct.pack(">I", 1) \
            + wire.sstr(old) + wire.sstr(new)
        return self.session(self.binary).run([wire.pkt(payload)])

    def test_rename_success(self):
        self.write_file("old.txt", b"payload")
        result = self._rename("old.txt", "new.txt")
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)
        self.assertFalse((self.cwd / "old.txt").exists())
        self.assertEqual((self.cwd / "new.txt").read_bytes(), b"payload")

    def test_rename_nonexistent_source_fails(self):
        result = self._rename("nope.txt", "new.txt")
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_NO_SUCH_FILE)


if __name__ == "__main__":
    unittest.main()
