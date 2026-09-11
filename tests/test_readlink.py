"""Tests for SSH_FXP_READLINK, which had zero coverage before this file."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build
import sftp_wire as wire
from testutil import SFTPTestCase, require_working_asan


@require_working_asan
class ReadlinkTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def _readlink(self, path):
        payload = struct.pack(">B", wire.SSH_FXP_READLINK) + struct.pack(">I", 1) + wire.sstr(path)
        return self.session(self.binary).run([wire.pkt(payload)])

    def test_readlink_on_symlink_returns_target(self):
        target = self.write_file("target.txt", b"data")
        link = self.cwd / "link"
        link.symlink_to(target)

        result = self._readlink("link")
        self.assertFalse(result.crashed, result.stderr_text())
        resp = result.responses[1]
        self.assertEqual(resp[0], wire.SSH_FXP_NAME)
        self.assertEqual(wire.name_path_of(resp), str(target).encode())

    def test_readlink_on_regular_file_fails(self):
        """readlink() on something that isn't a symlink fails with EINVAL,
        which errno_to_sftp maps to SSH_FX_BAD_MESSAGE.
        """
        self.write_file("notalink.txt")
        result = self._readlink("notalink.txt")
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_BAD_MESSAGE)

    def test_readlink_on_nonexistent_path_fails(self):
        result = self._readlink("nope")
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_NO_SUCH_FILE)


if __name__ == "__main__":
    unittest.main()
