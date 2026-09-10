"""Regression test for a permission-masking bug: SSH_FXP_OPEN with
SSH_FXF_CREAT passed the client-supplied permissions attribute straight to
open() without masking it with PERM_MASK, unlike every other code path
that sets permissions (SETSTAT, FSETSTAT, MKDIR). That meant a client
could set the setuid bit on a newly created file.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import os
import stat
import struct

import build
import sftp_wire as wire
from testutil import SFTPTestCase


class OpenPermissionMaskingTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.normal()

    def test_setuid_bit_is_stripped_on_creation(self):
        requested_perm = 0o4777  # setuid + rwxrwxrwx
        pflags = wire.SSH_FXF_WRITE | wire.SSH_FXF_CREAT
        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_PERMISSIONS) + struct.pack(">I", requested_perm)
        payload = struct.pack(">B", wire.SSH_FXP_OPEN) + struct.pack(">I", 1) \
            + wire.sstr("newfile") + struct.pack(">I", pflags) + attrs
        result = self.session(self.binary).run([wire.pkt(payload)])
        self.assertFalse(result.crashed, result.stderr_text())

        path = self.cwd / "newfile"
        self.assertTrue(path.exists(), "file should have been created")
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertFalse(mode & stat.S_ISUID, f"setuid bit should be stripped, got {oct(mode)}")
        self.assertFalse(mode & stat.S_ISGID, f"setgid bit should be stripped, got {oct(mode)}")
