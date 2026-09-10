"""Tests for SSH_FXP_REALPATH, in particular the OpenSSH-compatibility
fallback for paths whose basename doesn't exist yet, and the double-free /
use-after-free and NULL-pointer-dereference bugs found and fixed in that
code path during review.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import struct

import build
import sftp_wire as wire
from testutil import SFTPTestCase, require_working_asan


@require_working_asan
class RealpathOpenSSHCompatTest(SFTPTestCase):
    """Default build: OPENSSH_COMPAT=1 (the default)."""

    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def _realpath(self, path):
        payload = struct.pack(">B", wire.SSH_FXP_REALPATH) + struct.pack(">I", 1) + wire.sstr(path)
        return self.session(self.binary).run([wire.pkt(payload)])

    def test_existing_path_resolves(self):
        result = self._realpath(str(self.cwd))
        self.assertFalse(result.crashed, result.stderr_text())
        resp = result.responses[1]
        self.assertEqual(resp[0], wire.SSH_FXP_NAME)
        self.assertEqual(wire.name_path_of(resp), str(self.cwd).encode())

    def test_nonexistent_basename_with_existing_parent_resolves(self):
        """The core OpenSSH-compat feature: a not-yet-created target (e.g.
        the destination of `scp -r`) should resolve rather than fail.
        """
        result = self._realpath("does_not_exist_yet")
        self.assertFalse(result.crashed, result.stderr_text())
        resp = result.responses[1]
        self.assertEqual(resp[0], wire.SSH_FXP_NAME, "expected NAME (resolved), got STATUS (failed)")

    def test_nonexistent_parent_fails_cleanly(self):
        result = self._realpath("no/such/parent/child")
        self.assertFalse(result.crashed, result.stderr_text())
        resp = result.responses[1]
        self.assertEqual(wire.status_of(resp), wire.SSH_FX_NO_SUCH_FILE)

    def test_trailing_slash_on_nonexistent_path_fails_cleanly(self):
        result = self._realpath("does_not_exist_dir/")
        self.assertFalse(result.crashed, result.stderr_text())
        resp = result.responses[1]
        self.assertEqual(wire.status_of(resp), wire.SSH_FX_NO_SUCH_FILE)

    def test_bare_filename_with_no_slash_resolves(self):
        """Exercises dirname() returning static "." storage rather than
        aliasing the strdup'd buffer - a case that mattered for a
        double-free bug found during review (see the "MAX_HANDLES"-style
        aliasing discussion in nih-sftp-server.c's history).
        """
        result = self._realpath("bare_no_slash_doesnotexist")
        self.assertFalse(result.crashed, result.stderr_text())
        resp = result.responses[1]
        self.assertEqual(resp[0], wire.SSH_FXP_NAME)

    def test_permission_denied_style_failure_does_not_crash(self):
        """Regression test: a realpath() failure with an errno other than
        ENOENT (here, ENOTDIR, from treating a regular file as a directory
        component) must still be reported cleanly. An earlier version of
        the OpenSSH-compat fallback fell through to put_cstring(NULL) on
        this path - a guaranteed NULL-pointer dereference.
        """
        self.write_file("regularfile")
        result = self._realpath("regularfile/x")
        self.assertFalse(result.crashed, result.stderr_text())
        resp = result.responses[1]
        self.assertEqual(wire.status_of(resp), wire.SSH_FX_NO_SUCH_FILE)


@require_working_asan
class RealpathDraftSpecTest(SFTPTestCase):
    """-DOPENSSH_COMPAT=0 build: strict SFTPv3 draft behavior."""

    @classmethod
    def setUpClass(cls):
        cls.binary = build.draft_spec_asan()

    def test_nonexistent_basename_fails_outright(self):
        """Without OPENSSH_COMPAT, a not-yet-existing target must fail
        immediately rather than being resolved via the dirname fallback.
        """
        payload = struct.pack(">B", wire.SSH_FXP_REALPATH) + struct.pack(">I", 1) \
            + wire.sstr("does_not_exist_yet")
        result = self.session(self.binary).run([wire.pkt(payload)])
        self.assertFalse(result.crashed, result.stderr_text())
        resp = result.responses[1]
        self.assertEqual(resp[0], wire.SSH_FXP_STATUS, "draft build should fail, not resolve")
        self.assertEqual(wire.status_of(resp), wire.SSH_FX_NO_SUCH_FILE)
