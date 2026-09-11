"""Tests for SSH_FXP_SYMLINK argument order.

OpenSSH's sftp-server has always sent/expected these reversed relative to
the literal SFTPv3 draft (targetpath before linkpath, not the other way
round) - see OpenSSH's PROTOCOL file, "3.1. sftp: Reversal of arguments to
SSH_FXP_SYMLINK". These tests send the same wire bytes against both build
configurations and check each interprets them as it should.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import struct

import build
import sftp_wire as wire
from testutil import SFTPTestCase, require_working_asan


def _symlink_request(reqid, first_string, second_string):
    payload = struct.pack(">B", wire.SSH_FXP_SYMLINK) + struct.pack(">I", reqid) \
        + wire.sstr(first_string) + wire.sstr(second_string)
    return wire.pkt(payload)


@require_working_asan
class SymlinkOpenSSHCompatTest(SFTPTestCase):
    """Default build: OPENSSH_COMPAT=1. Wire order is (targetpath, linkpath)."""

    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def test_openssh_order_creates_correct_link(self):
        self.write_file("target.txt", b"hello")
        # Sent in OpenSSH's actual wire order: targetpath first, linkpath second.
        packet = _symlink_request(1, "target.txt", "mylink")
        result = self.session(self.binary).run([packet])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)

        link_path = self.cwd / "mylink"
        self.assertTrue(link_path.is_symlink())
        self.assertEqual(link_path.readlink().name, "target.txt")

    def test_symlink_fails_when_link_path_already_exists(self):
        """Exercises sftp_symlink()'s errno_to_sftp() failure path, which
        isn't reachable via the success-only test above.
        """
        self.write_file("target.txt", b"hello")
        self.write_file("mylink")  # already exists as a regular file
        packet = _symlink_request(1, "target.txt", "mylink")
        result = self.session(self.binary).run([packet])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_FAILURE)


@require_working_asan
class SymlinkDraftSpecTest(SFTPTestCase):
    """-DOPENSSH_COMPAT=0 build: strict draft order (linkpath, targetpath)."""

    @classmethod
    def setUpClass(cls):
        cls.binary = build.draft_spec_asan()

    def test_draft_order_creates_correct_link(self):
        self.write_file("target.txt", b"hello")
        # Sent in draft order: linkpath first, targetpath second.
        packet = _symlink_request(1, "mylink", "target.txt")
        result = self.session(self.binary).run([packet])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)

        link_path = self.cwd / "mylink"
        self.assertTrue(link_path.is_symlink())
        self.assertEqual(link_path.readlink().name, "target.txt")

    def test_openssh_order_bytes_are_misinterpreted_by_draft_build(self):
        """Demonstrates *why* the two configurations aren't interchangeable:
        the exact same OpenSSH-order bytes that succeed against the
        OPENSSH_COMPAT build fail against the draft build, because it
        swaps which string it treats as the link path vs. the target.
        Here that produces an EEXIST failure, since it tries to create the
        link at the path "target.txt", which already exists as a real file.
        """
        self.write_file("target.txt", b"hello")
        packet = _symlink_request(1, "target.txt", "mylink")  # OpenSSH order
        result = self.session(self.binary).run([packet])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_FAILURE)
        self.assertFalse((self.cwd / "mylink").exists())
