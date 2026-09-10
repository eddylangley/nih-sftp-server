"""Tests that buffer-bounds checks on remote-peer-controlled data reject
malformed input cleanly, even in a -DNDEBUG build where assert() is
compiled out.

Background: nih-sftp-server.c uses a REQUIRE() macro (not assert()) for
every check that guards attacker-controlled protocol fields, precisely so
these checks cannot be silently disabled by an NDEBUG build. Every test
here runs against the ndebug_asan() binary specifically to prove that:
  (a) the check still fires (no crash / no ASan report), and
  (b) it produces a clean "Protocol error: ..." rejection instead.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import struct

import build
from testutil import SFTPTestCase, require_working_asan


@require_working_asan
class RequireChecksTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.ndebug_asan()

    def test_oversized_payload_length_is_rejected_not_overflowed(self):
        """A packet claiming a payload far larger than the fixed input
        buffer (MAX_PACKET) must be rejected before read_input() tries to
        fill that many bytes into ibuff.data. Without a REQUIRE() here
        (e.g. if this were still an assert() under NDEBUG), this exact
        packet overflows the buffer into adjacent globals - confirmed with
        AddressSanitizer during development.
        """
        evil_len = 34000 + 20000
        header = struct.pack(">I", evil_len)
        body = b"A" * 40000  # only needs to be "a lot", not the full claimed length
        result = self.session(self.binary).run([header + body], include_init=True)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertIn("Protocol error", result.stderr_text())

    def test_first_packet_must_be_init(self):
        """The very first packet from a client must be SSH_FXP_INIT."""
        bad_first = struct.pack(">I", 9) + struct.pack(">B", 16) + struct.pack(">I", 1) + struct.pack(">I", 0)
        result = self.session(self.binary).run([bad_first], include_init=False)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertIn("Protocol error", result.stderr_text())
        self.assertIn("INIT", result.stderr_text())

    def test_embedded_string_length_exceeding_packet_is_rejected(self):
        """A string's own length field (inside a REALPATH request) can lie
        about its size independently of the outer packet length. get_string()
        must catch this - the outer payload_len check alone isn't enough.
        """
        opcode_and_id = struct.pack(">B", 16) + struct.pack(">I", 1)  # SSH_FXP_REALPATH
        lying_string = struct.pack(">I", 0xFFFF) + b"abc"  # claims 65535 bytes, has 3
        payload = opcode_and_id + lying_string
        packet = struct.pack(">I", len(payload)) + payload
        result = self.session(self.binary).run([packet], include_init=True)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertIn("Protocol error", result.stderr_text())

    def test_embedded_data_length_exceeding_packet_is_rejected(self):
        """Same as above, but for get_data() via an SSH_FXP_WRITE request."""
        opcode_and_id = struct.pack(">B", 6) + struct.pack(">I", 1)  # SSH_FXP_WRITE
        handle = struct.pack(">I", 2) + b"01"
        offset = struct.pack(">Q", 0)
        lying_data = struct.pack(">I", 0xFFFF) + b"short"
        payload = opcode_and_id + handle + offset + lying_data
        packet = struct.pack(">I", len(payload)) + payload
        result = self.session(self.binary).run([packet], include_init=True)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertIn("Protocol error", result.stderr_text())

    def test_client_version_too_old_is_reported_correctly(self):
        """Regression test for a message-text bug: this must say 'too old',
        not 'too new', when the client's version is below what's required.
        """
        low_version_init = struct.pack(">I", 5) + struct.pack(">B", 1) + struct.pack(">I", 1)
        result = self.session(self.binary).run([low_version_init], include_init=False)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertIn("too old", result.stderr_text())
        self.assertNotIn("too new", result.stderr_text())
