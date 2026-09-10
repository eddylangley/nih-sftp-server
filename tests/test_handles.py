"""Tests for the hex-format handle scheme (MAX_HANDLES derived from
MAX_HANDLE_DIGITS) and get_handle()'s parsing of client-supplied handle
strings, including a range of malformed values.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import struct

import build
import sftp_wire as wire
from testutil import SFTPTestCase, require_working_asan


@require_working_asan
class HandleRoundTripTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def test_open_read_close_round_trip_with_hex_handle(self):
        self.write_file("testfile.txt", b"hello sftp world\n")

        open_payload = struct.pack(">B", wire.SSH_FXP_OPEN) + struct.pack(">I", 1) \
            + wire.sstr("testfile.txt") + struct.pack(">I", wire.SSH_FXF_READ) + struct.pack(">I", 0)
        result = self.session(self.binary).run([wire.pkt(open_payload)])
        self.assertFalse(result.crashed, result.stderr_text())

        handle_resp = result.responses[1]
        self.assertEqual(handle_resp[0], wire.SSH_FXP_HANDLE)
        handle = wire.handle_of(handle_resp)
        self.assertIsNotNone(handle)
        # Two hex digits by default (MAX_HANDLE_DIGITS) - first handle issued is "01"
        self.assertRegex(handle.decode(), r"^[0-9A-Fa-f]{2}$")

        read_payload = struct.pack(">B", wire.SSH_FXP_READ) + struct.pack(">I", 2) \
            + wire.sstr(handle) + struct.pack(">Q", 0) + struct.pack(">I", 100)
        close_payload = struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", 3) + wire.sstr(handle)

        result = self.session(self.binary).run([
            wire.pkt(open_payload), wire.pkt(read_payload), wire.pkt(close_payload)
        ])
        self.assertFalse(result.crashed, result.stderr_text())
        read_resp = result.responses[2]
        self.assertEqual(read_resp[0], wire.SSH_FXP_DATA)
        dlen = struct.unpack(">I", read_resp[5:9])[0]
        self.assertEqual(read_resp[9:9 + dlen], b"hello sftp world\n")
        close_resp = result.responses[3]
        self.assertEqual(wire.status_of(close_resp), wire.SSH_FX_OK)


@require_working_asan
class MalformedHandleTest(SFTPTestCase):
    """A CLOSE request with a malformed handle string must be rejected
    cleanly (SSH_FX_FAILURE) rather than crash, for every kind of
    malformed value a hostile or buggy client might send.
    """

    @classmethod
    def setUpClass(cls):
        cls.binary = build.ndebug_asan()

    CASES = {
        "too_short": b"1",
        "too_long": b"001",
        "non_hex_chars": b"ZZ",
        "all_zeros": b"00",  # handle 0 is never valid
        "unallocated_but_well_formed": b"FF",
        "empty": b"",
        "embedded_null_bytes": b"\x00\x01",
        "looks_negative": b"-1",
        "hex_prefix": b"0x",
    }

    def test_malformed_handles_are_rejected_cleanly(self):
        for name, handle_bytes in self.CASES.items():
            with self.subTest(case=name):
                payload = struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", 1) + wire.sstr(handle_bytes)
                result = self.session(self.binary).run([wire.pkt(payload)])
                self.assertFalse(result.crashed, f"{name}: {result.stderr_text()}")
                self.assertEqual(
                    wire.status_of(result.responses[1]), wire.SSH_FX_FAILURE,
                    f"case {name!r} should fail cleanly",
                )
