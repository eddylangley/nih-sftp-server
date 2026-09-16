"""Randomized fuzz testing against the -DNDEBUG + ASan build.

Seeds are fixed so CI runs are reproducible - a failure here should be
reproducible locally by running this file directly with the same seed.
Counts are kept modest (hundreds, not millions) to keep CI fast; this is a
sanity sweep, not a substitute for a real coverage-guided fuzzer (e.g.
AFL/libFuzzer) if you want to go further.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import random
import struct

import build
from testutil import SFTPTestCase, require_working_asan


@require_working_asan
class SinglePacketFuzzTest(SFTPTestCase):
    """Random single packets across every opcode, one fresh server process
    per packet. Verifies nothing crashes or hangs - it does not assert
    anything about the specific response, since most of these packets are
    nonsensical by construction.
    """

    @classmethod
    def setUpClass(cls):
        cls.binary = build.ndebug_asan()

    SEED = 1337
    ITERATIONS = 500
    OPCODES = list(range(3, 21)) + [1, 99, 200, 0, 255]

    def test_random_single_packets_do_not_crash_or_hang(self):
        rng = random.Random(self.SEED)
        failures = []
        for i in range(self.ITERATIONS):
            opcode = rng.choice(self.OPCODES)
            body_len = rng.choice([0, 1, 2, 3, 4, 8, 9, 13, 20, 50, 100, rng.randint(0, 2000)])
            body = bytes(rng.randint(0, 255) for _ in range(body_len))
            payload = struct.pack(">B", opcode) + body
            packet = struct.pack(">I", len(payload)) + payload

            result = self.session(self.binary).run([packet])
            if result.timed_out:
                failures.append(f"[{i}] HANG opcode={opcode} body_len={body_len}")
            elif result.crashed:
                failures.append(
                    f"[{i}] CRASH opcode={opcode} body_len={body_len} "
                    f"body={body[:60]!r}\n{result.stderr_text()[:1000]}"
                )
        self.assertEqual(failures, [], "\n".join(failures))


@require_working_asan
class StatefulMultiPacketFuzzTest(SFTPTestCase):
    """Random sequences of packets within a single session, mixing
    plausible handle-string / path-string / numeric fields across many
    opcodes - closer to how the handle table and buffer reuse logic
    actually get exercised in normal use than one-packet-per-connection
    fuzzing.
    """

    @classmethod
    def setUpClass(cls):
        cls.binary = build.ndebug_asan()

    SEED = 2024
    SESSIONS = 150
    OPCODES = list(range(3, 21))

    def _rand_handle_str(self, rng):
        choices = [b"00", b"01", b"02", b"FF", b"ff", b"XY", b"", b"1",
                   bytes(rng.randint(0, 255) for _ in range(2))]
        return rng.choice(choices)

    def _rand_packet(self, rng):
        opcode = rng.choice(self.OPCODES)
        reqid = rng.randint(0, 5)
        pieces = [struct.pack(">B", opcode), struct.pack(">I", reqid)]
        for _ in range(rng.randint(0, 3)):
            choice = rng.random()
            if choice < 0.3:
                h = self._rand_handle_str(rng)
                pieces.append(struct.pack(">I", len(h)) + h)
            elif choice < 0.6:
                s = rng.choice([
                    b"testfile.txt", b"/tmp", b"", b"..", b"nonexistent",
                    bytes(rng.randint(32, 126) for _ in range(rng.randint(0, 30))),
                ])
                pieces.append(struct.pack(">I", len(s)) + s)
            elif choice < 0.8:
                pieces.append(struct.pack(">I", rng.randint(0, 0xFFFFFFFF)))
            else:
                pieces.append(struct.pack(">Q", rng.randint(0, 0xFFFFFFFFFFFFFFFF)))
        payload = b"".join(pieces)
        return struct.pack(">I", len(payload)) + payload

    def test_random_sessions_do_not_crash_or_hang(self):
        rng = random.Random(self.SEED)
        failures = []
        for s in range(self.SESSIONS):
            n_packets = rng.randint(3, 15)
            packets = [self._rand_packet(rng) for _ in range(n_packets)]

            result = self.session(self.binary).run(packets)
            if result.timed_out:
                failures.append(f"[session {s}] HANG, {n_packets} packets")
            elif result.crashed:
                failures.append(f"[session {s}] CRASH\n{result.stderr_text()[:1500]}")
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    import unittest
    unittest.main()
