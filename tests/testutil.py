"""Shared test-case base class for the nih-sftp-server test suite."""
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build  # noqa: E402  (import after sys.path bootstrap above)
import sftp_wire as wire  # noqa: E402


def running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


skip_if_root = unittest.skipIf(
    running_as_root(),
    "running as root - DAC permission checks (EACCES/EPERM) are bypassed",
)


class SFTPTestCase(unittest.TestCase):
    """Gives each test method a fresh temporary directory to use as the
    server's working directory, cleaned up automatically afterward.

    Each test spawns its own server process (matching how sshd invokes the
    real subsystem: one process per session), so tests never share server
    state - only, if they choose to, files placed in self.cwd.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cwd = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def session(self, binary) -> wire.Session:
        return wire.Session(binary, cwd=self.cwd)

    def write_file(self, name: str, content: bytes = b"") -> pathlib.Path:
        path = self.cwd / name
        path.write_bytes(content)
        return path


def require_working_asan(test_class):
    """Class decorator: skip the whole test class (with a clear reason)
    instead of running it, if AddressSanitizer itself doesn't work on this
    host. See build.asan_functional's docstring for why this can happen on
    otherwise-fine hardware (e.g. some Raspberry Pi boards) and isn't a bug
    in this project.

    Without this, ASan-based tests on an affected host either report
    confusing failures that have nothing to do with the code under test, or
    - worse, before sftp_wire.SessionResult.crashed was broadened to catch
    this failure mode - silently "pass" without the server code actually
    having run at all.
    """
    original_setUpClass = test_class.setUpClass

    @classmethod
    def wrapped_setUpClass(cls):
        if not build.asan_functional():
            raise unittest.SkipTest(
                "AddressSanitizer does not run correctly on this host - this is "
                "a known issue on some aarch64 boards (e.g. Raspberry Pi 3/4, "
                "see https://bugs.debian.org/1115578), not a bug in this "
                "project. Tests that don't require ASan (e.g. "
                "test_permissions.py) still cover this host. If "
                "NIH_SFTP_FORCE_ASAN_UNAVAILABLE is set in your environment and "
                "you believe this is now fixed, unset it to allow a re-probe."
            )
        original_setUpClass()

    test_class.setUpClass = wrapped_setUpClass
    return test_class
