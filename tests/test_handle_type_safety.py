"""Regression tests for handle type confusion: sending a request meant
for one handle type (file vs. directory) against a handle of the other
type.

sftp_readdir() was found to be missing its use == HANDLE_DIR check -
every other handle-consuming operation (sftp_read, sftp_write,
sftp_fstat, sftp_fsetstat) already validated use == HANDLE_FILE before
touching handle-type-specific fields, but sftp_readdir() only checked
that a handle existed at all, not that it was actually a directory
handle. Two concrete ways this bites:

1. A freshly-opened FILE handle has p_dir == NULL (fxp_handle_t's fields
   are never a union, and handle_alloc_file() never touches p_dir), so
   READDIR against it dereferences NULL directly inside telldir() - a
   straightforward SIGSEGV, triggerable with nothing more than an
   ordinary OPEN followed by READDIR. No malformed input required.

2. A FILE handle that reused a directory handle's just-freed table slot
   (open a dir, close it, open a file - handle numbers are reused
   deterministically) has a p_dir field left dangling: sftp_close()
   calls closedir() (which frees the DIR* and closes its fd) but never
   resets p_dir to NULL. Dereferencing it doesn't reliably crash - in
   practice, the freed fd number is very likely reused by the very next
   open() for a regular file, so the kernel's getdents() rejects the
   dangling DIR*'s stale fd with ENOTDIR and glibc's readdir() just
   returns NULL, which the buggy code reported as a clean SSH_FX_EOF
   instead of an error. Silently wrong, not just unsafe - a client
   would see "empty directory" instead of "invalid handle".

Both are fixed by checking use == HANDLE_DIR up front, matching the
pattern every other handle-consuming function already used.
"""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build
import sftp_wire as wire
from testutil import SFTPTestCase, require_working_asan


def _open_file_pkt(reqid, path, pflags=None):
    if pflags is None:
        pflags = wire.SSH_FXF_WRITE | wire.SSH_FXF_CREAT
    return struct.pack(">B", wire.SSH_FXP_OPEN) + struct.pack(">I", reqid) \
        + wire.sstr(path) + struct.pack(">I", pflags) + struct.pack(">I", 0)


def _opendir_pkt(reqid, path="."):
    return struct.pack(">B", wire.SSH_FXP_OPENDIR) + struct.pack(">I", reqid) + wire.sstr(path)


def _close_pkt(reqid, handle):
    return struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", reqid) + wire.sstr(handle)


@require_working_asan
class ReaddirOnFileHandleTest(SFTPTestCase):
    """The bug as found: SSH_FXP_READDIR sent against a handle that is
    not (or is no longer) a directory handle.
    """

    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def test_readdir_on_freshly_opened_file_handle_fails_cleanly(self):
        """Simplest reproduction: OPEN a file, then READDIR that same
        handle. p_dir is NULL (never set for a file handle) - this must
        not dereference it.
        """
        packets = [
            wire.pkt(_open_file_pkt(1, "dummy.txt")),
            wire.pkt(struct.pack(">B", wire.SSH_FXP_READDIR) + struct.pack(">I", 2) + wire.sstr(b"01")),
        ]
        result = self.session(self.binary).run(packets)
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(len(result.responses), 3)  # VERSION, HANDLE, STATUS
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_FAILURE)

    def test_readdir_on_file_handle_reusing_a_closed_directory_slot(self):
        """Closer to how this would actually surface in practice: a
        directory handle's table slot gets closed and its number reused
        for a new file handle. p_dir here is a dangling pointer (left
        over from before closedir() freed it), not NULL - a distinct
        memory-safety state from the simpler case above, worth covering
        separately.
        """
        packets = [
            wire.pkt(_opendir_pkt(1)),
            wire.pkt(_close_pkt(2, b"01")),
            wire.pkt(_open_file_pkt(3, "newfile.txt")),
            wire.pkt(struct.pack(">B", wire.SSH_FXP_READDIR) + struct.pack(">I", 4) + wire.sstr(b"01")),
        ]
        result = self.session(self.binary).run(packets)
        self.assertFalse(result.crashed, result.stderr_text())
        # responses: VERSION, HANDLE(dir), STATUS(close ok), HANDLE(file), STATUS(readdir)
        self.assertEqual(len(result.responses), 5)
        close_resp, open2_resp, readdir_resp = result.responses[2], result.responses[3], result.responses[4]
        self.assertEqual(wire.status_of(close_resp), wire.SSH_FX_OK)
        self.assertEqual(wire.handle_of(open2_resp), b"01", "handle slot should have been reused")
        self.assertEqual(
            wire.status_of(readdir_resp), wire.SSH_FX_FAILURE,
            "must not silently report EOF (or worse) for a stale/wrong-type handle",
        )


@require_working_asan
class FileOperationsOnDirectoryHandleTest(SFTPTestCase):
    """Mirror image of the bug above: file-specific operations sent
    against a directory handle. These were already correctly guarded
    (use == HANDLE_FILE checks already existed on every one of these),
    but weren't locked in by a regression test - adding that here so the
    same asymmetry can't quietly reappear on one of these in the future.
    """

    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def _dir_handle(self, session):
        probe = session.run([wire.pkt(_opendir_pkt(1))])
        handle = wire.handle_of(probe.responses[1])
        self.assertIsNotNone(handle)
        return handle

    def test_read_on_directory_handle_fails_cleanly(self):
        session = self.session(self.binary)
        handle = self._dir_handle(session)
        read_pkt = struct.pack(">B", wire.SSH_FXP_READ) + struct.pack(">I", 2) \
            + wire.sstr(handle) + struct.pack(">Q", 0) + struct.pack(">I", 10)
        result = session.run([wire.pkt(_opendir_pkt(1)), wire.pkt(read_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_FAILURE)

    def test_write_on_directory_handle_fails_cleanly(self):
        session = self.session(self.binary)
        handle = self._dir_handle(session)
        write_pkt = struct.pack(">B", wire.SSH_FXP_WRITE) + struct.pack(">I", 2) \
            + wire.sstr(handle) + struct.pack(">Q", 0) + wire.sstr(b"data")
        result = session.run([wire.pkt(_opendir_pkt(1)), wire.pkt(write_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_FAILURE)

    def test_fstat_on_directory_handle_fails_cleanly(self):
        session = self.session(self.binary)
        handle = self._dir_handle(session)
        fstat_pkt = struct.pack(">B", wire.SSH_FXP_FSTAT) + struct.pack(">I", 2) + wire.sstr(handle)
        result = session.run([wire.pkt(_opendir_pkt(1)), wire.pkt(fstat_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_FAILURE)

    def test_fsetstat_on_directory_handle_fails_cleanly(self):
        session = self.session(self.binary)
        handle = self._dir_handle(session)
        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_PERMISSIONS) + struct.pack(">I", 0o644)
        fsetstat_pkt = struct.pack(">B", wire.SSH_FXP_FSETSTAT) + struct.pack(">I", 2) \
            + wire.sstr(handle) + attrs
        result = session.run([wire.pkt(_opendir_pkt(1)), wire.pkt(fsetstat_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_FAILURE)


if __name__ == "__main__":
    unittest.main()
