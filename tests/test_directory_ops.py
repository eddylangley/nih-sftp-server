"""Tests for the directory-related handlers: SSH_FXP_OPENDIR,
SSH_FXP_READDIR, SSH_FXP_MKDIR, SSH_FXP_RMDIR.

SSH_FXP_READDIR in particular had zero coverage before this file - an
entire feature that was never exercised by any earlier test.
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
class OpendirReaddirTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def test_readdir_lists_directory_entries_and_reaches_eof(self):
        self.write_file("one.txt", b"1")
        self.write_file("two.txt", b"22")

        opendir_pkt = struct.pack(">B", wire.SSH_FXP_OPENDIR) + struct.pack(">I", 1) + wire.sstr(".")
        session = self.session(self.binary)
        # The first handle issued in a fresh process/session is always "01"
        # (see test_handles.py) - hardcoding this avoids a separate,
        # never-closed probe call that would itself leak fdopendir()'s
        # allocation under ASan/LeakSanitizer.
        handle = b"01"

        readdir_pkt = struct.pack(">B", wire.SSH_FXP_READDIR) + struct.pack(">I", 2) + wire.sstr(handle)
        readdir_pkt2 = struct.pack(">B", wire.SSH_FXP_READDIR) + struct.pack(">I", 3) + wire.sstr(handle)
        close_pkt = struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", 4) + wire.sstr(handle)

        result = session.run([
            wire.pkt(opendir_pkt), wire.pkt(readdir_pkt), wire.pkt(readdir_pkt2), wire.pkt(close_pkt),
        ])
        self.assertFalse(result.crashed, result.stderr_text())

        first_readdir_resp = result.responses[2]
        self.assertEqual(first_readdir_resp[0], wire.SSH_FXP_NAME,
                          "expected a NAME response listing entries")
        entries = wire.parse_name_response(first_readdir_resp)
        names = {filename.decode() for filename, _, _ in entries}
        # A small directory like this fits in one READDIR response, along
        # with the "." and ".." entries readdir() itself always returns.
        self.assertEqual(names, {"one.txt", "two.txt", ".", ".."})

        # All entries were returned in the first response, so the second
        # READDIR call should report EOF.
        second_readdir_resp = result.responses[3]
        self.assertEqual(wire.status_of(second_readdir_resp), wire.SSH_FX_EOF)

        # Exercises sftp_close()'s HANDLE_DIR branch (closedir()), which had
        # no coverage before this file since no directory had ever been
        # opened by any earlier test.
        close_resp = result.responses[4]
        self.assertEqual(wire.status_of(close_resp), wire.SSH_FX_OK)

    def test_readdir_reports_file_sizes(self):
        self.write_file("sized.txt", b"1234567890")
        opendir_pkt = struct.pack(">B", wire.SSH_FXP_OPENDIR) + struct.pack(">I", 1) + wire.sstr(".")

        session = self.session(self.binary)
        handle = b"01"  # deterministic first handle - see comment above

        readdir_pkt = struct.pack(">B", wire.SSH_FXP_READDIR) + struct.pack(">I", 2) + wire.sstr(handle)
        close_pkt = struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", 3) + wire.sstr(handle)
        result = session.run([wire.pkt(opendir_pkt), wire.pkt(readdir_pkt), wire.pkt(close_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())

        entries = wire.parse_name_response(result.responses[2])
        by_name = {filename: attrs for filename, _, attrs in entries}
        sized_attrs = by_name[b"sized.txt"]
        flags = struct.unpack(">I", sized_attrs[0:4])[0]
        self.assertTrue(flags & wire.SSH_FILEXFER_ATTR_SIZE)
        size = struct.unpack(">Q", sized_attrs[4:12])[0]
        self.assertEqual(size, 10)

    def test_opendir_nonexistent_path_fails(self):
        payload = struct.pack(">B", wire.SSH_FXP_OPENDIR) + struct.pack(">I", 1) + wire.sstr("nope")
        result = self.session(self.binary).run([wire.pkt(payload)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_NO_SUCH_FILE)

    def test_opendir_on_regular_file_fails(self):
        """A regular file opens fine via open() (no O_DIRECTORY flag is
        used), so this exercises sftp_opendir()'s *second* failure branch -
        fdopendir() itself rejecting a non-directory fd with ENOTDIR -
        distinct from the open()-fails-outright case above.
        """
        self.write_file("notadir.txt")
        payload = struct.pack(">B", wire.SSH_FXP_OPENDIR) + struct.pack(">I", 1) + wire.sstr("notadir.txt")
        result = self.session(self.binary).run([wire.pkt(payload)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_NO_SUCH_FILE)

    def test_readdir_skips_entries_that_fail_to_stat(self):
        """A dangling symlink (pointing at a nonexistent target) fails
        fstatat() (which follows symlinks by default), exercising
        sftp_readdir()'s "ignore entries we can't stat" continue branch.
        The dangling entry should be silently omitted; everything else
        should still be listed normally.
        """
        self.write_file("real.txt", b"x")
        dangling = self.cwd / "dangling"
        dangling.symlink_to(self.cwd / "does_not_exist_anywhere")

        opendir_pkt = struct.pack(">B", wire.SSH_FXP_OPENDIR) + struct.pack(">I", 1) + wire.sstr(".")
        session = self.session(self.binary)
        handle = b"01"  # deterministic first handle - see comment above

        readdir_pkt = struct.pack(">B", wire.SSH_FXP_READDIR) + struct.pack(">I", 2) + wire.sstr(handle)
        close_pkt = struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", 3) + wire.sstr(handle)
        result = session.run([wire.pkt(opendir_pkt), wire.pkt(readdir_pkt), wire.pkt(close_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())

        entries = wire.parse_name_response(result.responses[2])
        names = {filename.decode() for filename, _, _ in entries}
        self.assertIn("real.txt", names)
        self.assertNotIn("dangling", names, "dangling symlink should be silently skipped")

    def test_readdir_with_many_entries_spans_multiple_calls(self):
        """With enough directory entries that a single READDIR response
        can't hold them all, the server must rewind (seekdir) and continue
        on the next call rather than silently dropping entries. This is
        the only way to exercise that rewind branch.
        """
        n_files = 700  # comfortably more than fit in one ~34000-byte packet
        for i in range(n_files):
            self.write_file(f"f{i:04d}.txt")

        opendir_pkt = struct.pack(">B", wire.SSH_FXP_OPENDIR) + struct.pack(">I", 1) + wire.sstr(".")
        session = self.session(self.binary)
        handle = b"01"  # deterministic first handle - see comment above

        all_names = set()
        call_count = 0
        reqid = 2
        packets = [wire.pkt(opendir_pkt)]
        # Issue enough READDIR calls up front to drain the directory
        # (each call is independent given the server processes requests
        # in order within one session/process).
        for _ in range(10):
            readdir_pkt = struct.pack(">B", wire.SSH_FXP_READDIR) + struct.pack(">I", reqid) + wire.sstr(handle)
            packets.append(wire.pkt(readdir_pkt))
            reqid += 1
        close_pkt = struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", reqid) + wire.sstr(handle)
        packets.append(wire.pkt(close_pkt))

        result = session.run(packets)
        self.assertFalse(result.crashed, result.stderr_text())
        for resp in result.responses[2:]:
            call_count += 1
            if resp[0] == wire.SSH_FXP_NAME:
                entries = wire.parse_name_response(resp)
                all_names.update(f.decode() for f, _, _ in entries)
            elif wire.status_of(resp) == wire.SSH_FX_EOF:
                break

        expected = {f"f{i:04d}.txt" for i in range(n_files)} | {".", ".."}
        self.assertEqual(all_names, expected)
        self.assertGreater(call_count, 1, "expected more than one READDIR call to drain this many entries")


@require_working_asan
class DirectoryHandleExhaustionTest(SFTPTestCase):
    """Exercises handle_alloc_dir()'s "out of handles" branch - the
    directory-handle equivalent of test_handles.py's
    HandleExhaustionTest, which only covers file handles.
    """

    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def test_opening_more_than_max_handles_directories_fails_cleanly(self):
        session = self.session(self.binary)
        attempts = 300
        packets = []
        for i in range(attempts):
            pkt = struct.pack(">B", wire.SSH_FXP_OPENDIR) + struct.pack(">I", i + 1) + wire.sstr(".")
            packets.append(wire.pkt(pkt))

        # Close every handle that could possibly have been allocated,
        # appended to the same session/process so LeakSanitizer sees each
        # fdopendir() allocation explicitly freed before exit. Closing a
        # handle number that was never actually allocated just fails
        # cleanly (SSH_FX_FAILURE) - harmless, and simpler than first
        # probing which handles actually succeeded.
        max_possible_handles = 255  # tied to current MAX_HANDLE_DIGITS=2
        close_reqid = attempts + 1
        for h in range(1, max_possible_handles + 1):
            handle_str = f"{h:02X}".encode()
            close_pkt = struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", close_reqid) + wire.sstr(handle_str)
            packets.append(wire.pkt(close_pkt))
            close_reqid += 1

        result = session.run(packets)
        self.assertFalse(result.crashed, result.stderr_text())
        open_responses = result.responses[1:attempts + 1]
        self.assertEqual(len(open_responses), attempts)

        handles_seen = []
        first_failure_at = None
        for i, resp in enumerate(open_responses):
            if resp[0] == wire.SSH_FXP_HANDLE:
                handles_seen.append(wire.handle_of(resp))
            else:
                self.assertEqual(wire.status_of(resp), wire.SSH_FX_FAILURE)
                if first_failure_at is None:
                    first_failure_at = i

        self.assertIsNotNone(first_failure_at, f"expected to exhaust the handle table within {attempts} opens")
        self.assertEqual(len(handles_seen), len(set(handles_seen)))
        self.assertEqual(len(handles_seen), max_possible_handles)


@require_working_asan
class MkdirRmdirTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.asan()

    def _mkdir(self, path, perm_attr=None):
        attrs = b"\x00\x00\x00\x00"
        if perm_attr is not None:
            attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_PERMISSIONS) + struct.pack(">I", perm_attr)
        payload = struct.pack(">B", wire.SSH_FXP_MKDIR) + struct.pack(">I", 1) + wire.sstr(path) + attrs
        return self.session(self.binary).run([wire.pkt(payload)])

    def _rmdir(self, path):
        payload = struct.pack(">B", wire.SSH_FXP_RMDIR) + struct.pack(">I", 1) + wire.sstr(path)
        return self.session(self.binary).run([wire.pkt(payload)])

    def test_mkdir_creates_directory(self):
        result = self._mkdir("newdir")
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)
        self.assertTrue((self.cwd / "newdir").is_dir())

    def test_mkdir_already_exists_fails(self):
        self._mkdir("dupdir")
        result = self._mkdir("dupdir")
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_FAILURE)

    def test_rmdir_removes_empty_directory(self):
        self._mkdir("emptydir")
        result = self._rmdir("emptydir")
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)
        self.assertFalse((self.cwd / "emptydir").exists())

    def test_rmdir_nonexistent_fails(self):
        result = self._rmdir("nope")
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_NO_SUCH_FILE)

    def test_rmdir_nonempty_fails(self):
        self._mkdir("nonempty")
        self.write_file("nonempty/inside.txt")
        result = self._rmdir("nonempty")
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_FAILURE)
        self.assertTrue((self.cwd / "nonempty").exists())


if __name__ == "__main__":
    unittest.main()
