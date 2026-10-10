"""Functional smoke test for musl libc compatibility (e.g. Void Linux
ships both glibc and musl builds).

Deliberately *not* ASan/UBSan-based like most of this suite: musl-gcc on
Ubuntu links against glibc's libasan/libubsan (they're glibc shared
libraries, not part of musl), and musl's dynamic loader can't find or load
them at runtime - confirmed by actually running a musl+ASan build, not
just by ldd (which fails for musl binaries for unrelated reasons). A fully
static link isn't a workaround either - gcc rejects -static combined with
-fsanitize=address outright. See build.musl_normal's docstring.

These tests exercise the main POSIX surface most likely to differ between
libcs - telldir/seekdir/fdopendir (READDIR), futimens/utimensat (SETSTAT/
FSETSTAT), and the manually-written dirname-splitting REALPATH fallback -
rather than re-running the whole protocol surface already covered (under
ASan) elsewhere in this suite.
"""
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build
import sftp_wire as wire
from testutil import SFTPTestCase, require_musl_gcc


@require_musl_gcc
class MuslSmokeTest(SFTPTestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = build.musl_normal()

    def test_open_write_close_then_read_roundtrips_content(self):
        pflags = wire.SSH_FXF_WRITE | wire.SSH_FXF_CREAT
        open_pkt = struct.pack(">B", wire.SSH_FXP_OPEN) + struct.pack(">I", 1) \
            + wire.sstr("f.txt") + struct.pack(">I", pflags) + struct.pack(">I", 0)
        write_pkt = struct.pack(">B", wire.SSH_FXP_WRITE) + struct.pack(">I", 2) \
            + wire.sstr(b"01") + struct.pack(">Q", 0) + wire.sstr(b"hello-musl")
        close_pkt = struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", 3) + wire.sstr(b"01")

        session = self.session(self.binary)
        result = session.run([wire.pkt(open_pkt), wire.pkt(write_pkt), wire.pkt(close_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[3]), wire.SSH_FX_OK)
        self.assertEqual((self.cwd / "f.txt").read_bytes(), b"hello-musl")

    def test_fsetstat_updates_mtime_via_futimens(self):
        """Exercises futimens() specifically (replaced non-POSIX futimes())."""
        self.write_file("f.txt", b"x")
        open_pkt = struct.pack(">B", wire.SSH_FXP_OPEN) + struct.pack(">I", 1) \
            + wire.sstr("f.txt") + struct.pack(">I", wire.SSH_FXF_WRITE) + struct.pack(">I", 0)
        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_ACMODTIME) + struct.pack(">II", 1700000000, 1700000000)
        fsetstat_pkt = struct.pack(">B", wire.SSH_FXP_FSETSTAT) + struct.pack(">I", 2) + wire.sstr(b"01") + attrs
        close_pkt = struct.pack(">B", wire.SSH_FXP_CLOSE) + struct.pack(">I", 3) + wire.sstr(b"01")

        result = self.session(self.binary).run([wire.pkt(open_pkt), wire.pkt(fsetstat_pkt), wire.pkt(close_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_OK)

    def test_setstat_updates_mtime_via_utimensat(self):
        """Exercises utimensat() specifically (replaced non-POSIX utimes())."""
        self.write_file("f.txt", b"x")
        attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_ACMODTIME) + struct.pack(">II", 1700000000, 1700000000)
        setstat_pkt = struct.pack(">B", wire.SSH_FXP_SETSTAT) + struct.pack(">I", 1) + wire.sstr("f.txt") + attrs

        result = self.session(self.binary).run([wire.pkt(setstat_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)

    def test_symlink_and_readlink_roundtrip(self):
        symlink_pkt = struct.pack(">B", wire.SSH_FXP_SYMLINK) + struct.pack(">I", 1) \
            + wire.sstr("target.txt") + wire.sstr("link.txt")
        readlink_pkt = struct.pack(">B", wire.SSH_FXP_READLINK) + struct.pack(">I", 2) + wire.sstr("link.txt")

        result = self.session(self.binary).run([wire.pkt(symlink_pkt), wire.pkt(readlink_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)
        self.assertEqual(wire.name_path_of(result.responses[2]), b"target.txt")

    def test_mkdir_then_rmdir(self):
        mkdir_pkt = struct.pack(">B", wire.SSH_FXP_MKDIR) + struct.pack(">I", 1) + wire.sstr("subdir") + struct.pack(">I", 0)
        rmdir_pkt = struct.pack(">B", wire.SSH_FXP_RMDIR) + struct.pack(">I", 2) + wire.sstr("subdir")

        result = self.session(self.binary).run([wire.pkt(mkdir_pkt), wire.pkt(rmdir_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)
        self.assertEqual(wire.status_of(result.responses[2]), wire.SSH_FX_OK)

    def test_opendir_and_readdir_lists_entries(self):
        """Exercises fdopendir()/telldir()/seekdir(), the POSIX surface
        READDIR's rewind logic depends on."""
        self.write_file("one.txt")
        opendir_pkt = struct.pack(">B", wire.SSH_FXP_OPENDIR) + struct.pack(">I", 1) + wire.sstr(".")
        readdir_pkt = struct.pack(">B", wire.SSH_FXP_READDIR) + struct.pack(">I", 2) + wire.sstr(b"01")

        result = self.session(self.binary).run([wire.pkt(opendir_pkt), wire.pkt(readdir_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        entries = wire.parse_name_response(result.responses[2])
        names = {filename.decode() for filename, _, _ in entries}
        self.assertIn("one.txt", names)

    def test_realpath_resolves_existing_path(self):
        realpath_pkt = struct.pack(">B", wire.SSH_FXP_REALPATH) + struct.pack(">I", 1) + wire.sstr(".")
        result = self.session(self.binary).run([wire.pkt(realpath_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.name_path_of(result.responses[1]), str(self.cwd).encode())

    def test_realpath_openssh_compat_fallback_for_nonexistent_basename(self):
        """The core OPENSSH_COMPAT feature: a not-yet-created target still
        resolves, via this project's own manually-written dirname-splitting
        fallback (not libc's dirname())."""
        realpath_pkt = struct.pack(">B", wire.SSH_FXP_REALPATH) + struct.pack(">I", 1) + wire.sstr("notyet.txt")
        result = self.session(self.binary).run([wire.pkt(realpath_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.name_path_of(result.responses[1]), str(self.cwd / "notyet.txt").encode())

    def test_remove_deletes_file(self):
        self.write_file("f.txt", b"x")
        remove_pkt = struct.pack(">B", wire.SSH_FXP_REMOVE) + struct.pack(">I", 1) + wire.sstr("f.txt")

        result = self.session(self.binary).run([wire.pkt(remove_pkt)])
        self.assertFalse(result.crashed, result.stderr_text())
        self.assertEqual(wire.status_of(result.responses[1]), wire.SSH_FX_OK)
        self.assertFalse((self.cwd / "f.txt").exists())
