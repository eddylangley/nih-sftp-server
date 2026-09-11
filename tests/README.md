# Tests

A black-box test suite for `nih-sftp-server`: it builds the server binary
in several configurations and drives it over stdin/stdout with real (and
deliberately malformed) SFTPv3 packets, the same way `sshd` does.

No dependencies beyond Python 3's standard library and a working `gcc` -
consistent with the project's own zero-dependency philosophy.

## Running locally

From the repository root:

```sh
python3 tests/run_all.py -v
```

This builds four binary variants (see `tests/build.py`) and runs every
`test_*.py` module against them:

| Variant | Flags | Used for |
|---|---|---|
| `normal` | `-O2` | Realistic-deployment sanity checks (e.g. permission masking) |
| `asan` | `-O0 -g -fsanitize=address,undefined` | Filesystem-touching tests (realpath, symlink, handles) where memory-safety matters |
| `ndebug_asan` | `-O0 -g -DNDEBUG -fsanitize=address,undefined` | Protocol-hardening and fuzz tests - the configuration where `assert()` would be compiled out, so anything guarding remote input must be `REQUIRE()` |
| `draft_spec_asan` | `-O0 -g -fsanitize=address,undefined -DOPENSSH_COMPAT=0` | Confirms the strict-draft-spec code paths (as opposed to OpenSSH-compat) also work correctly |

You can also run an individual module directly, e.g.:

```sh
python3 -m unittest tests.test_realpath -v
```

or via `python3 -m unittest discover -s tests -p 'test_*.py'`.

## What's covered

- `test_protocol_hardening.py` - malformed-packet rejection (oversized
  payload length, non-INIT first packet, lying embedded string/data
  lengths, the version-check message text), specifically under
  `-DNDEBUG` to prove these survive an assert()-less build.
- `test_realpath.py` - the OpenSSH-compatibility fallback for
  not-yet-existing paths, plus its `-DOPENSSH_COMPAT=0` override, plus the
  edge cases (bare filenames, trailing slashes, non-`ENOENT` failures,
  empty paths) that surfaced real bugs during development.
- `test_symlink.py` - `SSH_FXP_SYMLINK` argument order and failure path,
  under both `OPENSSH_COMPAT` configurations.
- `test_permissions.py` - that `SSH_FXP_OPEN` can't be used to set the
  setuid/setgid bits on a newly created file.
- `test_handles.py` - a full open/read/close round trip exercising the
  hex-format handle scheme, a battery of malformed handle strings, and
  file-handle exhaustion (opening past `MAX_HANDLES`).
- `test_stat_attrs.py` - `STAT`/`LSTAT`/`FSTAT`/`SETSTAT`/`FSETSTAT`,
  including permission-denied and unowned-chown failure paths (these need
  a non-root user - see "Running as root" below).
- `test_directory_ops.py` - `OPENDIR`/`READDIR`/`MKDIR`/`RMDIR`, including
  directory-handle exhaustion, a dangling symlink that fails to `stat()`,
  and a directory large enough to force `READDIR` across multiple calls.
  This file is what found two real server bugs - see "Bugs this suite has
  found" below.
- `test_file_ops.py` - `WRITE`/`REMOVE`/`RENAME`, plus flag combinations
  (`O_RDWR`, `O_TRUNC`, `O_EXCL`) and `EBADF`-style handle/mode mismatches.
- `test_readlink.py` - success, non-symlink, and nonexistent-path cases.
- `test_fuzz.py` - randomized single-packet and stateful multi-packet
  fuzzing with fixed seeds, as a broad sanity sweep rather than a targeted
  test. Not a substitute for a real coverage-guided fuzzer (AFL,
  libFuzzer) if you want to go further.

## Bugs this suite has found

Writing tests toward full coverage (not just toward a percentage) found
two real bugs in `nih-sftp-server.c` that no earlier testing in this
project's history had caught:

- **`sftp_opendir()` leaked a file descriptor and `fdopendir()`'s internal
  allocation** whenever `handle_alloc_dir()` failed (the handle table
  full). `sftp_open()` already closed its fd in the equivalent situation;
  `sftp_opendir()` didn't. Caught by `DirectoryHandleExhaustionTest` under
  `LeakSanitizer`.
- **`sftp_readdir()` could hang the server forever** on a directory large
  enough that its entries don't all fit in one response: the code that
  rewinds (`seekdir()`) to retry an entry next time was missing a `break`,
  so it looped rereading and rewinding past the same entry indefinitely.
  Any authenticated client listing a sufficiently large directory would
  hang the session - no malformed input required. Caught by
  `test_readdir_with_many_entries_spans_multiple_calls` timing out.

Both are fixed in the current `nih-sftp-server.c`.

## Measuring coverage

```sh
python3 tests/run_coverage.py [-v]
```

Builds gcov-instrumented binaries (separately for the default and
`-DOPENSSH_COMPAT=0` configurations, since that macro compiles two
mutually-exclusive versions of `sftp_realpath`/`sftp_symlink`), runs the
whole suite against them, then reports line/branch coverage and every
never-executed line, grouped by function.

A handful of lines are intentionally not chased: they're reachable only
via memory-allocation failure (`strdup`/`malloc` returning `NULL`), via
syscalls that essentially never fail on a valid fd (`fstat`, `close`,
`lseek` on a regular file), or via deliberate fault injection into
`stdin`/`stdout` (`main`'s and `read_input`'s `perror`/`exit` paths).
`sftp_realpath`'s `discard_basename` aliasing branch is similarly
near-unreachable through any normal filesystem state - see the comment at
its call site. `put_status`'s `default` case and `errno_to_sftp`'s `case
0` are unreachable from any external input at all, since the server never
generates a status code outside the ones already handled. None of these
are worth contriving a test for at the expense of a fragile or misleading
one.

## Running as root

A few tests need `EACCES`/`EPERM` to actually occur, which root bypasses
(root ignores DAC permission checks). These are decorated with
`testutil.skip_if_root` and skip cleanly - rather than fail for the wrong
reason - when run as root. They run for real in CI (GitHub-hosted runners
use a non-root user by default) and in any normal local development
environment. If you're running as root locally (as in a container) and
want to exercise these, run as a different user, e.g.:

```sh
useradd -m tester   # if one doesn't already exist
chown -R tester .
su tester -c 'python3 tests/run_all.py -v'
```

## Adding a test

Subclass `testutil.SFTPTestCase` for a temp working directory per test
method, pick a `build.py` variant appropriate to what you're testing (ASan
if it touches the filesystem or memory safety matters; `ndebug_asan` if
you're testing that a malformed-input check survives `-DNDEBUG`), and use
`sftp_wire.py`'s packet helpers to build requests. Handle numbering is
deterministic within a fresh process (the first handle issued is always
`"01"`), so tests can hardcode it rather than probing for it - useful
since an unclosed directory handle leaks under `LeakSanitizer`, so a
throwaway probe call needs its own `CLOSE` or should be avoided
altogether.
