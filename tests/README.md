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
  edge cases (bare filenames, trailing slashes, non-`ENOENT` failures)
  that surfaced real bugs during development.
- `test_symlink.py` - `SSH_FXP_SYMLINK` argument order under both
  `OPENSSH_COMPAT` configurations.
- `test_permissions.py` - that `SSH_FXP_OPEN` can't be used to set the
  setuid/setgid bits on a newly created file.
- `test_handles.py` - a full open/read/close round trip exercising the
  hex-format handle scheme, plus a battery of malformed handle strings.
- `test_fuzz.py` - randomized single-packet and stateful multi-packet
  fuzzing with fixed seeds, as a broad sanity sweep rather than a targeted
  test. Not a substitute for a real coverage-guided fuzzer (AFL,
  libFuzzer) if you want to go further.

## Adding a test

Subclass `testutil.SFTPTestCase` for a temp working directory per test
method, pick a `build.py` variant appropriate to what you're testing (ASan
if it touches the filesystem or memory safety matters; `ndebug_asan` if
you're testing that a malformed-input check survives `-DNDEBUG`), and use
`sftp_wire.py`'s packet helpers to build requests.
