# Coverage-guided fuzzing

`fuzz/fuzz_harness.c` drives `nih-sftp-server.c`'s real, unmodified
`main()` against fuzzer-supplied byte streams via
[libFuzzer](https://llvm.org/docs/LibFuzzer.html), without forking a new
process per input - essential for the throughput a coverage-guided
fuzzer needs. See the comment at the top of `fuzz_harness.c` for exactly
how it redirects the server's I/O and `exit()` calls without touching
`nih-sftp-server.c` itself.

This exists because coverage-guided fuzzing found real bugs that neither
manual review nor `tests/test_fuzz.py`'s fixed-seed sanity-sweep fuzzing
caught - see "Why this exists" below.

`nih-sftp-server.c` itself has, and must keep, zero dependencies beyond
the C standard library and POSIX. This directory is the one place that's
not true: fuzzing it properly needs `clang` (libFuzzer is an LLVM/
compiler-rt feature - GCC has never implemented it) and
[`bubblewrap`](https://github.com/containers/bubblewrap) (for sandboxing
- see below). Both are development/CI-only dependencies for this one
piece of tooling, not something the server itself ever needs.

## Requirements

```sh
apt install clang bubblewrap   # or your distro's equivalent
```

## ⚠️ Always run inside bubblewrap

This harness drives a **real, filesystem-touching SFTP server** with no
path sanitization of its own (`nih-sftp-server.c` relies on `sshd`'s
`ChrootDirectory` for that in real deployment - see the top-level
README). A fuzzer-mutated `OPEN`/`RENAME`/`SYMLINK`/`REALPATH` path can
easily contain `../..` or an absolute path, and nothing stops it from
being used. Never run the harness directly against a real filesystem -
always run it inside `bwrap`, which gives it its own throwaway root with
only an empty scratch directory writable. **Run this from the repo
root** - the command below captures that directory as an absolute path
before invoking `bwrap`:

```sh
mkdir -p /tmp/nih-sftp-fuzz-scratch
repo_root="$(pwd)"

bwrap --unshare-all --share-net --die-with-parent \
    --ro-bind / / \
    --tmpfs /tmp \
    --bind /tmp/nih-sftp-fuzz-scratch /tmp/scratch \
    --chdir /tmp/scratch \
    "$repo_root/fuzz/fuzz_harness" "$repo_root/fuzz/corpus" -max_len=34100 -timeout=5
```

The paths to the harness binary and corpus **must** be absolute, not
`fuzz/fuzz_harness fuzz/corpus` - `--chdir /tmp/scratch` changes the
working directory *inside* the sandbox before the command runs, so a
relative path resolves against that empty scratch directory, not
wherever you were in your checkout when you ran `bwrap`
(`$repo_root="$(pwd)"` above is captured by the outer shell before
`bwrap` starts, so it's unaffected by the `--chdir` and correctly points
back at your checkout).

`--share-net` matters, not just `--unshare-all` on its own: without it,
`bwrap` tries to set up a network namespace (including configuring a
loopback interface), which fails with `bwrap: loopback: Failed
RTM_NEWADDR: Operation not permitted` on any reasonably modern
Ubuntu/Debian (24.04+ restricts that capability for unprivileged user
namespaces by default - this isn't specific to this project, it's a
common `bwrap` gotcha on current distros). We don't need network
isolation for this harness anyway - `nih-sftp-server.c` does no
networking of its own, only stdin/stdout - so sharing the host's network
namespace instead of isolating it costs nothing here.

**If you instead see `bwrap: setting up uid map: Permission denied`**,
that's a step earlier and separate: Ubuntu 24.04+ (and some other current
distros) set `kernel.apparmor_restrict_unprivileged_userns=1` by default,
which blocks the user namespace `bwrap` needs to sandbox *anything* at
all, before it even gets to networking. Fix:

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

Worth knowing what that trades away: unprivileged user namespaces have
historically been an attack surface for local privilege-escalation bugs,
which is exactly why distros started restricting them - this setting
exists for a real reason, not by accident. Relaxing it system-wide isn't
something to do without thinking about it on a machine you don't fully
control; on a scoped CI runner (see `.github/workflows/tests.yml`, which
does exactly this) or a personal dev machine you administer yourself,
it's a reasonable, common trade-off. The command above only changes the
running kernel's setting for the current boot - it doesn't persist across
a reboot unless you also write it to a file under `/etc/sysctl.d/`.

`--ro-bind / /` gives the fuzzer read access to the host filesystem (so
it can find its own binary, libraries, and the corpus) without write
access to any of it; `--tmpfs /tmp` plus the `--bind` makes the one
directory it actually runs in the *only* writable path anywhere. A
mutated path that tries to escape - `../../etc/passwd`, an absolute
path, anything - simply doesn't exist from inside the sandbox.

## Building and running

```sh
clang -O1 -g -fsanitize=fuzzer,address,undefined \
    -std=gnu99 fuzz/fuzz_harness.c -o fuzz/fuzz_harness
```

Then run it as shown above. Useful flags: `-jobs=N -workers=N` for
parallel fuzzing; `-max_total_time=N` to bound a run to N seconds;
`-artifact_prefix=/path/` to control where crash/hang reproducers land
(as `crash-<hash>` / `timeout-<hash>` files inside the scratch
directory). To replay one, run the same `bwrap` command as above but
with the crash file's absolute host path appended as an extra argument
after `$repo_root/fuzz/corpus` - same absolute-path requirement applies
to it as to the harness binary and corpus.

`-max_len=34100` matches `MAX_PACKET` (34000) plus a little headroom for
the length header. `-timeout=5` bounds how long a single input may run
before libFuzzer treats it as a hang - see "Why this exists" below for
why that matters more than usual here.

## Regenerating the seed corpus

`fuzz/corpus/` starts from `fuzz/generate_corpus.py`, which builds a
handful of valid sessions (one per major opcode) using the same
wire-protocol helpers `tests/` uses, plus one deliberately malformed
seed. Regenerate it if the protocol helpers change:

```sh
python3 fuzz/generate_corpus.py
```

libFuzzer grows the corpus on its own as it discovers new coverage; you
don't need to feed it more seeds than this to get started.

## CI integration

`.github/workflows/tests.yml`'s `fuzz` job installs `clang` and
`bubblewrap`, builds the harness, and runs it inside `bwrap` for a
bounded time on every push - short enough not to slow down CI
meaningfully, long enough to catch regressions a human wouldn't think to
write a specific test for. It's not a substitute for a longer fuzzing
run; if you want deeper coverage, run the harness locally for minutes to
hours rather than seconds.

## Why this exists

Two real bugs in `nih-sftp-server.c` were found via structured,
coverage-driven *test writing* (see `tests/README.md`), not by fuzzing -
including one, an infinite loop in `sftp_readdir()`, that would only ever
show up as a **hang**, never a crash. That's exactly the failure mode a
short-timeout fuzzer is well-suited to catch automatically, and exactly
what motivated building this: the manual test-writing pass that found it
was thorough but ad hoc, and there's no guarantee it caught everything of
that shape. Coverage-guided fuzzing, run for real wall-clock time, is a
more systematic way to keep looking.

A separate bug turned up in the harness itself during development:
`LLVMFuzzerTestOneInput()`'s per-iteration state reset originally just
zeroed the handle table without closing whatever it still referenced, so
a fuzzer input that opened a handle and never sent a matching `CLOSE`
leaked that handle's fd (and, for a directory handle, `fdopendir()`'s
allocated buffer) on every such iteration - confirmed with
`LeakSanitizer`: 199 leaked allocations out of 200 iterations of a single
repeated input, before the fix. Not a bug in `nih-sftp-server.c` - a real
deployment spawns a fresh process per session, so the OS reclaims
everything at exit regardless - purely an artifact of the persistent-mode
reuse this harness needs for throughput. `LLVMFuzzerTestOneInput()` now
closes anything still open before resetting the table each iteration.
