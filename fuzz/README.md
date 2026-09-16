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
mkdir -p /tmp/nih-sftp-fuzz-scratch /tmp/nih-sftp-fuzz-artifacts
repo_root="$(pwd)"

bwrap --unshare-all --share-net --die-with-parent \
    --ro-bind / / \
    --bind "$repo_root/fuzz/corpus" "$repo_root/fuzz/corpus" \
    --tmpfs /tmp \
    --bind /tmp/nih-sftp-fuzz-scratch /tmp/scratch \
    --bind /tmp/nih-sftp-fuzz-artifacts /tmp/artifacts \
    --chdir /tmp/scratch \
    "$repo_root/fuzz/fuzz_harness" "$repo_root/fuzz/corpus" -max_len=34100 -timeout=5 \
    -artifact_prefix=/tmp/artifacts/
```

**Two separate writable binds, not one.** `/tmp/scratch` is the SFTP
server's own sandboxed playground - the filesystem it actually serves
`OPEN`/`MKDIR`/`SETSTAT`/etc. requests against - while `/tmp/artifacts`
is *only* for libFuzzer's own crash/hang output, and the server under
test has no protocol-level path that reaches it. This split matters
more than it looks: this harness runs the real, unmodified
`nih-sftp-server.c` against a real filesystem, so a fuzzer-generated
`SSH_FXP_SETSTAT` on path `"."` with `permissions=0` makes the server's
own (entirely correct) `chmod(sz_path, attr.permissions & PERM_MASK)`
call in `sftp_setstat()` legitimately strip all access from whatever
directory the sandbox is `--chdir`'d into. If that directory is also
where libFuzzer writes `-artifact_prefix` output (its default, `./`,
if you don't pass one explicitly), a crash found later in the same run
can have its own artifact file silently fail to write - libFuzzer still
logs `Test unit written to ./crash-<hash>`, but the file was never
actually left on disk, only ordinary fuzzer-generated protocol traffic
did it to itself, nothing exotic. Keeping artifacts in a directory the
server under test can never name sidesteps this entirely.

The extra `--bind "$repo_root/fuzz/corpus" "$repo_root/fuzz/corpus"`
layers a read-write mount for just that one directory on top of the
otherwise-read-only `/` (later `bwrap` binds override earlier ones for
the same path) - everything else on the host stays read-only, but
libFuzzer can now actually write newly-discovered, coverage-increasing
inputs into the corpus directory as it finds them, the same way it would
outside a sandbox. Without this, every run silently started fresh from
the same static seed files and threw away anything discovered along the
way.

Deliberately not something this repo commits back to version control,
though - see "Should the corpus be committed?" below.

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
parallel fuzzing; `-max_total_time=N` to bound a run to N seconds.

## Replaying a crash found locally

A crash or hang found by a local run (not CI - see below for that)
lands in the artifacts directory, since the command above passes
`-artifact_prefix=/tmp/artifacts/` explicitly - see "Two separate
writable binds, not one" above for why it's not the scratch directory:

```sh
ls /tmp/nih-sftp-fuzz-artifacts/     # crash-<hash> or timeout-<hash>
```

To replay one, run the *same* `bwrap` invocation used to fuzz, but
replace the trailing `"$repo_root/fuzz/corpus" -max_len=... -timeout=...
-artifact_prefix=...` with the single crash file - and reference it by
its path **inside the sandbox**, not the host path you just `ls`'d
above:

```sh
bwrap --unshare-all --share-net --die-with-parent \
    --ro-bind / / \
    --bind "$repo_root/fuzz/corpus" "$repo_root/fuzz/corpus" \
    --tmpfs /tmp \
    --bind /tmp/nih-sftp-fuzz-scratch /tmp/scratch \
    --bind /tmp/nih-sftp-fuzz-artifacts /tmp/artifacts \
    --chdir /tmp/scratch \
    "$repo_root/fuzz/fuzz_harness" /tmp/artifacts/crash-<hash>
```

That last substitution matters and is easy to get backwards: the crash
file physically lives on the host at
`/tmp/nih-sftp-fuzz-artifacts/crash-<hash>`, but `--tmpfs /tmp` replaces
everything under `/tmp` *inside* the sandbox with an empty filesystem -
so that host path isn't reachable from inside at all. Only
`/tmp/artifacts/crash-<hash>` is, via the explicit `--bind` for the
artifacts directory. Passing a single file (rather than the corpus
directory) puts libFuzzer into one-shot replay mode: it runs that one
input once and exits, with a full stack trace on the crash/hang you
already saw.

(The `--bind` for `/tmp/scratch` is still needed here even though this
replay doesn't write anything there - `--chdir /tmp/scratch` still
targets it, and `bwrap` fails outright with `Can't chdir to /tmp/scratch:
Permission denied` if that bind's target doesn't exist or was left with
broken permissions by the SETSTAT-on-"." scenario above. `chmod 755
/tmp/nih-sftp-fuzz-scratch` fixes it if you hit that; it's a leftover
side effect of a previous run, not data loss.)

**If CI found it instead**, download the `fuzz-findings` artifact from
the failed workflow run, extract it, and use the same replay command
above - but since the file isn't already sitting in your artifacts
directory this time, copy it there first (`cp downloaded-crash-file
/tmp/nih-sftp-fuzz-artifacts/`) so it's reachable at the same
`/tmp/artifacts/...` path inside the sandbox.

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

With the writable `--bind` above, libFuzzer grows this corpus on disk
as it discovers new coverage during a run, the same way it would outside
a sandbox - you don't need to feed it more seeds than this to get
started.

## Should the corpus be committed?

Deliberately, no - `fuzz/corpus/` only ever holds the small seed set
`generate_corpus.py` produces; growth discovered during a fuzzing run is
real (and useful for that session), but isn't checked into version
control, and the CI job doesn't need the writable `--bind` above at all
for exactly this reason - a single run already keeps newly-discovered
inputs in memory for further mutation regardless of whether they're also
written to disk, so a read-only corpus directory doesn't hurt CI's
in-run effectiveness, only persistence *across* separate runs, which CI
doesn't need anyway (its workspace is discarded after the job either way).

The reasoning for not committing: corpus entries here are raw SFTP
wire-format bytes - length prefixes, opcodes, field layouts - not
something with a stable, self-describing structure. They don't become
"invalid" as the protocol code changes (`LLVMFuzzerTestOneInput` accepts
any byte sequence), but they can quietly become *stale* - a `REQUIRE()`
check tightening, or a field layout changing, could make an old entry
silently degrade from "exercises interesting deep logic" to "immediately
rejected as malformed" with no signal that it happened. libFuzzer has no
built-in staleness detection for this; the closest tool is running it
with `-merge=1` periodically, which re-evaluates the corpus against
current coverage and drops fully-redundant entries - but that catches
redundancy, not "this entry quietly lost its value after a refactor."
Without deliberately running that on some cadence, a persisted, growing
corpus becomes a maintenance liability nobody's actually watching, for a
benefit (deeper coverage in one bounded CI run) a fresh seed set already
mostly provides. If you want the accumulated value of a long local
fuzzing session to persist, that's a `git add fuzz/corpus/` away
whenever you decide it's worth it - just not something this repo does by
default.

## CI integration

`.github/workflows/tests.yml`'s `fuzz` job installs `clang` and
`bubblewrap`, builds the harness, and runs it inside `bwrap` for a
bounded time on every push - short enough not to slow down CI
meaningfully, long enough to catch regressions a human wouldn't think to
write a specific test for. It's not a substitute for a longer fuzzing
run; if you want deeper coverage, run the harness locally for minutes to
hours rather than seconds.

If this job fails, it uploads whatever it found as a `fuzz-findings`
artifact - see "Replaying a crash found locally" above for how to
reproduce it on your own machine (the same steps, once you've downloaded
and placed the file).
