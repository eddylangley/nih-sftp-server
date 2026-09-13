# Coverage-guided fuzzing

`fuzz/fuzz_harness.c` drives `nih-sftp-server.c`'s real, unmodified
`main()` against fuzzer-supplied byte streams via
[libFuzzer](https://llvm.org/docs/LibFuzzer.html), without forking a new
process per input - essential for the throughput a coverage-guided
fuzzer needs (thousands to millions of executions per second, versus the
hundreds per second `tests/test_fuzz.py`'s process-per-input model can
manage). See the comment at the top of `fuzz_harness.c` for exactly how
it redirects the server's I/O and `exit()` calls without touching
`nih-sftp-server.c` itself.

This exists because coverage-guided fuzzing found real bugs that neither
manual review nor the fixed-seed sanity-sweep fuzzing in
`tests/test_fuzz.py` caught - see "Why this exists" below.

## ⚠️ Always run from an empty scratch directory

This harness drives a **real, filesystem-touching SFTP server**, not a
pure in-memory parser. The fuzzer *will* create, rename, and delete real
files and directories relative to wherever you run it from, driven by
whatever paths appear in its mutated inputs. Never run it from the repo
checkout or any directory containing anything you care about:

```sh
mkdir -p /tmp/nih-sftp-fuzz && cd /tmp/nih-sftp-fuzz
/path/to/repo/fuzz/fuzz_harness /path/to/repo/fuzz/corpus -max_len=34100 -timeout=5
```

## Requirements

**`clang`** - libFuzzer is an LLVM/compiler-rt feature; GCC has never
implemented it. If you're on a machine without `clang`, the easiest path
is usually your OS package manager (`apt install clang`,
`brew install llvm`, etc.) - no special "libFuzzer package" is needed,
it ships as part of clang itself via `-fsanitize=fuzzer`.

## Building and running

```sh
clang -O1 -g -fsanitize=fuzzer,address,undefined \
    -std=gnu99 fuzz/fuzz_harness.c -o fuzz/fuzz_harness

mkdir -p /tmp/nih-sftp-fuzz && cd /tmp/nih-sftp-fuzz
/path/to/fuzz_harness /path/to/fuzz/corpus -max_len=34100 -timeout=5
```

`-max_len=34100` matches `MAX_PACKET` (34000) plus a little headroom for
the length header - there's little value in the fuzzer spending time on
inputs bigger than the server will ever accept. `-timeout=5` bounds how
long a single input is allowed to run before libFuzzer treats it as a
hang and reports it - see "Why this exists" below for why this matters
more than usual for this project.

Useful flags: `-jobs=N -workers=N` for parallel fuzzing;
`-max_total_time=N` to bound a CI run to N seconds;
`-artifact_prefix=/path/` to control where crash/hang reproducers land
(they're written as `crash-<hash>` / `timeout-<hash>` files - replay one
directly: `./fuzz_harness crash-abc123`).

## Regenerating the seed corpus

`fuzz/corpus/` starts from `fuzz/generate_corpus.py`, which builds a
handful of valid sessions (one per major opcode) using the same
wire-protocol helpers `tests/` uses, plus one deliberately malformed
seed. Regenerate it if the protocol helpers change:

```sh
python3 fuzz/generate_corpus.py
```

libFuzzer will grow the corpus on its own as it discovers new coverage;
you don't need to feed it more seeds than this to get started.

## Verifying the harness (no clang available)

If you don't have `clang` handy but want to sanity-check the harness
logic itself compiles and runs correctly under plain GCC (without real
libFuzzer, since GCC can't provide that), two small standalone drivers
are included for exactly that - they are **not** part of the fuzzing
setup itself, just a way to smoke-test the harness's I/O-redirection and
state-reset plumbing:

```sh
mkdir -p /tmp/nih-sftp-fuzz-check && cd /tmp/nih-sftp-fuzz-check
gcc -O0 -g -fsanitize=address,undefined -std=gnu99 \
    /path/to/fuzz/smoke_test_driver.c /path/to/fuzz/fuzz_harness.c -o smoke_test
./smoke_test

gcc -O0 -g -fsanitize=address,undefined -std=gnu99 \
    /path/to/fuzz/replay_driver.c /path/to/fuzz/fuzz_harness.c -o replay_test
./replay_test /path/to/fuzz/corpus
```

(This is how the harness in this repository was actually verified before
being committed - see the development history for details. Both drivers
also respect the scratch-directory warning above.)

## CI integration

`.github/workflows/tests.yml`'s `fuzz` job installs `clang`, builds the
harness, and runs it for a bounded time on every push - short enough not
to slow down CI meaningfully, long enough to catch regressions a human
wouldn't think to write a specific test for. It is not a substitute for
a longer fuzzing run; if you want deeper coverage, run the harness
locally (or in a dedicated longer-running CI job) for minutes to hours
rather than seconds.

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

## No clang available? `local_coverage_fuzzer.py`

`fuzz/local_coverage_fuzzer.py` is a small, dependency-free
coverage-guided mutation fuzzer using only `gcc`/`gcov` - built
specifically for environments with no `clang` and no network access to
install one (which is how this tool came to exist in the first place).
It's not a replacement for the real libFuzzer harness above; use that
one if you can. This one exists so results can be verified without it.

```sh
python3 fuzz/local_coverage_fuzzer.py --seconds 150
```

How it works: it builds `build.coverage_asan()` (gcov instrumentation +
ASan/UBSan combined), mutates entries from `fuzz/corpus/` (bit flips,
chunk insertion/deletion/duplication, splicing two seeds together,
substituting protocol-relevant "interesting" values like `0`,
`MAX_PACKET`, `MAX_PACKET+1` at plausible length-field positions), and
after every run checks for a crash or hang and for whether the mutation
touched any source line gcov hasn't seen yet across the whole campaign
(if so, the mutation is kept in the corpus for further mutation).

**Honest limitations**, compared to the real libFuzzer harness:
- Each mutation forks a fresh process and shells out to `gcov` to check
  coverage, versus libFuzzer's in-process execution with live counters -
  expect roughly 100-500 iterations/second here, not libFuzzer's
  thousands-to-millions.
- It has no awareness of the protocol's *statefulness* - specifically,
  it doesn't track handle values the server actually returns and thread
  them back into later mutated requests. That makes it much less likely
  to construct a valid `OPEN` → (matching handle) → `WRITE` → `CLOSE`
  sequence than a human-written or protocol-aware test would. In a real
  150-second, ~13,000-iteration run during development, it reached 570
  distinct covered source lines - solid, but short of the ~608-620 lines
  (93-95%) the deliberately-written test suite in `tests/` covers,
  precisely because of this gap. Coverage plateaued well before the run
  ended, suggesting more time alone wouldn't close it - a smarter
  mutator (or real libFuzzer, given enough time) would be needed to make
  further progress here.
- It doesn't persist newly-discovered corpus entries to disk between
  runs the way libFuzzer's corpus directory does - each run starts fresh
  from `fuzz/corpus/`'s seeds every time.
- `--seconds 150` with the development seed seeds and RNG seed 42 found
  **zero crashes and zero hangs** across 12,927 iterations. That's a
  genuinely clean result, not a strong one - see the coverage gap above
  for why it doesn't mean as much as a clean libFuzzer run of the same
  duration would.
