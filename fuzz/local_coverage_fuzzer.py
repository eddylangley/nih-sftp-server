#!/usr/bin/env python3
"""A dependency-free coverage-guided mutation fuzzer for
nih-sftp-server.c, using only gcc + gcov - no clang/libFuzzer required.

This exists specifically because this environment has no clang (libFuzzer
is LLVM-only) and no network access to install one. fuzz/fuzz_harness.c
(the real libFuzzer harness) is the better tool wherever clang is
available - see fuzz/README.md. This script is what let that gap actually
get verified with real results instead of shipped untested.

It's much slower than libFuzzer (each mutation forks a fresh server
process rather than running in-process, and coverage feedback is checked
via the external `gcov` tool rather than in-process counters), so it
won't approach libFuzzer's throughput - but it's real coverage-guided
fuzzing: mutations that touch new coverage are kept and mutated further;
every execution (regardless of whether it found new coverage) is checked
for a crash or hang.

Usage:
    python3 fuzz/local_coverage_fuzzer.py [--seconds N] [--seed N]
"""
import argparse
import pathlib
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tests"))
import build  # noqa: E402

FUZZ_DIR = pathlib.Path(__file__).resolve().parent
CORPUS_SEED_DIR = FUZZ_DIR / "corpus"
FINDINGS_DIR = FUZZ_DIR / "findings"

INTERESTING_U32 = [0, 1, 2, 3, 4, 8, 9, 0xFF, 0x100, 0xFFFF, 34000, 34001, 34100,
                    0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]
INTERESTING_BYTES = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                      0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
                      0x14, 0x16, 0x64, 0x65, 0xC8, 0xFF, 0x7F, 0x80]


def mutate(data: bytes, rng: random.Random) -> bytes:
    if len(data) == 0:
        return bytes([rng.randint(0, 255) for _ in range(rng.randint(1, 16))])

    data = bytearray(data)
    strategy = rng.choice([
        "bitflip", "byteset", "delete_chunk", "insert_chunk",
        "duplicate_chunk", "interesting_u32", "interesting_byte", "truncate",
    ])

    if strategy == "bitflip":
        i = rng.randrange(len(data))
        data[i] ^= (1 << rng.randrange(8))
    elif strategy == "byteset":
        i = rng.randrange(len(data))
        data[i] = rng.randint(0, 255)
    elif strategy == "delete_chunk" and len(data) > 4:
        i = rng.randrange(len(data))
        n = rng.randint(1, min(16, len(data) - i))
        del data[i:i + n]
    elif strategy == "insert_chunk":
        i = rng.randrange(len(data) + 1)
        n = rng.randint(1, 16)
        chunk = bytes(rng.choice(INTERESTING_BYTES) for _ in range(n))
        data[i:i] = chunk
    elif strategy == "duplicate_chunk" and len(data) > 4:
        i = rng.randrange(len(data))
        n = rng.randint(1, min(16, len(data) - i))
        chunk = data[i:i + n]
        j = rng.randrange(len(data) + 1)
        data[j:j] = chunk
    elif strategy == "interesting_u32" and len(data) >= 4:
        i = rng.randrange(len(data) - 3)
        val = rng.choice(INTERESTING_U32)
        data[i:i + 4] = struct.pack(">I", val & 0xFFFFFFFF)
    elif strategy == "interesting_byte":
        i = rng.randrange(len(data))
        data[i] = rng.choice(INTERESTING_BYTES)
    elif strategy == "truncate" and len(data) > 1:
        data = data[:rng.randrange(1, len(data))]

    return bytes(data)


def splice(a: bytes, b: bytes, rng: random.Random) -> bytes:
    if not a or not b:
        return a or b
    return a[:rng.randrange(1, len(a) + 1)] + b[rng.randrange(0, len(b)):]


_SUMMARY_RE = re.compile(r"Lines executed:([\d.]+)% of (\d+)")


def covered_line_set(gcov_file: pathlib.Path):
    """Returns the set of line numbers gcov reports as executed (nonzero
    hit count) in the most recently generated annotated source file."""
    covered = set()
    text = gcov_file.read_text(errors="replace")
    for line in text.splitlines():
        m = re.match(r"\s*([^:]+):\s*(\d+):", line)
        if not m:
            continue
        marker, line_no = m.group(1).strip(), int(m.group(2))
        if marker not in ("-", "#####"):
            covered.add(line_no)
    return covered


def run_gcov(binary_path: pathlib.Path):
    build_dir = binary_path.parent
    gcno_path = build_dir / f"{binary_path.name}-{build.SOURCE.stem}.gcno"
    result = subprocess.run(["gcov", "-b", str(gcno_path)], cwd=str(build_dir),
                             capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return build_dir / (build.SOURCE.name + ".gcov")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=150)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    binary = build.coverage_asan()
    build_dir = binary.parent
    gcda_path = build_dir / f"{binary.name}-{build.SOURCE.stem}.gcda"

    corpus = [p.read_bytes() for p in sorted(CORPUS_SEED_DIR.iterdir()) if p.is_file()]
    print(f"Loaded {len(corpus)} seed(s) from {CORPUS_SEED_DIR}")

    global_covered = set()
    FINDINGS_DIR.mkdir(exist_ok=True)

    scratch = pathlib.Path(tempfile.mkdtemp(prefix="nih-sftp-fuzz-"))
    print(f"Scratch dir: {scratch}")

    iterations = 0
    crashes = 0
    hangs = 0
    new_coverage_events = 0
    start = time.monotonic()
    last_report = start

    try:
        while time.monotonic() - start < args.seconds:
            iterations += 1
            parent = rng.choice(corpus)
            if len(corpus) > 1 and rng.random() < 0.2:
                other = rng.choice(corpus)
                candidate = splice(parent, other, rng)
            else:
                candidate = mutate(parent, rng)
            candidate = candidate[:40000]  # keep individual runs bounded

            gcda_path.unlink(missing_ok=True)

            run_dir = scratch / f"run{iterations % 50}"
            run_dir.mkdir(exist_ok=True)
            for child in run_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)

            try:
                proc = subprocess.run([str(binary)], input=candidate, capture_output=True,
                                       cwd=str(run_dir), timeout=3)
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
                proc = None

            stderr_text = proc.stderr.decode(errors="replace") if proc else ""
            is_crash = (not timed_out) and (
                "ERROR: AddressSanitizer" in stderr_text
                or "ERROR: LeakSanitizer" in stderr_text
                or "runtime error:" in stderr_text
                or "Sanitizer: CHECK failed" in stderr_text
                or (proc is not None and proc.returncode is not None and proc.returncode < 0)
            )

            if timed_out or is_crash:
                kind = "timeout" if timed_out else "crash"
                if kind == "timeout":
                    hangs += 1
                else:
                    crashes += 1
                finding_path = FINDINGS_DIR / f"{kind}-{iterations}"
                finding_path.write_bytes(candidate)
                print(f"\n!!! {kind.upper()} at iteration {iterations}, saved to {finding_path}")
                if proc is not None:
                    print(f"    stderr: {stderr_text[:500]}")
                continue

            gcov_file = run_gcov(binary)
            if gcov_file is not None:
                covered_now = covered_line_set(gcov_file)
                new_lines = covered_now - global_covered
                if new_lines:
                    global_covered |= new_lines
                    corpus.append(candidate)
                    new_coverage_events += 1

            if time.monotonic() - last_report > 15:
                elapsed = time.monotonic() - start
                print(f"[{elapsed:6.1f}s] iterations={iterations:6d}  corpus={len(corpus):4d}  "
                      f"lines_ever_covered={len(global_covered):4d}  crashes={crashes}  hangs={hangs}")
                last_report = time.monotonic()
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    elapsed = time.monotonic() - start
    print(f"\n{'=' * 70}")
    print(f"Done: {iterations} iterations in {elapsed:.1f}s ({iterations/elapsed:.1f}/s)")
    print(f"Final corpus size: {len(corpus)}  (started with {len(list(CORPUS_SEED_DIR.iterdir()))})")
    print(f"Distinct lines ever covered by a mutation: {len(global_covered)}")
    print(f"New-coverage events: {new_coverage_events}")
    print(f"Crashes: {crashes}   Hangs: {hangs}")
    if crashes or hangs:
        print(f"Findings saved in {FINDINGS_DIR}/")
    return 1 if (crashes or hangs) else 0


if __name__ == "__main__":
    sys.exit(main())
