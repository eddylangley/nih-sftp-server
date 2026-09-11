#!/usr/bin/env python3
"""Measures test-suite code coverage of nih-sftp-server.c using gcov.

Usage: python3 tests/run_coverage.py [-v]

How this works: it temporarily monkeypatches tests/build.py's binary
builders so every test in the suite runs against a gcov-instrumented
binary instead of its usual (ASan or plain) one, runs the whole suite
in-process, then invokes gcov and reports:
  - overall line/branch/function coverage percentages
  - every function with 0% line coverage (never called at all)
  - every source line gcov marks as never executed, grouped by function

Two coverage binaries are needed, not one: OPENSSH_COMPAT branches code
(sftp_realpath, sftp_symlink) into two mutually exclusive versions at
compile time, so the "default" and "-DOPENSSH_COMPAT=0" code paths need
separate instrumented binaries to both be visible to gcov at all. A line
inside an #else branch simply doesn't exist in a binary compiled with the
#if branch taken, and vice versa - gcov has no way to report on code that
isn't there.

This intentionally does NOT use ASan (coverage doesn't need memory-safety
checking) or -DNDEBUG (that would compile away the two genuinely-internal
assert()s in nih-sftp-server.c, hiding them from coverage entirely) - see
build.coverage()'s docstring.
"""
import pathlib
import re
import subprocess
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build  # noqa: E402


def _install_coverage_monkeypatches():
    """Redirect every test's binary choice to a coverage-instrumented build.

    Test modules call build.asan(), build.ndebug_asan(), build.normal(), and
    build.draft_spec_asan() from inside setUpClass, which runs when the
    suite executes - not at import time - so patching these module
    attributes before running the suite is enough to redirect every test,
    without editing any test file.
    """
    build.asan = build.coverage
    build.ndebug_asan = build.coverage
    build.normal = build.coverage
    build.draft_spec_asan = build.coverage_draft
    # Coverage binaries aren't ASan-instrumented at all, so the Raspberry-Pi
    # style ASan bug this normally guards against doesn't apply here.
    build.asan_functional = lambda: True


def _run_gcov(binary_path: pathlib.Path, label: str):
    """Runs gcov for one coverage binary, returns (summary_text, gcov_file_path).

    Must point gcov directly at the .gcno file, not just its directory:
    since our binaries are built with a custom -o name (not a separate -c
    step), gcc names the notes/data files "<binary-name>-<source-stem>.gcno"
    rather than the plain "<source-stem>.gcno" gcov looks for by default
    when only given a search directory.
    """
    build_dir = binary_path.parent
    gcno_path = build_dir / f"{binary_path.name}-{build.SOURCE.stem}.gcno"
    if not gcno_path.exists():
        print(f"WARNING: expected notes file not found: {gcno_path}")
        return None, None
    result = subprocess.run(
        ["gcov", "-b", str(gcno_path)],
        cwd=str(build_dir), capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"WARNING: gcov failed for {label}:\n{result.stdout}\n{result.stderr}")
        return None, None
    gcov_file = build_dir / (build.SOURCE.name + ".gcov")
    return result.stdout, gcov_file


_SUMMARY_RE = re.compile(r"(Lines|Branches|Taken at least once) executed:([\d.]+)% of (\d+)")


def _parse_summary(gcov_stdout: str) -> dict:
    stats = {}
    for label, pct, total in _SUMMARY_RE.findall(gcov_stdout):
        stats[label] = (float(pct), int(total))
    return stats


def _parse_uncovered(gcov_file: pathlib.Path):
    """Returns {line_no: source_text} for every line gcov marks '#####' (never executed).

    Skips lines gcov marks with a call-count comment for a function that was
    never called at all in a way that's already implied by the function
    itself - just reports raw uncovered source lines, callers group them.
    """
    uncovered = {}
    current_func = None
    func_of_line = {}
    text = gcov_file.read_text(errors="replace")
    for line in text.splitlines():
        m = re.match(r"\s*-:\s*(\d+):(.*)", line)
        # gcov annotated format: "<count or - or #####>:<line_no>:<source>"
        m = re.match(r"\s*([^:]+):\s*(\d+):(.*)", line)
        if not m:
            continue
        marker, line_no, source = m.group(1).strip(), int(m.group(2)), m.group(3)
        func_match = re.match(r"\s*(?:static\s+)?\w[\w\s\*]*?\b(\w+)\s*\([^;{]*\)\s*$", source)
        if func_match and source.strip().endswith(")") and "{" not in source:
            current_func = func_match.group(1)
        func_of_line[line_no] = current_func
        if marker == "#####":
            uncovered[line_no] = (current_func, source)
    return uncovered


def _print_coverage_report(label: str, binary_path: pathlib.Path):
    print(f"\n{'=' * 70}\n{label}\n{'=' * 70}")
    gcov_stdout, gcov_file = _run_gcov(binary_path, label)
    if gcov_stdout is None:
        return None
    stats = _parse_summary(gcov_stdout)
    for name in ("Lines", "Branches"):
        if name in stats:
            pct, total = stats[name]
            print(f"  {name} executed: {pct:.1f}% of {total}")

    uncovered = _parse_uncovered(gcov_file)
    if uncovered:
        by_func = {}
        for line_no, (func, source) in sorted(uncovered.items()):
            by_func.setdefault(func or "(file scope)", []).append((line_no, source))
        print(f"\n  Never-executed lines ({len(uncovered)}), by function:")
        for func, lines in sorted(by_func.items()):
            print(f"    {func}:")
            for line_no, source in lines:
                print(f"      {line_no:5d}: {source.strip()}")
    return uncovered


def main():
    verbose = "-v" in sys.argv
    _install_coverage_monkeypatches()

    print("Building coverage-instrumented binaries...")
    coverage_bin = build.coverage()
    coverage_draft_bin = build.coverage_draft()
    print(f"  coverage       -> {coverage_bin}")
    print(f"  coverage_draft -> {coverage_draft_bin}")

    print("\nRunning full test suite against coverage binaries...")
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(HERE), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1)
    result = runner.run(suite)

    if not result.wasSuccessful():
        print("\nTest suite did not pass - coverage numbers below are still "
              "meaningful, but treat them with that in mind.")

    _print_coverage_report("Default build (OPENSSH_COMPAT=1)", coverage_bin)
    _print_coverage_report("Draft-spec build (OPENSSH_COMPAT=0)", coverage_draft_bin)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
