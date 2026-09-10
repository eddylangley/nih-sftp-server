#!/usr/bin/env python3
"""Convenience entry point: `python3 tests/run_all.py [-v]`

Builds every binary variant the suite needs, then runs all tests. This is
what the GitHub Actions workflow (.github/workflows/tests.yml) invokes;
it's also the easiest way to run everything locally.

Equivalent to:
    python3 -m unittest discover -s tests -p 'test_*.py'
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build  # noqa: E402


def main():
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    print("Building binary variants...")
    for builder in build.ALL_VARIANTS:
        path = builder()
        print(f"  {builder.__name__:16s} -> {path}")
    print()

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(HERE), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
