"""Builds nih-sftp-server in the variants the test suite exercises.

Each function is cached so a full test run only compiles each variant once,
regardless of how many test modules ask for it.
"""
import functools
import os
import pathlib
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "nih-sftp-server.c"
BUILD_DIR = REPO_ROOT / "tests" / ".build"

COMMON_FLAGS = ["-Wall", "-Wextra", "-std=iso9899:1999", "-pedantic-errors"]


def _compile(name, extra_flags):
    if not SOURCE.exists():
        raise FileNotFoundError(
            f"{SOURCE} not found - run tests from a checkout with "
            f"nih-sftp-server.c at the repository root"
        )
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    out = BUILD_DIR / name
    cmd = ["gcc", *COMMON_FLAGS, *extra_flags, str(SOURCE), "-o", str(out)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"build failed for {name}:\n"
            f"  command: {' '.join(cmd)}\n"
            f"  stdout: {result.stdout}\n"
            f"  stderr: {result.stderr}"
        )
    return out


@functools.lru_cache(maxsize=None)
def normal():
    """Plain optimized build - closest to a real deployment, asserts enabled."""
    return _compile("sftp-server-normal", ["-O2"])


@functools.lru_cache(maxsize=None)
def asan():
    """Debug build with AddressSanitizer + UBSan, asserts enabled.

    Used for tests that exercise real filesystem operations (realpath,
    symlink, open/read/close, ...) where we want memory-safety checking
    without also disabling REQUIRE()'s companion asserts.
    """
    return _compile("sftp-server-asan", ["-O0", "-g", "-fsanitize=address,undefined"])


@functools.lru_cache(maxsize=None)
def ndebug_asan():
    """AddressSanitizer + UBSan, but with NDEBUG defined (assert() compiled out).

    This is the configuration that matters most for anything guarding
    attacker-controlled protocol data: those checks must be REQUIRE(), not
    assert(), specifically so they still run here. See the REQUIRE comment
    in nih-sftp-server.c.
    """
    return _compile(
        "sftp-server-ndebug-asan",
        ["-O0", "-g", "-DNDEBUG", "-fsanitize=address,undefined"],
    )


@functools.lru_cache(maxsize=None)
def draft_spec_asan():
    """ASan build with OpenSSH compatibility explicitly disabled.

    Note: -DOPENSSH_COMPAT=0, not -UOPENSSH_COMPAT - seeing plain -U used
    here would silently fail to change behavior, since the source
    unconditionally defines OPENSSH_COMPAT unless it's already defined.
    See the comment above that #define in nih-sftp-server.c.
    """
    return _compile(
        "sftp-server-draft-asan",
        ["-O0", "-g", "-fsanitize=address,undefined", "-DOPENSSH_COMPAT=0"],
    )


ALL_VARIANTS = (normal, asan, ndebug_asan, draft_spec_asan)


@functools.lru_cache(maxsize=None)
def asan_functional() -> bool:
    """True if a trivial AddressSanitizer-instrumented binary actually runs
    on this host, False if ASan itself is broken here.

    This matters because ASan has a known bug on some 64-bit ARM boards -
    including, per Debian bug #1115578, Raspberry Pi 3 and 4 (but not 5) -
    where its allocator fails a fatal internal consistency check at process
    startup, before any real code runs:

        AddressSanitizer: CHECK failed: sanitizer_allocator_primary64.h:131
        "((kSpaceBeg)) == (...)"

    See https://bugs.debian.org/1115578 and
    https://github.com/google/sanitizers/issues/1674. On affected hosts,
    every ASan-instrumented binary fails the same way, regardless of what
    it does - it's not something this project's code can work around.

    Set NIH_SFTP_FORCE_ASAN_UNAVAILABLE=1 to force this to report
    unavailable without probing (e.g. if the probe itself is unreliable on
    your hardware).
    """
    if os.environ.get("NIH_SFTP_FORCE_ASAN_UNAVAILABLE"):
        return False

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    probe_c = BUILD_DIR / "_asan_probe.c"
    probe_bin = BUILD_DIR / "_asan_probe"
    probe_c.write_text("int main(void) { return 0; }\n")

    compiled = subprocess.run(
        ["gcc", "-O0", "-fsanitize=address", str(probe_c), "-o", str(probe_bin)],
        capture_output=True, text=True,
    )
    if compiled.returncode != 0:
        return False

    try:
        ran = subprocess.run([str(probe_bin)], capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        return False
    return ran.returncode == 0


if __name__ == "__main__":
    for builder in ALL_VARIANTS:
        path = builder()
        print(f"built {builder.__name__:16s} -> {path}")
    print(f"{'asan_functional':16s} -> {asan_functional()}")
