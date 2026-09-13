/* libFuzzer harness for nih-sftp-server.c.

Drives the server's real, unmodified packet-processing logic (the actual
main() function, included directly from the shipped source) against
fuzzer-supplied byte streams, without needing real file descriptors or a
new process per test case - essential for libFuzzer's persistent-mode
model, which executes many thousands of inputs per second in a single
process.

How it works: before #include-ing the real source file, read()/write()/
select()/exit() are redefined via the preprocessor to redirect to fake
implementations that operate on an in-memory buffer instead of real
stdin/stdout, and turn the server's various legitimate exit() calls
(clean protocol_error() rejections, EOF at end of input, fatal syscall
error paths) into a longjmp back into this harness instead of killing the
whole (persistent, many-iterations-per-process) fuzzing run. main() itself
is renamed via the same #define trick, so the harness can call it
directly once per iteration without colliding with libFuzzer's own main().
A sanitizer-detected bug still aborts the process for real, since ASan/
UBSan raise SIGABRT directly rather than going through this exit() path -
only the server's own *legitimate* control-flow exits are redirected.

Nothing in nih-sftp-server.c itself is modified - this file lives
entirely outside it and #includes it unchanged.

Build (requires clang - GCC does not implement libFuzzer):
    clang -O1 -g -fsanitize=fuzzer,address,undefined \
        -std=gnu99 fuzz/fuzz_harness.c -o fuzz/fuzz_harness

Run:
    ./fuzz/fuzz_harness fuzz/corpus -max_len=34100 -timeout=5

A -timeout well under libFuzzer's 1200s default matters here specifically:
this project has already had one real bug (an infinite loop in
sftp_readdir(), fixed during development - see tests/README.md) that
would only show up as a hang, not a crash. A short --timeout is what
makes that whole bug *class* detectable at all.

See fuzz/README.md for more.
*/
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>

static const uint8_t *g_fuzz_data;
static size_t g_fuzz_size;
static size_t g_fuzz_pos;
static jmp_buf g_fuzz_jmpbuf;

/* Pull bytes from the fuzzer-supplied buffer instead of a real fd. Returns
0 once exhausted, simulating EOF the same way a closed stdin would - this
is what makes the server's own read_input() naturally wind down and call
exit(EXIT_SUCCESS) (redirected below) at the end of each input, the same
way it would at the end of a real SSH session. */
static ssize_t fuzz_read(int fd, void *buf, size_t count)
{
    (void)fd;
    size_t remaining = g_fuzz_size - g_fuzz_pos;
    size_t n = count < remaining ? count : remaining;
    if (n > 0)
    {
        memcpy(buf, g_fuzz_data + g_fuzz_pos, n);
        g_fuzz_pos += n;
    }
    return (ssize_t)n;
}

/* Discard all output - a fuzzer only needs to know whether processing an
input crashes or hangs, not what response it produces. */
static ssize_t fuzz_write(int fd, const void *buf, size_t count)
{
    (void)fd; (void)buf;
    return (ssize_t)count;
}

/* No real fds to block on - always report ready immediately. Signature
must exactly match POSIX select(), since the system header's own
prototype for it gets textually rewritten by the #define below too, and
a mismatched redeclaration is a hard compile error. */
static int fuzz_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    (void)nfds; (void)readfds; (void)writefds; (void)exceptfds; (void)timeout;
    return 1;
}

static void fuzz_exit(int code)
{
    (void)code;
    longjmp(g_fuzz_jmpbuf, 1);
}

#define read fuzz_read
#define write fuzz_write
#define select fuzz_select
#define exit fuzz_exit
#define main nih_main

#include "../nih-sftp-server.c"

#undef read
#undef write
#undef select
#undef exit
#undef main

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    g_fuzz_data = data;
    g_fuzz_size = size;
    g_fuzz_pos = 0;

    /* Reset state that would normally only ever be initialized once per
    real process/session. Persistent-mode fuzzing reuses this same
    process - and these same static globals - across many iterations, so
    without this, iteration N+1 would incorrectly start already-INIT'd
    and/or with iteration N's handles still "open". */
    have_init = SSH_FALSE;
    memset(handles, 0, sizeof(handles));

    if (setjmp(g_fuzz_jmpbuf) == 0)
    {
        nih_main(0, NULL);
    }
    return 0;
}
