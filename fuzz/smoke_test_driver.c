/* Smoke-test driver for fuzz_harness.c, standing in for libFuzzer's own
driver (which requires clang, unavailable in this environment). Not part
of the delivered fuzzing setup - this exists purely to verify the harness
plumbing (read/write/select/exit interception, the longjmp iteration
boundary, state reset between calls) actually works before trusting it,
by calling LLVMFuzzerTestOneInput directly, repeatedly, the way libFuzzer
would, and checking nothing crashes/hangs/corrupts state across calls. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void run_one(const char *label, const uint8_t *data, size_t size)
{
    printf("  [%s] %zu bytes ... ", label, size);
    fflush(stdout);
    LLVMFuzzerTestOneInput(data, size);
    printf("ok\n");
}

int main(void)
{
    /* Empty input */
    run_one("empty", (const uint8_t *)"", 0);

    /* Valid INIT only */
    static const uint8_t init_only[] = {
        0,0,0,5, 1, 0,0,0,3
    };
    run_one("init_only", init_only, sizeof(init_only));

    /* Valid INIT + REALPATH "." */
    static const uint8_t init_realpath[] = {
        0,0,0,5, 1, 0,0,0,3,
        0,0,0,10, 16, 0,0,0,1, 0,0,0,1,'.'
    };
    run_one("init_realpath", init_realpath, sizeof(init_realpath));

    /* Malformed: oversized payload length claim (the original
    payload_len overflow scenario from earlier in this project's
    development) */
    static const uint8_t evil_length[] = {
        0xFF,0xFF,0xFF,0xFF, 'A','A','A','A'
    };
    run_one("evil_length", evil_length, sizeof(evil_length));

    /* Malformed: non-INIT first opcode */
    static const uint8_t bad_first[] = {
        0,0,0,5, 16, 0,0,0,1
    };
    run_one("bad_first_opcode", bad_first, sizeof(bad_first));

    /* Repeat the valid sequence several times in a row, proving state
    (have_init, handles[]) is correctly reset between iterations rather
    than accumulating/corrupting across calls - this is the part unique
    to persistent-mode fuzzing that's easy to get wrong. */
    for (int i = 0; i < 5; i++)
    {
        run_one("repeat_init_realpath", init_realpath, sizeof(init_realpath));
    }

    /* Purely random-looking garbage, several times */
    static const uint8_t garbage1[] = { 5,9,2,255,0,0,0,0,1,1,1,1,1 };
    static const uint8_t garbage2[] = { 0,0,0,20, 6, 1,2,3,4,5,6,7,8,9,10 };
    run_one("garbage1", garbage1, sizeof(garbage1));
    run_one("garbage2", garbage2, sizeof(garbage2));

    printf("\nAll smoke-test inputs processed without crashing or hanging.\n");
    printf("(This is a plumbing check using a stand-in driver, not a real\n");
    printf("libFuzzer/coverage-guided fuzzing run - see fuzz/README.md.)\n");
    return 0;
}
