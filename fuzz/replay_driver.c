/* Feeds every file in fuzz/corpus/ (and, if given, a second directory of
arbitrary mutated inputs) through the harness via LLVMFuzzerTestOneInput,
the same way libFuzzer would replay a corpus. Verification-only, like
smoke_test_driver.c - not part of the delivered fuzzing setup. */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void run_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { printf("  [%s] could not open\n", path); return; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(size > 0 ? (size_t)size : 1);
    size_t got = fread(buf, 1, (size_t)size, f);
    fclose(f);
    printf("  [%s] %ld bytes ... ", path, size);
    fflush(stdout);
    LLVMFuzzerTestOneInput(buf, got);
    printf("ok\n");
    free(buf);
}

static void run_dir(const char *dirpath)
{
    DIR *d = opendir(dirpath);
    if (!d) { printf("(no directory %s)\n", dirpath); return; }
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL)
    {
        if (entry->d_name[0] == '.') continue;
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dirpath, entry->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
        {
            run_file(path);
        }
    }
    closedir(d);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "fuzz/corpus";
    printf("Replaying files from %s/ through the harness:\n", dir);
    run_dir(dir);
    printf("\nAll files processed without crashing or hanging.\n");
    return 0;
}
