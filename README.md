# nih-sftp-server

A tiny, dependency-free SFTP version 3 server, in a single ISO C99 file.

`nih-sftp-server` implements the server-side half of the SFTP subsystem that
`sshd` execs after authentication (the same role OpenSSH's own
`sftp-server` binary plays). It has no dependencies beyond the C standard
library and POSIX, does essentially no heap allocation, and is small enough
to read start to finish in one sitting.

## Design goals

- **No third-party dependencies.** Just the C standard library and POSIX
  (`unistd.h`, `fcntl.h`, `dirent.h`, `sys/stat.h`, `sys/time.h`).
- **No dynamic memory allocation**, with one unavoidable exception:
  `realpath(path, NULL)` allocates its result. Every other request is
  served out of two fixed-size, statically-allocated packet buffers.
- **Small and auditable.** The entire server, including every request
  handler, buffer-handling primitive, and error-code mapping, is one file.
- **Directory listings avoid path concatenation.** `SSH_FXP_OPENDIR` keeps
  both a `DIR *` and its underlying file descriptor, so `SSH_FXP_READDIR`
  can `fstatat()` each entry relative to that fd instead of building
  `dirname + "/" + entry` strings by hand.

## What this is *not*

This binary provides **no authentication and no access control of its
own**. It's designed to be invoked by `sshd` after the user has already
authenticated, and to have its filesystem view constrained by `sshd`'s own
`ChrootDirectory` (or equivalent) if you want to confine a user to part of
the filesystem. If you run it any other way, it will act as its inputs
tell it to, exactly like OpenSSH's own `sftp-server`.

## Building

```sh
gcc -O2 -Wall -Wextra -Werror -std=iso9899:1999 -pedantic-errors nih-sftp-server.c -o sftp-server
```

The file targets strict ISO C99 and should build warning-free with the
above. It relies on a few POSIX feature-test macros, already set at the
top of the file:

| Macro | Needed for |
|---|---|
| `_XOPEN_SOURCE 700` | `telldir`/`seekdir`, `lstat`, `readlink`/`symlink`, `fstatat`/`fdopendir` |
| `_BSD_SOURCE` (or `_DEFAULT_SOURCE`) | `futimes` — without it, `SSH_FXP_FSETSTAT` degrades gracefully to `SSH_FX_OP_UNSUPPORTED` |

See `man 7 feature_test_macros` if you need to adjust these for your
platform.

## Installing

Add it as an SFTP subsystem in `sshd_config`:

```
Subsystem sftp /path/to/sftp-server
```

To confine users to a directory, combine with `ChrootDirectory` in a
`Match` block — this server does not enforce that itself:

```
Match Group sftpusers
    ChrootDirectory /srv/sftp/%u
    ForceCommand internal-sftp
    Subsystem sftp /path/to/sftp-server
```

(Consult your `sshd_config` documentation for the exact chroot/jail
mechanism you want; the details are outside this server's scope.)

## Compatibility with real-world clients: `OPENSSH_COMPAT`

The SFTPv3 draft is ambiguous or under-specified in a couple of places,
and OpenSSH's `sftp-server` — the de facto reference implementation most
real-world clients are built and tested against — doesn't always follow
the draft literally. `OPENSSH_COMPAT` (on by default) makes this server
match OpenSSH's actual behavior rather than the letter of the draft:

- **`SSH_FXP_SYMLINK` argument order.** OpenSSH's `sftp-server` has always
  sent/expected `targetpath` before `linkpath`, the reverse of what the
  draft specifies. See OpenSSH's `PROTOCOL` file, *"3.1. sftp: Reversal of
  arguments to SSH_FXP_SYMLINK."* Turning `OPENSSH_COMPAT` off restores
  the draft's literal (`linkpath`, `targetpath`) order.
- **`SSH_FXP_REALPATH` on a path whose basename doesn't exist yet.**
  OpenSSH resolves as far as it can and appends the unresolved remainder,
  rather than failing outright — this is what lets clients query the
  destination of a not-yet-created file or directory (e.g. `scp -r`'s
  destination path). Turning `OPENSSH_COMPAT` off makes any such request
  fail with `SSH_FX_NO_SUCH_FILE`, per the draft.

To build with strict draft-spec behavior instead of OpenSSH compatibility,
override the macro on the command line (don't use `-U`; see the comment
above the `#define` in the source for why that alone doesn't work):

```sh
gcc ... -DOPENSSH_COMPAT=0 nih-sftp-server.c -o sftp-server
```

## Other build-time constants

| Constant | Meaning |
|---|---|
| `MAX_PACKET` | Largest SFTP packet accepted (34000 bytes — the SFTPv3 draft's recommended minimum for server support) |
| `MAX_HANDLE_DIGITS` | Width, in hex digits, of file/directory handle strings. `MAX_HANDLES` (the number of file/directory handles that can be open at once) is derived from this automatically, so the two can never drift out of sync — see the comment above their `#define`s. |

## Security-relevant implementation notes

- All buffer-bounds checks on data that originates from the remote peer
  (packet lengths, embedded string/data lengths, output buffer space) use
  a `REQUIRE()` macro rather than `assert()`, specifically so they can
  never be compiled out by `-DNDEBUG`. A small number of checks that guard
  purely internal invariants (never influenced by remote input) still use
  `assert()`.
- File-creation permissions (`SSH_FXP_OPEN` with `SSH_FXF_CREAT`) are
  masked with `PERM_MASK` (`0777`) before being passed to `open()`, so a
  client cannot set `setuid`/`setgid`/sticky bits on newly created files —
  consistent with how `SSH_FXP_SETSTAT`, `SSH_FXP_FSETSTAT`, and
  `SSH_FXP_MKDIR` already handle permissions.

If you find a security issue, please open an issue (or, for anything you'd
rather not post publicly first, contact the maintainer directly).

## Testing

There's no bundled test suite yet, but the server's design — reading a
fixed protocol from stdin and writing a fixed protocol to stdout, no
sockets or global state beyond the handle table — makes it straightforward
to test by piping crafted SFTP packets to the binary and inspecting the
response. Building with `-fsanitize=address,undefined` (and, if you want
to specifically check that `REQUIRE()` checks survive release builds,
`-DNDEBUG -fsanitize=address`) is a good way to catch memory-safety
regressions.

## License

BSD 3-Clause. See the license header at the top of `nih-sftp-server.c`.

## More information

<https://eddylangley.net/nih-sftp-server/>
