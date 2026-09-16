"""Minimal SFTPv3 wire-protocol helpers for testing nih-sftp-server.

This is not a general-purpose SFTP client - just enough packet building and
parsing to drive the server directly over stdin/stdout, including sending
deliberately malformed packets that a real client library wouldn't let you
construct.
"""
import struct
import subprocess

# Opcodes (draft-ietf-secsh-filexfer-02), matching the #defines in
# nih-sftp-server.c
SSH_FXP_INIT = 1
SSH_FXP_VERSION = 2
SSH_FXP_OPEN = 3
SSH_FXP_CLOSE = 4
SSH_FXP_READ = 5
SSH_FXP_WRITE = 6
SSH_FXP_LSTAT = 7
SSH_FXP_FSTAT = 8
SSH_FXP_SETSTAT = 9
SSH_FXP_FSETSTAT = 10
SSH_FXP_OPENDIR = 11
SSH_FXP_READDIR = 12
SSH_FXP_REMOVE = 13
SSH_FXP_MKDIR = 14
SSH_FXP_RMDIR = 15
SSH_FXP_REALPATH = 16
SSH_FXP_STAT = 17
SSH_FXP_RENAME = 18
SSH_FXP_READLINK = 19
SSH_FXP_SYMLINK = 20
SSH_FXP_STATUS = 101
SSH_FXP_HANDLE = 102
SSH_FXP_DATA = 103
SSH_FXP_NAME = 104
SSH_FXP_ATTRS = 105

SSH_FX_OK = 0
SSH_FX_EOF = 1
SSH_FX_NO_SUCH_FILE = 2
SSH_FX_PERMISSION_DENIED = 3
SSH_FX_FAILURE = 4
SSH_FX_BAD_MESSAGE = 5
SSH_FX_OP_UNSUPPORTED = 8

SSH_FILEXFER_ATTR_SIZE = 0x00000001
SSH_FILEXFER_ATTR_UIDGID = 0x00000002
SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004
SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008

SSH_FXF_READ = 0x00000001
SSH_FXF_WRITE = 0x00000002
SSH_FXF_APPEND = 0x00000004
SSH_FXF_CREAT = 0x00000008
SSH_FXF_TRUNC = 0x00000010
SSH_FXF_EXCL = 0x00000020

PROTOCOL_VERSION = 3


def pkt(payload: bytes) -> bytes:
    """Wrap a payload (opcode byte + body) in its 4-byte big-endian length prefix."""
    return struct.pack(">I", len(payload)) + payload


def sstr(value) -> bytes:
    """Encode a value as an SFTP string: 4-byte length + raw bytes."""
    b = value.encode() if isinstance(value, str) else value
    return struct.pack(">I", len(b)) + b


def init_packet(version: int = PROTOCOL_VERSION) -> bytes:
    return pkt(struct.pack(">B", SSH_FXP_INIT) + struct.pack(">I", version))


def parse_responses(data: bytes):
    """Split a stream of length-prefixed response packets into a list of payloads.

    Each returned payload starts with its opcode byte, matching what
    put_byte()/put_uint32()/etc. wrote in the server.
    """
    resps = []
    while data:
        if len(data) < 4:
            raise ValueError(f"truncated length header, {len(data)} bytes left: {data!r}")
        length = struct.unpack(">I", data[:4])[0]
        if len(data) < 4 + length:
            raise ValueError(f"truncated packet body: wanted {length}, have {len(data) - 4}")
        resps.append(data[4:4 + length])
        data = data[4 + length:]
    return resps


def status_of(resp: bytes):
    """If resp is an SSH_FXP_STATUS packet, return its status code, else None."""
    if resp and resp[0] == SSH_FXP_STATUS:
        return struct.unpack(">I", resp[5:9])[0]
    return None


def handle_of(resp: bytes):
    """If resp is an SSH_FXP_HANDLE packet, return the raw handle bytes, else None."""
    if resp and resp[0] == SSH_FXP_HANDLE:
        hlen = struct.unpack(">I", resp[5:9])[0]
        return resp[9:9 + hlen]
    return None


def name_path_of(resp: bytes):
    """If resp is a single-entry SSH_FXP_NAME packet, return the first name string."""
    if resp and resp[0] == SSH_FXP_NAME:
        count = struct.unpack(">I", resp[5:9])[0]
        if count >= 1:
            nlen = struct.unpack(">I", resp[9:13])[0]
            return resp[13:13 + nlen]
    return None


def parse_name_response(resp: bytes):
    """Parse a (possibly multi-entry) SSH_FXP_NAME response, e.g. from
    SSH_FXP_READDIR, into a list of (filename, longname, attrs_bytes)
    tuples. attrs_bytes is left undecoded, since its layout depends on
    which flag bits are set (callers who know which handler produced the
    response - e.g. stat_to_attr always sets SIZE|UIDGID|PERMISSIONS|
    ACMODTIME - can decode it themselves).
    """
    assert resp and resp[0] == SSH_FXP_NAME
    count = struct.unpack(">I", resp[5:9])[0]
    offset = 9
    entries = []
    for _ in range(count):
        nlen = struct.unpack(">I", resp[offset:offset + 4])[0]
        offset += 4
        filename = resp[offset:offset + nlen]
        offset += nlen

        llen = struct.unpack(">I", resp[offset:offset + 4])[0]
        offset += 4
        longname = resp[offset:offset + llen]
        offset += llen

        attrs_start = offset
        flags = struct.unpack(">I", resp[offset:offset + 4])[0]
        offset += 4
        if flags & SSH_FILEXFER_ATTR_SIZE:
            offset += 8
        if flags & SSH_FILEXFER_ATTR_UIDGID:
            offset += 8
        if flags & SSH_FILEXFER_ATTR_PERMISSIONS:
            offset += 4
        if flags & SSH_FILEXFER_ATTR_ACMODTIME:
            offset += 8
        entries.append((filename, longname, resp[attrs_start:offset]))
    return entries


class SessionResult:
    def __init__(self, returncode, stdout, stderr, timed_out):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.responses = [] if timed_out else parse_responses(stdout)

    @property
    def crashed(self) -> bool:
        """True if a sanitizer reported an error, or the process died from a signal.

        A clean protocol_error()/exit(EXIT_FAILURE) rejection is NOT a crash -
        that's the expected, correct response to malformed input.

        The marker list is deliberately broad: an early version of this only
        matched "ERROR: AddressSanitizer", which missed ASan's fatal internal
        "AddressSanitizer: CHECK failed: ..." startup errors (no "ERROR: "
        prefix) - the exact failure mode seen when ASan's allocator itself
        can't initialize on some hosts (e.g. a known aarch64 issue on some
        Raspberry Pi boards, https://bugs.debian.org/1115578). That gap let
        every ASan-based subprocess call in a run silently count as "not
        crashed" instead of surfacing the problem. returncode < 0 alone isn't
        reliable either, since a sanitizer's fatal-CHECK exit path doesn't
        necessarily go through a signal on every platform.
        """
        text = self.stderr.decode(errors="replace")
        sanitizer_failure_markers = (
            "ERROR: AddressSanitizer",
            "ERROR: UndefinedBehaviorSanitizer",
            "ERROR: LeakSanitizer",
            "runtime error:",
            "Sanitizer: CHECK failed",  # covers AddressSanitizer/MemorySanitizer/... CHECK failed
            "SUMMARY: AddressSanitizer",
            "SUMMARY: UndefinedBehaviorSanitizer",
        )
        if any(marker in text for marker in sanitizer_failure_markers):
            return True
        return self.returncode is not None and self.returncode < 0

    def stderr_text(self) -> str:
        return self.stderr.decode(errors="replace")


class Session:
    """Runs one instance of the server binary against a batch of input packets.

    Each call to run() spawns a fresh process, matching how sshd actually
    invokes the sftp-server subsystem (one process per session).
    """

    def __init__(self, binary, cwd=None, timeout=5):
        self.binary = str(binary)
        self.cwd = str(cwd) if cwd is not None else None
        self.timeout = timeout

    def run(self, packets, include_init=True) -> SessionResult:
        data = b"".join(packets)
        if include_init:
            data = init_packet() + data
        proc = subprocess.Popen(
            [self.binary],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.cwd,
        )
        try:
            out, err = proc.communicate(data, timeout=self.timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            timed_out = True
        return SessionResult(proc.returncode, out, err, timed_out)
