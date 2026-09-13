#!/usr/bin/env python3
"""Generates a seed corpus for fuzz/fuzz_harness.c: a handful of valid
session byte streams (INIT plus one or more well-formed requests) covering
most opcodes, so the fuzzer starts from valid-ish protocol structure
instead of pure noise. Run once; libFuzzer's own mutation and coverage
feedback take it from there.

Usage: python3 fuzz/generate_corpus.py
"""
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tests"))
import sftp_wire as wire  # noqa: E402

CORPUS_DIR = pathlib.Path(__file__).resolve().parent / "corpus"


def request(opcode, reqid, *field_bytes):
    return struct.pack(">B", opcode) + struct.pack(">I", reqid) + b"".join(field_bytes)


def write_seed(name, packets):
    data = wire.init_packet() + b"".join(packets)
    path = CORPUS_DIR / name
    path.write_bytes(data)
    print(f"  {name}: {len(data)} bytes")


def main():
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Writing seed corpus to {CORPUS_DIR}/")

    write_seed("realpath", [
        wire.pkt(request(wire.SSH_FXP_REALPATH, 1, wire.sstr("."))),
    ])

    write_seed("open_write_close", [
        wire.pkt(request(
            wire.SSH_FXP_OPEN, 1, wire.sstr("seed.txt"),
            struct.pack(">I", wire.SSH_FXF_WRITE | wire.SSH_FXF_CREAT), struct.pack(">I", 0),
        )),
        wire.pkt(request(
            wire.SSH_FXP_WRITE, 2, wire.sstr(b"01"),
            struct.pack(">Q", 0), wire.sstr(b"hello"),
        )),
        wire.pkt(request(wire.SSH_FXP_CLOSE, 3, wire.sstr(b"01"))),
    ])

    write_seed("opendir_readdir_close", [
        wire.pkt(request(wire.SSH_FXP_OPENDIR, 1, wire.sstr("."))),
        wire.pkt(request(wire.SSH_FXP_READDIR, 2, wire.sstr(b"01"))),
        wire.pkt(request(wire.SSH_FXP_CLOSE, 3, wire.sstr(b"01"))),
    ])

    write_seed("stat_lstat_fstat", [
        wire.pkt(request(wire.SSH_FXP_STAT, 1, wire.sstr("."))),
        wire.pkt(request(wire.SSH_FXP_LSTAT, 2, wire.sstr("."))),
    ])

    attrs = struct.pack(">I", wire.SSH_FILEXFER_ATTR_PERMISSIONS) + struct.pack(">I", 0o644)
    write_seed("setstat_mkdir_rmdir", [
        wire.pkt(request(wire.SSH_FXP_SETSTAT, 1, wire.sstr("."), attrs)),
        wire.pkt(request(wire.SSH_FXP_MKDIR, 2, wire.sstr("seeddir"), b"\x00\x00\x00\x00")),
        wire.pkt(request(wire.SSH_FXP_RMDIR, 3, wire.sstr("seeddir"))),
    ])

    write_seed("symlink_readlink", [
        wire.pkt(request(wire.SSH_FXP_SYMLINK, 1, wire.sstr("target"), wire.sstr("seedlink"))),
        wire.pkt(request(wire.SSH_FXP_READLINK, 2, wire.sstr("seedlink"))),
    ])

    write_seed("rename_remove", [
        wire.pkt(request(wire.SSH_FXP_RENAME, 1, wire.sstr("a"), wire.sstr("b"))),
        wire.pkt(request(wire.SSH_FXP_REMOVE, 2, wire.sstr("b"))),
    ])

    write_seed("malformed_length", [
        struct.pack(">I", 999999) + b"AAAA",
    ])

    print("Done.")


if __name__ == "__main__":
    main()
