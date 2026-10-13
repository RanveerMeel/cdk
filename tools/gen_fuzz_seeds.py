#!/usr/bin/env python3
"""Write starting inputs for the fuzz targets (roadmap 4.3) to fuzz/seeds/.

Valid examples get the fuzzer past checks it cannot easily guess (frame
CRC-32s, ustar checksums, ELF headers). Deterministic, standard library
only; the output is not committed. Usage: tools/gen_fuzz_seeds.py
"""

import io
import struct
import tarfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fuzz/seeds"


def write(target, name, data):
    d = OUT / target
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data)


def frame(kind, payload, flags=0):
    body = struct.pack("<BBH", kind, flags, len(payload)) + payload
    return b"CDK1" + body + struct.pack("<I", zlib.crc32(body))


def frames():
    hello = frame(1, b"cdk issuer=0123456789abcdef")
    ping = frame(2, struct.pack("<Q", 42))
    data = frame(4, b"hello gateway")
    sealed = frame(6, bytes(range(40)))
    hs = frame(5, b"\x01" * 200, flags=1) + frame(5, b"\x02" * 100)
    write("frame_decoder", "single", b"\x00" + hello)
    write("frame_decoder", "stream", b"\x07" + hello + ping + data + sealed + hs)
    write("frame_decoder", "garbage-then-frame", b"\x03" + b"CDK1\xff\xff" + b"\x00" * 7 + ping)
    write("frame_decoder", "max-payload", b"\x3f" + frame(4, b"x" * 1024))


def messages():
    entry = lambda name, flags, ep: bytes([len(name)]) + name + bytes([flags, len(ep)]) + ep
    lst = bytes([4, 2]) + entry(b"echo", 0, b"mcp:demo") + entry(b"model:qwen", 3, b"api.example.com:443")
    call = bytes([1]) + struct.pack("<I", 7) + bytes([4]) + b"echo" + struct.pack("<H", 13) + b'{"text":"hi"}'
    resp = bytes([2]) + struct.pack("<IBH", 7, 0, 2) + b"hi"
    chunk = bytes([5]) + struct.pack("<IH", 7, 3) + b"abc"
    text = b"=== HUMAN APPROVAL REQUIRED (request #1) ===\n  action : call tool 'echo'\n"
    req = bytes([0x20]) + struct.pack("<I", 3) + b"\x11" * 16 + bytes([1, 2]) + struct.pack("<H", 300) + b"\x22" * 32 + struct.pack("<H", len(text)) + text
    part = lambda off, b: bytes([0x21]) + struct.pack("<I", 3) + b"\x33" * 16 + bytes([1]) + struct.pack("<HHH", 8, off, len(b)) + b
    for name, m in [("list-request", b"\x03"), ("list", lst), ("call", call), ("response", resp), ("chunk", chunk),
                    ("approval-request", req), ("resolved", bytes([0x22]) + struct.pack("<IB", 3, 1))]:
        write("link_messages", name, m)
    write("link_messages", "decision-parts", part(0, b"abcd") + b"\xff" + part(4, b"efgh"))


def ustar():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data in [("hello", b"\x7fELF" + b"\x00" * 60), ("policy.rules", b"approval credential\n")]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    write("initrd", "two-files.tar", buf.getvalue())


def elves():
    # The kernel's own built-in smoke ELF layout: one PT_LOAD at USER_BASE + 4 MiB.
    vaddr = (1 << 39) + 0x40_0000
    code = b"\xb8\x3c\x00\x00\x00\x0f\x05" + b"\x90" * 9
    ehdr = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    ehdr += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, vaddr, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 120, vaddr, vaddr, len(code), len(code), 4096)
    write("elf", "smoke", ehdr + phdr + code)
    for prog in ["hello", "spin"]:
        p = ROOT / "user/target/x86_64-unknown-none/release" / prog
        if p.exists():
            write("elf", prog, p.read_bytes())


def policies():
    write("policy", "default", (ROOT / "policy/default.rules").read_bytes())
    write("policy", "full", b"deny remote\nseparate customer-data tool\napproval credential\n"
                            b"label obj-2 customer-data\nquorum credential 2\nquorum policy 2\napproval-timeout 120\n")


def spool():
    write("spool_decision", "approve", struct.pack("<I", 3) + b"\x44" * 16 + b"\x01" + b"\x55" * (64 + 3309))


if __name__ == "__main__":
    frames(); messages(); ustar(); elves(); policies(); spool()
    n = sum(1 for _ in OUT.rglob("*") if _.is_file())
    print(f"wrote {n} seed files to {OUT.relative_to(ROOT)}")
