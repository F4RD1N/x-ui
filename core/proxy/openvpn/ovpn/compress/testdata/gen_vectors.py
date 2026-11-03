#!/usr/bin/env python3
"""Generate compress/testdata/vectors.json from the system liblzo2 and liblz4.

The Go package may not use cgo, so its decompressors are checked against
vectors that the reference libraries (the ones /usr/sbin/openvpn links)
produce here:

  vectors    inputs and their compression by LZ4_compress_default,
             lzo1x_1_15_compress (what OpenVPN uses) and lzo1x_999_compress.
  crafted    hand-written streams, one per instruction kind, decoded by
             lzo1x_decompress_safe / LZ4_decompress_safe: the reference's
             verdict and output are recorded.
  mutations  deterministic corruptions (set, xor, truncate, delete, insert)
             of the compressed vectors, again with the reference's verdict.

For a mutation or crafted stream "ok" is the reference's verdict at output
capacity "cap"; on success "out_len" and "out_sha256" (the first 128 bits of
the SHA-256, in hex) describe its output.

Run from anywhere:  python3 gen_vectors.py
The output is deterministic for a given library version.
"""

import base64
import ctypes
import hashlib
import json
import os
import random
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "vectors.json")

lzo = ctypes.CDLL("liblzo2.so.2")
lz4 = ctypes.CDLL("liblz4.so.1")

lzo.lzo_version.restype = ctypes.c_uint
lzo.lzo_version_string.restype = ctypes.c_char_p
lz4.LZ4_versionString.restype = ctypes.c_char_p

# lzo_init() is a macro around __lzo_init_v2 with the ABI's type sizes.
ptr = ctypes.sizeof(ctypes.c_void_p)
callback_t = 3 * ptr + ptr + 2 * ctypes.sizeof(ctypes.c_size_t)
rc = lzo.__lzo_init_v2(
    lzo.lzo_version(),
    ctypes.sizeof(ctypes.c_short),
    ctypes.sizeof(ctypes.c_int),
    ctypes.sizeof(ctypes.c_long),
    4,  # lzo_uint32_t
    ctypes.sizeof(ctypes.c_size_t),  # lzo_uint
    ptr,  # lzo_sizeof_dict_t
    ptr,  # char *
    ptr,  # lzo_voidp
    callback_t,
)
if rc != 0:
    raise SystemExit("__lzo_init_v2 failed: %d" % rc)

WRKMEM = ctypes.create_string_buffer(1 << 20)  # >= LZO1X_999_MEM_COMPRESS


def _buf(data, pad=16):
    # Pad so a reader that looks one byte past the end reads our zeros.
    return ctypes.create_string_buffer(bytes(data) + b"\0" * pad, len(data) + pad)


def lzo_compress(fn, data):
    src = _buf(data)
    cap = len(data) + len(data) // 16 + 64 + 3
    dst = ctypes.create_string_buffer(cap)
    dlen = ctypes.c_size_t(cap)
    r = fn(src, ctypes.c_size_t(len(data)), dst, ctypes.byref(dlen), WRKMEM)
    if r != 0:
        raise RuntimeError("lzo compress: %d" % r)
    return dst.raw[: dlen.value]


def lzo1x_1_15(data):
    return lzo_compress(lzo.lzo1x_1_15_compress, data)


def lzo1x_999(data):
    return lzo_compress(lzo.lzo1x_999_compress, data)


def lz4_compress(data):
    bound = lz4.LZ4_compressBound(len(data))
    dst = ctypes.create_string_buffer(max(bound, 1))
    n = lz4.LZ4_compress_default(_buf(data), dst, len(data), bound)
    if n <= 0:
        raise RuntimeError("LZ4_compress_default failed")
    return dst.raw[:n]


def lzo_decompress(src, cap):
    """Returns (ok, output or error code) from lzo1x_decompress_safe."""
    dst = ctypes.create_string_buffer(cap + 16)
    dlen = ctypes.c_size_t(cap)
    r = lzo.lzo1x_decompress_safe(_buf(src), ctypes.c_size_t(len(src)), dst, ctypes.byref(dlen), None)
    if r != 0:
        return False, r
    return True, dst.raw[: dlen.value]


def lz4_decompress(src, cap):
    # Note: liblz4 1.9.4 accepts a match offset of 0, which the LZ4 block
    # format calls invalid, and writes zeros for it. The Go decoder rejects
    # such blocks; its tests allow exactly that difference.
    dst = ctypes.create_string_buffer(cap + 16)
    n = lz4.LZ4_decompress_safe(_buf(src), dst, len(src), cap)
    if n < 0:
        return False, n
    return True, dst.raw[:n]


DECOMPRESS = {"lz4": lz4_decompress, "lzo1x_1_15": lzo_decompress, "lzo1x_999": lzo_decompress}
CODEC_LIB = {"lz4": "lz4", "lzo1x_1_15": "lzo", "lzo1x_999": "lzo"}

rng = random.Random(20261009)


def rand_bytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


WORDS = (
    "the of and to in is was that for on with as by at from it an be this which "
    "or are have not had but were all their one can there been has more if will "
    "would its when who also into other some time two may only these new first "
    "tunnel packet server client route address network gateway compress "
    "openvpn data channel key cipher remote protocol"
).split()


def text(n):
    out = []
    size = 0
    while size < n:
        w = rng.choice(WORDS)
        if rng.random() < 0.08:
            w = w.capitalize() + "."
        out.append(w)
        size += len(w) + 1
    return (" ".join(out) + "\n").encode()[:n]


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(proto, payload, src="10.8.0.2", dst="93.184.216.34", ident=0x1C46):
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, s, d)
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def tcp_http():
    body = (
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\n"
        b"Accept: */*\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n"
        b"Cookie: session=0123456789abcdef0123456789abcdef; theme=dark\r\n\r\n"
    )
    tcp = struct.pack("!HHIIBBHHH", 51234, 80, 0x1A2B3C4D, 0x5E6F7081, 0x50, 0x18, 64240, 0, 0)
    return ipv4(6, tcp + body)


def icmp_echo():
    pattern = bytes(range(0x10, 0x38))  # what ping(8) fills with
    payload = struct.pack("!Q", 0x65F1A2B300000000) + pattern
    hdr = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1)
    c = csum(hdr + payload)
    return ipv4(1, struct.pack("!BBHHH", 8, 0, c, 0x1234, 1) + payload, dst="10.8.0.1")


def udp_dns():
    q = struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0)
    for label in (b"www", b"example", b"com"):
        q += bytes([len(label)]) + label
    q += b"\0" + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 53535, 53, 8 + len(q), 0) + q
    return ipv4(17, udp, dst="1.1.1.1")


def tcp_bulk():
    # A full-size segment of compressible HTML, as a web download would carry.
    html = b"<tr><td class=\"name\">item</td><td class=\"size\">1024</td></tr>\n" * 40
    tcp = struct.pack("!HHIIBBHHH", 443, 51234, 7, 9, 0x50, 0x10, 501, 0, 0)
    return ipv4(6, tcp + html[: 1500 - 40], src="93.184.216.34", dst="10.8.0.2")


def mixed_64k():
    a = rand_bytes(4096)
    b = rand_bytes(1024)
    parts = [
        text(8000), a, bytes(2000), rand_bytes(6000), b, text(6000),
        a[:3000],  # ~21 KiB back: LZO M4 with H=0
        tcp_http(), tcp_http(), icmp_echo(), rand_bytes(5000), b"\xff" * 700,
        text(4000), b,
        a,  # ~36 KiB back: LZO M4 with H=1
        udp_dns() * 3, rand_bytes(3000), bytes(range(256)) * 8, text(3000),
    ]
    data = b"".join(parts)
    while len(data) < 65536:
        data += text(min(4096, 65536 - len(data)))
    return data[:65536]


def far_three_byte_copies():
    # Short literal runs then 3-byte matches 2049..3072 bytes back: the
    # instruction LZO1X uses for a 3-byte copy right after >= 4 literals.
    base = bytearray(rand_bytes(3100))
    out = bytearray(base)
    for _ in range(300):
        out += rand_bytes(rng.randint(4, 9))
        d = rng.randint(2049, 3072)
        out += out[len(out) - d : len(out) - d + 3]
    return bytes(out)


def short_copies_after_short_literals():
    # 1-3 literals then 2-byte matches <= 1 KiB back (M1), and 3..8 byte
    # matches <= 2 KiB back (M2).
    out = bytearray(rand_bytes(1200))
    for i in range(500):
        out += rand_bytes(rng.randint(1, 3))
        d = rng.randint(1, 1024)
        n = 2 if i % 3 else rng.randint(3, 8)
        for _ in range(n):
            out.append(out[len(out) - d])
    return bytes(out)


VECTOR_INPUTS = [
    ("empty", b""),
    ("one-byte", b"A"),
    ("two-bytes", b"\x00\xff"),
    ("twelve", b"hello world!"),
    ("thirteen", b"hello, world!"),
    ("short-text", b"OpenVPN data channel payload, compressed by the peer."),
    ("random-17", rand_bytes(17)),
    ("random-1500", rand_bytes(1500)),
    ("random-8k", rand_bytes(8192)),
    ("zeros-1k", bytes(1024)),
    ("zeros-20000", bytes(20000)),
    ("period-1-a", b"a" * 300),
    ("period-2", b"ab" * 400),
    ("period-3", b"abc" * 500),
    ("period-7", b"0123456" * 300),
    ("period-17", rand_bytes(17) * 120),
    ("ascending-4k", bytes(range(256)) * 16),
    ("text-4k", text(4096)),
    ("ip-tcp-http", tcp_http()),
    ("ip-icmp-echo", icmp_echo()),
    ("ip-udp-dns", udp_dns()),
    ("ip-tcp-bulk", tcp_bulk()),
    ("far-3-byte-copies", far_three_byte_copies()),
    ("short-copies", short_copies_after_short_literals()),
    ("mixed-64k", mixed_64k()),
]


def h(data):
    # Half a SHA-256 is plenty to compare outputs and keeps the file small.
    return hashlib.sha256(data).hexdigest()[:32]


def b64(data):
    return base64.b64encode(data).decode()


def verdict(codec, data, cap):
    if codec != "lz4" and len(data) == 0:
        # lzo1x_decompress_safe reads the first byte without a length check;
        # an empty stream is simply not a stream.
        return {"ok": False, "code": "empty"}
    ok, res = DECOMPRESS[codec](data, cap)
    if not ok:
        return {"ok": False, "code": res}
    return {"ok": True, "out_len": len(res), "out_sha256": h(res)}


# Hand-written LZO1X streams. EOF is the M4 instruction 0x11 0x00 0x00.
EOF = [0x11, 0x00, 0x00]
LIT2100 = list(rand_bytes(2100))
LIT3100 = list(rand_bytes(3100))
LIT40 = list(rand_bytes(40))
CRAFTED = [
    # name, codec, stream bytes, cap
    ("lzo-only-eof", "lzo", EOF, 16),
    ("lzo-first-1-literal-m1", "lzo", [18, 0x61, 0x00, 0x00] + EOF, 16),
    # 1 literal, M1 (dist 1, 2 trailing literals), M1 (dist 2), EOF.
    ("lzo-m1-trailing-literals", "lzo", [18, 0x61, 0x02, 0x00, 0x62, 0x63, 0x04, 0x00] + EOF, 32),
    ("lzo-first-3-literals-m1-dist3", "lzo", [20, 1, 2, 3, 0x08, 0x00] + EOF, 32),
    # 238 literals (first byte 255), the longest first-byte literal run.
    ("lzo-first-238-literals", "lzo", [255] + list(range(238)) + EOF, 512),
    # first byte 21: 4 literals, state 4, then an M2 (len 3, dist 4).
    ("lzo-first-4-literals-m2", "lzo", [21, 9, 8, 7, 6, 0x4C, 0x00] + EOF, 32),
    # Long literal run (instruction 0, 8 zero bytes, 42) then a far 3-byte
    # copy 2049 + D + (H << 2) back with D=1, H=2.
    ("lzo-long-literals-far-copy", "lzo", [0x00] + [0] * 8 + [42] + LIT2100 + [0x04, 0x02] + EOF, 4096),
    # 3100 literals (12 zero bytes, 22) then the farthest 3-byte copy, 3072 back.
    ("lzo-far-copy-max", "lzo", [0x00] + [0] * 12 + [22] + LIT3100 + [0x0C, 0xFF] + EOF, 4096),
    ("lzo-far-copy-lookbehind", "lzo", [0x00] + [0] * 7 + [42] + LIT2100[:1845] + [0x0C, 0xFF] + EOF, 4096),
    ("lzo-literal-run-short-form", "lzo", [0x05] + LIT40[:8] + [0x40, 0x00] + EOF, 64),
    # M2 forms: 0x40..0x7F len 3-4, 0x80..0xFF len 5-8, trailing literals.
    ("lzo-m2-long", "lzo", [0x00, 22] + LIT40 + [0xFD, 0x04, 0x61] + EOF, 128),
    # M3: 0x20 | L, LE16 = (D << 2) | S; extended length with zero bytes.
    ("lzo-m3-short", "lzo", [0x00, 22] + LIT40 + [0x25, 0x4C, 0x00] + EOF, 128),
    ("lzo-m3-ext", "lzo", [0x00, 22] + LIT40 + [0x20, 0x00, 0x00, 0x07, 0x9C, 0x00] + EOF, 1024),
    ("lzo-m3-trailing", "lzo", [0x00, 22] + LIT40 + [0x23, 0x9D, 0x00, 0x41] + EOF, 128),
    # M4: 0x10 | H << 3 | L, LE16 = (D << 2) | S, dist = 16384 + H*16384 + D.
    ("lzo-m4-lookbehind", "lzo", [0x00, 22] + LIT40 + [0x12, 0x04, 0x00] + EOF, 128),
    ("lzo-eof-with-trailing-literal-bits", "lzo", [18, 0x61, 0x11, 0x01, 0x00], 16),
    ("lzo-eof-h-bit", "lzo", [18, 0x61, 0x19, 0x00, 0x00], 16),
    ("lzo-eof-long-form", "lzo", [18, 0x61, 0x10, 0x00, 0x05, 0x00, 0x00], 16),
    ("lzo-trailing-garbage", "lzo", [18, 0x61] + EOF + [0x00], 16),
    ("lzo-missing-eof", "lzo", [18, 0x61, 0x00, 0x00], 16),
    ("lzo-first-byte-17", "lzo", [17, 0x00, 0x00], 16),
    ("lzo-first-byte-16", "lzo", [16, 0x01, 0x00, 0x00], 16),
    ("lzo-m1-lookbehind", "lzo", [18, 0x61, 0x04, 0x00] + EOF, 16),
    ("lzo-output-overrun", "lzo", [18, 0x61, 0x00, 0x00] + EOF, 2),
    ("lzo-exact-cap", "lzo", [18, 0x61, 0x00, 0x00] + EOF, 3),
    ("lzo-truncated-literals", "lzo", [0x05, 1, 2, 3], 64),
    ("lzo-zero-run-no-end", "lzo", [0x00] + [0] * 20, 1 << 16),
    # LZ4 blocks: token = literals << 4 | (match - 4), LE16 offset.
    ("lz4-empty-block", "lz4", [0x00], 16),
    ("lz4-no-input", "lz4", [], 16),
    ("lz4-one-literal", "lz4", [0x10, 0x41], 16),
    ("lz4-offset-zero", "lz4", [0x14, 0x41, 0x00, 0x00, 0x50, 1, 2, 3, 4, 5], 64),
    ("lz4-offset-too-far", "lz4", [0x14, 0x41, 0x02, 0x00, 0x50, 1, 2, 3, 4, 5], 64),
    ("lz4-overlap-run", "lz4", [0x1F, 0x41, 0x01, 0x00, 0x10, 0x50, 1, 2, 3, 4, 5], 128),
    ("lz4-last-seq-has-match-nibble", "lz4", [0x14, 0x41, 0x01, 0x00, 0x5F, 1, 2, 3, 4, 5], 64),
    # 4 literals, an 8-byte match 4 back, then a last sequence of 1 literal:
    # liblz4 wants 8 bytes after a non-final sequence's literals.
    ("lz4-short-last-literals", "lz4", [0x44] + list(b"ABCD") + [0x04, 0x00, 0x10, 0x5A], 64),
    ("lz4-truncated-offset", "lz4", [0x14, 0x41, 0x01], 64),
    ("lz4-truncated-literals", "lz4", [0x50, 1, 2, 3], 64),
    ("lz4-literal-ext", "lz4", [0xF0, 0x05] + list(range(20)), 64),
    ("lz4-literal-ext-255", "lz4", [0xF0, 0xFF, 0x00] + list(rand_bytes(270)), 512),
    ("lz4-match-ext-truncated", "lz4", [0x1F, 0x41, 0x01, 0x00, 0xFF], 4096),
    ("lz4-output-overrun", "lz4", [0x1F, 0x41, 0x01, 0x00, 0x10, 0x50, 1, 2, 3, 4, 5], 30),
]


def mutations(codec, data, cap, n):
    out = []
    if not data:
        return out
    for i in range(n):
        kind = ("set", "xor", "trunc", "delete", "insert")[i % 5]
        if kind == "trunc":
            pos = rng.randrange(0, len(data))
            m = data[:pos]
            val = 0
        elif kind == "set":
            pos = rng.randrange(0, len(data))
            val = rng.choice((0, 1, 0x11, 0xFF, rng.getrandbits(8)))
            m = data[:pos] + bytes([val]) + data[pos + 1 :]
        elif kind == "xor":
            pos = rng.randrange(0, len(data))
            val = 1 << rng.randrange(8)
            m = data[:pos] + bytes([data[pos] ^ val]) + data[pos + 1 :]
        elif kind == "delete":
            pos = rng.randrange(0, len(data))
            val = 0
            m = data[:pos] + data[pos + 1 :]
        else:
            pos = rng.randrange(0, len(data) + 1)
            val = rng.getrandbits(8)
            m = data[:pos] + bytes([val]) + data[pos:]
        e = {"op": kind, "pos": pos, "val": val, "cap": cap}
        e.update(verdict(codec, m, cap))
        out.append(e)
    return out


def main():
    vectors = []
    muts = []
    for name, data in VECTOR_INPUTS:
        v = {"name": name, "input": b64(data)}
        for codec, fn in (("lz4", lz4_compress), ("lzo1x_1_15", lzo1x_1_15), ("lzo1x_999", lzo1x_999)):
            c = fn(data)
            ok, res = DECOMPRESS[codec](c, max(len(data), 1))
            if not ok or res != data:
                raise RuntimeError("%s %s does not round trip" % (name, codec))
            v[codec] = b64(c)
            cap = 2 * len(data) + 256
            n = 10 if len(data) > 20000 else 24
            for e in mutations(codec, c, cap, n):
                e = dict({"vector": name, "codec": codec}, **e)
                muts.append(e)
        vectors.append(v)

    crafted = []
    for name, lib, stream, cap in CRAFTED:
        codec = "lz4" if lib == "lz4" else "lzo1x_1_15"
        e = {"name": name, "codec": CODEC_LIB[codec], "stream": b64(bytes(stream)), "cap": cap}
        e.update(verdict(codec, bytes(stream), cap))
        crafted.append(e)

    doc = {
        "generator": "gen_vectors.py",
        "lzo": lzo.lzo_version_string().decode(),
        "lz4": lz4.LZ4_versionString().decode(),
    }
    with open(OUT, "w") as f:
        f.write("{\n")
        for k, v in doc.items():
            f.write("%s: %s,\n" % (json.dumps(k), json.dumps(v)))
        for key, rows in (("vectors", vectors), ("crafted", crafted), ("mutations", muts)):
            f.write('"%s": [\n' % key)
            f.write(",\n".join(json.dumps(r, separators=(",", ":")) for r in rows))
            f.write("\n]%s\n" % ("," if key != "mutations" else ""))
        f.write("}\n")
    print("wrote %s: %d vectors, %d crafted, %d mutations (%d bytes)" % (
        OUT, len(vectors), len(crafted), len(muts), os.path.getsize(OUT)))


if __name__ == "__main__":
    main()
