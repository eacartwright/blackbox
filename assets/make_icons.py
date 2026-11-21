"""Draw the BlackBox icons and write them as multi-size .ico files.

    python assets/make_icons.py

blackbox.ico          recording: dark rounded square with a red dot
blackbox-stopped.ico  stopped:   the same square with a grey ring

No dependencies: shapes are rendered with supersampling and stored as PNG
entries inside the .ico (supported since Windows Vista).
"""
import math
import os
import struct
import zlib

SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
HERE = os.path.dirname(os.path.abspath(__file__))

BOX = (0x1F, 0x1F, 0x1E)
EDGE = (0x6B, 0x6B, 0x68)
RED = (0xE2, 0x4B, 0x4A)
GREY = (0xB4, 0xB2, 0xA9)


def rrect_dist(x, y, cx, cy, hw, hh, r):
    qx, qy = abs(x - cx) - (hw - r), abs(y - cy) - (hh - r)
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r


def render(n, stopped):
    s = n / 32.0
    sub = 8 if n <= 48 else 4
    c = n / 2.0
    half = 13.5 * s  # square spans 2.5..29.5 in the 32-unit design
    radius = 7 * s
    edge = max(1.0, 0.5 * s)  # keep a visible outline on dark taskbars
    dot_r = 7 * s
    ring_r, ring_w = 6 * s, max(1.25, 2.6 * s)
    px = bytearray()
    for j in range(n):
        px.append(0)  # PNG filter byte
        for i in range(n):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sj in range(sub):
                for si in range(sub):
                    x = i + (si + 0.5) / sub
                    y = j + (sj + 0.5) / sub
                    d = rrect_dist(x, y, c, c, half, half, radius)
                    if d > 0:
                        continue
                    col = EDGE if d > -edge else BOX
                    dc = math.hypot(x - c, y - c)
                    if stopped:
                        if abs(dc - ring_r) <= ring_w / 2:
                            col = GREY
                    elif dc <= dot_r:
                        col = RED
                    acc[0] += col[0]
                    acc[1] += col[1]
                    acc[2] += col[2]
                    acc[3] += 1
            k = sub * sub
            a = acc[3] / k
            if acc[3]:
                px += bytes((round(acc[0] / acc[3]), round(acc[1] / acc[3]), round(acc[2] / acc[3]), round(a * 255)))
            else:
                px += b"\0\0\0\0"
    return png(n, bytes(px))


def png(n, raw):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def write_ico(path, images):
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    body = b""
    for n, data in images:
        dim = 0 if n >= 256 else n
        out += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset + len(body))
        body += data
    with open(path, "wb") as f:
        f.write(out + body)


if __name__ == "__main__":
    for name, stopped in (("blackbox.ico", False), ("blackbox-stopped.ico", True)):
        imgs = [(n, render(n, stopped)) for n in SIZES]
        write_ico(os.path.join(HERE, name), imgs)
        print("wrote", name)
