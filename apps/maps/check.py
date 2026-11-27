# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
"""Checks that two builds of the world map hold the same map.

usage: python3 -I check.py A.pmtiles B.pmtiles

Compares what the archives say rather than their bytes: the header's zooms, bounds and kinds, the
metadata, and every tile, by its ID, after decompressing it. Two builds from the same inputs agree
on all of that, though zlib and zlib-ng compress the same bytes differently. Python's standard
library only; reads only archives whose root directory holds every tile, as world.py writes them.
"""
import gzip
import hashlib
import json
import struct
import sys


def varint(b, i):
    n = s = 0
    while True:
        c = b[i]
        i += 1
        n |= (c & 0x7F) << s
        s += 7
        if c < 0x80:
            return n, i


def content(path):
    data = open(path, "rb").read()
    if data[:7] != b"PMTiles" or data[7] != 3:
        raise SystemExit(f"{path}: not a PMTiles v3 archive")
    root_off, root_len, meta_off, meta_len, leaf_off, leaf_len, data_off, data_len = struct.unpack_from("<QQQQQQQQ", data, 8)
    if leaf_len:
        raise SystemExit(f"{path}: has leaf directories, which this check doesn't read")
    clustered, internal, tile_comp, tile_type, minz, maxz = data[96:102]
    bounds = struct.unpack_from("<iiii", data, 102)
    root = gzip.decompress(data[root_off:root_off + root_len]) if internal == 2 else data[root_off:root_off + root_len]
    n, i = varint(root, 0)
    ids, runs, lengths, offsets = [], [], [], []
    last = 0
    for _ in range(n):
        d, i = varint(root, i)
        last += d
        ids.append(last)
    for _ in range(n):
        r, i = varint(root, i)
        runs.append(r)
    for _ in range(n):
        l, i = varint(root, i)
        lengths.append(l)
    for k in range(n):
        o, i = varint(root, i)
        offsets.append(offsets[k - 1] + lengths[k - 1] if o == 0 and k > 0 else o - 1)
    h = hashlib.sha256()
    tiles = 0
    for tid, run, length, off in zip(ids, runs, lengths, offsets):
        body = data[data_off + off:data_off + off + length]
        tile = gzip.decompress(body) if tile_comp == 2 else body
        for t in range(tid, tid + run):
            h.update(struct.pack("<QI", t, len(tile)) + tile)
            tiles += 1
    meta = json.loads(gzip.decompress(data[meta_off:meta_off + meta_len]) if internal == 2 else data[meta_off:meta_off + meta_len])
    return {
        "zooms": (minz, maxz),
        "bounds": bounds,
        "kinds": (clustered, tile_comp, tile_type),
        "metadata": json.dumps(meta, sort_keys=True),
        "tiles": tiles,
        "content": h.hexdigest(),
    }


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__.split("\n\n")[1])
    a, b = content(sys.argv[1]), content(sys.argv[2])
    differ = [k for k in a if a[k] != b[k]]
    if differ:
        for k in differ:
            print(f"{k}: {a[k]} != {b[k]}")
        raise SystemExit(1)
    print(f"the same map: {a['tiles']} tiles, zoom {a['zooms'][0]} to {a['zooms'][1]}, content SHA-256 {a['content']}")


if __name__ == "__main__":
    main()
