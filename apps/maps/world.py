# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
"""Builds the world map the apps carry, so that their map is never blank: assets/world.pmtiles.

usage: python3 -I world.py NATURAL_EARTH_GEOJSON_DIR OUT.pmtiles
       python3 -I world.py --inputs     (the names of the files it reads, one a line)

Zoom 0 to 6 of the whole world, from Natural Earth 5.1.2 (public domain): land, lakes, country and
state or province borders, and the names of countries and of cities. Above zoom 6 the map draws
these tiles larger, and the family's downloaded region (API.md §13) takes over where it has tiles.

Nothing but Python's standard library: the vector tiles (Mapbox Vector Tile 2.1) and the archive
(PMTiles version 3) are written here, so the build pulls in no code from elsewhere. The inputs are
checked against the SHA-256s below before anything is read, and the same inputs always give the
same bytes out.

The layers follow the names and properties of the Protomaps basemap that regions are cut from, so
one style draws both: `earth` (polygons), `water` (lakes, with `kind`), `boundaries` (lines, with
`kind_detail` 2 for countries and 4 for states and provinces) and `places` (points, with `kind`
`country` or `locality`, `name`, `min_zoom` and `population_rank`).
"""
import gzip
import hashlib
import json
import math
import os
import struct
import sys

MAXZOOM = 6
EXTENT = 4096
BUFFER = 64  # units of EXTENT beyond each tile's edge, so that strokes and labels don't break there
TOLERANCE = 3  # simplification, in units of EXTENT

# Natural Earth 5.1.2, tag v5.1.2 of github.com/nvkelso/natural-earth-vector (commit
# f1890d9f152c896d250a77557a5751a93d494776), directory geojson/.
INPUTS = {
    "ne_110m_land.geojson": "9e0729ee253ca7d7a5c4ae9395fb1902264c5377c52e224d13dd85010e2835d9",
    "ne_50m_land.geojson": "e874b27a51d146452be360cafb3cc50c86001074a67d534113e6534682f9826b",
    "ne_110m_lakes.geojson": "eb02ecc86c82004fccbf979058bfabbbd6c2d07968c7844d38eb1c9152d2ffc9",
    "ne_50m_lakes.geojson": "d350b75978b26fe839b797c2c529b2fb8f47fb3983c03f4964e36d5df9378a52",
    "ne_110m_admin_0_boundary_lines_land.geojson": "d42479fd79552cca4eec7f85fcdca717a790d29ff06be7676f1af0568c6d3f7c",
    "ne_50m_admin_0_boundary_lines_land.geojson": "2faac4f6b34386f3d21b6e018cf151f241f00e5c936d44dd17d7d9bfb147fa48",
    "ne_10m_land.geojson": "1ac90796408bc6ad6911d69448485d3c4dbf2190370080368a09976e1c9f7416",
    "ne_10m_lakes.geojson": "2d036f53dedec578001c5c30c2959ee7d4eebc1306900fa4367c49929ec8f2d9",
    "ne_10m_admin_0_boundary_lines_land.geojson": "74d9c16229c095fde65943a9919e337682f044bcebccb120764f38edf3b70f4a",
    "ne_50m_admin_1_states_provinces_lines.geojson": "72cca93c850d412628a5da4bc5ebfe21ba4d376eb34611bde6b623ee73f0fdcf",
    "ne_50m_admin_0_countries.geojson": "3e458fc036ad0a66411f2c1e6cac49c5d7bfb81cb1123bc513b22511a2b7fdeb",
    "ne_10m_populated_places_simple.geojson": "fd3fa867a320cbd5c5b6bb5bc550afeec2939fb2cef688e508007282a55ac42f",
}

# Which scale each zoom draws from: the coarse one for the first zooms, then the finer.
SCALE = {0: "110m", 1: "110m", 2: "110m", 3: "50m", 4: "50m", 5: "50m", 6: "10m"}


def read(directory, name):
    data = open(os.path.join(directory, name), "rb").read()
    want = INPUTS[name]
    got = hashlib.sha256(data).hexdigest()
    if want and got != want:
        raise SystemExit(f"{name}: SHA-256 {got}, expected {want}")
    if not want:
        print(f"unpinned input {name}: {got}", file=sys.stderr)
    return json.loads(data)


# ---- geometry, in Web Mercator scaled to the unit square, y down ----

MAX_LAT = 85.0511287798066


def merc(lon, lat):
    lat = max(-MAX_LAT, min(MAX_LAT, lat))
    s = math.sin(math.radians(lat))
    return (lon + 180.0) / 360.0, 0.5 - math.log((1 + s) / (1 - s)) / (4 * math.pi)


def project(coords):
    return [merc(c[0], c[1]) for c in coords]


def polygons(geom):
    """Each polygon of a Polygon or MultiPolygon as a list of rings, the outer one first."""
    if geom["type"] == "Polygon":
        return [[project(r) for r in geom["coordinates"]]]
    if geom["type"] == "MultiPolygon":
        return [[project(r) for r in p] for p in geom["coordinates"]]
    return []


def lines(geom):
    if geom["type"] == "LineString":
        return [project(geom["coordinates"])]
    if geom["type"] == "MultiLineString":
        return [project(l) for l in geom["coordinates"]]
    return []


def simplify(points, tol):
    """Douglas–Peucker, without recursion; the first and last points stay."""
    if len(points) < 3:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    t2 = tol * tol
    while stack:
        a, b = stack.pop()
        ax, ay = points[a]
        bx, by = points[b]
        dx, dy = bx - ax, by - ay
        d2 = dx * dx + dy * dy
        best, at = -1.0, -1
        for i in range(a + 1, b):
            px, py = points[i]
            if d2 == 0:
                e = (px - ax) ** 2 + (py - ay) ** 2
            else:
                t = ((px - ax) * dx + (py - ay) * dy) / d2
                t = max(0.0, min(1.0, t))
                e = (px - ax - t * dx) ** 2 + (py - ay - t * dy) ** 2
            if e > best:
                best, at = e, i
        if best > t2:
            keep[at] = True
            stack.append((a, at))
            stack.append((at, b))
    return [p for p, k in zip(points, keep) if k]


def clip_ring(ring, x0, y0, x1, y1):
    """Sutherland–Hodgman against a rectangle; the ring comes back open (no repeated first point)."""
    pts = ring[:-1] if len(ring) > 1 and ring[0] == ring[-1] else ring

    def edge(pts, inside, cross):
        out = []
        if not pts:
            return out
        prev = pts[-1]
        for cur in pts:
            if inside(cur):
                if not inside(prev):
                    out.append(cross(prev, cur))
                out.append(cur)
            elif inside(prev):
                out.append(cross(prev, cur))
            prev = cur
        return out

    def at_x(x):
        return lambda p, q: (x, p[1] + (q[1] - p[1]) * (x - p[0]) / (q[0] - p[0]))

    def at_y(y):
        return lambda p, q: (p[0] + (q[0] - p[0]) * (y - p[1]) / (q[1] - p[1]), y)

    pts = edge(pts, lambda p: p[0] >= x0, at_x(x0))
    pts = edge(pts, lambda p: p[0] <= x1, at_x(x1))
    pts = edge(pts, lambda p: p[1] >= y0, at_y(y0))
    pts = edge(pts, lambda p: p[1] <= y1, at_y(y1))
    return pts


def clip_line(line, x0, y0, x1, y1):
    """Liang–Barsky on each segment; the parts of the line inside the rectangle."""
    parts, cur = [], []
    for (ax, ay), (bx, by) in zip(line, line[1:]):
        t0, t1 = 0.0, 1.0
        dx, dy = bx - ax, by - ay
        ok = True
        for p, q in ((-dx, ax - x0), (dx, x1 - ax), (-dy, ay - y0), (dy, y1 - ay)):
            if p == 0:
                if q < 0:
                    ok = False
                    break
            else:
                r = q / p
                if p < 0:
                    t0 = max(t0, r)
                else:
                    t1 = min(t1, r)
                if t0 > t1:
                    ok = False
                    break
        if not ok:
            if len(cur) > 1:
                parts.append(cur)
            cur = []
            continue
        s = (ax + t0 * dx, ay + t0 * dy)
        e = (ax + t1 * dx, ay + t1 * dy)
        if not cur or cur[-1] != s:
            if len(cur) > 1:
                parts.append(cur)
            cur = [s]
        cur.append(e)
        if t1 < 1.0:
            parts.append(cur)
            cur = []
    if len(cur) > 1:
        parts.append(cur)
    return parts


def bbox(pts):
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    return min(xs), min(ys), max(xs), max(ys)


# ---- Mapbox Vector Tile 2.1, written by hand ----


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def zigzag(n):
    return (n << 1) ^ (n >> 63)


def key(field, wire):
    return varint((field << 3) | wire)


def blob(field, data):
    return key(field, 2) + varint(len(data)) + data


def packed(field, ints):
    return blob(field, b"".join(varint(i) for i in ints))


def command(cmd, count):
    return (cmd & 7) | (count << 3)


def area(ring):
    """The surveyor's formula, twice over, in tile coordinates: positive for an outer ring (MVT 4.3.4.4)."""
    return sum(ring[i][0] * ring[(i + 1) % len(ring)][1] - ring[(i + 1) % len(ring)][0] * ring[i][1] for i in range(len(ring)))


def to_tile(pts, z, tx, ty):
    n = 1 << z
    out = []
    for x, y in pts:
        p = (round((x * n - tx) * EXTENT), round((y * n - ty) * EXTENT))
        if not out or out[-1] != p:
            out.append(p)
    return out


class Layer:
    def __init__(self, name):
        self.name = name
        self.features = []
        self.keys = {}
        self.values = {}

    def tag(self, props):
        tags = []
        for k in sorted(props):
            v = props[k]
            if k not in self.keys:
                self.keys[k] = len(self.keys)
            vk = (type(v).__name__, v)
            if vk not in self.values:
                self.values[vk] = len(self.values)
            tags += [self.keys[k], self.values[vk]]
        return tags

    def add(self, kind, geometry, props):
        """kind 1 point, 2 line, 3 polygon; geometry as MVT commands."""
        if geometry:
            self.features.append((self.tag(props), kind, geometry))

    def encode(self):
        out = key(15, 0) + varint(2) + blob(1, self.name.encode())
        for tags, kind, geometry in self.features:
            out += blob(2, packed(2, tags) + key(3, 0) + varint(kind) + packed(4, geometry))
        for k in self.keys:
            out += blob(3, k.encode())
        for (t, v) in self.values:
            if t == "str":
                out += blob(4, blob(1, v.encode()))
            else:
                out += blob(4, key(6, 0) + varint(zigzag(v)))
        out += key(5, 0) + varint(EXTENT)
        return out


def geometry_points(points):
    out = [command(1, len(points))]
    cx = cy = 0
    for x, y in points:
        out += [zigzag(x - cx), zigzag(y - cy)]
        cx, cy = x, y
    return out


class Cursor:
    def __init__(self):
        self.x = self.y = 0

    def run(self, pts, close):
        out = [command(1, 1), zigzag(pts[0][0] - self.x), zigzag(pts[0][1] - self.y)]
        self.x, self.y = pts[0]
        out.append(command(2, len(pts) - 1))
        for x, y in pts[1:]:
            out += [zigzag(x - self.x), zigzag(y - self.y)]
            self.x, self.y = x, y
        if close:
            out.append(command(7, 1))
        return out


# ---- the world's features, tile by tile ----


def tiles_for(box, z):
    n = 1 << z
    b = BUFFER / EXTENT / n
    x0 = max(0, int(math.floor((box[0] - b) * n)))
    x1 = min(n - 1, int(math.floor((box[2] + b) * n)))
    y0 = max(0, int(math.floor((box[1] - b) * n)))
    y1 = min(n - 1, int(math.floor((box[3] + b) * n)))
    for tx in range(x0, x1 + 1):
        for ty in range(y0, y1 + 1):
            yield tx, ty


def limits(z, tx, ty):
    n = 1 << z
    b = BUFFER / EXTENT / n
    return tx / n - b, ty / n - b, (tx + 1) / n + b, (ty + 1) / n + b


def add_polygons(tiles, layer, features, z, props_of):
    tol = TOLERANCE / EXTENT / (1 << z)
    for f in features:
        props = props_of(f)
        if props is None:
            continue
        for poly in polygons(f["geometry"]):
            rings = [simplify(r, tol) for r in poly]
            if len(rings[0]) < 4:
                continue
            for tx, ty in tiles_for(bbox(rings[0]), z):
                lim = limits(z, tx, ty)
                cur, geom = Cursor(), []
                for i, r in enumerate(rings):
                    c = to_tile(clip_ring(r, *lim), z, tx, ty)
                    if len(c) > 1 and c[0] == c[-1]:
                        c = c[:-1]
                    if len(c) < 3 or area(c) == 0:
                        if i == 0:
                            break
                        continue
                    outer = i == 0
                    if (area(c) > 0) != outer:
                        c.reverse()
                    geom += cur.run(c, close=True)
                if geom:
                    tiles.setdefault((z, tx, ty), {}).setdefault(layer, Layer(layer)).add(3, geom, props)


def add_lines(tiles, layer, features, z, props_of):
    tol = TOLERANCE / EXTENT / (1 << z)
    for f in features:
        props = props_of(f)
        if props is None:
            continue
        for line in lines(f["geometry"]):
            line = simplify(line, tol)
            if len(line) < 2:
                continue
            for tx, ty in tiles_for(bbox(line), z):
                cur, geom = Cursor(), []
                for part in clip_line(line, *limits(z, tx, ty)):
                    p = to_tile(part, z, tx, ty)
                    if len(p) >= 2:
                        geom += cur.run(p, close=False)
                if geom:
                    tiles.setdefault((z, tx, ty), {}).setdefault(layer, Layer(layer)).add(2, geom, props)


def add_points(tiles, layer, points, z):
    """points: (lon, lat, props, min_zoom); each goes in the one tile that holds it, from its min_zoom on."""
    n = 1 << z
    for lon, lat, props, min_zoom in points:
        if min_zoom > z + 1:
            continue
        x, y = merc(lon, lat)
        tx, ty = min(n - 1, int(x * n)), min(n - 1, int(y * n))
        p = to_tile([(x, y)], z, tx, ty)
        tiles.setdefault((z, tx, ty), {}).setdefault(layer, Layer(layer)).add(1, geometry_points(p), props)


def population_rank(pop):
    """0 to 15, as the Protomaps basemap ranks places: each step about doubles the population."""
    for rank, floor in enumerate((0, 200, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000, 5000000, 10000000, 20000000)):
        if pop < floor:
            return max(0, rank - 1)
    return 15


def build(src):
    data = {name: read(src, name) for name in INPUTS}
    tiles = {}
    countries = []
    for f in data["ne_50m_admin_0_countries.geojson"]["features"]:
        p = f["properties"]
        name = p.get("NAME_EN") or p.get("NAME")
        if name and p.get("LABEL_X") is not None:
            min_zoom = float(p.get("MIN_LABEL") or 3)
            countries.append((p["LABEL_X"], p["LABEL_Y"], {"kind": "country", "name": name, "min_zoom": int(math.floor(min_zoom)), "population_rank": population_rank(int(p.get("POP_EST") or 0))}, min_zoom))
    cities = []
    for f in data["ne_10m_populated_places_simple.geojson"]["features"]:
        p = f["properties"]
        mz = float(p.get("min_zoom") or 10)
        if mz > MAXZOOM + 1 or not p.get("name"):
            continue
        lon, lat = f["geometry"]["coordinates"][:2]
        props = {"kind": "locality", "name": p["name"], "min_zoom": int(math.floor(mz)), "population_rank": population_rank(int(p.get("pop_max") or 0))}
        if p.get("adm0cap") == 1:
            props["capital"] = "yes"
        cities.append((lon, lat, props, mz))
    # Bigger places first, so that a renderer that keeps the first label it can place keeps those.
    cities.sort(key=lambda c: (c[3], -c[2]["population_rank"], c[2]["name"]))
    countries.sort(key=lambda c: (c[3], c[2]["name"]))
    for z in range(MAXZOOM + 1):
        s = SCALE[z]
        add_polygons(tiles, "earth", data[f"ne_{s}_land.geojson"]["features"], z, lambda f: {})
        add_polygons(tiles, "water", data[f"ne_{s}_lakes.geojson"]["features"], z, lambda f: {"kind": "lake"})
        add_lines(tiles, "boundaries", data[f"ne_{s}_admin_0_boundary_lines_land.geojson"]["features"], z, lambda f: {"kind": "country", "kind_detail": 2})
        if z >= 3:
            add_lines(tiles, "boundaries", data["ne_50m_admin_1_states_provinces_lines.geojson"]["features"], z, lambda f: {"kind": "region", "kind_detail": 4})
        add_points(tiles, "places", countries, z)
        add_points(tiles, "places", cities, z)
    return tiles


# ---- PMTiles version 3 ----


def tile_id(z, x, y):
    """The Hilbert tile ID of PMTiles v3 §2."""
    acc = ((1 << (2 * z)) - 1) // 3
    n = 1 << z
    d = 0
    s = n >> 1
    while s > 0:
        rx = 1 if x & s else 0
        ry = 1 if y & s else 0
        d += s * s * ((3 * rx) ^ ry)
        if ry == 0:
            if rx == 1:
                x, y = n - 1 - x, n - 1 - y
            x, y = y, x
        s >>= 1
    return acc + d


def gz(data):
    return gzip.compress(data, compresslevel=9, mtime=0)


def directory(entries):
    out = varint(len(entries))
    last = 0
    for e in entries:
        out += varint(e[0] - last)
        last = e[0]
    for e in entries:
        out += varint(e[1])
    for e in entries:
        out += varint(e[3])
    for i, e in enumerate(entries):
        prev = entries[i - 1] if i else None
        out += varint(0 if prev and e[2] == prev[2] + prev[3] else e[2] + 1)
    return gz(out)


LAYERS = ["earth", "water", "boundaries", "places"]


def archive(tiles):
    blobs = []
    entries = []  # tile_id, run_length, offset, length
    seen = {}
    size = 0
    for (z, x, y) in sorted(tiles, key=lambda k: tile_id(*k)):
        layers = tiles[(z, x, y)]
        body = gz(b"".join(blob(3, layers[name].encode()) for name in LAYERS if name in layers and layers[name].features))
        tid = tile_id(z, x, y)
        if body in seen:
            off = seen[body]
        else:
            off = size
            seen[body] = off
            blobs.append(body)
            size += len(body)
        last = entries[-1] if entries else None
        if last and last[0] + last[1] == tid and last[2] == off:
            last[1] += 1
        else:
            entries.append([tid, 1, off, len(body)])
    root = directory(entries)
    meta = gz(json.dumps({
        "name": "Kinfold world",
        "description": "Zoom 0 to 6 of the world, from Natural Earth 5.1.2, for the apps' map before a region is downloaded",
        "attribution": "Made with Natural Earth",
        "type": "baselayer",
        "vector_layers": [{"id": name, "fields": {}, "minzoom": 0, "maxzoom": MAXZOOM} for name in LAYERS],
    }, sort_keys=True, separators=(",", ":")).encode())
    if 127 + len(root) > 16384:
        raise SystemExit("the root directory doesn't fit the first 16 KiB; leaf directories aren't written")
    root_off = 127
    meta_off = root_off + len(root)
    data_off = meta_off + len(meta)
    e7 = lambda d: int(round(d * 1e7))
    header = b"PMTiles" + bytes([3]) + struct.pack(
        "<QQQQQQQQQQQ", root_off, len(root), meta_off, len(meta), data_off, 0, data_off, size,
        sum(e[1] for e in entries), len(entries), len(blobs),
    ) + bytes([1, 2, 2, 1, 0, MAXZOOM]) + struct.pack("<iiii", e7(-180), e7(-MAX_LAT), e7(180), e7(MAX_LAT)) + bytes([0]) + struct.pack("<ii", 0, 0)
    assert len(header) == 127
    return header + root + meta + b"".join(blobs)


def main():
    if sys.argv[1:] == ["--inputs"]:
        print("\n".join(INPUTS))
        return
    if len(sys.argv) != 3:
        raise SystemExit(__doc__.split("\n\n")[1])
    assert tile_id(1, 1, 0) == 4 and tile_id(2, 0, 0) == 5 and tile_id(12, 3423, 1763) == 19078479
    tiles = build(sys.argv[1])
    out = archive(tiles)
    open(sys.argv[2], "wb").write(out)
    print(f"{sys.argv[2]}: {len(tiles)} tiles, {len(out)} bytes, SHA-256 {hashlib.sha256(out).hexdigest()}")


if __name__ == "__main__":
    main()
