# Map files

What the apps draw their map with, shared by both apps. Everything is drawn on the phone from files on the phone: these, inside the app, and the family's region, downloaded whole from the server (API.md §13). No style, tile or glyph is ever asked of a server while the map is drawn, so nobody learns where anyone looks.

| File | What it is | Made by | License |
| --- | --- | --- | --- |
| `assets/style.json` | The style: plan §11's colours, with a `world` source drawn at every zoom and a `region` source drawn from zoom 7 | `style.py` | CC0-1.0 |
| `assets/world.pmtiles` | The whole world at zoom 0 to 6: land, lakes, country and state or province borders, the names of countries and cities (2.2 MB) | `world.py`, from Natural Earth 5.1.2 | Natural Earth is in the public domain; the archive is CC0-1.0 |
| `assets/glyphs/` | Noto Sans Regular, Medium and Italic, as MapLibre glyph ranges for Latin, Greek, Cyrillic and punctuation | taken from [protomaps/basemaps-assets](https://github.com/protomaps/basemaps-assets) at commit `028c18f713baecad011301ff7a69acc39bcc2ae7` | OFL-1.1 (`assets/glyphs/OFL.txt`) |

`style.py`, `world.py` and `check.py` use nothing but Python's standard library, so making the files pulls in no code from elsewhere.

## The style

The layers follow the layer names and properties of the [Protomaps basemap](https://docs.protomaps.com/basemaps/layers) (as in `@protomaps/basemaps` 5.7.2), which regions are cut from: `earth`, `water`, `landuse`, `roads`, `buildings`, `boundaries` and `places`. `world.py` writes the same names, so one style draws both sources. The world map's labels end at zoom 7, where the region's begin; its land and water carry on underneath, drawn larger, so the map is never blank where the region has no tiles.

The style names its files with placeholders, which each app replaces when it loads the style:

- `pmtiles://KINFOLD_WORLD`: the world map inside the app (Android: `pmtiles://asset://world.pmtiles`);
- `pmtiles://KINFOLD_REGION`: the downloaded region (Android: `pmtiles://file://` and its path). An app without a region takes this source and the layers that use it out of the style;
- `KINFOLD_GLYPHS`: the glyphs inside the app (Android: `asset://glyphs`).

The credits the data asks for are each source's `attribution`: "© OpenStreetMap contributors" and "Made with Natural Earth". The apps show them in a corner of the map, Natural Earth's alone where there is no region.

## Making the files again

```sh
python3 -I style.py assets/style.json

# The files world.py reads, from tag v5.1.2 of Natural Earth (world.py checks each one's SHA-256)
git init -q /tmp/ne && cd /tmp/ne
git remote add origin https://github.com/nvkelso/natural-earth-vector.git
git sparse-checkout set --no-cone $(python3 -I /path/to/apps/maps/world.py --inputs | sed 's|^|/geojson/|')
git fetch -q --depth 1 --filter=blob:none origin f1890d9f152c896d250a77557a5751a93d494776
git checkout -q FETCH_HEAD
cd -
python3 -I world.py /tmp/ne/geojson assets/world.pmtiles
```

The same inputs give the same map. They give the same bytes too where Python's zlib is the classic one; zlib-ng compresses the same tiles differently, so `python3 -I check.py A.pmtiles B.pmtiles` compares two archives by what they hold: header, metadata and every tile, decompressed. CI (`.github/workflows/apps.yml`, job `maps`) makes all three again and compares them: the style byte for byte, the world map with `check.py`, and the glyphs byte for byte with the commit they were taken from.

## Regions

A region is cut from the Protomaps daily build and added to the server (server/README.md, "Maps"). The apps list what the server offers (`GET /v1/tiles`) and download one region whole, resuming with `Range` and `If-Range` after a break, and keep it only once its SHA-256 matches the one in the list.
