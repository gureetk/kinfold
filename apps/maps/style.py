# SPDX-License-Identifier: CC0-1.0
"""Writes the map style both apps draw with: assets/style.json.

usage: python3 -I style.py OUT.json

The friendly style of plan §11 (cream land, soft greens and blues, white streets, yellow highways,
grey labels with white halos), after the layer names and properties of the Protomaps basemap.
Python's standard library only.

Two sources, which the apps point at their files when they load the style:

- `world` (KINFOLD_WORLD): the world map inside the app, zoom 0 to 6 (world.py). It is drawn at
  every zoom, so the map is never blank, and its labels only up to zoom 7;
- `region` (KINFOLD_REGION): the family's region, downloaded whole from the server (API.md §13),
  drawn from zoom 7. An app without a region takes out this source and its layers.

Glyphs come from inside the app too (KINFOLD_GLYPHS): Noto Sans in three weights. Nothing in the
style names a URL on the network, so drawing the map never asks a server for anything.
"""
import json
import sys

LAND = "#F3F1EC"
PARK = "#D2E7C6"
WATER = "#AAD3EA"
BUILDING = "#E4E0D7"
BUILDING_EDGE = "#D6D0C4"
STREET = "#FFFFFF"
STREET_CASING = "#E0DBD1"
MAJOR_CASING = "#D5CFC3"
HIGHWAY = "#F8DF9C"
HIGHWAY_CASING = "#E2C072"
BORDER = "#B4AC9F"
BORDER_REGION = "#CFC8BC"
LABEL = "#6B665E"
LABEL_STRONG = "#4A463F"
LABEL_WATER = "#5A86A3"
HALO = "#FFFFFF"

REGULAR = ["Noto Sans Regular"]
MEDIUM = ["Noto Sans Medium"]
ITALIC = ["Noto Sans Italic"]

# The world's labels end, and the region's begin, at this zoom.
HANDOVER = 7

NAME = ["coalesce", ["get", "name:en"], ["get", "name"]]


def width(*stops):
    """A line width that grows exponentially with zoom, through (zoom, width) stops."""
    out = ["interpolate", ["exponential", 1.6], ["zoom"]]
    for z, w in stops:
        out += [z, w]
    return out


def world_layers():
    s = {"source": "world"}
    return [
        {"id": "world_earth", "type": "fill", **s, "source-layer": "earth", "paint": {"fill-color": LAND}},
        {"id": "world_water", "type": "fill", **s, "source-layer": "water", "paint": {"fill-color": WATER}},
        {
            "id": "world_boundaries_region", "type": "line", **s, "source-layer": "boundaries", "minzoom": 3,
            "filter": [">", ["get", "kind_detail"], 2],
            "paint": {"line-color": BORDER_REGION, "line-width": 0.7, "line-dasharray": [3, 2]},
        },
        {
            "id": "world_boundaries_country", "type": "line", **s, "source-layer": "boundaries",
            "filter": ["<=", ["get", "kind_detail"], 2],
            "paint": {"line-color": BORDER, "line-width": ["interpolate", ["linear"], ["zoom"], 0, 0.6, 6, 1.4]},
        },
    ]


def region_layers():
    s = {"source": "region", "minzoom": HANDOVER}
    parks = ["national_park", "park", "cemetery", "protected_area", "nature_reserve", "forest", "golf_course", "wood", "grass", "grassland", "scrub", "allotments", "village_green", "playground", "garden"]
    plain = ["all", ["!", ["has", "is_tunnel"]], ["!", ["has", "is_bridge"]]]
    return [
        {"id": "region_earth", "type": "fill", **s, "source-layer": "earth", "paint": {"fill-color": LAND}},
        {
            "id": "region_parks", "type": "fill", **s, "source-layer": "landuse",
            "filter": ["in", ["get", "kind"], ["literal", parks]],
            "paint": {"fill-color": PARK, "fill-opacity": ["interpolate", ["linear"], ["zoom"], 7, 0.4, 11, 1]},
        },
        {
            "id": "region_water", "type": "fill", **s, "source-layer": "water",
            "filter": ["==", ["geometry-type"], "Polygon"],
            "paint": {"fill-color": WATER},
        },
        {
            "id": "region_rivers", "type": "line", **s, "source-layer": "water", "minzoom": 9,
            "filter": ["all", ["==", ["geometry-type"], "LineString"], ["in", ["get", "kind"], ["literal", ["river", "canal", "stream"]]]],
            "paint": {"line-color": WATER, "line-width": width((9, 0.5), (18, 10))},
        },
        {
            "id": "region_buildings", "type": "fill", "source": "region", "minzoom": 14, "source-layer": "buildings",
            "paint": {"fill-color": BUILDING, "fill-outline-color": BUILDING_EDGE},
        },
        {
            "id": "region_minor_casing", "type": "line", "source": "region", "minzoom": 13, "source-layer": "roads",
            "filter": plain + [["==", ["get", "kind"], "minor_road"]],
            "layout": {"line-cap": "round", "line-join": "round"},
            "paint": {"line-color": STREET_CASING, "line-width": width((13, 0), (13.5, 1)), "line-gap-width": width((13, 0.5), (18, 14))},
        },
        {
            "id": "region_major_casing", "type": "line", "source": "region", "minzoom": 10, "source-layer": "roads",
            "filter": plain + [["==", ["get", "kind"], "major_road"]],
            "layout": {"line-cap": "round", "line-join": "round"},
            "paint": {"line-color": MAJOR_CASING, "line-width": width((10, 0), (10.5, 1)), "line-gap-width": width((10, 0.8), (18, 18))},
        },
        {
            "id": "region_highway_casing", "type": "line", **s, "source-layer": "roads",
            "filter": plain + [["==", ["get", "kind"], "highway"]],
            "layout": {"line-cap": "round", "line-join": "round"},
            "paint": {"line-color": HIGHWAY_CASING, "line-width": width((7, 0.5), (10, 1)), "line-gap-width": width((7, 0.6), (18, 20))},
        },
        {
            "id": "region_paths", "type": "line", "source": "region", "minzoom": 15, "source-layer": "roads",
            "filter": plain + [["in", ["get", "kind"], ["literal", ["path", "other"]]]],
            "paint": {"line-color": STREET, "line-width": width((15, 0.6), (18, 3)), "line-dasharray": [2, 1]},
        },
        {
            "id": "region_minor", "type": "line", "source": "region", "minzoom": 12, "source-layer": "roads",
            "filter": plain + [["==", ["get", "kind"], "minor_road"]],
            "layout": {"line-cap": "round", "line-join": "round"},
            "paint": {"line-color": STREET, "line-width": width((12, 0.3), (13, 0.5), (18, 14))},
        },
        {
            "id": "region_major", "type": "line", "source": "region", "minzoom": 8, "source-layer": "roads",
            "filter": plain + [["==", ["get", "kind"], "major_road"]],
            "layout": {"line-cap": "round", "line-join": "round"},
            "paint": {"line-color": STREET, "line-width": width((8, 0.4), (10, 0.8), (18, 18))},
        },
        {
            "id": "region_highway", "type": "line", **s, "source-layer": "roads",
            "filter": plain + [["==", ["get", "kind"], "highway"]],
            "layout": {"line-cap": "round", "line-join": "round"},
            "paint": {"line-color": HIGHWAY, "line-width": width((7, 0.6), (18, 20))},
        },
        {
            "id": "region_bridges", "type": "line", "source": "region", "minzoom": 12, "source-layer": "roads",
            "filter": ["all", ["has", "is_bridge"], ["in", ["get", "kind"], ["literal", ["highway", "major_road", "minor_road"]]]],
            "layout": {"line-cap": "butt", "line-join": "round"},
            "paint": {
                "line-color": ["match", ["get", "kind"], "highway", HIGHWAY, STREET],
                "line-width": width((12, 0.8), (18, 18)),
            },
        },
        {
            "id": "region_boundaries", "type": "line", **s, "source-layer": "boundaries",
            "paint": {
                "line-color": ["case", ["<=", ["get", "kind_detail"], 2], BORDER, BORDER_REGION],
                "line-width": ["case", ["<=", ["get", "kind_detail"], 2], 1.4, 0.8],
                "line-dasharray": [3, 2],
            },
        },
    ]


def labels():
    def text(size, color=LABEL, font=None):
        return {
            "layout": {"text-field": NAME, "text-font": font or REGULAR, "text-size": size, "text-max-width": 8},
            "paint": {"text-color": color, "text-halo-color": HALO, "text-halo-width": 1.6, "text-halo-blur": 0.5},
        }

    def merged(base, extra):
        out = dict(base)
        for k, v in extra.items():
            out[k] = {**out.get(k, {}), **v} if isinstance(v, dict) else v
        return out

    shown = ["<=", ["get", "min_zoom"], ["zoom"]]
    world = {"source": "world", "source-layer": "places", "maxzoom": HANDOVER}
    region = {"source": "region", "minzoom": HANDOVER}
    return [
        merged({"id": "region_water_labels", "type": "symbol", **region, "source-layer": "water", "filter": ["all", ["==", ["geometry-type"], "Point"], ["has", "name"]]},
               text(["interpolate", ["linear"], ["zoom"], 7, 11, 14, 14], LABEL_WATER, ITALIC)),
        merged({"id": "region_road_labels", "type": "symbol", "source": "region", "minzoom": 13, "source-layer": "roads",
                "filter": ["in", ["get", "kind"], ["literal", ["highway", "major_road", "minor_road"]]]},
               merged(text(["interpolate", ["linear"], ["zoom"], 13, 10, 18, 13]), {"layout": {"symbol-placement": "line", "symbol-sort-key": ["get", "min_zoom"]}})),
        merged({"id": "region_places_locality", "type": "symbol", **region, "source-layer": "places",
                "filter": ["all", ["in", ["get", "kind"], ["literal", ["locality", "neighbourhood", "macrohood"]]], shown]},
               merged(text(["interpolate", ["linear"], ["zoom"], 7, ["case", ["<", ["get", "population_rank"], 9], 11, 13], 14, ["case", ["<", ["get", "population_rank"], 9], 14, 17]], LABEL_STRONG),
                      {"layout": {"symbol-sort-key": ["get", "min_zoom"]}})),
        merged({"id": "region_places_region", "type": "symbol", **region, "source-layer": "places", "maxzoom": 9, "filter": ["==", ["get", "kind"], "region"]},
               merged(text(12, LABEL, MEDIUM), {"layout": {"text-transform": "uppercase", "text-letter-spacing": 0.08}})),
        merged({"id": "region_places_country", "type": "symbol", **region, "source-layer": "places", "maxzoom": 9, "filter": ["==", ["get", "kind"], "country"]},
               merged(text(13, LABEL_STRONG, MEDIUM), {"layout": {"text-transform": "uppercase", "text-letter-spacing": 0.08}})),
        merged({"id": "world_places_locality", "type": "symbol", **world, "minzoom": 2, "filter": ["all", ["==", ["get", "kind"], "locality"], shown]},
               merged(text(["interpolate", ["linear"], ["zoom"], 2, ["case", ["has", "capital"], 11, 10], 6, ["case", ["has", "capital"], 14, 12]], LABEL_STRONG),
                      {"layout": {"symbol-sort-key": ["get", "min_zoom"]}})),
        merged({"id": "world_places_country", "type": "symbol", **world, "filter": ["all", ["==", ["get", "kind"], "country"], shown]},
               merged(text(["interpolate", ["linear"], ["zoom"], 1, 10, 6, 14], LABEL_STRONG, MEDIUM),
                      {"layout": {"text-transform": "uppercase", "text-letter-spacing": 0.08, "symbol-sort-key": ["get", "min_zoom"]}})),
    ]


def style():
    return {
        "version": 8,
        "name": "Kinfold",
        "glyphs": "KINFOLD_GLYPHS/{fontstack}/{range}.pbf",
        "sources": {
            "world": {"type": "vector", "url": "pmtiles://KINFOLD_WORLD", "attribution": "Made with Natural Earth"},
            "region": {"type": "vector", "url": "pmtiles://KINFOLD_REGION", "attribution": "© OpenStreetMap contributors"},
        },
        "layers": [{"id": "background", "type": "background", "paint": {"background-color": WATER}}]
        + world_layers() + region_layers() + labels(),
    }


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 -I style.py OUT.json")
    with open(sys.argv[1], "w") as f:
        json.dump(style(), f, indent=1, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
