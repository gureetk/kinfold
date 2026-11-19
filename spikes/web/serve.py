#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
"""Serves the repository on http://localhost:8000, to this computer only, for the vectors page:
open http://localhost:8000/spikes/web/ in each browser. A browser gives a page WebCrypto only over
https or from localhost, and modules only with a JavaScript type, which this server sets."""
import functools
import http.server
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map,
                      ".mjs": "text/javascript", ".js": "text/javascript", ".json": "application/json"}

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), functools.partial(Handler, directory=ROOT))
    print(f"Open http://localhost:{PORT}/spikes/web/ in Safari and in Firefox. Ctrl-C stops the server.")
    server.serve_forever()
