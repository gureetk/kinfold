#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
#
# A build phase of the Kinfold target: copies spike 5's page into the app, laid out as in the
# repository, since the page fetches reference/js and the vectors by their paths there.
set -eu

repo="$SRCROOT/../.."
web="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/web"
rm -rf "$web"
mkdir -p "$web/spikes/web/shims" "$web/reference/js" "$web/spec/vectors"
cp "$repo/spikes/web/index.html" "$repo/spikes/web/run.mjs" "$web/spikes/web/"
cp "$repo"/spikes/web/shims/*.mjs "$web/spikes/web/shims/"
cp "$repo"/reference/js/*.mjs "$web/reference/js/"
cp "$repo/spec/vectors/kinfold-v0.json" "$web/spec/vectors/"
