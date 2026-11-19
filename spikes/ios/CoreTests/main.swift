// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The build replaces this program with the core's test binary, which runs every test in the core's
// commonTest and iosTest against CryptoKit (scripts/core-tests.sh). If this runs instead, that step
// didn't happen.

import Foundation

FileHandle.standardError.write(Data("This build doesn't carry the core's tests: run spikes/ios/build-core.sh, then build again.\n".utf8))
exit(1)
