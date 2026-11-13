// SPDX-License-Identifier: AGPL-3.0-or-later

package memstore_test

import (
	"testing"

	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/store/memstore"
	"github.com/gureetk/kinfold/server/internal/store/storetest"
)

func TestStore(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return memstore.New() })
}
