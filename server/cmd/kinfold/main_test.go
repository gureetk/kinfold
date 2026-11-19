// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gureetk/kinfold/server/internal/admin"
	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/clock"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/store/sqlstore"
)

// backupOf makes a backup of a data directory holding an account and two keys, through the
// admin socket's handler, as kinfold backup does.
func backupOf(t *testing.T) (file string, serverKey []byte) {
	t.Helper()
	src := t.TempDir()
	st, err := sqlstore.Open(filepath.Join(src, "kinfold.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	serverKey = bytes.Repeat([]byte{7}, 32)
	os.WriteFile(filepath.Join(src, "server.key"), serverKey, 0o600)
	os.WriteFile(filepath.Join(src, "vapid.key"), bytes.Repeat([]byte{8}, 32), 0o600)
	st.Update(func(tx store.Tx) error { return tx.PutAccount(store.Account{ID: []byte("acc"), IK: []byte("ik")}) })
	file = filepath.Join(t.TempDir(), "backup.tar")
	body, _ := json.Marshal(map[string]string{"file": file})
	rec := httptest.NewRecorder()
	(&admin.Admin{Store: st, Clock: clock.NewFake(1_793_635_200_000), DataDir: src}).Handler().
		ServeHTTP(rec, httptest.NewRequest("POST", "/backup", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("backup: %d %s", rec.Code, rec.Body)
	}
	return file, serverKey
}

// A backup restored into a directory brings back the database and the keys, with repair mode
// on; restore refuses while a server runs there, and an archive that isn't a backup changes
// nothing.
func TestRestore(t *testing.T) {
	file, serverKey := backupOf(t)
	dst := t.TempDir()
	os.WriteFile(filepath.Join(dst, "server.key"), bytes.Repeat([]byte{1}, 32), 0o600) // another server's
	if err := restore([]string{file, "--data", dst}); err != nil {
		t.Fatal(err)
	}
	if k, _ := os.ReadFile(filepath.Join(dst, "server.key")); !bytes.Equal(k, serverKey) {
		t.Fatal("the server key isn't the backup's")
	}
	st, err := sqlstore.Open(filepath.Join(dst, "kinfold.db"))
	if err != nil {
		t.Fatal(err)
	}
	st.View(func(tx store.Tx) error {
		if _, err := tx.Account([]byte("acc")); err != nil {
			t.Errorf("the account: %v", err)
		}
		if s, _ := tx.Settings(); s.RepairUntil <= (clock.System{}).Now() {
			t.Errorf("repair mode isn't on: %+v", s)
		}
		return nil
	})
	st.Close()
	entries, _ := os.ReadDir(dst)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".restoring") {
			t.Errorf("left behind: %s", e.Name())
		}
		if fi, _ := e.Info(); fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is readable by others: %v", e.Name(), fi.Mode())
		}
	}

	// An archive that isn't a backup changes nothing.
	keyBefore, _ := os.ReadFile(filepath.Join(dst, "server.key"))
	for name, files := range map[string]map[string][]byte{
		"a stranger's file": {"kinfold.db": []byte("x"), "server.key": serverKey, "../etc/passwd": []byte("x")},
		"no server key":     {"kinfold.db": []byte("x")},
		"a short key":       {"kinfold.db": []byte("x"), "server.key": []byte("short")},
		"not a database":    {"kinfold.db": []byte("not sqlite"), "server.key": bytes.Repeat([]byte{9}, 32)},
	} {
		bad := filepath.Join(t.TempDir(), "bad.tar")
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for n, b := range files {
			tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(b))})
			tw.Write(b)
		}
		tw.Close()
		os.WriteFile(bad, buf.Bytes(), 0o600)
		if err := restore([]string{bad, "--data", dst}); err == nil {
			t.Errorf("%s: restored", name)
		}
		if k, _ := os.ReadFile(filepath.Join(dst, "server.key")); !bytes.Equal(k, keyBefore) {
			t.Fatalf("%s: the server key changed", name)
		}
	}

	// Not while a server runs on the directory.
	l, err := net.Listen("unix", filepath.Join(dst, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := restore([]string{file, "--data", dst}); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("while running: %v", err)
	}
}

// The limits the operator set are in force from the next start; the rest keep their defaults.
func TestSavedLimits(t *testing.T) {
	st, err := sqlstore.Open(filepath.Join(t.TempDir(), "kinfold.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if l, err := savedLimits(st); err != nil || l != (api.Limits{}) {
		t.Fatalf("none set: %+v %v", l, err)
	}
	st.Update(func(tx store.Tx) error {
		s, _ := tx.Settings()
		s.Limits = `{"search_per_minute":5,"wake_notify":120}`
		return tx.PutSettings(s)
	})
	if l, err := savedLimits(st); err != nil || l != (api.Limits{SearchPerMinute: 5, WakeNotify: 120}) {
		t.Fatalf("two set: %+v %v", l, err)
	}
}

func TestParseProxies(t *testing.T) {
	got, err := parseProxies(" 127.0.0.1, ::1,10.1.2.3/8 ,::ffff:192.168.0.0/112,, 2001:db8::/48")
	if err != nil {
		t.Fatal(err)
	}
	want := "[127.0.0.1/32 ::1/128 10.0.0.0/8 192.168.0.0/16 2001:db8::/48]"
	if fmt.Sprint(got) != want {
		t.Errorf("got %v, want %s", got, want)
	}
	if got, err := parseProxies(""); err != nil || got != nil {
		t.Errorf("none: %v %v", got, err)
	}
	for _, bad := range []string{"localhost", "127.0.0.1:80", "fe80::1%eth0", "10.0.0.0/33", "0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96"} {
		if _, err := parseProxies(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// Apple push keys come from .p8 files under the names Apple gives them, with a team ID and a
// bundle ID; anything less is refused before the server starts.
func TestLoadApple(t *testing.T) {
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	p8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	write := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	sandbox, production := write("AuthKey_ABC123DEFG.p8", p8), write("AuthKey_XYZ987WVUT.p8", p8)
	renamed, notKey := write("apple.p8", p8), write("AuthKey_BAD0000000.p8", []byte("not a key"))

	cfg, err := loadApple("TEAM123456", "ca.gureet.kinfold", sandbox, production)
	if err != nil || cfg.BundleID != "ca.gureet.kinfold" || len(cfg.Keys) != 2 || cfg.Keys["sandbox"].ID != "ABC123DEFG" ||
		cfg.Keys["production"].ID != "XYZ987WVUT" || cfg.Keys["sandbox"].Team != "TEAM123456" || !cfg.Keys["sandbox"].Private.Equal(k) {
		t.Fatalf("two keys: %+v %v", cfg, err)
	}
	if cfg, err := loadApple("", "", "", ""); err != nil || len(cfg.Keys) != 0 {
		t.Fatalf("no keys: %+v %v", cfg, err)
	}
	for name, args := range map[string][4]string{
		"renamed":           {"TEAM123456", "ca.gureet.kinfold", renamed, ""},
		"not a key":         {"TEAM123456", "ca.gureet.kinfold", notKey, ""},
		"missing":           {"TEAM123456", "ca.gureet.kinfold", filepath.Join(dir, "AuthKey_NONE000000.p8"), ""},
		"no team":           {"", "ca.gureet.kinfold", sandbox, ""},
		"a short team":      {"TEAM12345", "ca.gureet.kinfold", "", production},
		"no bundle ID":      {"TEAM123456", "", sandbox, ""},
		"one-part bundle":   {"TEAM123456", "kinfold", sandbox, ""},
		"a bundle with a /": {"TEAM123456", "ca.gureet/kinfold", sandbox, ""},
		"a team, no key":    {"TEAM123456", "ca.gureet.kinfold", "", ""},
	} {
		if _, err := loadApple(args[0], args[1], args[2], args[3]); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}
