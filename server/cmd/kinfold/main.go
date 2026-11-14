// SPDX-License-Identifier: AGPL-3.0-or-later

// Command kinfold is the Kinfold server and its operator's command line.
//
//	kinfold serve --url https://kinfold.example.org [--listen 127.0.0.1:8080] [--data DIR]
//	              [--tls-cert FILE --tls-key FILE] [--no-clock-check]
//	              [--relay https://relay.example] [--push-hosts HOST,…] [--push-hosts-only]
//	              [--no-webpush] [--search http://127.0.0.1:2322]
//
// serve keeps everything in DIR: the server key (server.key), the Web Push key (vapid.key),
// the database (kinfold.db, with its -wal and -shm files), the map files (tiles/) and the
// admin socket (admin.sock).
//
//	kinfold setup [--expires 24h]                 print a setup code for the first phone
//	kinfold token create [--expires 168h]         a registration token
//	kinfold token list | token revoke ID
//	kinfold settings [--member-tokens on|off] [--web-devices on|off]
//	kinfold operator add|remove ACCOUNT_ID
//	kinfold repair start [--hours 72] | repair end
//	kinfold region add ID FILE [--name NAME]      offer a PMTiles region for download
//	kinfold region list | region remove ID
//	kinfold coarse set FILE | coarse remove       the share viewer's map, zoom 13 at most
//
// Every command but serve talks to the running server through the admin socket in the data
// directory (DIR/admin.sock), which only the server's user can open.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gureetk/kinfold/server/internal/admin"
	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/clock"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/store/sqlstore"
	"github.com/gureetk/kinfold/server/internal/tiles"
	"github.com/gureetk/kinfold/server/internal/wire"
)

const defaultData = "/var/lib/kinfold"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "serve":
		err = serve(args)
	case "setup", "token", "settings", "operator", "repair", "region", "coarse":
		err = adminCommand(cmd, args)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kinfold:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: kinfold serve|setup|token|settings|operator|repair|region|coarse [flags]; see the package documentation")
	os.Exit(2)
}

// ---- serve ----

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	url := fs.String("url", "", "the server's base URL, https and no trailing slash (required)")
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	data := fs.String("data", defaultData, "data directory: server key, database and admin socket")
	certFile := fs.String("tls-cert", "", "TLS certificate; without it, serve plain HTTP behind a TLS proxy")
	keyFile := fs.String("tls-key", "", "TLS private key")
	noClock := fs.Bool("no-clock-check", false, "don't ask the kernel whether the clock is synchronized")
	relay := fs.String("relay", "", "the iOS relay's base URL (API.md §14); without it, iPhones from the App Store get no pushes")
	pushHosts := fs.String("push-hosts", "", "Web Push hosts allowed without the public-address check, comma-separated")
	pushHostsOnly := fs.Bool("push-hosts-only", false, "send Web Push only to the hosts in --push-hosts")
	noWebPush := fs.Bool("no-webpush", false, "take no Web Push (UnifiedPush) registrations; Android phones then rely on their stream")
	search := fs.String("search", "", "the search add-on: a Photon instance's base URL, such as http://127.0.0.1:2322; without it, no search")
	fs.Parse(args)
	privateFiles()
	if !strings.HasPrefix(*url, "https://") || strings.HasSuffix(*url, "/") {
		return errors.New("--url must be an https URL without a trailing slash")
	}
	if *relay != "" && (!strings.HasPrefix(*relay, "https://") || strings.HasSuffix(*relay, "/")) {
		return errors.New("--relay must be an https URL without a trailing slash")
	}
	if u, err := neturl.Parse(*search); *search != "" && (err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		strings.HasSuffix(*search, "/") || u.RawQuery != "" || u.Fragment != "") {
		return errors.New("--search must be an http or https URL without a trailing slash, such as http://127.0.0.1:2322")
	}
	var hosts []string
	for _, h := range strings.Split(*pushHosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	if err := os.MkdirAll(*data, 0o700); err != nil {
		return err
	}
	key, err := loadKey(filepath.Join(*data, "server.key"))
	if err != nil {
		return err
	}
	var vapid *ecdsa.PrivateKey
	if !*noWebPush {
		if vapid, err = loadVAPID(filepath.Join(*data, "vapid.key")); err != nil {
			return err
		}
	}
	maps, err := tiles.Open(filepath.Join(*data, "tiles"))
	if err != nil {
		return err
	}
	st, err := sqlstore.Open(filepath.Join(*data, "kinfold.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	clk := clock.System{CheckSync: !*noClock}
	handler := api.New(api.Config{URL: *url, Key: key, Clock: clk, Store: st, Tiles: maps, Search: *search,
		Push: api.PushConfig{Relay: *relay, Hosts: hosts, HostsOnly: *pushHostsOnly, VAPID: vapid}})

	srv := &http.Server{Addr: *listen, Handler: handler,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	adminSrv := &http.Server{Handler: (&admin.Admin{Store: st, Clock: clk, Key: key, URL: *url, Notify: handler.Notice,
		Tiles: maps}).Handler(), ReadHeaderTimeout: 10 * time.Second}

	sock := filepath.Join(*data, "admin.sock")
	os.Remove(sock)
	al, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		return err
	}
	errs := make(chan error, 2)
	go func() { errs <- adminSrv.Serve(al) }()
	go func() {
		if *certFile != "" {
			errs <- srv.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			errs <- srv.ListenAndServe()
		}
	}()
	slog.Info("serving", "url", *url, "listen", *listen, "admin", sock)
	go everyMinute(handler)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err = <-errs:
	case <-stop:
	}
	handler.CloseStreams(5 * time.Second) // Shutdown leaves upgraded connections alone
	handler.FlushPushes(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	adminSrv.Shutdown(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// everyMinute sweeps away what has run out (API.md §15), runs the silence check (§8) and
// forgets link mailboxes that have ended (§10): at start, then every minute. It logs counts,
// never what it deleted.
func everyMinute(s *api.Server) {
	for {
		if n, err := s.Sweep(); err != nil {
			slog.Error("sweep failed", "err", err)
		} else if n != (store.Swept{}) {
			slog.Info("swept", "envelopes", n.Envelopes, "replay_records", n.Seen, "sessions", n.Sessions,
				"challenges", n.Challenges, "tokens", n.Tokens, "invites", n.Invites, "removals", n.Removals,
				"watches", n.Watches, "shares", n.Shares, "circles", n.Circles)
		}
		if err := s.CheckSilences(); err != nil {
			slog.Error("silence check failed", "err", err)
		}
		s.SweepLinks()
		time.Sleep(time.Minute)
	}
}

// loadKey reads the server key's seed, making one on first start. It never leaves this file.
func loadKey(path string) (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a server key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// loadVAPID reads the server's Web Push key (RFC 8292), making one on first start. Phones
// hand its public half to their distributors, so it stays as long as this file does.
func loadVAPID(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		if raw, err = k.Bytes(); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not a VAPID key", path)
	}
	return k, nil
}

// ---- the operator's commands ----

func adminCommand(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	data := fs.String("data", defaultData, "data directory of the running server")
	expires := fs.Duration("expires", 0, "how long the token or setup code works")
	hours := fs.Uint64("hours", admin.MaxRepairHours, "how long repair mode lasts, at most 72 hours")
	memberTokens := fs.String("member-tokens", "", "on or off: admins may mint registration tokens with invites")
	webDevices := fs.String("web-devices", "", "on or off: web and Home Assistant devices may be registered")
	name := fs.String("name", "", "the region's name, as apps show it; its ID if left out")
	// Subcommands come before the flags: kinfold token create --expires 48h.
	var sub []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = append(sub, args[0]), args[1:]
	}
	fs.Parse(args)
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(*data, "admin.sock"))
	}}}
	call := func(method, path string, in any) (map[string]any, []map[string]any, error) {
		var body io.Reader
		if in != nil {
			b, _ := json.Marshal(in)
			body = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, "http://admin"+path, body)
		resp, err := c.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("is the server running? %w", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var obj map[string]any
		var list []map[string]any
		if json.Unmarshal(raw, &obj) != nil {
			json.Unmarshal(raw, &list)
		}
		if resp.StatusCode >= 300 {
			return nil, nil, fmt.Errorf("%s: %v", resp.Status, obj["error"])
		}
		return obj, list, nil
	}
	ms := uint64(expires.Milliseconds())
	onOff := func(v string) (*bool, error) {
		switch v {
		case "":
			return nil, nil
		case "on", "off":
			b := v == "on"
			return &b, nil
		}
		return nil, fmt.Errorf("use on or off, not %q", v)
	}

	switch {
	case cmd == "setup":
		out, _, err := call("POST", "/setup", map[string]any{"expires_in_ms": ms})
		if err != nil {
			return err
		}
		fmt.Printf("Setup code for the first phone (scan it in the app, or type it):\n\n  %v\n\n", out["code"])
		fmt.Printf("Server:      %v\nServer key:  %v\nExpires at:  %v\n", out["server_url"], out["server_key"], when(out["expires_at"]))
		fmt.Println("\nCompare the server key with the one the app shows before you trust it.")
	case cmd == "token" && len(sub) == 1 && sub[0] == "create":
		out, _, err := call("POST", "/tokens", map[string]any{"expires_in_ms": ms})
		if err != nil {
			return err
		}
		fmt.Printf("%v\n(id %v, expires %v)\n", out["token"], out["token_id"], when(out["expires_at"]))
	case cmd == "token" && len(sub) == 1 && sub[0] == "list":
		_, list, err := call("GET", "/tokens", nil)
		if err != nil {
			return err
		}
		for _, t := range list {
			fmt.Printf("%v  expires %v  spent %v  invite %v\n", t["token_id"], when(t["expires_at"]), t["spent"], t["invite"] != nil)
		}
	case cmd == "token" && len(sub) == 2 && sub[0] == "revoke":
		_, _, err := call("DELETE", "/tokens/"+sub[1], nil)
		return err
	case cmd == "settings":
		mt, err := onOff(*memberTokens)
		if err != nil {
			return err
		}
		wd, err := onOff(*webDevices)
		if err != nil {
			return err
		}
		method, in := "GET", any(nil)
		if mt != nil || wd != nil {
			method, in = "PATCH", map[string]any{"member_tokens": mt, "web_devices": wd}
		}
		out, _, err := call(method, "/settings", in)
		if err != nil {
			return err
		}
		fmt.Printf("member tokens %v, web devices %v, repair until %v\n", out["member_tokens"], out["web_devices"], when(out["repair_until"]))
	case cmd == "operator" && len(sub) == 2 && (sub[0] == "add" || sub[0] == "remove"):
		if _, err := wire.DecodeB64u(sub[1]); err != nil {
			return errors.New("account IDs are base64url")
		}
		method := map[string]string{"add": "PUT", "remove": "DELETE"}[sub[0]]
		_, _, err := call(method, "/operators/"+sub[1], nil)
		return err
	case cmd == "repair" && len(sub) == 1 && sub[0] == "start":
		out, _, err := call("POST", "/repair", map[string]any{"hours": *hours})
		if err != nil {
			return err
		}
		fmt.Printf("repair mode until %v\n", when(out["repair_until"]))
	case cmd == "repair" && len(sub) == 1 && sub[0] == "end":
		_, _, err := call("DELETE", "/repair", nil)
		return err
	case cmd == "region" && len(sub) == 1 && sub[0] == "list":
		out, _, err := call("GET", "/regions", nil)
		if err != nil {
			return err
		}
		regions, _ := out["regions"].([]any)
		for _, r := range regions {
			printMap(r)
		}
		if out["coarse"] != nil {
			printMap(out["coarse"])
		} else {
			fmt.Println("no coarse archive: shared links show positions as text")
		}
	case cmd == "region" && len(sub) == 3 && sub[0] == "add", cmd == "coarse" && len(sub) == 2 && sub[0] == "set":
		path, err := filepath.Abs(sub[len(sub)-1])
		if err != nil {
			return err
		}
		where := "/coarse"
		if cmd == "region" {
			where = "/regions/" + neturl.PathEscape(sub[1])
		}
		out, _, err := call("PUT", where, map[string]any{"file": path, "name": *name}) // copying a region takes a while
		if err != nil {
			return err
		}
		printMap(out)
	case cmd == "region" && len(sub) == 2 && sub[0] == "remove":
		_, _, err := call("DELETE", "/regions/"+neturl.PathEscape(sub[1]), nil)
		return err
	case cmd == "coarse" && len(sub) == 1 && sub[0] == "remove":
		_, _, err := call("DELETE", "/coarse", nil)
		return err
	default:
		usage()
	}
	return nil
}

// printMap prints a region or the coarse archive as the admin socket describes it.
func printMap(v any) {
	m, _ := v.(map[string]any)
	size, _ := m["size"].(float64)
	sum, _ := m["sha256"].(string)
	fmt.Printf("%v  %q  %.1f MB  zoom %v to %v  sha256 %.16s…  updated %v\n", m["id"], m["name"], size/1e6, m["minzoom"],
		m["maxzoom"], sum, when(m["updated_at"]))
}

func when(v any) string {
	ms, ok := v.(float64)
	if !ok || ms == 0 {
		return "-"
	}
	return time.UnixMilli(int64(ms)).UTC().Format(time.RFC3339)
}
