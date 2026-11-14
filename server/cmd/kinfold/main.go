// SPDX-License-Identifier: AGPL-3.0-or-later

// Command kinfold is the Kinfold server and its operator's command line.
//
//	kinfold serve --url https://kinfold.example.org [--listen 127.0.0.1:8080] [--data DIR]
//	              [--tls-cert FILE --tls-key FILE] [--trusted-proxy ADDRESS,…] [--no-clock-check]
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
//	kinfold settings [--member-tokens on|off] [--web-devices on|off] [--web-tile-ranges on|off]
//	kinfold limits | limits set NAME N | limits reset NAME    the rate limits of API.md §3
//	kinfold operator add|remove ACCOUNT_ID
//	kinfold repair start [--hours 72] | repair end
//	kinfold status                                health: clock, disk, streams, pushes, relay, last backup
//	kinfold backup FILE                           the database (a snapshot) and the keys, as a tar archive
//	kinfold restore FILE                          with the server stopped: put a backup in place, in repair mode
//	kinfold accounts | circles                    what the server knows of them: IDs, kinds, counts, days
//	kinfold account nickname ID NAME | account remove ID
//	kinfold device nickname ID NAME | device remove ID
//	kinfold region add ID FILE [--name NAME]      offer a PMTiles region for download
//	kinfold region list | region remove ID
//	kinfold coarse set FILE | coarse remove       the share viewer's map, zoom 13 at most
//
// Every command but serve talks to the running server through the admin socket in the data
// directory (DIR/admin.sock), which only the server's user can open.
package main

import (
	"archive/tar"
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
	"maps"
	"net"
	"net/http"
	"net/netip"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
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
	case "restore":
		err = restore(args)
	case "setup", "token", "settings", "operator", "repair", "region", "coarse", "accounts", "circles", "account", "device",
		"backup", "status", "limits":
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
	fmt.Fprintln(os.Stderr, "usage: kinfold serve|setup|token|settings|limits|operator|repair|status|backup|restore|accounts|circles|"+
		"account|device|region|coarse [flags]; see the package documentation")
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
	trustedProxy := fs.String("trusted-proxy", "", "the reverse proxies in front of the server, as addresses or prefixes, comma-separated, "+
		"such as 127.0.0.1,::1; on their connections, a client's address for the per-address limits comes from X-Forwarded-For")
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
	proxies, err := parseProxies(*trustedProxy)
	if err != nil {
		return err
	}
	if *certFile == "" && len(proxies) == 0 {
		slog.Warn("plain HTTP and no --trusted-proxy: every client behind the proxy counts as one address for the per-address limits")
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
	library, err := tiles.Open(filepath.Join(*data, "tiles"))
	if err != nil {
		return err
	}
	st, err := sqlstore.Open(filepath.Join(*data, "kinfold.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	limits, err := savedLimits(st)
	if err != nil {
		return err
	}
	clk := clock.System{CheckSync: !*noClock}
	handler := api.New(api.Config{URL: *url, Key: key, Clock: clk, Store: st, Tiles: library, Search: *search, DataDir: *data, Limits: limits,
		Push: api.PushConfig{Relay: *relay, Hosts: hosts, HostsOnly: *pushHostsOnly, VAPID: vapid}, TrustedProxies: proxies})

	srv := &http.Server{Addr: *listen, Handler: handler,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	adminSrv := &http.Server{Handler: (&admin.Admin{Store: st, Clock: clk, Key: key, URL: *url, Notify: handler.Notice,
		Tiles: library, API: handler, DataDir: *data}).Handler(), ReadHeaderTimeout: 10 * time.Second}

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
				"watches", n.Watches, "shares", n.Shares, "circles", n.Circles, "dropped_for_space", n.Dropped)
		}
		if err := s.CheckSilences(); err != nil {
			slog.Error("silence check failed", "err", err)
		}
		s.SweepLinks()
		time.Sleep(time.Minute)
	}
}

// parseProxies reads --trusted-proxy: addresses or prefixes, comma-separated. A prefix that
// covers every address is refused, since it would let any client choose its own address.
func parseProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			a, err := netip.ParseAddr(f)
			if err != nil || a.Zone() != "" {
				return nil, fmt.Errorf("--trusted-proxy: %q is neither an address nor a prefix such as 10.0.0.0/8", f)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 { // the server reads such addresses as IPv4
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("--trusted-proxy: %s would trust every address", f)
		}
		out = append(out, p.Masked())
	}
	return out, nil
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

// savedLimits are the rate limits the operator has set (kinfold limits); the rest keep their
// defaults.
func savedLimits(st store.Store) (api.Limits, error) {
	var l api.Limits
	err := st.View(func(tx store.Tx) error {
		s, err := tx.Settings()
		if err != nil || s.Limits == "" {
			return err
		}
		return json.Unmarshal([]byte(s.Limits), &l)
	})
	return l, err
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

// restore puts a backup in place in a data directory while the server is stopped, and starts
// repair mode there (API.md §6) for when it next runs, so phones can post again what the
// backup lacks. The keys come back with the database: the server is the one that was backed up.
func restore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	data := fs.String("data", defaultData, "data directory to restore into, with the server stopped")
	hours := fs.Uint64("hours", admin.MaxRepairHours, "how long repair mode lasts, at most 72 hours")
	var file string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		file, args = args[0], args[1:]
	}
	fs.Parse(args)
	if file == "" || fs.NArg() != 0 {
		return errors.New("usage: kinfold restore FILE [--data DIR] [--hours 72]")
	}
	privateFiles()
	if c, err := net.Dial("unix", filepath.Join(*data, "admin.sock")); err == nil {
		c.Close()
		return errors.New("the server is running: stop it first")
	}
	if err := os.MkdirAll(*data, 0o700); err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	// Every file is written beside its place first, and moved there once the whole archive
	// has been read.
	staged := map[string]string{}
	defer func() {
		for _, tmp := range staged {
			os.Remove(tmp)
		}
	}()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("%s isn't a backup: %w", file, err)
		}
		name := hdr.Name
		if !slices.Contains(admin.BackupFiles, name) || staged[name] != "" || hdr.Typeflag != tar.TypeReg ||
			(name != "kinfold.db" && hdr.Size != 32) {
			return fmt.Errorf("%s isn't a backup: it holds %q", file, name)
		}
		tmp := filepath.Join(*data, name+".restoring")
		out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		staged[name] = tmp
		_, err = io.Copy(out, tr)
		if err == nil {
			err = out.Sync()
		}
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	if staged["kinfold.db"] == "" || staged["server.key"] == "" {
		return fmt.Errorf("%s isn't a backup: it lacks the database or the server key", file)
	}
	// The database is opened, brought to this server's schema and put in repair mode before
	// anything in the directory is replaced, so a backup this server can't read changes nothing.
	until := clock.System{}.Now() + min(max(*hours, 1), admin.MaxRepairHours)*3_600_000
	if err := repairFrom(staged["kinfold.db"], until); err != nil {
		return fmt.Errorf("the backup's database: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(filepath.Join(*data, "kinfold.db"+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for name, tmp := range staged {
		if err := os.Rename(tmp, filepath.Join(*data, name)); err != nil {
			return err
		}
		delete(staged, name)
	}
	fmt.Printf("Restored into %s. The server starts in repair mode until %v, so phones can post again what the backup lacks.\n",
		*data, when(float64(until)))
	return nil
}

// repairFrom opens a restored database, which brings it to this server's schema, and starts
// repair mode in it until the given time.
func repairFrom(path string, until uint64) error {
	st, err := sqlstore.Open(path)
	if err != nil {
		return err
	}
	err = st.Update(func(tx store.Tx) error {
		s, err := tx.Settings()
		if err != nil {
			return err
		}
		s.RepairUntil = until
		return tx.PutSettings(s)
	})
	if cerr := st.Close(); err == nil {
		err = cerr
	}
	if _, serr := os.Stat(path + "-wal"); err == nil && serr == nil {
		err = errors.New("it didn't close cleanly")
	}
	return err
}

// ---- the operator's commands ----

func adminCommand(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	data := fs.String("data", defaultData, "data directory of the running server")
	expires := fs.Duration("expires", 0, "how long the token or setup code works")
	hours := fs.Uint64("hours", admin.MaxRepairHours, "how long repair mode lasts, at most 72 hours")
	memberTokens := fs.String("member-tokens", "", "on or off: admins may mint registration tokens with invites")
	webDevices := fs.String("web-devices", "", "on or off: web and Home Assistant devices may be registered")
	webRanges := fs.String("web-tile-ranges", "", "on or off: web devices may read map regions in parts, which shows the server what they look at")
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
		wr, err := onOff(*webRanges)
		if err != nil {
			return err
		}
		method, in := "GET", any(nil)
		if mt != nil || wd != nil || wr != nil {
			method, in = "PATCH", map[string]any{"member_tokens": mt, "web_devices": wd, "web_tile_ranges": wr}
		}
		out, _, err := call(method, "/settings", in)
		if err != nil {
			return err
		}
		fmt.Printf("member tokens %v, web devices %v, web tile ranges %v, repair until %v\n", out["member_tokens"], out["web_devices"],
			out["web_tile_ranges"], when(out["repair_until"]))
	case cmd == "limits" && (len(sub) == 0 || len(sub) == 3 && sub[0] == "set" || len(sub) == 2 && sub[0] == "reset"):
		method, in := "GET", map[string]int(nil)
		if len(sub) > 0 {
			n := 0
			if sub[0] == "set" {
				var err error
				if n, err = strconv.Atoi(sub[2]); err != nil || n < 1 {
					return errors.New("a limit is a whole number from 1 to 1,000,000")
				}
			}
			method, in = "PATCH", map[string]int{sub[1]: n}
		}
		out, _, err := call(method, "/limits", in)
		if err != nil {
			return err
		}
		inForce, _ := out["in_force"].(map[string]any)
		set, _ := out["set"].(map[string]any)
		names := slices.Sorted(maps.Keys(inForce))
		for _, name := range names {
			mark := ""
			if _, ok := set[name]; ok {
				mark = "  (set)"
			}
			fmt.Printf("%-24s %v%s\n", name, inForce[name], mark)
		}
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
	case cmd == "backup" && len(sub) == 1:
		path, err := filepath.Abs(sub[0])
		if err != nil {
			return err
		}
		out, _, err := call("POST", "/backup", map[string]any{"file": path})
		if err != nil {
			return err
		}
		size, _ := out["size"].(float64)
		fmt.Printf("%v: %.1f MB, the database as of %v and the server's keys. Keep it as safe as the keys.\n", out["file"],
			size/1e6, when(out["at"]))
	case cmd == "status" && len(sub) == 0:
		out, _, err := call("GET", "/status", nil)
		if err != nil {
			return err
		}
		up, _ := out["uptime_ms"].(float64)
		fmt.Printf("up %v, clock synchronized: %v\n", time.Duration(up)*time.Millisecond, out["clock_synced"])
		if free, ok := out["free_disk"].(float64); ok {
			fmt.Printf("free disk: %.1f GB\n", free/1e9)
		}
		fmt.Printf("streams open: %v, pushes in flight: %v, link mailboxes: %v\n", out["streams"], out["pushes_in_flight"], out["link_mailboxes"])
		if r, ok := out["relay_reachable"].(bool); ok {
			fmt.Printf("relay reachable: %v\n", r)
		}
		fmt.Printf("repair mode until: %v\nlast backup: %v\n", when(out["repair_until"]), when(out["last_backup_at"]))
	case cmd == "accounts" && len(sub) == 0:
		_, list, err := call("GET", "/accounts", nil)
		if err != nil {
			return err
		}
		for _, a := range list {
			op := ""
			if a["operator"] == true {
				op = "  operator"
			}
			fmt.Printf("%v  %q  %v circles  since %v%s\n", a["account_id"], a["nickname"], a["circles"], a["created_day"], op)
			devices, _ := a["devices"].([]any)
			for _, d := range devices {
				m, _ := d.(map[string]any)
				kind, _ := m["kind"].(float64)
				fmt.Printf("    %v  %-14s %q  last seen %v\n", m["device_id"], kindNames[int(kind)], m["nickname"], m["last_seen_day"])
			}
		}
	case cmd == "circles" && len(sub) == 0:
		_, list, err := call("GET", "/circles", nil)
		if err != nil {
			return err
		}
		for _, c := range list {
			closed := ""
			if c["closed"] == true {
				closed = "  closed"
			}
			fmt.Printf("%v  %v members, %v devices, %v log entries, since %v%s\n", c["circle_id"], c["members"], c["devices"],
				c["entries"], c["created_day"], closed)
		}
	case (cmd == "account" || cmd == "device") && len(sub) == 3 && sub[0] == "nickname":
		_, _, err := call("PATCH", "/"+cmd+"s/"+neturl.PathEscape(sub[1]), map[string]any{"nickname": sub[2]})
		return err
	case (cmd == "account" || cmd == "device") && len(sub) == 2 && sub[0] == "remove":
		_, _, err := call("DELETE", "/"+cmd+"s/"+neturl.PathEscape(sub[1]), nil)
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

var kindNames = map[int]string{1: "phone", 2: "tablet", 3: "web", 4: "home assistant", 5: "recovery kit"}

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
