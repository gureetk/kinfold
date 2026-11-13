// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api serves the Kinfold HTTP API (spec/API.md): discovery, accounts, devices and
// login, circles and the member log, envelopes and the inbox, and invites. The protocol
// rules themselves are in the protocol packages; this package decides who may call what,
// keeps what the server stores, and maps refusals onto the API's errors.
package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gureetk/kinfold/server/internal/clock"
	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/tiles"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// API revisions this server speaks (API.md §1).
const (
	APIMin = 1
	APIMax = 1
)

// Durations in milliseconds.
const (
	second = 1000
	minute = 60 * second
	hour   = 60 * minute
	day    = 24 * hour

	ChallengeLife   = 60 * second
	SessionLife     = 24 * hour
	InfoLife        = 7 * day
	InviteMaxLife   = 7 * day
	ResultKeep      = 24 * hour
	RemovedReadLife = 30 * day
	ClosedKeep      = 30 * day // a closed circle, after its last member leaves
	RepairMaxLife   = 72 * hour
	SeenKeep        = 32 * day
	MaxWaitSeconds  = 25
)

// Body limits (API.md §3).
const (
	maxJSON       = 16 << 10
	maxRegister   = 4 << 10
	maxJoin       = 4 << 10
	maxPageBytes  = 4 << 20
	maxLogPage    = 1024
	maxInboxPage  = 256
	maxIdentity   = identity.LinkLen
	maxDeviceBody = 1 << 10
)

// Config is what a Server needs.
type Config struct {
	URL   string             // server_url: https, no trailing slash
	Key   ed25519.PrivateKey // the server key (PROTOCOL.md §13)
	Clock clock.Clock
	Store store.Store
	// Limits are the rate limits; zero values take the defaults of API.md §3.
	Limits Limits
	// Random is the source of challenges, tokens and session tokens; crypto/rand if nil.
	Random io.Reader
	// Stream sets the stream's intervals; zero values take the defaults of API.md §7.
	Stream StreamTimes
	// Push is how the server reaches push hosts (API.md §12).
	Push PushConfig
	// Tiles are the map files on offer (API.md §13); none if nil.
	Tiles *tiles.Library
	// Search is the search add-on's base URL, a Photon instance (API.md §13); no search if
	// empty.
	Search string
	// DataDir is where the server keeps its files, for the free space it reports; none if
	// empty.
	DataDir string
}

// Server is the HTTP API.
type Server struct {
	cfg      Config
	mux      *http.ServeMux
	limiter  *limiter
	waits    *hub
	streams  *streams
	links    *mailboxes
	sending  chan struct{} // pushes in flight
	webPush  *http.Client
	searcher *http.Client
	start    uint64

	infoMu sync.Mutex
	info   []byte
	infoAt uint64
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	cfg.Stream = cfg.Stream.withDefaults()
	cfg.Push = cfg.Push.withDefaults()
	s := &Server{cfg: cfg, mux: http.NewServeMux(), limiter: newLimiter(cfg.Limits.withDefaults()), waits: newHub(),
		streams: newStreams(), links: newMailboxes(), sending: make(chan struct{}, maxSending), start: cfg.Clock.Now()}
	s.webPush, s.searcher = s.webPushClient(), searchClient()
	s.routes()
	return s
}

// ServerKey is the server's public key.
func (s *Server) ServerKey() ed25519.PublicKey { return s.cfg.Key.Public().(ed25519.PublicKey) }

// Retention is how long the server keeps what has ended (API.md §15).
var Retention = store.Retention{Removals: RemovedReadLife, Results: ResultKeep, ClosedCircles: ClosedKeep}

// Sweep deletes what has run out (API.md §15). The server runs it every minute.
func (s *Server) Sweep() (store.Swept, error) {
	var n store.Swept
	err := s.cfg.Store.Update(func(tx store.Tx) (err error) {
		n, err = tx.Sweep(s.cfg.Clock.Now(), Retention)
		return err
	})
	return n, err
}

func (s *Server) routes() {
	h := func(pattern string, fn func(*request) error) {
		s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { s.serve(w, r, fn) })
	}
	h("GET /.well-known/kinfold", s.discovery)
	h("GET /healthz", s.healthz)
	h("GET /v1/server/status", s.status)

	h("POST /v1/accounts", s.register)
	h("DELETE /v1/accounts/me", s.deleteAccount)
	h("POST /v1/accounts/me/identity", s.rotateIdentity)
	h("GET /v1/devices", s.listDevices)
	h("POST /v1/devices", s.addDevice)
	h("DELETE /v1/devices/{device_id}", s.deleteDevice)
	h("GET /v1/circles", s.listCircles)
	h("POST /v1/auth/challenge", s.challenge)
	h("POST /v1/auth/session", s.login)
	h("DELETE /v1/auth/session", s.logout)

	h("POST /v1/circles", s.createCircle)
	h("GET /v1/circles/{id}/head", s.head)
	h("GET /v1/circles/{id}/log", s.readLog)
	h("POST /v1/circles/{id}/log", s.appendEntry)
	h("POST /v1/circles/{id}/log/repair", s.repairEntry)

	h("POST /v1/circles/{id}/envelopes", s.postEnvelope)
	h("GET /v1/inbox", s.inbox)
	h("GET /v1/stream", s.openStream)
	h("PUT /v1/push", s.putPush)
	h("DELETE /v1/push", s.deletePush)

	h("GET /v1/tiles", s.listTiles)
	h("GET /tiles/{file}", s.tileFile)
	h("POST /v1/search", s.search)

	h("PUT /v1/circles/{id}/watches/{device_id}", s.putWatch)
	h("GET /v1/circles/{id}/watches", s.listWatches)
	h("DELETE /v1/circles/{id}/watches/{device_id}", s.deleteWatch)

	h("POST /v1/links", s.createLink)
	h("PUT /v1/links/{link_id}/{slot}", s.putLinkSlot)
	h("GET /v1/links/{link_id}/{slot}", s.getLinkSlot)

	h("POST /v1/shares", s.createShare)
	h("POST /v1/shares/{link_id}/updates", s.postShareUpdate)
	h("GET /v1/shares/{link_id}", s.getShare)
	h("DELETE /v1/shares/{link_id}", s.deleteShare)
	h("GET /v1/shares/{link_id}/latest", s.latestShare)
	h("GET /s/{link_id}", s.viewerPage)
	h("GET /assets/{name}", s.viewerAsset)

	h("POST /v1/invites", s.createInvite)
	h("POST /v1/invites/{invite_id}/requests", s.postJoinRequest)
	h("GET /v1/invites/{invite_id}/requests", s.joinRequests)
	h("PUT /v1/invites/{invite_id}/result", s.putJoinResult)
	h("GET /v1/invites/{invite_id}/result", s.joinResult)
	h("DELETE /v1/invites/{invite_id}", s.deleteInvite)

	h("/", func(*request) error { return errNotFound })
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// ---- the request pipeline ----

// request is one call, with what the pipeline learned about it.
type request struct {
	w   http.ResponseWriter
	r   *http.Request
	now uint64
	// set by session()
	sess store.Session
	dev  store.Device
	// what happens once the transaction commits (see update)
	later []func()
}

// afterCommit asks for f to run once the transaction in progress has committed.
func (q *request) afterCommit(f func()) { q.later = append(q.later, f) }

// update runs fn in a write transaction, and then what fn asked to happen after it, only
// if it committed.
func (s *Server) update(q *request, fn func(store.Tx) error) error {
	q.later = nil
	err := s.cfg.Store.Update(fn)
	later := q.later
	q.later = nil
	if err != nil {
		return err
	}
	for _, f := range later {
		f()
	}
	return nil
}

// serve runs the checks every call shares (API.md §1, §2), then fn.
func (s *Server) serve(w http.ResponseWriter, r *http.Request, fn func(*request) error) {
	now := s.cfg.Clock.Now()
	w.Header().Set("Kinfold-Time", strconv.FormatUint(now, 10))
	w.Header().Set("Cache-Control", "no-store")
	req := &request{w: w, r: r, now: now}
	err := func() error {
		if r.URL.Path != "/healthz" && !s.cfg.Clock.Synced() {
			return &apiError{status: http.StatusServiceUnavailable, code: "unavailable", msg: "the server's clock isn't synchronized"}
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			if err := checkRevision(r); err != nil {
				return err
			}
		}
		return fn(req)
	}()
	if err != nil {
		writeError(w, err)
	}
}

func checkRevision(r *http.Request) error {
	v := r.Header.Get("Kinfold-Api")
	n, err := strconv.Atoi(v)
	switch {
	case v == "" || err != nil:
		return badRequest("send the API revision in Kinfold-Api")
	case n < APIMin:
		return &apiError{status: http.StatusUpgradeRequired, code: "update_required", msg: "this API revision is no longer served",
			extra: map[string]any{"api_min": APIMin}}
	case n > APIMax:
		return badRequest("this server speaks API revisions up to " + strconv.Itoa(APIMax))
	}
	return nil
}

// ---- errors (API.md §2) ----

type apiError struct {
	status     int
	code       string
	msg        string
	extra      map[string]any
	retryAfter int // seconds
}

func (e *apiError) Error() string { return e.code + ": " + e.msg }

var (
	errNotFound     = &apiError{status: http.StatusNotFound, code: "not_found", msg: "no such thing"}
	errUnauthorized = &apiError{status: http.StatusUnauthorized, code: "unauthorized", msg: "log in again"}
	errForbidden    = &apiError{status: http.StatusForbidden, code: "forbidden", msg: "this device or account may not make this call"}
	errGone         = &apiError{status: http.StatusGone, code: "gone", msg: "it has ended"}
)

func badRequest(msg string) *apiError {
	return &apiError{status: http.StatusBadRequest, code: "bad_request", msg: msg}
}

func tooLarge() *apiError {
	return &apiError{status: http.StatusRequestEntityTooLarge, code: "too_large", msg: "the body is over this endpoint's limit"}
}

func rateLimited(retryAfter int) *apiError {
	return &apiError{status: http.StatusTooManyRequests, code: "rate_limited", msg: "too many requests", retryAfter: max(retryAfter, 1)}
}

// refused is 422 with a reason code of PROTOCOL.md §16.5.
func refused(reason string, extra map[string]any) *apiError {
	return &apiError{status: http.StatusUnprocessableEntity, code: reason, msg: "the object was refused", extra: extra}
}

func writeError(w http.ResponseWriter, err error) {
	e, body := errorBody(err)
	if e.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.retryAfter))
	}
	writeJSON(w, e.status, body)
}

// errorBody is the JSON an error is answered with (API.md §2).
func errorBody(err error) (*apiError, map[string]any) {
	var e *apiError
	if !errors.As(err, &e) {
		// Nothing about the request is logged (API.md §1); the error text is generic.
		e = &apiError{status: http.StatusInternalServerError, code: "internal", msg: "the server failed"}
	}
	body := map[string]any{"error": e.code, "message": e.msg}
	for k, v := range e.extra {
		body[k] = v
	}
	return e, body
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeBytes(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	w.Write(b)
}

// ---- bodies ----

// body reads a protocol object or a list of frames (application/octet-stream).
func (q *request) body(limit int) ([]byte, error) {
	if ct := q.r.Header.Get("Content-Type"); ct != "application/octet-stream" {
		return nil, badRequest("send application/octet-stream")
	}
	return q.read(limit)
}

func (q *request) read(limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(q.r.Body, int64(limit)+1))
	if err != nil {
		return nil, badRequest("unreadable body")
	}
	if len(b) > limit {
		return nil, tooLarge()
	}
	return b, nil
}

// json reads a JSON body into v. Unknown fields are ignored.
func (q *request) json(v any) error {
	if ct := q.r.Header.Get("Content-Type"); ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
		return badRequest("send application/json")
	}
	b, err := q.read(maxJSON)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return badRequest("unreadable JSON")
	}
	return nil
}

// b64 is a base64url field of a JSON body.
type b64 []byte

func (b *b64) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, err := wire.DecodeB64u(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

func (b b64) MarshalJSON() ([]byte, error) { return json.Marshal(wire.EncodeB64u(b)) }

// pathID reads a base64url ID from the path: 16 bytes.
func (q *request) pathID(name string) ([]byte, error) {
	id, err := wire.DecodeB64u(q.r.PathValue(name))
	if err != nil || len(id) != 16 {
		return nil, badRequest("bad " + name)
	}
	return id, nil
}

// ---- sessions (API.md §1, §5) ----

// Who may call (API.md §1).
const (
	anyDevice  = iota // any
	phone             // P: a phone or tablet
	receiving         // R: phone, tablet, web or Home Assistant
	phoneOrKit        // P+K: a phone or tablet, or the account's recovery device
	phoneOrWeb        // a phone or tablet, or a web device
)

func allowed(kind uint8, who int) bool {
	switch who {
	case phone:
		return identity.PhoneOrTablet(kind)
	case receiving:
		return identity.Receiving(kind)
	case phoneOrKit:
		return identity.PhoneOrTablet(kind) || kind == identity.Recovery
	case phoneOrWeb:
		return identity.PhoneOrTablet(kind) || kind == identity.Web
	}
	return true
}

func hashToken(token []byte) []byte { h := sha256.Sum256(token); return h[:] }

// session authenticates the call and checks the kind of device it comes from.
func (s *Server) session(q *request, tx store.Tx, who int) error {
	auth := q.r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return errUnauthorized
	}
	token, err := wire.DecodeB64u(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		return errUnauthorized
	}
	sess, err := tx.Session(hashToken(token))
	if err != nil || q.now >= sess.ExpiresAt {
		return errUnauthorized
	}
	dev, err := tx.Device(sess.Device)
	if err != nil {
		return errUnauthorized
	}
	if !allowed(dev.Kind, who) {
		return errForbidden
	}
	q.sess, q.dev = sess, dev
	return nil
}

// random returns n random bytes.
func (s *Server) random(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.cfg.Random, b); err != nil {
		panic("api: no randomness: " + err.Error())
	}
	return b
}

// ---- rate limits (API.md §3) ----

// Limits are the operator's rate limits.
type Limits struct {
	ChallengesPerDevice  int `json:"challenges_per_device,omitempty"`  // a minute
	ChallengesPerAddress int `json:"challenges_per_address,omitempty"` // a minute
	AppendsPerDevice     int `json:"appends_per_device,omitempty"`     // an hour
	AppendsPerCircle     int `json:"appends_per_circle,omitempty"`     // a day
	EnvelopesPerMinute   int `json:"envelopes_per_minute,omitempty"`   // per device
	EnvelopesPerHour     int `json:"envelopes_per_hour,omitempty"`     // per device
	StreamsPerMinute     int `json:"streams_per_minute,omitempty"`     // connections, per device
	WakeNotify           int `json:"wake_notify,omitempty"`            // uploads with Kinfold-Wake: notify, an hour per device
	WakeLocate           int `json:"wake_locate,omitempty"`            // uploads with Kinfold-Wake: locate, an hour per sender and recipient
	LinksPerDevice       int `json:"links_per_device,omitempty"`       // link mailboxes an hour, per device (direction 1)
	LinksPerAddress      int `json:"links_per_address,omitempty"`      // link mailboxes an hour without a session, per address (direction 2)
	LinksPerServer       int `json:"links_per_server,omitempty"`       // link mailboxes an hour without a session, for the whole server
	SharesPerDevice      int `json:"shares_per_device,omitempty"`      // share links open at once, per device
	SearchPerMinute      int `json:"search_per_minute,omitempty"`      // searches, per device
	PendingInvites       int `json:"pending_invites,omitempty"`        // per circle
	WaitingRequests      int `json:"waiting_requests,omitempty"`       // per invite
}

func (l Limits) withDefaults() Limits {
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	def(&l.ChallengesPerDevice, 10)
	def(&l.ChallengesPerAddress, 60)
	def(&l.AppendsPerDevice, 30)
	def(&l.AppendsPerCircle, 500)
	def(&l.EnvelopesPerMinute, 20)
	def(&l.EnvelopesPerHour, 600)
	def(&l.StreamsPerMinute, 10)
	def(&l.WakeNotify, 60)
	def(&l.WakeLocate, 6)
	def(&l.LinksPerDevice, 20)
	def(&l.LinksPerAddress, 6)
	def(&l.LinksPerServer, 60)
	def(&l.SharesPerDevice, 5)
	def(&l.SearchPerMinute, 30)
	def(&l.PendingInvites, 16)
	def(&l.WaitingRequests, 3)
	return l
}

// limiter counts calls in fixed windows. It forgets everything on restart, which only
// ever lets a little more through.
type limiter struct {
	mu     sync.Mutex
	limits Limits
	count  map[string]window
	sweep  int // the number of windows at which closed ones are next swept away
}

type window struct {
	end uint64 // when the window closes
	n   int
}

// minSweep is the fewest windows the limiter keeps before it sweeps.
const minSweep = 4096

func newLimiter(l Limits) *limiter {
	return &limiter{limits: l, count: map[string]window{}, sweep: minSweep}
}

// limits are the rate limits in force.
func (s *Server) limits() Limits {
	s.limiter.mu.Lock()
	defer s.limiter.mu.Unlock()
	return s.limiter.limits
}

// Limits are the rate limits in force (API.md §3).
func (s *Server) Limits() Limits { return s.limits() }

// DefaultLimits are the rate limits of API.md §3.
func DefaultLimits() Limits { return Limits{}.withDefaults() }

// SetLimits puts new rate limits in force at once; zero values take the defaults. Counts
// already made in the current windows stand.
func (s *Server) SetLimits(l Limits) {
	l = l.withDefaults()
	s.limiter.mu.Lock()
	s.limiter.limits = l
	s.limiter.mu.Unlock()
}

// allow counts one call for key in a window of the given length, and returns the seconds
// to wait when the limit is reached.
func (l *limiter) allow(key string, limit int, length, now uint64) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Closed windows are swept away whenever the map has doubled since the last sweep, so
	// the cost of sweeping stays in proportion to the calls that filled it.
	if len(l.count) >= l.sweep {
		for k, w := range l.count {
			if now >= w.end {
				delete(l.count, k)
			}
		}
		l.sweep = max(minSweep, 2*len(l.count))
	}
	w := l.count[key]
	if now >= w.end {
		w = window{end: now - now%length + length}
	}
	if w.n >= limit {
		return false, int((w.end - now + 999) / 1000)
	}
	w.n++
	l.count[key] = w
	return true, 0
}

// ---- waiting for a result (API.md §9) ----

// hub wakes calls that wait for something to be written.
type hub struct {
	mu sync.Mutex
	ch map[string]chan struct{}
}

func newHub() *hub { return &hub{ch: map[string]chan struct{}{}} }

func (h *hub) wait(key string) <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.ch[key]
	if !ok {
		c = make(chan struct{})
		h.ch[key] = c
	}
	return c
}

func (h *hub) wake(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.ch[key]; ok {
		close(c)
		delete(h.ch, key)
	}
}
