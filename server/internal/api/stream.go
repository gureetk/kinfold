// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// Message types on the stream (API.md §7): one byte, then the body.
const (
	msgRecord = 0x01
	msgCursor = 0x02
	msgLog    = 0x03
	msgPush   = 0x04
	msgEvent  = 0x05
	msgTime   = 0x06
)

// Close codes of the stream (API.md §7).
const (
	CloseRestarting   websocket.StatusCode = 4000
	CloseSessionEnded websocket.StatusCode = 4401
	CloseIdle         websocket.StatusCode = 4408
	CloseReplaced     websocket.StatusCode = 4409
	CloseRateLimited  websocket.StatusCode = 4429
)

var closeReasons = map[websocket.StatusCode]string{
	CloseRestarting:   "the server is restarting",
	CloseSessionEnded: "the session ended",
	CloseIdle:         "idle too long",
	CloseReplaced:     "replaced by a newer connection",
	CloseRateLimited:  "too many connections",
}

// StreamTimes are the stream's intervals, in real time. Zero values take the defaults.
type StreamTimes struct {
	Time  time.Duration // a time message at least this often: 15 minutes
	Idle  time.Duration // closed after nothing has come from the device for this long: 35 minutes
	Check time.Duration // how often idleness and the session are checked: a minute
	Write time.Duration // the longest one message may take to write: 30 seconds
}

func (t StreamTimes) withDefaults() StreamTimes {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&t.Time, 15*time.Minute)
	def(&t.Idle, 35*time.Minute)
	def(&t.Check, time.Minute)
	def(&t.Write, 30*time.Second)
	return t
}

// maxEvents is how many events and pushes may wait for a slow connection; later ones are
// dropped. Events are hints, each confirmed by a fetch.
const maxEvents = 64

// stream is a device's open WebSocket. Records aren't queued: a stream is woken and reads
// them from the store after its cursor, so it can't skip one, repeat one or fall behind
// in memory. Log frames keep only the latest per circle.
type stream struct {
	dev     store.Device
	session []byte // the session's hash
	expires uint64 // when the session ends, on the server's clock
	conn    *websocket.Conn
	heard   atomic.Int64 // when something last came from the device (Unix ms, real time)

	wake chan struct{} // records may be waiting
	note chan struct{} // log frames or events are waiting

	mu     sync.Mutex
	logs   map[string][]byte // by circle: its latest log frame not yet sent
	events [][]byte
	end    websocket.StatusCode // why the server ends the stream, once it does
	ended  chan struct{}
}

func newStream(dev store.Device, sess store.Session) *stream {
	st := &stream{dev: dev, session: sess.Hash, expires: sess.ExpiresAt, wake: make(chan struct{}, 1),
		note: make(chan struct{}, 1), logs: map[string][]byte{}, ended: make(chan struct{})}
	st.heard.Store(time.Now().UnixMilli())
	return st
}

func ring(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// close asks the stream to close with code. The first reason given wins.
func (st *stream) close(code websocket.StatusCode) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.end == 0 {
		st.end = code
		close(st.ended)
	}
}

func (st *stream) log(circle []byte, seq int64, head []byte) {
	st.mu.Lock()
	st.logs[string(circle)] = wire.Concat([]byte{msgLog}, circle, wire.U64(uint64(seq)), head)
	st.mu.Unlock()
	ring(st.note)
}

func (st *stream) event(ev map[string]any) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	st.queue(append([]byte{msgEvent}, b...))
}

// push queues a Push (PROTOCOL.md §14.2), signed but not sealed: a silence alert.
func (st *stream) push(p []byte) { st.queue(append([]byte{msgPush}, p...)) }

func (st *stream) queue(msg []byte) {
	st.mu.Lock()
	if len(st.events) < maxEvents {
		st.events = append(st.events, msg)
	}
	st.mu.Unlock()
	ring(st.note)
}

// notes takes the events, pushes and log frames waiting: events and pushes in order, then
// log frames by circle.
func (st *stream) notes() [][]byte {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := st.events
	st.events = nil
	logs := make([][]byte, 0, len(st.logs))
	for _, m := range st.logs {
		logs = append(logs, m)
	}
	clear(st.logs)
	slices.SortFunc(logs, bytes.Compare)
	return append(out, logs...)
}

// streams are the open streams, one per device.
type streams struct {
	mu      sync.Mutex
	open    map[string]*stream
	closing bool           // the server is shutting down: no new streams
	running sync.WaitGroup // streams that haven't finished
}

func newStreams() *streams { return &streams{open: map[string]*stream{}} }

// add registers st, and closes an older stream of the same device with 4409. It refuses
// while the server shuts down.
func (h *streams) add(st *stream) bool {
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		return false
	}
	old := h.open[string(st.dev.ID)]
	h.open[string(st.dev.ID)] = st
	h.running.Add(1)
	h.mu.Unlock()
	if old != nil {
		old.close(CloseReplaced)
	}
	return true
}

// remove forgets st, once it has finished.
func (h *streams) remove(st *stream) {
	h.mu.Lock()
	if h.open[string(st.dev.ID)] == st {
		delete(h.open, string(st.dev.ID))
	}
	h.mu.Unlock()
	h.running.Done()
}

func (h *streams) of(device []byte) *stream {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.open[string(device)]
}

func (h *streams) all() []*stream {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*stream, 0, len(h.open))
	for _, st := range h.open {
		out = append(out, st)
	}
	return out
}

// ---- what other calls tell the streams ----

// tellRecords wakes the streams of the devices an envelope was stored for.
func (s *Server) tellRecords(devices [][]byte) {
	for _, d := range devices {
		if st := s.streams.of(d); st != nil {
			ring(st.wake)
		}
	}
}

// tellLog sends a log frame to every active device of the circle after an append, and a
// removed event to each device the entry removed (API.md §6).
func (s *Server) tellLog(circle []byte, old, ns *memberlog.State) {
	for _, m := range ns.Members {
		for id := range m.Devices {
			if st := s.streams.of([]byte(id)); st != nil {
				st.log(circle, ns.Seq, ns.Head)
			}
		}
	}
	if old == nil {
		return
	}
	for _, m := range old.Members {
		for id := range m.Devices {
			if ns.Device([]byte(id)) != nil {
				continue
			}
			if st := s.streams.of([]byte(id)); st != nil {
				st.event(map[string]any{"type": "removed", "circle_id": b64(circle), "seq": ns.Seq})
			}
		}
	}
}

// tellDevices sends an event to the streams of the given devices.
func (s *Server) tellDevices(devices []store.Device, ev map[string]any) {
	for _, d := range devices {
		if st := s.streams.of(d.ID); st != nil {
			st.event(ev)
		}
	}
}

// endStream closes a device's stream because its session ended: all its sessions, or the
// one given.
func (s *Server) endStream(device, session []byte) {
	if st := s.streams.of(device); st != nil && (session == nil || bytes.Equal(st.session, session)) {
		st.close(CloseSessionEnded)
	}
}

// Notice sends every open stream a notice event: repair_mode, moving or restarting.
func (s *Server) Notice(code string) {
	for _, st := range s.streams.all() {
		st.event(map[string]any{"type": "notice", "code": code})
	}
}

// CloseStreams tells every stream the server is restarting, closes it with 4000, and
// waits up to the timeout for them to finish. New streams are closed with 4000 from then
// on. http.Server.Shutdown leaves upgraded connections alone: call this before it.
func (s *Server) CloseStreams(timeout time.Duration) {
	s.streams.mu.Lock()
	s.streams.closing = true
	s.streams.mu.Unlock()
	s.Notice("restarting")
	for _, st := range s.streams.all() {
		st.close(CloseRestarting)
	}
	done := make(chan struct{})
	go func() { s.streams.running.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// ---- the stream ----

// openStream is GET /v1/stream?since=: live delivery for a receiving device (API.md §7).
func (s *Server) openStream(q *request) error {
	since, err := cursorParam(q)
	if err != nil {
		return err
	}
	if !upgrading(q.r) {
		return badRequest("the stream is a WebSocket")
	}
	if err := s.cfg.Store.View(func(tx store.Tx) error { return s.session(q, tx, receiving) }); err != nil {
		return err
	}
	st := newStream(q.dev, q.sess)
	heard := func(context.Context, []byte) { st.heard.Store(time.Now().UnixMilli()) }
	conn, err := websocket.Accept(q.w, q.r, &websocket.AcceptOptions{
		OnPingReceived: func(ctx context.Context, p []byte) bool { heard(ctx, p); return true },
		OnPongReceived: heard,
	})
	if err != nil {
		return nil // Accept has answered
	}
	st.conn = conn
	l := s.limiter.limits
	if ok, _ := s.limiter.allow("stream/"+string(q.dev.ID), l.StreamsPerMinute, minute, q.now); !ok {
		conn.Close(CloseRateLimited, closeReasons[CloseRateLimited])
		return nil
	}
	if !s.streams.add(st) {
		conn.Close(CloseRestarting, closeReasons[CloseRestarting])
		return nil
	}
	defer s.streams.remove(st)
	s.runStream(st, since)
	return nil
}

// upgrading says whether a request asks for a WebSocket.
func upgrading(r *http.Request) bool {
	for _, v := range r.Header.Values("Upgrade") {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), "websocket") {
				return true
			}
		}
	}
	return false
}

// cursorParam reads since, the cursor of a previous inbox page or stream.
func cursorParam(q *request) (uint64, error) {
	v := q.r.URL.Query().Get("since")
	if v == "" {
		return 0, nil
	}
	c, err := wire.DecodeB64u(v)
	if err != nil || len(c) != 8 {
		return 0, badRequest("bad cursor")
	}
	return wire.NewReader(c).U64(), nil
}

func cursorText(seq uint64) string { return wire.EncodeB64u(wire.U64(seq)) }

// runStream sends the time, what waits after the cursor and a cursor, then whatever comes,
// until the stream ends.
func (s *Server) runStream(st *stream, cursor uint64) {
	t := s.cfg.Stream
	ctx := st.conn.CloseRead(context.Background()) // answers pings; a message from the device closes it
	write := func(msg []byte) error {
		wctx, cancel := context.WithTimeout(ctx, t.Write)
		defer cancel()
		return st.conn.Write(wctx, websocket.MessageBinary, msg)
	}
	sendTime := func() error { return write(wire.Concat([]byte{msgTime}, wire.U64(s.cfg.Clock.Now()))) }
	// records sends every record after the cursor, then a cursor if it sent any, or always.
	records := func(always bool) error {
		sent := false
		for {
			envs, more, err := s.waitingRecords(st.dev, cursor)
			if err != nil {
				return err
			}
			for _, e := range envs {
				if err := write(wire.Concat([]byte{msgRecord}, wire.U64(e.ReceivedAt), e.Raw)); err != nil {
					return err
				}
				cursor, sent = e.Seq, true
			}
			if !more {
				break
			}
		}
		if !sent && !always {
			return nil
		}
		return write(append([]byte{msgCursor}, cursorText(cursor)...))
	}
	notes := func() error {
		for _, m := range st.notes() {
			if err := write(m); err != nil {
				return err
			}
		}
		return nil
	}

	if err := errors.Join(sendTime(), records(true)); err != nil {
		st.conn.CloseNow()
		return
	}
	clock := time.NewTicker(t.Time)
	defer clock.Stop()
	check := time.NewTicker(t.Check)
	defer check.Stop()
	for {
		var err error
		select {
		case <-ctx.Done(): // the device closed it, or it broke
			st.conn.CloseNow()
			return
		case <-st.ended:
			notes() // a notice before a restart, if it can still go
			st.conn.Close(st.end, closeReasons[st.end])
			return
		case <-st.wake:
			err = records(false)
		case <-st.note:
			err = notes()
		case <-clock.C:
			err = sendTime()
		case <-check.C:
			if time.Since(time.UnixMilli(st.heard.Load())) >= t.Idle {
				st.close(CloseIdle)
			} else if !s.sessionLive(st) {
				st.close(CloseSessionEnded)
			}
		}
		if err != nil {
			st.conn.CloseNow()
			return
		}
	}
}

// waitingRecords reads a page of the device's records after the cursor.
func (s *Server) waitingRecords(dev store.Device, after uint64) (envs []store.Envelope, more bool, err error) {
	err = s.cfg.Store.View(func(tx store.Tx) error {
		circles, err := activeCircles(tx, dev)
		if err != nil {
			return err
		}
		envs, more, err = tx.Inbox(dev.ID, circles, after, maxInboxPage, maxPageBytes, s.cfg.Clock.Now())
		return err
	})
	return envs, more, err
}

// sessionLive says whether the stream's session still stands. A store that can't answer
// leaves it open.
func (s *Server) sessionLive(st *stream) bool {
	now := s.cfg.Clock.Now()
	if now >= st.expires {
		return false
	}
	live := true
	s.cfg.Store.View(func(tx store.Tx) error {
		if _, err := tx.Session(st.session); errors.Is(err, store.ErrNotFound) {
			live = false
		}
		return nil
	})
	return live
}
