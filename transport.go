package suritap

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Dir is the direction of payload relative to the proxied connection.
type Dir uint8

const (
	ToServer Dir = 0
	ToClient Dir = 1
)

// Action is the outcome of a verdict.
type Action uint8

const (
	Pass  Action = 0
	Drop  Action = 1
	Error Action = 2 // no verdict could be computed
)

// Meta tags (suritap protocol, logged in EVE under "suritap").
const (
	MetaSNI       uint8 = 1
	MetaALPN      uint8 = 2
	MetaRoute     uint8 = 4
	MetaRequestID uint8 = 5
	MetaEndpoint  uint8 = 6
	MetaProto     uint8 = 9
	MetaProxy     uint8 = 10
)

// Meta is one metadata item of a connection.
type Meta struct {
	Tag   uint8
	Value string
}

// Addr is an IP address and port.
type Addr struct {
	IP   net.IP
	Port int
}

// Verdict answers an Inspect call.
type Verdict struct {
	Action Action
	Reason uint8
	SIDs   []uint32
}

var reasonNames = []string{"none", "rule", "policy", "flow", "unknown-flow", "protocol", "engine"}

// ReasonString names a verdict reason.
func (v Verdict) ReasonString() string {
	if int(v.Reason) < len(reasonNames) {
		return reasonNames[v.Reason]
	}
	return strconv.Itoa(int(v.Reason))
}

// Transport carries connections to Suricata. The plugin uses the socket
// transport (StreamTransport); a natively compiled proxy may plug in the
// shared-memory client instead.
type Transport interface {
	// Open announces a connection; ctx bounds waiting for Suricata.
	Open(ctx context.Context, src, dst Addr, meta []Meta) (Conn, error)
	// EndpointMode returns the operator's mode for an endpoint from the
	// plugin's endpoint policy; false when the policy does not list it (or
	// none was received yet), and the middleware's own setting applies.
	EndpointMode(endpoint string) (EndpointMode, bool)
	Close() error
}

// EndpointMode is an endpoint's inspection mode set by the operator
// (suri-controller → suri-node-agent → suritap plugin → clients).
type EndpointMode uint8

const (
	ModeOff     EndpointMode = 1 // not inspected
	ModeDetect  EndpointMode = 2 // inspected without waiting; never blocked
	ModePrevent EndpointMode = 3 // drop verdicts block
)

// Conn is one inspected connection (one HTTP request for the HTTP tap).
type Conn interface {
	CID() uint64
	// Send streams payload without waiting (detect).
	Send(ctx context.Context, dir Dir, data []byte) error
	// Inspect sends payload and waits for the verdict covering everything
	// sent so far in dir, until ctx is done.
	Inspect(ctx context.Context, dir Dir, data []byte) (Verdict, error)
	Close(reset bool) error
}

// ErrUnavailable is returned while Suricata cannot be reached.
var ErrUnavailable = errors.New("suritap: Suricata unavailable")

// Wire protocol (see docs/suritap.md): 64-byte HELLO/WELCOME, then frames
// "len:u32 kind:u16 flags:u16 body", little-endian.
const (
	protoMagic     = 0x50415453
	protoVersion   = 1
	helloSize      = 64
	frameHeader    = 8
	kOpen          = 1
	kData          = 2
	kGap           = 3
	kClose         = 5
	kVerdict       = 0x81
	kPong          = 0x83
	kPolicy        = 0x85
	fWantVerdict   = 1
	openFixed      = 56
	dataFixed      = 16
	verdictFixed   = 24
	alertSize      = 16
	maxMeta        = 2048
	maxInflight    = 1024
	defaultPayload = 64 * 1024
)

// Timing of the socket transport (variables for tests).
var (
	// dialTimeout bounds connecting and the HELLO/WELCOME exchange.
	dialTimeout = 2 * time.Second
	// retryDelay is how long a worker whose session could not be opened
	// is reported unavailable before the next attempt.
	retryDelay = time.Second
	// writeStall bounds one frame write. Frames are never abandoned
	// halfway (that would break the stream), so a request's verdict
	// timeout applies between frames only; a server that takes longer
	// than this to accept a frame is considered stuck and the session is
	// torn down.
	writeStall = 5 * time.Second
	// stuckAfter: a session with abandoned verdict requests and no verdict
	// at all for this long is considered stuck and torn down.
	stuckAfter = 5 * time.Second
	// idleTimeout closes sessions without traffic, so sessions of
	// configurations Traefik no longer uses do not linger (plugins get no
	// close callback); they are re-opened on demand.
	idleTimeout = 5 * time.Minute
)

// StreamTransport talks to the suritap plugin over its socket transport
// (worker-N.stream.sock). It uses only the Go standard library, so it runs
// inside Traefik's Yaegi interpreter.
type StreamTransport struct {
	dir  string
	name string

	mu       sync.Mutex
	sessions []*streamSession // per worker; nil until the worker count is known
	dialing  []bool           // per worker: a session is being opened
	probing  bool             // opening worker 0 to learn the worker count
	layout   int              // incremented whenever sessions is replaced
	retryAt  time.Time
	nextCID  uint64
	closed   bool
	// policy is the last endpoint policy received (kept across
	// reconnects); replaced, never modified. Compiled value type only (see
	// streamSession).
	policy map[string]uint8
	// Requests waiting for a session being opened. Woken (one value each,
	// buffered) whenever an attempt ends; plain channels and
	// context.AfterFunc instead of select, see streamSession.
	waiters []chan struct{}
}

// NewStreamTransport creates a transport for the sockets in dir; sessions
// are opened on first use and re-opened after failures.
func NewStreamTransport(dir, name string) *StreamTransport {
	return &StreamTransport{dir: dir, name: name, nextCID: uint64(time.Now().UnixNano()) << 8}
}

func streamPath(dir string, i int) string {
	return filepath.Join(dir, "worker-"+strconv.Itoa(i)+".stream.sock")
}

func mix(x uint64) uint64 {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	return x ^ x>>33
}

// session allocates a connection id and returns a live session for it.
// Sessions are opened without holding t.mu, so a worker that does not
// answer never blocks requests for the others; requests for a worker whose
// session is being opened wait for it until ctx is done.
func (t *StreamTransport) session(ctx context.Context) (uint64, *streamSession, error) {
	t.mu.Lock()
	t.nextCID++
	cid := t.nextCID
	var idx, layout int
	for {
		if t.closed {
			t.mu.Unlock()
			return cid, nil, ErrUnavailable
		}
		idx = 0
		busy := t.probing
		if len(t.sessions) > 0 {
			idx = int(mix(cid) % uint64(len(t.sessions)))
			if s := t.sessions[idx]; s != nil && !s.isDead() {
				t.mu.Unlock()
				return cid, s, nil
			}
			busy = t.dialing[idx]
		}
		if !busy {
			break
		}
		ch := make(chan struct{}, 2)
		t.waiters = append(t.waiters, ch)
		t.mu.Unlock()
		stop := context.AfterFunc(ctx, func() { ch <- struct{}{} })
		<-ch
		stop()
		if ctx.Err() != nil {
			return cid, nil, ErrUnavailable
		}
		t.mu.Lock()
	}
	if time.Now().Before(t.retryAt) {
		t.mu.Unlock()
		return cid, nil, ErrUnavailable
	}
	if len(t.sessions) > 0 {
		t.dialing[idx] = true
	} else {
		t.probing = true
	}
	layout = t.layout
	t.mu.Unlock()

	s, err := dialStream(streamPath(t.dir, idx), t.name, t)

	t.mu.Lock()
	defer t.mu.Unlock()
	if layout == t.layout && idx < len(t.dialing) {
		t.dialing[idx] = false
	}
	if t.sessions == nil {
		t.probing = false
	}
	// Index loops: Yaegi mixes up the range operand with other locals of
	// this function (reflect: call of Value.Len on int Value).
	for i := 0; i < len(t.waiters); i++ {
		t.waiters[i] <- struct{}{}
	}
	t.waiters = nil
	if err != nil {
		t.retryAt = time.Now().Add(retryDelay)
		return cid, nil, err
	}
	if t.closed {
		s.fail(errors.New("suritap: transport closed"))
		return cid, nil, ErrUnavailable
	}
	if err := t.install(s); err != nil {
		return cid, nil, err
	}
	// Any worker may take a new connection; idx only spreads the load.
	return cid, s, nil
}

// install records a new session. A worker count different from the known
// one means Suricata restarted with another configuration: the old
// sessions are torn down and the layout is rebuilt. Called with t.mu held.
func (t *StreamTransport) install(s *streamSession) error {
	if s.workers != len(t.sessions) {
		for i := 0; i < len(t.sessions); i++ {
			if t.sessions[i] != nil {
				t.sessions[i].fail(errors.New("suritap: worker layout changed"))
			}
		}
		t.sessions = make([]*streamSession, s.workers)
		t.dialing = make([]bool, s.workers)
		t.layout++
	}
	if s.worker >= len(t.sessions) {
		s.fail(errors.New("suritap: bad worker index"))
		return ErrUnavailable
	}
	if old := t.sessions[s.worker]; old != nil && old != s {
		old.fail(errors.New("suritap: session replaced"))
	}
	t.sessions[s.worker] = s
	return nil
}

// Open announces a new connection.
func (t *StreamTransport) Open(ctx context.Context, src, dst Addr, meta []Meta) (Conn, error) {
	cid, s, err := t.session(ctx)
	if err != nil {
		return nil, err
	}
	body, err := encodeOpen(cid, src, dst, meta)
	if err != nil {
		return nil, err
	}
	if err := s.write(frameHead(kOpen, 0, len(body)), body); err != nil {
		return nil, err
	}
	return &streamConn{s: s, cid: cid}, nil
}

func (t *StreamTransport) setPolicy(p map[string]uint8) {
	t.mu.Lock()
	t.policy = p
	t.mu.Unlock()
}

// EndpointMode implements Transport. Without a live session it opens one in
// the background, so that policy changes keep arriving even when every
// request is skipped (endpoint off).
func (t *StreamTransport) EndpointMode(endpoint string) (EndpointMode, bool) {
	t.mu.Lock()
	m, ok := t.policy[endpoint]
	live := false
	for i := 0; i < len(t.sessions); i++ {
		if t.sessions[i] != nil && !t.sessions[i].isDead() {
			live = true
			break
		}
	}
	probe := !live && !t.closed && !t.probing && time.Now().After(t.retryAt)
	t.mu.Unlock()
	if probe {
		go t.probe()
	}
	return EndpointMode(m), ok
}

func (t *StreamTransport) probe() {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	_, _, _ = t.session(ctx)
}

// decodePolicy parses a POLICY body: version:u32 count:u16 rsv:u16, then
// per endpoint mode:u8 len:u8 name[len].
func decodePolicy(b []byte) (map[string]uint8, bool) {
	if len(b) < 8 {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint16(b[4:]))
	p := make(map[string]uint8, n)
	off := 8
	for i := 0; i < n; i++ {
		if off+2 > len(b) {
			return nil, false
		}
		m, l := b[off], int(b[off+1])
		off += 2
		if off+l > len(b) || m < uint8(ModeOff) || m > uint8(ModePrevent) {
			return nil, false
		}
		p[string(b[off:off+l])] = m
		off += l
	}
	return p, true
}

// Close closes all sessions; the transport cannot be used afterwards.
func (t *StreamTransport) Close() error {
	t.mu.Lock()
	sessions := t.sessions
	t.sessions = nil
	t.dialing = nil
	t.closed = true
	t.layout++
	t.mu.Unlock()
	for _, s := range sessions {
		if s != nil {
			s.fail(errors.New("suritap: transport closed"))
		}
	}
	return nil
}

type streamSession struct {
	owner      *StreamTransport // receives POLICY records
	conn       net.Conn
	worker     int
	workers    int
	maxPayload int

	wmu sync.Mutex // serializes frame writes

	// Outstanding verdict requests live in fixed slots (token =
	// generation<<10 | slot); the free list bounds them to the server's
	// in-flight limit. A slot is released when its verdict arrives, also
	// after the waiter gave up (abandoned). Waiters receive the raw VERDICT
	// body, nil when the session failed or an empty slice when cancelled.
	//
	// Written for Yaegi (v0.16): only compiled types are stored, since
	// collections of channels of interpreted types crash it; there is no
	// select statement on concurrent paths, since all goroutines running
	// one select statement share its case list; and no sync/atomic on
	// fields.
	pmu         sync.Mutex // guards everything below
	slots       []chan []byte
	gens        []uint32
	free        []int
	abandoned   int       // reserved slots whose waiter gave up
	lastVerdict time.Time // last verdict received (or session start)
	lastUse     time.Time // last frame written
	dead        bool
}

func dialStream(path, name string, owner *StreamTransport) (*streamSession, error) {
	c, err := net.DialTimeout("unix", path, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("suritap: %v", err)
	}
	hello := make([]byte, helloSize)
	binary.LittleEndian.PutUint32(hello[0:], protoMagic)
	binary.LittleEndian.PutUint16(hello[4:], protoVersion)
	binary.LittleEndian.PutUint16(hello[6:], helloSize)
	binary.LittleEndian.PutUint32(hello[8:], uint32(os.Getpid()))
	binary.LittleEndian.PutUint32(hello[12:], 1) // socket transport
	copy(hello[16:48], name)
	_ = c.SetDeadline(time.Now().Add(dialTimeout))
	if _, err := c.Write(hello); err != nil {
		c.Close()
		return nil, fmt.Errorf("suritap: hello: %v", err)
	}
	w := make([]byte, helloSize)
	if _, err := io.ReadFull(c, w); err != nil {
		c.Close()
		return nil, fmt.Errorf("suritap: welcome: %v", err)
	}
	_ = c.SetDeadline(time.Time{})
	if binary.LittleEndian.Uint32(w[0:]) != protoMagic || binary.LittleEndian.Uint16(w[4:]) != protoVersion {
		c.Close()
		return nil, errors.New("suritap: malformed welcome")
	}
	if status := binary.LittleEndian.Uint16(w[6:]); status != 0 {
		msg := w[24:]
		for i, b := range msg {
			if b == 0 {
				msg = msg[:i]
				break
			}
		}
		c.Close()
		return nil, fmt.Errorf("suritap: session refused (%d): %s", status, msg)
	}
	now := time.Now()
	s := &streamSession{
		owner:       owner,
		conn:        c,
		worker:      int(binary.LittleEndian.Uint16(w[8:])),
		workers:     int(binary.LittleEndian.Uint16(w[10:])),
		maxPayload:  int(binary.LittleEndian.Uint32(w[12:])),
		slots:       make([]chan []byte, maxInflight),
		gens:        make([]uint32, maxInflight),
		free:        make([]int, maxInflight),
		lastVerdict: now,
		lastUse:     now,
	}
	if s.workers < 1 {
		c.Close()
		return nil, errors.New("suritap: bad welcome")
	}
	for i := range s.free {
		s.free[i] = maxInflight - 1 - i
	}
	if s.maxPayload <= 0 || s.maxPayload > defaultPayload {
		s.maxPayload = defaultPayload
	}
	go s.readLoop()
	return s, nil
}

func (s *streamSession) isDead() bool {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	return s.dead
}

// fail tears the session down once and fails the requests waiting on it.
// Written for Yaegi, whose interpreter crashes on closures in sync.Once,
// map deletes while ranging and sync/atomic on fields from goroutines.
func (s *streamSession) fail(cause error) {
	s.pmu.Lock()
	if s.dead {
		s.pmu.Unlock()
		return
	}
	s.dead = true
	var waiting []chan []byte
	for i := 0; i < len(s.slots); i++ {
		if s.slots[i] != nil {
			waiting = append(waiting, s.slots[i])
			s.slots[i] = nil
		}
	}
	s.pmu.Unlock()
	if cause != errIdle {
		Logf(false, "session to worker %d closed: %v", s.worker, cause)
	}
	_ = s.conn.Close()
	for i := 0; i < len(waiting); i++ {
		waiting[i] <- nil
	}
}

var (
	errIdle  = errors.New("suritap: idle")
	errStuck = errors.New("suritap: Suricata worker stopped answering")
)

// register reserves a slot for a verdict (false when the session failed or
// too many verdicts are outstanding). When the slots are used up mostly by
// requests whose verdicts never came, the worker is stuck: the session is
// torn down so that it gets re-opened.
func (s *streamSession) register(ch chan []byte) (uint32, bool) {
	s.pmu.Lock()
	if s.dead || len(s.free) == 0 {
		stuck := !s.dead && s.abandoned >= maxInflight/2
		s.pmu.Unlock()
		if stuck {
			s.fail(errStuck)
		}
		return 0, false
	}
	idx := s.free[len(s.free)-1]
	s.free = s.free[:len(s.free)-1]
	s.gens[idx]++ // odd: reserved
	s.slots[idx] = ch
	token := s.gens[idx]<<10 | uint32(idx)
	s.pmu.Unlock()
	return token, true
}

// take releases the slot of token once its verdict arrived (or the request
// was never sent) and returns its waiter, nil when it gave up already.
func (s *streamSession) take(token uint32, arrived bool) chan []byte {
	idx := int(token & (maxInflight - 1))
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if arrived {
		s.lastVerdict = time.Now()
	}
	if s.gens[idx]<<10|uint32(idx) != token || s.gens[idx]&1 == 0 {
		return nil
	}
	s.gens[idx]++ // even: free
	ch := s.slots[idx]
	if ch == nil {
		s.abandoned--
	}
	s.slots[idx] = nil
	s.free = append(s.free, idx)
	return ch
}

// abandon detaches the waiter of token; the slot stays reserved until the
// late verdict arrives. It reports whether the waiter was still attached.
func (s *streamSession) abandon(token uint32) bool {
	idx := int(token & (maxInflight - 1))
	s.pmu.Lock()
	if s.gens[idx]<<10|uint32(idx) != token || s.slots[idx] == nil {
		s.pmu.Unlock()
		return false
	}
	s.slots[idx] = nil
	s.abandoned++
	stuck := !s.dead && time.Since(s.lastVerdict) > stuckAfter
	s.pmu.Unlock()
	if stuck {
		s.fail(errStuck)
	}
	return true
}

// idle reports a session without outstanding requests or writes for
// idleTimeout; otherwise it returns when to check again.
func (s *streamSession) idle() (bool, time.Time) {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	next := s.lastUse.Add(idleTimeout)
	if len(s.free) != maxInflight || time.Now().Before(next) {
		if !next.After(time.Now()) {
			next = time.Now().Add(idleTimeout)
		}
		return false, next
	}
	return true, next
}

func (s *streamSession) readLoop() {
	// A panic in a plugin goroutine would take Traefik down with it.
	defer func() {
		if r := recover(); r != nil {
			Logf(true, "session reader crashed: %v", r)
			s.fail(fmt.Errorf("suritap: reader crashed: %v", r))
		}
	}()
	r := bufio.NewReaderSize(s.conn, 64*1024)
	head := make([]byte, frameHeader)
	_ = s.conn.SetReadDeadline(time.Now().Add(idleTimeout))
	for {
		if n, err := io.ReadFull(r, head); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && n == 0 {
				idle, next := s.idle()
				if idle {
					s.fail(errIdle)
					return
				}
				_ = s.conn.SetReadDeadline(next)
				continue
			}
			s.fail(fmt.Errorf("suritap: session closed: %v", err))
			return
		}
		n := int(binary.LittleEndian.Uint32(head))
		kind := binary.LittleEndian.Uint16(head[4:])
		if n < frameHeader || n > 1<<20 {
			s.fail(errors.New("suritap: bad frame from server"))
			return
		}
		body := make([]byte, n-frameHeader)
		if _, err := io.ReadFull(r, body); err != nil {
			s.fail(fmt.Errorf("suritap: session closed: %v", err))
			return
		}
		switch kind {
		case kVerdict:
			if len(body) >= verdictFixed {
				s.complete(binary.LittleEndian.Uint32(body[8:]), body)
			}
		case kPong:
			if len(body) >= 4 {
				s.complete(binary.LittleEndian.Uint32(body), body)
			}
		case kPolicy:
			if p, ok := decodePolicy(body); ok && s.owner != nil {
				s.owner.setPolicy(p)
			}
		}
	}
}

func (s *streamSession) complete(token uint32, body []byte) {
	if ch := s.take(token, true); ch != nil {
		ch <- body
	}
}

// write sends one frame (writev, no copy). Frames are written whole: a
// write that fails or stalls for writeStall leaves the stream unusable, so
// the session is torn down.
func (s *streamSession) write(parts ...[]byte) error {
	now := time.Now()
	s.wmu.Lock()
	s.pmu.Lock()
	dead := s.dead
	s.lastUse = now
	s.pmu.Unlock()
	if dead {
		s.wmu.Unlock()
		return ErrUnavailable
	}
	_ = s.conn.SetWriteDeadline(now.Add(writeStall))
	bufs := net.Buffers(parts)
	_, err := bufs.WriteTo(s.conn)
	s.wmu.Unlock()
	if err != nil {
		s.fail(fmt.Errorf("suritap: write: %v", err))
		return ErrUnavailable
	}
	return nil
}

func frameHead(kind, flags uint16, body int) []byte {
	h := make([]byte, frameHeader)
	binary.LittleEndian.PutUint32(h, uint32(frameHeader+body))
	binary.LittleEndian.PutUint16(h[4:], kind)
	binary.LittleEndian.PutUint16(h[6:], flags)
	return h
}

func dataHead(cid uint64, dir Dir, token uint32) []byte {
	b := make([]byte, dataFixed)
	binary.LittleEndian.PutUint64(b, cid)
	b[8] = byte(dir)
	binary.LittleEndian.PutUint32(b[12:], token)
	return b
}

func encodeOpen(cid uint64, src, dst Addr, meta []Meta) ([]byte, error) {
	s4, d4 := src.IP.To4(), dst.IP.To4()
	if (s4 == nil) != (d4 == nil) {
		return nil, errors.New("suritap: address families differ")
	}
	b := make([]byte, openFixed)
	binary.LittleEndian.PutUint64(b, cid)
	if s4 != nil {
		b[8] = 4
		copy(b[24:], s4)
		copy(b[40:], d4)
	} else {
		s16, d16 := src.IP.To16(), dst.IP.To16()
		if s16 == nil || d16 == nil {
			return nil, errors.New("suritap: invalid address")
		}
		b[8] = 6
		copy(b[24:], s16)
		copy(b[40:], d16)
	}
	binary.LittleEndian.PutUint16(b[16:], uint16(src.Port))
	binary.LittleEndian.PutUint16(b[18:], uint16(dst.Port))
	total := 0
	for _, m := range meta {
		v := m.Value
		if len(v) > 1024 {
			v = v[:1024]
		}
		if total+4+len(v) > maxMeta {
			break
		}
		total += 4 + len(v)
		b = append(b, m.Tag, 0, byte(len(v)), byte(len(v)>>8))
		b = append(b, v...)
	}
	return b, nil
}

func decodeVerdict(body []byte) Verdict {
	v := Verdict{Action: Action(body[13]), Reason: body[14]}
	if v.Action > Error {
		v.Action = Error
	}
	na := int(body[15])
	for i := 0; i < na && verdictFixed+(i+1)*alertSize <= len(body); i++ {
		v.SIDs = append(v.SIDs, binary.LittleEndian.Uint32(body[verdictFixed+i*alertSize:]))
	}
	return v
}

// streamConn is one connection on a session. Each direction must be used
// by one goroutine at a time; Close must not race with the others.
type streamConn struct {
	s      *streamSession
	cid    uint64
	closed bool
}

func (c *streamConn) CID() uint64 { return c.cid }

// sendChunks writes data as DATA frames. The deadline of ctx is checked
// between frames: when it passed, the rest is reported as a gap so that the
// engine stays aligned with the byte stream, and ctx's error is returned.
func (c *streamConn) sendChunks(ctx context.Context, dir Dir, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			c.gap(dir, len(data))
			return err
		}
		n := len(data)
		if n > c.s.maxPayload {
			n = c.s.maxPayload
		}
		if err := c.s.write(frameHead(kData, 0, dataFixed+n), dataHead(c.cid, dir, 0), data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// gap reports n bytes of dir that were not sent.
func (c *streamConn) gap(dir Dir, n int) {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b, c.cid)
	b[8] = byte(dir)
	binary.LittleEndian.PutUint32(b[12:], uint32(n))
	_ = c.s.write(frameHead(kGap, 0, len(b)), b)
}

func (c *streamConn) Send(ctx context.Context, dir Dir, data []byte) error {
	return c.sendChunks(ctx, dir, data)
}

func (c *streamConn) Inspect(ctx context.Context, dir Dir, data []byte) (Verdict, error) {
	split := 0
	if len(data) > 0 {
		split = (len(data) - 1) / c.s.maxPayload * c.s.maxPayload
	}
	if err := c.sendChunks(ctx, dir, data[:split]); err != nil {
		return Verdict{}, err
	}
	last := data[split:]
	if err := ctx.Err(); err != nil {
		if len(last) > 0 {
			c.gap(dir, len(last))
		}
		return Verdict{}, err
	}
	// Room for the verdict (or nil on failure) and the cancellation
	// marker, so neither sender blocks.
	ch := make(chan []byte, 2)
	token, ok := c.s.register(ch)
	if !ok {
		if len(last) > 0 {
			c.gap(dir, len(last))
		}
		return Verdict{}, ErrUnavailable
	}
	if err := c.s.write(frameHead(kData, fWantVerdict, dataFixed+len(last)), dataHead(c.cid, dir, token), last); err != nil {
		c.s.take(token, false)
		return Verdict{}, err
	}
	// No select (see streamSession): cancellation posts a marker instead.
	stop := context.AfterFunc(ctx, func() { ch <- []byte{} })
	body := <-ch
	stop()
	switch {
	case body == nil:
		return Verdict{}, ErrUnavailable
	case len(body) == 0:
		if c.s.abandon(token) {
			return Verdict{}, ctx.Err()
		}
		// The verdict (or failure) raced the cancellation and is queued.
		if body = <-ch; body == nil {
			return Verdict{}, ErrUnavailable
		}
	}
	return decodeVerdict(body), nil
}

func (c *streamConn) Close(reset bool) error {
	if c.closed {
		return nil
	}
	c.closed = true
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b, c.cid)
	if reset {
		b[8] = 1
	}
	return c.s.write(frameHead(kClose, 0, len(b)), b)
}
