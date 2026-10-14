package suritap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
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
	Open(src, dst Addr, meta []Meta) (Conn, error)
	Close() error
}

// Conn is one inspected connection (one HTTP request for the HTTP tap).
type Conn interface {
	CID() uint64
	// Send streams payload without waiting (detect).
	Send(deadline time.Time, dir Dir, data []byte) error
	// Inspect sends payload and waits until deadline for the verdict
	// covering everything sent so far in dir.
	Inspect(deadline time.Time, dir Dir, data []byte) (Verdict, error)
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
	kClose         = 5
	kVerdict       = 0x81
	kPong          = 0x83
	fWantVerdict   = 1
	openFixed      = 56
	dataFixed      = 16
	verdictFixed   = 24
	alertSize      = 16
	maxMeta        = 2048
	maxInflight    = 1024
	defaultPayload = 64 * 1024
)

// StreamTransport talks to the suritap plugin over its socket transport
// (worker-N.stream.sock). It uses only the Go standard library, so it runs
// inside Traefik's Yaegi interpreter.
type StreamTransport struct {
	dir  string
	name string

	mu       sync.Mutex
	sessions []*streamSession
	retryAt  time.Time
	nextCID  uint64
}

// NewStreamTransport creates a transport for the sockets in dir; sessions
// are opened on first use and re-opened after failures.
func NewStreamTransport(dir, name string) *StreamTransport {
	return &StreamTransport{dir: dir, name: name, nextCID: uint64(time.Now().UnixNano())<<8 | 1}
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

// session returns the live session for the worker owning cid.
func (t *StreamTransport) session(cid uint64) (*streamSession, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.sessions) == 0 {
		if time.Now().Before(t.retryAt) {
			return nil, ErrUnavailable
		}
		s, err := dialStream(streamPath(t.dir, 0), t.name)
		if err != nil {
			t.retryAt = time.Now().Add(time.Second)
			return nil, err
		}
		t.sessions = make([]*streamSession, s.workers)
		t.sessions[0] = s
	}
	idx := int(mix(cid) % uint64(len(t.sessions)))
	s := t.sessions[idx]
	if s != nil && !s.isDead() {
		return s, nil
	}
	if time.Now().Before(t.retryAt) {
		return nil, ErrUnavailable
	}
	s, err := dialStream(streamPath(t.dir, idx), t.name)
	if err != nil {
		t.retryAt = time.Now().Add(time.Second)
		if idx == 0 {
			// Suricata may have restarted with another worker count.
			t.sessions = nil
		}
		return nil, err
	}
	if s.worker != idx || s.workers != len(t.sessions) {
		s.fail(errors.New("suritap: worker layout changed"))
		t.sessions = nil
		return nil, ErrUnavailable
	}
	t.sessions[idx] = s
	return s, nil
}

// Open announces a new connection.
func (t *StreamTransport) Open(src, dst Addr, meta []Meta) (Conn, error) {
	cid := atomic.AddUint64(&t.nextCID, 1)
	s, err := t.session(cid)
	if err != nil {
		return nil, err
	}
	body, err := encodeOpen(cid, src, dst, meta)
	if err != nil {
		return nil, err
	}
	if err := s.write(time.Now().Add(2*time.Second), [][]byte{frameHead(kOpen, 0, len(body)), body}); err != nil {
		return nil, err
	}
	return &streamConn{s: s, cid: cid}, nil
}

// Close closes all sessions.
func (t *StreamTransport) Close() error {
	t.mu.Lock()
	sessions := t.sessions
	t.sessions = nil
	t.mu.Unlock()
	for _, s := range sessions {
		if s != nil {
			s.fail(errors.New("suritap: transport closed"))
		}
	}
	return nil
}

type streamSession struct {
	conn       net.Conn
	worker     int
	workers    int
	maxPayload int

	wmu sync.Mutex // serializes frame writes

	// Outstanding verdict requests live in fixed slots (token =
	// generation<<10 | slot); the free list bounds them to the server's
	// in-flight limit. A slot is released when its verdict arrives, also
	// after the waiter timed out. Waiters receive the raw VERDICT body, nil
	// when the session failed or an empty slice on timeout.
	//
	// Written for Yaegi (v0.16): only compiled types are stored, since
	// collections of channels of interpreted types crash it, and there is
	// no select statement on concurrent paths, since all goroutines running
	// one select statement share its case list.
	pmu   sync.Mutex // guards slots, gens, free and dead
	slots []chan []byte
	gens  []uint32
	free  []int
	dead  bool
}

func dialStream(path, name string) (*streamSession, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
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
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
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
	s := &streamSession{
		conn:       c,
		worker:     int(binary.LittleEndian.Uint16(w[8:])),
		workers:    int(binary.LittleEndian.Uint16(w[10:])),
		maxPayload: int(binary.LittleEndian.Uint32(w[12:])),
		slots:      make([]chan []byte, maxInflight),
		gens:       make([]uint32, maxInflight),
		free:       make([]int, maxInflight),
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
	_ = s.conn.Close()
	for i := 0; i < len(waiting); i++ {
		waiting[i] <- nil
	}
}

// register reserves a slot for a verdict (false when the session failed or
// too many verdicts are outstanding).
func (s *streamSession) register(ch chan []byte) (uint32, bool) {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if s.dead || len(s.free) == 0 {
		return 0, false
	}
	idx := s.free[len(s.free)-1]
	s.free = s.free[:len(s.free)-1]
	s.gens[idx]++ // odd: reserved
	s.slots[idx] = ch
	return s.gens[idx]<<10 | uint32(idx), true
}

// take releases the slot of token once its verdict arrived (or the request
// was never sent) and returns its waiter, nil when it gave up already.
func (s *streamSession) take(token uint32) chan []byte {
	idx := int(token & (maxInflight - 1))
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if s.gens[idx]<<10|uint32(idx) != token || s.gens[idx]&1 == 0 {
		return nil
	}
	s.gens[idx]++ // even: free
	ch := s.slots[idx]
	s.slots[idx] = nil
	s.free = append(s.free, idx)
	return ch
}

// abandon detaches the waiter of token; the slot stays reserved until the
// late verdict arrives. It reports whether the waiter was still attached.
func (s *streamSession) abandon(token uint32) bool {
	idx := int(token & (maxInflight - 1))
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if s.gens[idx]<<10|uint32(idx) != token || s.slots[idx] == nil {
		return false
	}
	s.slots[idx] = nil
	return true
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
	for {
		if _, err := io.ReadFull(r, head); err != nil {
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
		}
	}
}

func (s *streamSession) complete(token uint32, body []byte) {
	if ch := s.take(token); ch != nil {
		ch <- body
	}
}

// write sends whole frames. A write that fails or times out midway leaves
// the stream unusable, so the session is torn down.
func (s *streamSession) write(deadline time.Time, parts [][]byte) error {
	if s.isDead() {
		return ErrUnavailable
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_ = s.conn.SetWriteDeadline(deadline)
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	buf := make([]byte, 0, n)
	for _, p := range parts {
		buf = append(buf, p...)
	}
	if _, err := s.conn.Write(buf); err != nil {
		s.fail(fmt.Errorf("suritap: write: %v", err))
		return err
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

type streamConn struct {
	s      *streamSession
	cid    uint64
	closed int32
}

func (c *streamConn) CID() uint64 { return c.cid }

func (c *streamConn) sendChunks(deadline time.Time, dir Dir, data []byte) error {
	for len(data) > 0 {
		n := len(data)
		if n > c.s.maxPayload {
			n = c.s.maxPayload
		}
		hd := dataHead(c.cid, dir, 0)
		if err := c.s.write(deadline, [][]byte{frameHead(kData, 0, dataFixed+n), hd, data[:n]}); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func (c *streamConn) Send(deadline time.Time, dir Dir, data []byte) error {
	return c.sendChunks(deadline, dir, data)
}

// errTimeout is returned when no verdict arrived before the deadline.
var errTimeout = errors.New("suritap: verdict timeout")

func (c *streamConn) Inspect(deadline time.Time, dir Dir, data []byte) (Verdict, error) {
	split := 0
	if len(data) > 0 {
		split = (len(data) - 1) / c.s.maxPayload * c.s.maxPayload
	}
	if err := c.sendChunks(deadline, dir, data[:split]); err != nil {
		return Verdict{}, err
	}
	last := data[split:]
	// Room for the verdict (or nil on failure) and the timeout marker, so
	// neither sender blocks.
	ch := make(chan []byte, 2)
	token, ok := c.s.register(ch)
	if !ok {
		return Verdict{}, ErrUnavailable
	}
	err := c.s.write(deadline, [][]byte{frameHead(kData, fWantVerdict, dataFixed+len(last)), dataHead(c.cid, dir, token), last})
	if err != nil {
		c.s.take(token)
		return Verdict{}, err
	}
	timer := time.AfterFunc(time.Until(deadline), func() { ch <- []byte{} })
	body := <-ch
	timer.Stop()
	switch {
	case body == nil:
		return Verdict{}, ErrUnavailable
	case len(body) == 0:
		if c.s.abandon(token) {
			return Verdict{}, errTimeout
		}
		// The verdict (or failure) raced the timer and is queued.
		if body = <-ch; body == nil {
			return Verdict{}, ErrUnavailable
		}
	}
	return decodeVerdict(body), nil
}

func (c *streamConn) Close(reset bool) error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b, c.cid)
	if reset {
		b[8] = 1
	}
	return c.s.write(time.Now().Add(time.Second), [][]byte{frameHead(kClose, 0, len(b)), b})
}
