package suritap

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeServer speaks the socket transport for tests. Each worker socket can
// be tuned: refuse sessions, never answer HELLO, answer verdicts or not,
// read slowly.
type fakeServer struct {
	dir     string
	workers int

	mu        sync.Mutex
	listeners []net.Listener
	conns     map[int][]net.Conn
	refuse    map[int]bool // answer HELLO with a refusal
	silent    map[int]bool // never answer HELLO
	noVerdict bool
	readDelay time.Duration

	accepted [8]atomic.Int32 // sessions established per worker
	closed   [8]atomic.Int32 // sessions that ended per worker
	gaps     atomic.Int64    // bytes reported as gaps
}

func newFakeServer(t *testing.T, workers int) *fakeServer {
	dir, err := os.MkdirTemp("", "stap")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{dir: dir, workers: workers, conns: map[int][]net.Conn{}, refuse: map[int]bool{}, silent: map[int]bool{}}
	f.listen(t)
	t.Cleanup(func() {
		f.stop()
		os.RemoveAll(dir)
	})
	return f
}

func (f *fakeServer) listen(t *testing.T) {
	for i := 0; i < f.workers; i++ {
		os.Remove(streamPath(f.dir, i))
		l, err := net.Listen("unix", streamPath(f.dir, i))
		if err != nil {
			t.Fatal(err)
		}
		f.listeners = append(f.listeners, l)
		go f.accept(l, i)
	}
}

// stop closes the listeners and all sessions.
func (f *fakeServer) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.listeners {
		l.Close()
	}
	f.listeners = nil
	for _, cs := range f.conns {
		for _, c := range cs {
			c.Close()
		}
	}
	f.conns = map[int][]net.Conn{}
}

// drop closes the sessions of one worker.
func (f *fakeServer) drop(worker int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.conns[worker] {
		c.Close()
	}
	f.conns[worker] = nil
}

func (f *fakeServer) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *fakeServer) accept(l net.Listener, worker int) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go f.serve(c, worker)
	}
}

func (f *fakeServer) serve(c net.Conn, worker int) {
	defer c.Close()
	hello := make([]byte, helloSize)
	if _, err := io.ReadFull(c, hello); err != nil {
		return
	}
	f.mu.Lock()
	refuse, silent, workers := f.refuse[worker], f.silent[worker], f.workers
	f.mu.Unlock()
	if silent {
		_, _ = io.Copy(io.Discard, c)
		return
	}
	w := make([]byte, helloSize)
	binary.LittleEndian.PutUint32(w[0:], protoMagic)
	binary.LittleEndian.PutUint16(w[4:], protoVersion)
	if refuse {
		binary.LittleEndian.PutUint16(w[6:], 3)
		copy(w[24:], "too many sessions")
		_, _ = c.Write(w)
		return
	}
	binary.LittleEndian.PutUint16(w[8:], uint16(worker))
	binary.LittleEndian.PutUint16(w[10:], uint16(workers))
	binary.LittleEndian.PutUint32(w[12:], defaultPayload)
	if _, err := c.Write(w); err != nil {
		return
	}
	f.mu.Lock()
	f.conns[worker] = append(f.conns[worker], c)
	f.mu.Unlock()
	f.accepted[worker].Add(1)
	defer f.closed[worker].Add(1)
	head := make([]byte, frameHeader)
	for {
		if _, err := io.ReadFull(c, head); err != nil {
			return
		}
		body := make([]byte, int(binary.LittleEndian.Uint32(head))-frameHeader)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		f.mu.Lock()
		delay, noVerdict := f.readDelay, f.noVerdict
		f.mu.Unlock()
		time.Sleep(delay)
		kind, flags := binary.LittleEndian.Uint16(head[4:]), binary.LittleEndian.Uint16(head[6:])
		switch {
		case kind == kGap:
			f.gaps.Add(int64(binary.LittleEndian.Uint32(body[12:])))
		case kind == kData && flags&fWantVerdict != 0 && !noVerdict:
			v := make([]byte, verdictFixed)
			copy(v, body[:8])
			copy(v[8:12], body[12:16])
			v[12] = body[8]
			if _, err := c.Write(append(frameHead(kVerdict, 0, len(v)), v...)); err != nil {
				return
			}
		}
	}
}

// tune overrides transport timing for one test.
func tune(t *testing.T, fn func()) {
	saved := [5]time.Duration{dialTimeout, retryDelay, writeStall, stuckAfter, idleTimeout}
	fn()
	t.Cleanup(func() {
		dialTimeout, retryDelay, writeStall, stuckAfter, idleTimeout = saved[0], saved[1], saved[2], saved[3], saved[4]
	})
}

var testAddr = Addr{IP: net.IPv4(203, 0, 113, 1), Port: 40000}

func inspect(t *testing.T, tr *StreamTransport, d time.Duration, data []byte) (Verdict, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	c, err := tr.Open(ctx, testAddr, testAddr, nil)
	if err != nil {
		return Verdict{}, err
	}
	defer c.Close(false)
	return c.Inspect(ctx, ToServer, data)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A request whose verdict timeout passes while its body is being written
// gives up between frames (reporting the rest as a gap); the session and
// the other requests on it are unaffected.
func TestSlowServerOnlyFailsTheSlowRequest(t *testing.T) {
	f := newFakeServer(t, 1)
	tr := NewStreamTransport(f.dir, "test")
	defer tr.Close()
	if _, err := inspect(t, tr, time.Second, []byte("warm up")); err != nil {
		t.Fatal(err)
	}
	f.set(func() { f.readDelay = 20 * time.Millisecond })
	big := make([]byte, 4<<20)
	errc := make(chan error, 1)
	go func() {
		_, err := inspect(t, tr, 100*time.Millisecond, big)
		errc <- err
	}()
	time.Sleep(30 * time.Millisecond)
	if _, err := inspect(t, tr, 5*time.Second, []byte("small")); err != nil {
		t.Fatalf("concurrent request: %v", err)
	}
	if err := <-errc; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow request: %v", err)
	}
	waitFor(t, "gap", func() bool { return f.gaps.Load() > 0 })
	f.set(func() { f.readDelay = 0 })
	if _, err := inspect(t, tr, time.Second, []byte("after")); err != nil {
		t.Fatal(err)
	}
	if n := f.accepted[0].Load(); n != 1 {
		t.Fatalf("%d sessions, want the first one kept", n)
	}
}

// Opening a session does not hold the transport lock: while a worker that
// accepts but never answers is being dialled, requests for other workers
// go through and those for that worker wait only until their deadline.
func TestStalledWorkerDoesNotBlockOthers(t *testing.T) {
	tune(t, func() { dialTimeout = 500 * time.Millisecond })
	f := newFakeServer(t, 2)
	tr := NewStreamTransport(f.dir, "test")
	defer tr.Close()
	if _, err := inspect(t, tr, time.Second, nil); err != nil && !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	f.set(func() { f.silent[1] = true })
	var wg sync.WaitGroup
	var slow, ok atomic.Int32
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			_, err := inspect(t, tr, 100*time.Millisecond, []byte("x"))
			if time.Since(t0) > 200*time.Millisecond {
				slow.Add(1)
			}
			if err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if slow.Load() > 1 || ok.Load() == 0 {
		t.Fatalf("%d requests waited for the stalled dial, %d succeeded", slow.Load(), ok.Load())
	}
}

// A failed re-dial of one worker leaves the other sessions alone (they
// used to be dropped without closing, leaking server sessions).
func TestFailedDialKeepsOtherSessions(t *testing.T) {
	tune(t, func() { retryDelay = 10 * time.Millisecond })
	f := newFakeServer(t, 2)
	tr := NewStreamTransport(f.dir, "test")
	defer tr.Close()
	waitFor(t, "both sessions", func() bool {
		_, _ = inspect(t, tr, time.Second, []byte("x"))
		return f.accepted[0].Load() == 1 && f.accepted[1].Load() == 1
	})
	f.set(func() { f.refuse[0] = true })
	f.drop(0)
	for i := 0; i < 200; i++ {
		_, _ = inspect(t, tr, time.Second, []byte("x"))
		if i%20 == 0 {
			time.Sleep(15 * time.Millisecond)
		}
	}
	f.set(func() { f.refuse[0] = false })
	waitFor(t, "worker 0 back", func() bool {
		_, _ = inspect(t, tr, time.Second, []byte("x"))
		time.Sleep(5 * time.Millisecond)
		return f.accepted[0].Load() == 2
	})
	if a, c := f.accepted[1].Load(), f.closed[1].Load(); a != 1 || c != 0 {
		t.Fatalf("worker 1: %d sessions opened, %d closed; want 1, 0", a, c)
	}
}

// A different worker count (Suricata restarted) replaces the layout and
// closes the old sessions.
func TestLayoutChangeClosesOldSessions(t *testing.T) {
	tune(t, func() { retryDelay = 10 * time.Millisecond })
	f := newFakeServer(t, 2)
	tr := NewStreamTransport(f.dir, "test")
	defer tr.Close()
	waitFor(t, "both sessions", func() bool {
		_, _ = inspect(t, tr, time.Second, []byte("x"))
		return f.accepted[0].Load() == 1 && f.accepted[1].Load() == 1
	})
	f.set(func() { f.workers = 3 })
	f.drop(0)
	waitFor(t, "new layout", func() bool {
		_, _ = inspect(t, tr, time.Second, []byte("x"))
		time.Sleep(5 * time.Millisecond)
		return f.closed[1].Load() == 1
	})
}

// A worker that stops answering is detected and its session re-opened.
func TestStuckWorkerIsRecycled(t *testing.T) {
	tune(t, func() { stuckAfter = 150 * time.Millisecond })
	f := newFakeServer(t, 1)
	tr := NewStreamTransport(f.dir, "test")
	defer tr.Close()
	f.set(func() { f.noVerdict = true })
	waitFor(t, "session recycled", func() bool {
		if _, err := inspect(t, tr, 30*time.Millisecond, []byte("x")); err == nil {
			t.Fatal("verdict from a silent server")
		}
		return f.accepted[0].Load() >= 2
	})
	f.set(func() { f.noVerdict = false })
	waitFor(t, "verdicts again", func() bool {
		_, err := inspect(t, tr, time.Second, []byte("x"))
		return err == nil
	})
}

// Idle sessions are closed and re-opened on demand.
func TestIdleSessionClosed(t *testing.T) {
	tune(t, func() { idleTimeout = 100 * time.Millisecond })
	f := newFakeServer(t, 1)
	tr := NewStreamTransport(f.dir, "test")
	defer tr.Close()
	if _, err := inspect(t, tr, time.Second, []byte("x")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle close", func() bool { return f.closed[0].Load() == 1 })
	if _, err := inspect(t, tr, time.Second, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if n := f.accepted[0].Load(); n != 2 {
		t.Fatalf("%d sessions", n)
	}
}

// Requests arriving while a session is being opened wait for it instead of
// failing (cold start, reconnect).
func TestRequestsWaitForSessionBeingOpened(t *testing.T) {
	f := newFakeServer(t, 1)
	tr := NewStreamTransport(f.dir, "test")
	defer tr.Close()
	var wg sync.WaitGroup
	var failed atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := inspect(t, tr, time.Second, []byte("x")); err != nil {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := failed.Load(); n != 0 {
		t.Fatalf("%d requests failed during the first dial", n)
	}
	if n := f.accepted[0].Load(); n != 1 {
		t.Fatalf("%d sessions opened", n)
	}
}
