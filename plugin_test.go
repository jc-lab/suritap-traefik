package suritap

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const marker = "SURITAP-TEST-DROP" // suritap-mockd drops packets containing it

func startMockd(t *testing.T, extra ...string) string {
	t.Helper()
	bin := os.Getenv("SURITAP_MOCKD")
	if bin == "" {
		_, file, _, _ := runtime.Caller(0)
		root := filepath.Join(filepath.Dir(file), "..", "..")
		for _, p := range []string{"tap/target/release/suritap-mockd", "tap/target/debug/suritap-mockd"} {
			if _, err := os.Stat(filepath.Join(root, p)); err == nil {
				bin = filepath.Join(root, p)
				break
			}
		}
	}
	if bin == "" {
		t.Skip("suritap-mockd not built (cargo build -p suritap in tap/)")
	}
	dir, err := os.MkdirTemp("", "stap")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, append([]string{"--dir", dir, "--workers", "2", "--max-segment", "4096"}, extra...)...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		os.RemoveAll(dir)
	})
	for range 100 {
		if _, err := os.Stat(streamPath(dir, 1)); err == nil {
			return dir
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("mockd did not start")
	return ""
}

type backend struct {
	calls atomic.Int32
	reply string
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.calls.Add(1)
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	w.Header().Set("Set-Cookie", "session=secret")
	_, _ = io.WriteString(w, b.reply)
}

func newServer(t *testing.T, h http.Handler, b *backend) *httptest.Server {
	_ = b
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, c *http.Client, method, url string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, body)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// newTap builds the middleware the way Traefik does (New), around next.
func newTap(t *testing.T, cfg Config, next http.Handler) http.Handler {
	h, err := New(context.Background(), next, &cfg, "websecure")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHTTPPrevent(t *testing.T) {
	dir := startMockd(t)
	b := &backend{reply: "hello"}
	srv := newServer(t, newTap(t, Config{SocketDir: dir, MaxRequestBody: 64 << 10, Timeout: "2s"}, b), b)

	h2 := srv.Client()
	h1 := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{},
	}}
	for name, c := range map[string]*http.Client{"h2": h2, "h1": h1} {
		t.Run(name, func(t *testing.T) {
			before := b.calls.Load()
			resp, body := do(t, c, "GET", srv.URL+"/index.html", nil)
			if resp.StatusCode != 200 || body != "hello" {
				t.Fatalf("benign: %d %q", resp.StatusCode, body)
			}
			if want := map[string]int{"h2": 2, "h1": 1}[name]; resp.ProtoMajor != want {
				t.Fatalf("protocol %s", resp.Proto)
			}
			resp, _ = do(t, c, "GET", srv.URL+"/"+marker, nil)
			if resp.StatusCode != 403 || resp.Header.Get("X-Suritap-Cid") == "" {
				t.Fatalf("attack in URI: %d %v", resp.StatusCode, resp.Header)
			}
			resp, _ = do(t, c, "POST", srv.URL+"/upload", strings.NewReader("a="+marker))
			if resp.StatusCode != 403 {
				t.Fatalf("attack in small body: %d", resp.StatusCode)
			}
			if got := b.calls.Load() - before; got != 1 {
				t.Fatalf("backend called %d times, want 1 (blocked requests must not reach it)", got)
			}
		})
	}

	// A large body is streamed and blocked when the marker arrives.
	big := bytes.Repeat([]byte("x"), 512<<10)
	copy(big[300<<10:], marker)
	resp, _ := do(t, h2, "POST", srv.URL+"/upload", bytes.NewReader(big))
	if resp.StatusCode != 403 {
		t.Fatalf("attack in streamed body: %d", resp.StatusCode)
	}
	resp, body := do(t, h2, "POST", srv.URL+"/upload", bytes.NewReader(bytes.Repeat([]byte("y"), 512<<10)))
	if resp.StatusCode != 200 || body != "hello" {
		t.Fatalf("benign streamed body: %d", resp.StatusCode)
	}
}

func TestHTTPResponseModes(t *testing.T) {
	dir := startMockd(t)
	leak := &backend{reply: "token " + marker}

	detect := newServer(t, newTap(t, Config{SocketDir: dir}, leak), leak)
	resp, body := do(t, detect.Client(), "GET", detect.URL+"/", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, marker) {
		t.Fatalf("detect mode must not block responses: %d", resp.StatusCode)
	}

	prevent := newServer(t, newTap(t, Config{SocketDir: dir, Response: "prevent", Timeout: "2s", Name: "prevent"}, leak), leak)
	resp, body = do(t, prevent.Client(), "GET", prevent.URL+"/", nil)
	if resp.StatusCode != 403 || strings.Contains(body, marker) || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("prevent mode: %d %q %v", resp.StatusCode, body, resp.Header)
	}
}

func TestFailPolicy(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none")
	b := &backend{reply: "ok"}
	open := newServer(t, newTap(t, Config{SocketDir: missing}, b), b)
	if resp, _ := do(t, open.Client(), "GET", open.URL+"/", nil); resp.StatusCode != 200 {
		t.Fatalf("fail open: %d", resp.StatusCode)
	}
	closed := newServer(t, newTap(t, Config{SocketDir: missing, FailPolicy: "closed"}, b), b)
	if resp, _ := do(t, closed.Client(), "GET", closed.URL+"/", nil); resp.StatusCode != 503 {
		t.Fatalf("fail closed: %d", resp.StatusCode)
	}
	if _, err := New(context.Background(), b, &Config{Mode: "bogus"}, "x"); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

// In response prevent mode a handler that flushes (event stream) gets each
// flushed part inspected and delivered right away; a dropped part aborts
// the response.
func TestPreventStreamsFlushedResponses(t *testing.T) {
	dir := startMockd(t)
	release := make(chan struct{})
	events := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if r.URL.Path == "/leak" {
			_, _ = io.WriteString(w, "data: "+marker+"\n\n")
			w.(http.Flusher).Flush()
		}
		_, _ = io.WriteString(w, "data: last\n\n")
	})
	srv := newServer(t, newTap(t, Config{SocketDir: dir, Response: "prevent", Timeout: "2s", Name: "events"}, events), nil)
	for _, path := range []string{"/ok", "/leak"} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		first := make([]byte, len("data: first\n\n"))
		got := make(chan error, 1)
		go func() { _, err := io.ReadFull(resp.Body, first); got <- err }()
		select {
		case err := <-got:
			if err != nil || string(first) != "data: first\n\n" {
				t.Fatalf("%s: first event %q %v", path, first, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s: flushed event held back", path)
		}
		release <- struct{}{}
		rest, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if path == "/ok" && (err != nil || string(rest) != "data: last\n\n") {
			t.Fatalf("rest %q %v", rest, err)
		}
		if path == "/leak" && (err == nil || strings.Contains(string(rest), marker)) {
			t.Fatalf("dropped event delivered: %q %v", rest, err)
		}
	}
}

// The operator's endpoint policy (pushed by the plugin) overrides the
// middleware's mode: off skips inspection, detect never blocks, prevent
// blocks even when the middleware says detect; unlisted endpoints keep the
// middleware's setting.
func TestEndpointPolicy(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "policy")
	write := func(text string) {
		if err := os.WriteFile(pf, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("ep-off off\nep-detect detect\nep-prevent prevent\n")
	dir := startMockd(t, "--policy-file", pf)
	b := &backend{reply: "hello"}
	srv := func(endpoint, mode string) *httptest.Server {
		return newServer(t, newTap(t, Config{SocketDir: dir, Endpoint: endpoint, Mode: mode, Timeout: "2s", Name: "policy-" + endpoint}, b), b)
	}
	off, detect, prevent, unlisted := srv("ep-off", "prevent"), srv("ep-detect", "prevent"), srv("ep-prevent", "detect"), srv("ep-other", "prevent")
	get := func(s *httptest.Server) int {
		resp, _ := do(t, s.Client(), "GET", s.URL+"/"+marker, nil)
		return resp.StatusCode
	}
	// The policy arrives with the first session; until then the
	// middleware's own mode applies.
	for i := 0; ; i++ {
		if get(prevent) == 403 && get(detect) == 200 {
			break
		}
		if i == 100 {
			t.Fatal("policy not applied")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c := get(off); c != 200 {
		t.Fatalf("off endpoint: %d", c)
	}
	if c := get(unlisted); c != 403 {
		t.Fatalf("unlisted endpoint keeps the middleware mode: %d", c)
	}
	write("ep-off prevent\n")
	for i := 0; get(off) != 403; i++ {
		if i == 300 {
			t.Fatal("policy change not applied")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c := get(prevent); c != 200 {
		t.Fatalf("endpoint dropped from the policy falls back to the middleware's detect: %d", c)
	}
}
