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

func startMockd(t *testing.T) string {
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
	cmd := exec.Command(bin, "--dir", dir, "--workers", "2", "--max-segment", "4096")
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
