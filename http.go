package suritap

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errBlocked = errors.New("suritap: blocked")

// handler inspects each request (and, depending on the configuration, its
// response) before calling next.
type handler struct {
	next http.Handler
	s    settings
	tr   Transport
}

func newHandler(next http.Handler, s settings, tr Transport) *handler {
	return &handler{next: next, s: s, tr: tr}
}

// open announces the request; src/dst of different or unknown families are
// mapped onto the source family.
func (t *handler) open(r *http.Request) (Conn, error) {
	ctx, cancel := context.WithTimeout(r.Context(), t.s.timeout)
	defer cancel()
	src, ok := parseAddr(r.RemoteAddr)
	if !ok {
		return nil, errors.New("suritap: unusable client address")
	}
	dst, ok := localAddr(r)
	if !ok || (dst.IP.To4() == nil) != (src.IP.To4() == nil) {
		if src.IP.To4() != nil {
			dst.IP = net.IPv4zero
		} else {
			dst.IP = net.IPv6zero
		}
	}
	meta := append(requestMeta(r), Meta{Tag: MetaProxy, Value: "traefik"}, Meta{Tag: MetaEndpoint, Value: t.s.endpoint})
	return t.tr.Open(ctx, src, dst, meta)
}

// modes returns the request and response modes of this request: the
// operator's endpoint policy when it lists the endpoint, else the
// middleware's settings. Detect never blocks, so it also turns response
// prevent into detect.
func (t *handler) modes() (mode, mode) {
	req, resp := t.s.mode, t.s.response
	if m, ok := t.tr.EndpointMode(t.s.endpoint); ok {
		switch m {
		case ModeOff:
			return modeOff, modeOff
		case ModeDetect:
			req = modeDetect
			if resp == modePrevent {
				resp = modeDetect
			}
		case ModePrevent:
			req = modePrevent
		}
	}
	return req, resp
}

func (t *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	next := t.next
	reqMode, respMode := t.modes()
	if reqMode == modeOff {
		next.ServeHTTP(w, r)
		return
	}
	conn, err := t.open(r)
	if err != nil {
		logUnavailable(t.s.endpoint, err)
		if t.s.failClosed && reqMode == modePrevent {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
		return
	}
	defer conn.Close(false)

	upgrade := r.Header.Get("Upgrade") != "" && headerHasToken(r.Header, "Connection", "upgrade")
	st := &reqState{mode: reqMode, response: respMode}
	blocked, v := t.inspectRequest(r, conn, st)
	if blocked {
		logBlock(t.s.endpoint, conn.CID(), "request", v)
		writeBlocked(w, conn.CID(), isDrop(v))
		return
	}
	if upgrade || respMode == modeOff {
		// Upgraded connections (websocket) are only inspected up to the
		// handshake; the response writer is passed through untouched.
		next.ServeHTTP(w, r)
		return
	}
	rw := &respWriter{ResponseWriter: w, t: t, conn: conn, r: r, st: st}
	next.ServeHTTP(rw, r)
	rw.finish()
}

// reqState is shared by the request body reader (run by the upstream
// transport's goroutine) and the response writer. A mutex rather than
// sync/atomic: Yaegi crashes on atomics on fields used across goroutines.
type reqState struct {
	// Effective modes of this request (set before the request is shared).
	mode, response mode

	mu      sync.Mutex
	blocked int // set when a streamed request body was blocked: 1 drop, 2 no verdict
}

// No defer and no helper calls on these hot paths: interpreted calls are
// costly under Yaegi.

func (st *reqState) isBlocked() bool {
	st.mu.Lock()
	b := st.blocked != 0
	st.mu.Unlock()
	return b
}

func (st *reqState) isDrop() bool {
	st.mu.Lock()
	d := st.blocked == 1
	st.mu.Unlock()
	return d
}

func (st *reqState) block(v *Verdict) {
	b := 2
	if isDrop(v) {
		b = 1
	}
	st.mu.Lock()
	st.blocked = b
	st.mu.Unlock()
}

func parseAddr(s string) (Addr, bool) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, false
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	if ip == nil || err != nil {
		return Addr{}, false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return Addr{IP: ip, Port: p}, true
}

func localAddr(r *http.Request) (Addr, bool) {
	// Check for nil before asserting: Yaegi panics on assertions of a nil
	// interface value.
	v := r.Context().Value(http.LocalAddrContextKey)
	if v == nil {
		return Addr{}, false
	}
	if a, ok := v.(net.Addr); ok {
		return parseAddr(a.String())
	}
	return Addr{}, false
}

func requestMeta(r *http.Request) []Meta {
	meta := []Meta{{Tag: MetaProto, Value: r.Proto}}
	if r.TLS != nil {
		if r.TLS.ServerName != "" {
			meta = append(meta, Meta{Tag: MetaSNI, Value: r.TLS.ServerName})
		}
		if r.TLS.NegotiatedProtocol != "" {
			meta = append(meta, Meta{Tag: MetaALPN, Value: r.TLS.NegotiatedProtocol})
		}
	}
	if id := r.Header.Get("X-Request-Id"); id != "" && len(id) <= 128 {
		meta = append(meta, Meta{Tag: MetaRequestID, Value: id})
	}
	return meta
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), token) {
				return true
			}
		}
	}
	return false
}

// isDrop tells a drop verdict from a refusal without one (fail closed).
func isDrop(v *Verdict) bool { return v != nil && v.Action == Drop }

// writeBlocked answers 403 for drop verdicts and 503 when the request was
// refused without one (fail closed). Headers already set for the response
// (by the upstream, e.g. Set-Cookie) are discarded.
func writeBlocked(w http.ResponseWriter, cid uint64, drop bool) {
	h := w.Header()
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	for _, k := range keys {
		h.Del(k)
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Suritap-Cid", strconv.FormatUint(cid, 10))
	if !drop {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "Service Unavailable\n")
		return
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, "Forbidden\n")
}

// inspectRequest sends the request head and body. Bodies up to maxBody are
// buffered and inspected before the request goes upstream; larger ones are
// inspected chunk by chunk as the upstream reads them.
func (t *handler) inspectRequest(r *http.Request, conn Conn, st *reqState) (bool, *Verdict) {
	hasBody := r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	if !hasBody {
		return t.verdict(r.Context(), conn, st.mode, ToServer, requestHead(r, 0))
	}
	var prefix []byte
	if r.ContentLength < 0 || r.ContentLength <= t.s.maxBody {
		data, err := io.ReadAll(io.LimitReader(r.Body, t.s.maxBody+1))
		if err != nil {
			// Truncated client upload: let the upstream see the same
			// failure, after inspecting what arrived.
			r.Body = &errReader{data: data, err: err}
			blocked, v := t.verdict(r.Context(), conn, st.mode, ToServer, append(requestHead(r, int64(len(data))), data...))
			return blocked, v
		}
		if int64(len(data)) <= t.s.maxBody {
			// Complete body: forward it with an explicit length.
			r.Body = io.NopCloser(bytes.NewReader(data))
			r.ContentLength = int64(len(data))
			r.TransferEncoding = nil
			return t.verdict(r.Context(), conn, st.mode, ToServer, append(requestHead(r, r.ContentLength), data...))
		}
		prefix = data
	}
	// Streaming.
	chunked := r.ContentLength < 0
	head := requestHead(r, r.ContentLength)
	if chunked {
		head = append(head, chunk(prefix)...)
	} else {
		head = append(head, prefix...)
	}
	if blocked, v := t.verdict(r.Context(), conn, st.mode, ToServer, head); blocked {
		return true, v
	}
	r.Body = &inspectBody{t: t, conn: conn, ctx: r.Context(), st: st, prefix: bytes.NewReader(prefix), body: r.Body, chunked: chunked}
	return false, nil
}

type errReader struct {
	data []byte
	err  error
}

func (e *errReader) Read(p []byte) (int, error) {
	if len(e.data) > 0 {
		n := copy(p, e.data)
		e.data = e.data[n:]
		return n, nil
	}
	return 0, e.err
}

func (e *errReader) Close() error { return nil }

// inspectBody inspects a large request body while the upstream reads it.
// A drop verdict aborts the upstream request.
type inspectBody struct {
	t       *handler
	conn    Conn
	ctx     context.Context // the request's; Read has no ctx parameter
	st      *reqState
	prefix  *bytes.Reader // already inspected
	body    io.ReadCloser
	chunked bool
	done    bool
}

func (b *inspectBody) Read(p []byte) (int, error) {
	if b.st.isBlocked() {
		return 0, errBlocked
	}
	if b.prefix.Len() > 0 {
		return b.prefix.Read(p)
	}
	n, err := b.body.Read(p)
	if n > 0 {
		data := p[:n]
		if b.chunked {
			data = chunk(data)
		}
		if blocked, v := b.t.verdict(b.ctx, b.conn, b.st.mode, ToServer, data); blocked {
			b.st.block(v)
			logBlock(b.t.s.endpoint, b.conn.CID(), "request body", v)
			return 0, errBlocked
		}
	}
	if err == io.EOF && b.chunked && !b.done {
		b.done = true
		if blocked, v := b.t.verdict(b.ctx, b.conn, b.st.mode, ToServer, []byte("0\r\n\r\n")); blocked {
			b.st.block(v)
			logBlock(b.t.s.endpoint, b.conn.CID(), "request body", v)
			return n, errBlocked
		}
	}
	return n, err
}

func (b *inspectBody) Close() error { return b.body.Close() }

// respWriter forwards the response and inspects it. Detect mode streams it
// to Suricata without waiting. Prevent mode buffers responses up to
// maxResponseBuffer and inspects them complete (a blocked response becomes
// a 403); larger responses, and responses the handler flushes (event
// streams, long polling), are inspected while streaming and the connection
// is aborted when later bytes are dropped.
type respWriter struct {
	http.ResponseWriter
	t    *handler
	conn Conn
	r    *http.Request
	st   *reqState

	status    int  // status set by the handler
	committed bool // status sent to the client
	sentHead  bool // status line sent to Suricata
	chunked   bool
	noBody    bool
	endSent   bool // terminating chunk sent to Suricata
	aborted   bool
	buf       []byte // prevent mode: body held back until inspected
}

func (w *respWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *respWriter) WriteHeader(code int) {
	if w.committed || w.aborted {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code) // informational, not inspected
		return
	}
	if w.st.isBlocked() {
		// The request body was blocked while streaming: answer 403 (or
		// 503) instead of the upstream error.
		w.aborted = true
		writeBlocked(w.ResponseWriter, w.conn.CID(), w.st.isDrop())
		return
	}
	if w.status == 0 {
		w.status = code
	}
	if w.st.response != modePrevent {
		w.commit(nil, false)
	}
}

// head returns the serialized status line and headers (once).
func (w *respWriter) head() []byte {
	if w.sentHead {
		return nil
	}
	w.sentHead = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	h := w.Header()
	w.noBody = w.r.Method == http.MethodHead || w.status == http.StatusNoContent || w.status == http.StatusNotModified
	length := int64(-1)
	if cl := h.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			length = n
		}
	}
	if w.noBody {
		length = 0
	}
	w.chunked = length < 0
	return responseHead(w.status, h, length)
}

// commit inspects (prevent) or sends (detect) the head and body (plus the
// end of a chunked message when final), then writes the status to the
// client. Returns false when blocked.
func (w *respWriter) commit(body []byte, final bool) bool {
	data := w.head()
	if !w.noBody {
		data = append(data, w.frame(body)...)
		if final && w.chunked {
			data = append(data, "0\r\n\r\n"...)
			w.endSent = true
		}
	}
	if blocked, v := w.t.verdict(w.r.Context(), w.conn, w.st.response, ToClient, data); blocked {
		logBlock(w.t.s.endpoint, w.conn.CID(), "response", v)
		w.aborted = true
		writeBlocked(w.ResponseWriter, w.conn.CID(), isDrop(v))
		return false
	}
	w.committed = true
	w.ResponseWriter.WriteHeader(w.status)
	return true
}

func (w *respWriter) frame(p []byte) []byte {
	if w.chunked {
		return chunk(p)
	}
	return p
}

func (w *respWriter) Write(p []byte) (int, error) {
	if w.aborted {
		return 0, errBlocked
	}
	if w.st.isBlocked() && !w.committed {
		w.WriteHeader(http.StatusForbidden)
		return 0, errBlocked
	}
	if !w.committed {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		if w.st.response != modePrevent {
			if !w.commit(p, false) {
				return 0, errBlocked
			}
			return w.ResponseWriter.Write(p)
		}
		if int64(len(w.buf)+len(p)) <= w.t.s.maxRespBuf {
			w.buf = append(w.buf, p...)
			return len(p), nil
		}
		data := append(w.buf, p...)
		w.buf = nil
		if !w.commit(data, false) {
			return 0, errBlocked
		}
		if _, err := w.ResponseWriter.Write(data); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if len(p) > 0 && !w.noBody {
		if blocked, v := w.t.verdict(w.r.Context(), w.conn, w.st.response, ToClient, w.frame(p)); blocked {
			logBlock(w.t.s.endpoint, w.conn.CID(), "response", v)
			w.aborted = true
			// Headers are gone already: abort the connection.
			panic(http.ErrAbortHandler)
		}
	}
	return w.ResponseWriter.Write(p)
}

func (w *respWriter) Flush() {
	if w.aborted {
		return
	}
	if !w.committed {
		// The handler streams: inspect what it wrote so far and send it
		// now instead of holding the response back until it ends.
		if w.status == 0 {
			w.status = http.StatusOK
		}
		data := w.buf
		w.buf = nil
		if !w.commit(data, false) {
			return
		}
		if len(data) > 0 {
			if _, err := w.ResponseWriter.Write(data); err != nil {
				return
			}
		}
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *respWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("suritap: hijacking not supported")
}

// finish completes the response after the handler returned.
func (w *respWriter) finish() {
	if w.aborted {
		return
	}
	if !w.committed {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		if w.commit(w.buf, true) && len(w.buf) > 0 {
			_, _ = w.ResponseWriter.Write(w.buf)
		}
		return
	}
	if w.chunked && !w.noBody && !w.endSent {
		if blocked, v := w.t.verdict(w.r.Context(), w.conn, w.st.response, ToClient, []byte("0\r\n\r\n")); blocked {
			logBlock(w.t.s.endpoint, w.conn.CID(), "response end", v)
			// The body is out already; abort so the client sees a
			// truncated response instead of a complete one.
			panic(http.ErrAbortHandler)
		}
	}
}

// requestHead serializes the request line and headers as HTTP/1.1.
// length: >0 Content-Length, 0 no body, <0 chunked.
func requestHead(r *http.Request, length int64) []byte {
	var b bytes.Buffer
	uri := r.RequestURI
	if uri == "" || r.ProtoMajor >= 2 && !strings.HasPrefix(uri, "/") && uri != "*" {
		uri = r.URL.RequestURI()
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", r.Method, uri)
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", host)
	}
	writeHeaders(&b, r.Header, "Host")
	writeFraming(&b, length)
	b.WriteString("\r\n")
	return b.Bytes()
}

func responseHead(status int, h http.Header, length int64) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	writeHeaders(&b, h, "")
	if length != 0 || h.Get("Content-Length") != "" {
		writeFraming(&b, length)
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

func writeHeaders(b *bytes.Buffer, h http.Header, skip string) {
	keys := make([]string, 0, len(h))
	for k := range h {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Transfer-Encoding", "Trailer":
			continue
		}
		if skip != "" && http.CanonicalHeaderKey(k) == skip {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
}

func writeFraming(b *bytes.Buffer, length int64) {
	switch {
	case length > 0:
		fmt.Fprintf(b, "Content-Length: %d\r\n", length)
	case length < 0:
		b.WriteString("Transfer-Encoding: chunked\r\n")
	}
}

func chunk(p []byte) []byte {
	if len(p) == 0 {
		return nil
	}
	out := make([]byte, 0, len(p)+16)
	out = strconv.AppendInt(out, int64(len(p)), 16)
	out = append(out, '\r', '\n')
	out = append(out, p...)
	return append(out, '\r', '\n')
}

// verdict sends data and reports whether the traffic must be blocked. In
// detect mode it never waits.
func (t *handler) verdict(ctx context.Context, conn Conn, m mode, dir Dir, data []byte) (bool, *Verdict) {
	if m == modeOff {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, t.s.timeout)
	defer cancel()
	if m == modeDetect {
		// Payload that could not be sent in time is reported to the
		// engine as a gap by the transport; detect mode never blocks.
		_ = conn.Send(ctx, dir, data)
		return false, nil
	}
	v, err := conn.Inspect(ctx, dir, data)
	switch {
	case err != nil:
		Logf(false, "no verdict for cid %d (%s): %v", conn.CID(), t.s.endpoint, err)
		return t.s.failClosed, nil
	case v.Action == Drop:
		return true, &v
	case v.Action == Error:
		return t.s.failClosed, &v
	}
	return false, &v
}

var (
	unavailMu   sync.Mutex
	unavailLast time.Time
)

// logUnavailable reports transport failures at most every 10 seconds.
func logUnavailable(endpoint string, err error) {
	unavailMu.Lock()
	defer unavailMu.Unlock()
	if time.Since(unavailLast) < 10*time.Second {
		return
	}
	unavailLast = time.Now()
	Logf(true, "cannot reach Suricata (%s): %v", endpoint, err)
}

func logBlock(endpoint string, cid uint64, what string, v *Verdict) {
	if v != nil {
		Logf(true, "blocked %s on %s: cid=%d reason=%s sids=%v", what, endpoint, cid, v.ReasonString(), v.SIDs)
		return
	}
	Logf(true, "blocked %s on %s: cid=%d (no verdict, fail closed)", what, endpoint, cid)
}

var (
	transportsMu sync.Mutex
	transports   = map[string]*StreamTransport{}
)

// sharedTransport returns one transport per socket directory and client
// name: Traefik creates a middleware instance per router and on every
// configuration reload.
func sharedTransport(dir, name string) Transport {
	transportsMu.Lock()
	defer transportsMu.Unlock()
	key := dir + "\x00" + name
	t, ok := transports[key]
	if !ok {
		t = NewStreamTransport(dir, name)
		transports[key] = t
	}
	return t
}
