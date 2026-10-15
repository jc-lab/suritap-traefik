// Package suritap is a Traefik middleware plugin (Yaegi) that inspects
// decrypted HTTP traffic with Suricata through the suritap plugin's socket
// transport (worker-N.stream.sock).
//
// Each request is normalized to HTTP/1.1 and inspected on its own
// synthetic flow before it reaches the next handler; drop verdicts become
// 403 responses carrying X-Suritap-Cid (the cid logged in EVE). Small
// request bodies are buffered and inspected before forwarding, larger ones
// while streaming. Responses can be ignored, sent without waiting
// (detect) or inspected (prevent).
//
// The package uses only the standard library so it runs unmodified in
// Traefik's interpreter. NewHandler also accepts another Transport, which
// lets natively compiled proxies use the shared-memory client.
package suritap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config is the plugin configuration (Traefik dynamic configuration,
// http.middlewares.<name>.plugin.suritap).
type Config struct {
	SocketDir         string `description:"Directory of the Suricata suritap worker sockets." json:"socketDir,omitempty" toml:"socketDir,omitempty" yaml:"socketDir,omitempty" export:"true"`
	Mode              string `description:"prevent (block on drop verdicts, default) or detect (never wait for verdicts)." json:"mode,omitempty" toml:"mode,omitempty" yaml:"mode,omitempty" export:"true"`
	FailPolicy        string `description:"Without a verdict (Suricata down, timeout): open (default) or closed." json:"failPolicy,omitempty" toml:"failPolicy,omitempty" yaml:"failPolicy,omitempty" export:"true"`
	Timeout           string `description:"Verdict timeout (default 100ms)." json:"timeout,omitempty" toml:"timeout,omitempty" yaml:"timeout,omitempty" export:"true"`
	MaxRequestBody    int64  `description:"Request bodies up to this size are buffered and inspected before forwarding (default 1048576); larger ones while streaming." json:"maxRequestBody,omitempty" toml:"maxRequestBody,omitempty" yaml:"maxRequestBody,omitempty" export:"true"`
	Response          string `description:"Response inspection: off, detect (default) or prevent." json:"response,omitempty" toml:"response,omitempty" yaml:"response,omitempty" export:"true"`
	MaxResponseBuffer int64  `description:"Prevent mode: responses up to this size are inspected complete before they are sent (default 65536)." json:"maxResponseBuffer,omitempty" toml:"maxResponseBuffer,omitempty" yaml:"maxResponseBuffer,omitempty" export:"true"`
	Name              string `description:"Client name reported to Suricata (default traefik)." json:"name,omitempty" toml:"name,omitempty" yaml:"name,omitempty" export:"true"`
	Endpoint          string `description:"Endpoint name logged in EVE (default: the middleware name)." json:"endpoint,omitempty" toml:"endpoint,omitempty" yaml:"endpoint,omitempty" export:"true"`
}

// CreateConfig returns the default configuration (Traefik plugin API).
func CreateConfig() *Config {
	return &Config{}
}

// New creates the middleware (Traefik plugin API).
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	s, err := cfg.settings(name)
	if err != nil {
		return nil, err
	}
	return newHandler(next, s, sharedTransport(s.dir, s.name)), nil
}

// NewHandler creates the middleware with a caller-provided transport.
func NewHandler(next http.Handler, cfg *Config, name string, t Transport) (http.Handler, error) {
	s, err := cfg.settings(name)
	if err != nil {
		return nil, err
	}
	return newHandler(next, s, t), nil
}

type mode int

const (
	modeOff mode = iota
	modeDetect
	modePrevent
)

func parseMode(s string, def mode, allowOff bool) (mode, error) {
	switch strings.ToLower(s) {
	case "":
		return def, nil
	case "detect":
		return modeDetect, nil
	case "prevent":
		return modePrevent, nil
	case "off":
		if allowOff {
			return modeOff, nil
		}
	}
	return 0, fmt.Errorf("invalid mode %q", s)
}

type settings struct {
	dir        string
	name       string
	endpoint   string
	mode       mode
	response   mode
	failClosed bool
	timeout    time.Duration
	maxBody    int64
	maxRespBuf int64
}

func (c *Config) settings(middleware string) (settings, error) {
	s := settings{dir: c.SocketDir, name: c.Name, endpoint: c.Endpoint, timeout: 100 * time.Millisecond, maxBody: 1 << 20, maxRespBuf: 64 << 10}
	if s.dir == "" {
		s.dir = "/run/suritap"
	}
	if s.name == "" {
		s.name = "traefik"
	}
	if s.endpoint == "" {
		s.endpoint = middleware
	}
	var err error
	if s.mode, err = parseMode(c.Mode, modePrevent, false); err != nil {
		return s, fmt.Errorf("suritap mode: %v", err)
	}
	if s.response, err = parseMode(c.Response, modeDetect, true); err != nil {
		return s, fmt.Errorf("suritap response: %v", err)
	}
	switch strings.ToLower(c.FailPolicy) {
	case "", "open":
	case "closed":
		s.failClosed = true
	default:
		return s, fmt.Errorf("suritap failPolicy: invalid value %q", c.FailPolicy)
	}
	if c.Timeout != "" {
		if s.timeout, err = time.ParseDuration(c.Timeout); err != nil || s.timeout <= 0 {
			return s, fmt.Errorf("suritap timeout: invalid duration %q", c.Timeout)
		}
	}
	if c.MaxRequestBody < 0 || c.MaxResponseBuffer < 0 {
		return s, errors.New("suritap: body limits must not be negative")
	}
	if c.MaxRequestBody > 0 {
		s.maxBody = c.MaxRequestBody
	}
	if c.MaxResponseBuffer > 0 {
		s.maxRespBuf = c.MaxResponseBuffer
	}
	return s, nil
}

// Logf receives the plugin's log lines (warn: block decisions and errors).
// Under Traefik, stdout is logged at debug and stderr at error level.
var Logf = func(warn bool, format string, args ...interface{}) {
	out := os.Stdout
	if warn {
		out = os.Stderr
	}
	fmt.Fprintf(out, "suritap: "+format+"\n", args...)
}
