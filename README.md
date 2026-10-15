# suritap-traefik

Traefik middleware plugin that inspects decrypted HTTP traffic with
[Suricata](https://suricata.io/) and blocks requests (and optionally
responses) on drop verdicts.

It is the Traefik adapter of **suritap**, part of
[jc-lab/suricontroller](https://github.com/jc-lab/suricontroller): Suricata
runs the suritap capture plugin, and proxies hand it the plaintext of the
TLS connections they terminate. This plugin talks to it over the plugin's
socket transport (`worker-N.stream.sock`), uses only the Go standard
library and runs in Traefik's Yaegi interpreter, so it works with the
official Traefik binary.

- Each request is normalized to HTTP/1.1 and inspected on its own synthetic
  flow before it reaches the router's service (HTTP/1.1, HTTP/2 and HTTP/3
  alike).
- A drop verdict answers `403` with `X-Suritap-Cid` (the `suritap.cid`
  logged in Suricata's EVE); without a verdict (Suricata down, timeout) the
  request passes or gets `503`, as configured.
- Small request bodies are buffered and inspected before forwarding, larger
  ones while the upstream reads them. Responses are ignored, streamed to
  Suricata without waiting (detect) or inspected before they are sent
  (prevent).
- When suri-controller manages the Suricata instance, the operator's
  endpoint mode (Off / Detect / Prevent), pushed by the suritap plugin,
  overrides `mode` for the endpoint; endpoints it does not list keep this
  configuration.

## Requirements

- Suricata 8 with the suritap capture plugin
  (`suricata --capture-plugin=suritap`), e.g. the suri-node-agent image of
  suricontroller with `tap.enabled`.
- The plugin's socket directory (default `/run/suritap`) mounted into the
  Traefik container and writable by Traefik's user.

## Configuration

Static configuration:

```yaml
experimental:
  plugins:
    suritap:
      moduleName: github.com/jc-lab/suritap-traefik
      version: v0.1.0
```

(or as a local plugin: the sources under
`plugins-local/src/github.com/jc-lab/suritap-traefik` and
`experimental.localPlugins.suritap.moduleName` set to the same path)

Dynamic configuration:

```yaml
http:
  middlewares:
    tap:
      plugin:
        suritap:
          socketDir: /run/suritap
          endpoint: websecure    # name reported to Suricata (EVE suritap.endpoint)
          mode: prevent          # prevent | detect
          response: detect       # off | detect | prevent
          failPolicy: open       # open | closed
          timeout: 100ms
          maxRequestBody: 1048576
          maxResponseBuffer: 65536
  routers:
    app:
      rule: Host(`app.example.com`)
      middlewares: [tap]
      service: app
      tls: {}
```

| Option | Default | Description |
|---|---|---|
| `socketDir` | `/run/suritap` | Directory of the suritap worker sockets |
| `mode` | `prevent` | `prevent`: block on drop verdicts; `detect`: never wait for verdicts |
| `response` | `detect` | `off`, `detect` or `prevent` (buffered up to `maxResponseBuffer`, then inspected while streaming) |
| `failPolicy` | `open` | Without a verdict: `open` (pass) or `closed` (`503`) |
| `timeout` | `100ms` | Verdict timeout |
| `maxRequestBody` | 1 MiB | Request bodies up to this size are inspected before forwarding; larger ones while streaming |
| `maxResponseBuffer` | 64 KiB | Prevent mode: responses up to this size are inspected complete before they are sent |
| `name` | `traefik` | Client name reported to Suricata |
| `endpoint` | middleware name | Endpoint name (EVE `suritap.endpoint`; key of the operator's endpoint policy) |

Logs: block decisions and errors go to stderr (Traefik logs them at ERROR),
the rest to stdout (DEBUG).

## Documentation

Protocol, design, Yaegi notes and benchmarks:
[docs/suritap.md](https://github.com/jc-lab/suricontroller/blob/main/docs/suritap.md)
in suricontroller.

## Development

The tests use `suritap-mockd` from suricontroller. In suricontroller this
repository is the submodule `adapters/traefik-plugin`; `make tap-test`
there builds the mock and runs these tests, a Yaegi harness that loads the
plugin the way Traefik does, and `make tap-traefik` an end-to-end test with
the official Traefik binary and a real Suricata.

## License

[MPL-2.0](LICENSE)
