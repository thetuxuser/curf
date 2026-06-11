# curf

A simple, fast reverse proxy and web server written in Rust.  
Designed to be easy to understand and use — simpler than nginx for common tasks.

```
                  ┌────────────────────────────────────┐
  Browser  ──────▶│  curf  (port 80 / 443)             │──────▶  Your app (port 3000)
                  │  • TLS termination                  │
                  │  • Load balancing                   │──────▶  Your app (port 3001)
                  │  • Static files                     │
                  │  • Rate limiting + WAF              │──────▶  Your app (port 3002)
                  └────────────────────────────────────┘
```

## Features

- **Reverse proxy** — forward requests to one or many backend servers
- **Load balancing** — round-robin, least-connections, or IP hash
- **Circuit breaker** — automatically routes around broken backends
- **TLS (HTTPS)** — multi-domain SNI support with Let's Encrypt certificates
- **Static files** — serve HTML/CSS/JS directly, with caching headers
- **HTTP → HTTPS redirect** — one line of config
- **Rate limiting** — per-IP token-bucket limiter
- **Basic WAF** — blocks SQLi, XSS, and path-traversal patterns
- **WebSocket** — transparently proxied
- **Health checks** — periodic checks; unhealthy backends are skipped

## Quick start

### 1. Install

```bash
# From source (requires Rust — https://rustup.rs)
git clone https://github.com/thetuxuser/curf
cd curf
cargo build --release
sudo cp target/release/curf /usr/local/bin/curf
```

### 2. Create a config file

The smallest possible config (`curf.yml`):

```yaml
domains:
  localhost:
    backends:
      - http://127.0.0.1:3000
```

That's it. curf will listen on port 80 and forward everything to your app on port 3000.

See [`examples/curf.yml`](examples/curf.yml) for a fully annotated example with TLS, load balancing, and static files.

### 3. Run

```bash
# Default config file is curf.yml in the current directory
curf

# Or specify a path
curf --config /etc/curf/curf.yml

# Override the HTTP port without editing the config
curf --http-port 8080
```

Control log verbosity with the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug curf      # verbose — shows every request
RUST_LOG=warn curf       # quiet   — only warnings and errors
```

---

## Configuration reference

All settings are in a single YAML file. Only `domains` is required; everything else has a sensible default.

### `server` (optional, global settings)

```yaml
server:
  http_port: 80             # HTTP port (default: 80)
  https_port: 443           # HTTPS port (default: 443)
  timeout_secs: 30          # Request timeout in seconds (default: 30)
  max_connections: 10000    # Max simultaneous connections (default: 10000)
  max_connections_per_ip: 100  # Per-IP limit (default: 100)
  rate_limit_rps: 100       # Max requests/sec per IP — 0 disables (default: 100)
  rate_limit_burst: 200     # Burst allowance (default: 200)
```

### `server.security` (optional)

```yaml
server:
  security:
    waf_sqli: true           # Block SQL injection patterns (default: true)
    waf_xss: true            # Block XSS patterns (default: true)
    waf_path_traversal: true # Block ../ traversal (default: true)
    block_tls_abusers: true  # Block IPs with many TLS failures (default: true)
    max_tls_failures: 10     # Failures before blocking (default: 10)
    block_empty_user_agent: false  # Block empty User-Agent (default: false)
```

### `domains.<name>` (required — at least one)

Each key is a domain name matched against the HTTP `Host` header.

#### Reverse proxy

```yaml
domains:
  example.com:
    backends:
      - http://127.0.0.1:3000   # One backend
      # or multiple for load balancing:
      - http://127.0.0.1:3001
      - http://127.0.0.1:3002

    load_balance: round_robin   # round_robin | least_connections | ip_hash
```

#### TLS (HTTPS)

```yaml
    tls:
      cert: /path/to/fullchain.pem
      key:  /path/to/privkey.pem
```

#### HTTP → HTTPS redirect

```yaml
    redirect_to_https: true
```

#### Static files

```yaml
    static_files:
      root: /var/www/mysite   # absolute path
      index:
        - index.html
      autoindex: false        # directory listing
```

You can combine `static_files` and `backends` — curf serves the file if it exists, otherwise proxies to the backend. This is perfect for single-page apps.

#### Health checks

```yaml
    health_check:
      enabled: true
      interval_secs: 15
      timeout_secs: 5
      path: /health
```

#### Extra response headers

```yaml
    headers:
      - name: Strict-Transport-Security
        value: "max-age=31536000"
      - name: X-Frame-Options
        value: SAMEORIGIN
```

---

## Running as a systemd service

Create `/etc/systemd/system/curf.service`:

```ini
[Unit]
Description=curf reverse proxy
After=network.target

[Service]
Type=simple
User=www-data
ExecStart=/usr/local/bin/curf --config /etc/curf/curf.yml
Restart=on-failure
RestartSec=5s
# Allow binding to ports 80 and 443 without root
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now curf
sudo systemctl status curf
```

---

## Getting free TLS certificates with Let's Encrypt

```bash
# Install certbot
sudo apt install certbot

# Get a certificate (temporarily stop curf if it's running on port 80)
sudo certbot certonly --standalone -d example.com

# Certificates are placed in:
#   /etc/letsencrypt/live/example.com/fullchain.pem
#   /etc/letsencrypt/live/example.com/privkey.pem
```

Then in your `curf.yml`:

```yaml
domains:
  example.com:
    backends:
      - http://127.0.0.1:3000
    redirect_to_https: true
    tls:
      cert: /etc/letsencrypt/live/example.com/fullchain.pem
      key:  /etc/letsencrypt/live/example.com/privkey.pem
```

---

## Differences from nginx

| Feature | nginx | curf |
|---|---|---|
| Config format | nginx.conf (custom syntax) | YAML |
| Multiple domains | `server { }` blocks | keys under `domains:` |
| Reverse proxy | `proxy_pass` | `backends:` list |
| Load balancing | `upstream { }` block | `load_balance: round_robin` |
| Static files | `root` + `try_files` | `static_files.root` |
| TLS | `ssl_certificate` etc. | `tls.cert` + `tls.key` |
| Reload config | `nginx -s reload` | restart process (hot-reload planned) |
| Modules | many | built-in features only |

curf does less than nginx by design — it covers the most common use cases with the simplest config possible.

---

## Building from source

```bash
# Debug build (faster to compile, good for development)
cargo build

# Release build (optimized, for production)
cargo build --release
```

---

## License

MIT — see [LICENSE](LICENSE)

## Contributing

Pull requests are welcome. Please keep the code simple and well-commented.
Open an issue before starting large changes.
