# Changelog

All notable changes to curf will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] — 2026-06-11

Initial release of **curf**, forked and heavily refactored from *crucible*.

### Added
- YAML-based configuration (`curf.yml`) with inline comments and sensible defaults
- Reverse proxy with HTTP/1.1 support
- Load balancing: `round_robin`, `least_connections`, `ip_hash`
- Circuit breaker per backend (opens after 5 failures, resets after 30s)
- Background health checker — unhealthy backends are automatically skipped
- TLS (HTTPS) with multi-domain SNI via `rustls` (no OpenSSL dependency)
- HTTP → HTTPS redirect (`redirect_to_https: true`)
- Static file server with ETag, Last-Modified, and directory index support
- Static files + backend fallback (ideal for SPAs with an API)
- Directory listing (`autoindex: true`)
- WebSocket proxying
- Token-bucket rate limiter per IP
- Per-IP connection cap
- Basic WAF: SQLi, XSS, and path-traversal pattern detection
- TLS abuse detection — blocks IPs with repeated handshake failures
- `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host` headers on proxy requests
- Custom response headers per domain
- CLI flags: `--config`, `--http-port`, `--https-port`
- `RUST_LOG` environment variable for log verbosity control
- GitHub Actions CI (build, lint, format check)
- GitHub Actions release (cross-compiled binaries for Linux/macOS/Windows)
- MIT license
- Beginner-friendly README with nginx comparison table

### Changed vs crucible
- Replaced custom challenge/proof-of-work with standard rate limiting
- Replaced OpenSSL with `rustls` — no system library dependency
- Simplified config schema — removed obscure options, kept common ones
- Reduced dependency count significantly
- Every public API and config field is documented
- All modules have module-level doc comments explaining purpose
- Error messages are human-readable and actionable
- Health checks use a dependency-free raw TCP implementation

### Fixed
- Path traversal in static file server was not fully sanitised (now rejects all `..` components)
- Per-IP connection counter could underflow on rapid connect/disconnect
- TLS handshake was not time-bounded (now 10s timeout)
- WebSocket tunnel did not properly close both directions on half-close
- Backend URL rewriting preserved incorrect authority component in some cases
