# Contributing to curf

Thanks for your interest! Here's everything you need to know.

## Philosophy

curf aims to be **simple**. Before adding a feature, ask:
> "Would a beginner reading curf.yml understand what this does in 10 seconds?"

If not, it probably belongs in a plugin or a separate tool.

## Development setup

```bash
# Requires Rust (https://rustup.rs)
git clone https://github.com/thetuxuser/curf
cd curf

# Run in debug mode (fast rebuild)
cargo run -- --config examples/curf-minimal.yml --http-port 8080

# Run tests
cargo test

# Check for warnings
cargo clippy

# Check formatting
cargo fmt --check

# Fix formatting
cargo fmt
```

## Making changes

1. **Open an issue first** for anything larger than a bug fix or small improvement.
2. Fork the repo and create a branch: `git checkout -b my-feature`
3. Write your code. Keep modules focused and add doc comments.
4. Run `cargo fmt`, `cargo clippy`, and `cargo test` before pushing.
5. Open a pull request. Describe *what* you changed and *why*.

## Code style

- Every `pub` struct, function, and field should have a doc comment.
- Every module (`mod foo`) should have a module-level doc comment (`//! ...` or `/// ...` at top).
- Prefer `anyhow` for error propagation in application code.
- Avoid `unwrap()` in non-test code — use `?` or handle the error.
- Keep dependencies minimal. Check if the stdlib or an existing dep covers the need first.

## Reporting bugs

Please include:
- Your `curf.yml` (redact any secrets)
- The curf version (`curf --version`)
- The full error output with `RUST_LOG=debug`
- Steps to reproduce

## Security issues

Please **do not** open a public issue for security vulnerabilities.  
Email the maintainer directly (see the GitHub profile) or use GitHub's private security advisory feature.
