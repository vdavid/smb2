# smb2 workspace development commands
# ===================================
#
# Available commands (run `just --list` for details):
#
#   Individual checks:
#     fmt         - Format code with cargo fmt
#     fmt-check   - Check formatting (CI mode)
#     clippy      - Run clippy with -D warnings
#     test        - Run tests
#     doc         - Build documentation
#     msrv        - Check MSRV (1.85) compatibility
#     audit       - Security audit (requires cargo-audit)
#     deny        - License/dependency check (requires cargo-deny)
#     udeps       - Find unused dependencies (requires nightly + cargo-udeps)
#
#   Composite commands:
#     check       - Run fast checks: fmt-check, clippy, test, doc (default)
#     check-all   - Run all checks including audit and deny
#     fix         - Auto-fix formatting and clippy warnings
#
#   Utility commands:
#     toolchain-fresh - Update the stable toolchain to match CI (runs as part of check)
#     clean       - Remove build artifacts
#     install-tools - Install required development tools
#
# MSRV: 1.85

set shell := ["bash", "-uc"]

# Default recipe - run fast checks
default: check

# ==============================================================================
# Individual Checks
# ==============================================================================

# Format code with cargo fmt
fmt:
    @echo "[*] Formatting..."
    @cargo fmt --all
    @echo "[+] Formatted"

# Check formatting without modifying files (for CI)
fmt-check:
    @echo "[*] Checking formatting..."
    @cargo fmt --all --check
    @echo "[+] Formatting OK"

# Run clippy with strict warnings
clippy:
    @echo "[*] Running clippy..."
    @cargo clippy --all-targets --quiet -- -D warnings
    @echo "[*] Running clippy with all features..."
    @cargo clippy --all-targets --all-features --quiet -- -D warnings
    @echo "[+] Clippy passed"

# Run tests
test:
    @echo "[*] Running tests..."
    @cargo test --quiet
    @echo "[*] Running tests with all features..."
    @cargo test --all-features --quiet
    @echo "[+] Tests passed"

# Run integration tests against real SMB servers (requires NAS + Pi on LAN)
test-integration:
    @echo "[*] Running integration tests..."
    @cargo test -p smb2 --test integration -- --ignored --quiet
    @echo "[+] Integration tests passed"

# Run Docker integration tests (starts/stops containers automatically)
test-docker:
    @echo "[*] Starting Docker containers..."
    @./crates/smb2/tests/docker/start.sh internal
    @echo "[*] Running Docker integration tests..."
    @cargo test -p smb2 --test docker_integration -- --ignored --quiet && \
        (echo "[*] Stopping Docker containers..." && ./crates/smb2/tests/docker/stop.sh && echo "[+] Docker integration tests passed") || \
        (echo "[*] Stopping Docker containers..." && ./crates/smb2/tests/docker/stop.sh && exit 1)

# Run consumer integration tests (starts/stops containers automatically)
test-consumer:
    @echo "[*] Starting consumer containers..."
    @./crates/smb2/tests/docker/start.sh consumer
    @echo "[*] Running consumer integration tests..."
    @cargo test -p smb2 --features testing --test consumer_integration -- --ignored --quiet && \
        (echo "[*] Stopping consumer containers..." && ./crates/smb2/tests/docker/stop.sh && echo "[+] Consumer integration tests passed") || \
        (echo "[*] Stopping consumer containers..." && ./crates/smb2/tests/docker/stop.sh && exit 1)

# Build documentation
doc:
    @echo "[*] Building docs..."
    @cargo doc --no-deps --quiet
    @echo "[+] Docs built"

# Check MSRV compatibility (requires rustup with 1.85 toolchain)
msrv:
    @echo "[*] Checking MSRV (1.85) compatibility..."
    @if ! rustup run 1.85.0 rustc --version &> /dev/null; then \
        echo "[!] Rust 1.85 not found. Install with: rustup toolchain install 1.85.0"; \
        exit 1; \
    fi
    @RUSTFLAGS="-D warnings" cargo +1.85.0 check --quiet
    @cargo +1.85.0 clippy --all-targets --quiet -- -D warnings
    @echo "[+] MSRV check passed"

# Run security audit (requires cargo-audit)
audit:
    @echo "[*] Running security audit..."
    @if ! command -v cargo-audit &> /dev/null; then \
        echo "[!] cargo-audit not found. Install with: just install-tools"; \
        exit 1; \
    fi
    @cargo audit --deny warnings
    @echo "[+] Security audit passed"

# Run cargo-deny checks (requires cargo-deny)
deny:
    @echo "[*] Running cargo-deny..."
    @if ! command -v cargo-deny &> /dev/null; then \
        echo "[!] cargo-deny not found. Install with: just install-tools"; \
        exit 1; \
    fi
    @cargo deny --log-level error check
    @echo "[+] Cargo deny passed"

# Find unused dependencies (requires nightly + cargo-udeps)
udeps:
    @echo "[*] Checking for unused dependencies..."
    @if ! command -v cargo-udeps &> /dev/null; then \
        echo "[!] cargo-udeps not found. Install with: just install-tools"; \
        exit 1; \
    fi
    @if ! rustup run nightly rustc --version &> /dev/null; then \
        echo "[!] Nightly toolchain not found. Install with: rustup install nightly"; \
        exit 1; \
    fi
    cargo +nightly udeps --all-targets
    @echo "[+] No unused dependencies found"

# ==============================================================================
# Composite Commands
# ==============================================================================

# Keep the local stable toolchain current so checks run against the same
# clippy/rustc as CI (CI always installs the latest stable; a stale local
# stable once passed `just check` while CI's newer clippy failed the same
# code). Soft-fails offline: checking against a slightly-stale stable beats
# blocking all local work.
toolchain-fresh:
    @echo "[*] Updating stable toolchain (CI runs latest stable)..."
    @rustup update stable --no-self-update || echo "[!] Couldn't update stable (offline?); continuing with the installed one"
    @echo "[+] Toolchain: $(rustc --version)"

# Run fast checks: fmt-check, clippy, test, doc (on a current stable toolchain)
check: toolchain-fresh fmt-check clippy test doc
    @echo ""
    @echo "[+] All fast checks passed!"

# Run fast checks + integration tests against real servers
check-live: check test-integration
    @echo ""
    @echo "[+] All checks + integration tests passed!"

# Run all checks including slow ones: check + msrv + audit + deny
check-all: check msrv audit deny
    @echo ""
    @echo "[+] All checks passed!"

# Auto-fix formatting and clippy warnings
fix: fmt
    @echo "[*] Running clippy --fix..."
    @cargo clippy --all-targets --fix --allow-dirty --allow-staged --quiet -- -D warnings
    @echo "[+] Fixed"

# ==============================================================================
# Utility Commands
# ==============================================================================

# Remove build artifacts
clean:
    @echo "[*] Cleaning build artifacts..."
    cargo clean
    @echo "[+] Clean complete"

# Run a single fuzz target for a short sweep (default: 5 minutes).
# Example: `just fuzz fuzz_header_parse` or `just fuzz fuzz_frame_parse 1800`.
# Requires the nightly toolchain and `cargo-fuzz` (run `cargo install cargo-fuzz`).
fuzz target duration="300":
    @if ! rustup run nightly rustc --version &> /dev/null; then \
        echo "[!] Nightly toolchain not found. Install with: rustup toolchain install nightly"; \
        exit 1; \
    fi
    @if ! command -v cargo-fuzz &> /dev/null; then \
        echo "[!] cargo-fuzz not found. Install with: cargo install cargo-fuzz"; \
        exit 1; \
    fi
    @echo "[*] Fuzzing {{target}} for {{duration}}s..."
    # cargo-fuzz looks for `fuzz/` beside the package it targets, so run from the library crate.
    cd crates/smb2 && cargo +nightly fuzz run {{target}} -- -max_total_time={{duration}} -print_final_stats=1

# Regenerate the committed seed corpus under `fuzz/corpus/`.
fuzz-seeds:
    @echo "[*] Regenerating fuzz seed corpus..."
    @cargo test -p smb2 --test fuzz_seeds -- --ignored --nocapture
    @echo "[+] Seed corpus updated"

# Install required development tools
install-tools:
    @echo "[*] Installing development tools..."
    @echo ""
    @echo "Installing cargo-audit..."
    cargo install cargo-audit
    @echo ""
    @echo "Installing cargo-deny..."
    cargo install cargo-deny
    @echo ""
    @echo "Installing cargo-udeps (requires nightly)..."
    rustup install nightly
    cargo install cargo-udeps
    @echo ""
    @echo "[+] All tools installed"
