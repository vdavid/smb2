# smb2 Development Commands
# =========================
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
    @cargo fmt
    @echo "[+] Formatted"

# Check formatting without modifying files (for CI)
fmt-check:
    @echo "[*] Checking formatting..."
    @cargo fmt --check
    @echo "[+] Formatting OK"

# Run clippy with strict warnings
clippy:
    @echo "[*] Running clippy..."
    @cargo clippy --all-targets --quiet -- -D warnings
    @echo "[+] Clippy passed"

# Run tests
test:
    @echo "[*] Running tests..."
    @cargo test --quiet
    @echo "[+] Tests passed"

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

# Run fast checks: fmt-check, clippy, test, doc
check: fmt-check clippy test doc
    @echo ""
    @echo "[+] All fast checks passed!"

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
