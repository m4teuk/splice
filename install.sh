#!/usr/bin/env bash
# splice client installer — builds `spl` from source and installs it to
# ~/.local/bin. No root required.
#
#   From a checkout:  bash install.sh
#   One-liner:        curl -fsSL https://raw.githubusercontent.com/m4teuk/splice/main/install.sh | bash
#
# Rust is bootstrapped automatically if missing. The C/C++ toolchain, CMake,
# Ninja, pkg-config and OpenSSL 3 headers must already be present — if any are
# missing the script prints the one command to install them (which needs sudo)
# and stops. It never runs sudo itself.
#
# Override the install dir with SPL_PREFIX=/somewhere/bin bash install.sh
set -euo pipefail

REPO_URL="https://github.com/m4teuk/splice.git"
PREFIX="${SPL_PREFIX:-$HOME/.local/bin}"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m xx\033[0m %s\n' "$*" >&2; exit 1; }

# --- package-manager hint for missing build tools (printed, never executed) ---
install_hint() {
    if   command -v apt-get >/dev/null 2>&1; then
        echo "sudo apt-get install -y build-essential cmake ninja-build pkg-config libssl-dev git"
    elif command -v dnf     >/dev/null 2>&1; then
        echo "sudo dnf install -y gcc-c++ cmake ninja-build pkgconf-pkg-config openssl-devel git"
    elif command -v pacman  >/dev/null 2>&1; then
        echo "sudo pacman -S --needed base-devel cmake ninja pkgconf openssl git"
    elif command -v brew    >/dev/null 2>&1; then
        echo "brew install cmake ninja openssl@3 pkg-config git   (plus: xcode-select --install)"
    else
        echo "(install a C++ toolchain, cmake, ninja, pkg-config and OpenSSL 3 headers)"
    fi
}

# --- 1. locate the source: a checkout next to us, or a throwaway clone ---
SELF="${BASH_SOURCE[0]:-}"
SRC=""
if [ -n "$SELF" ] && [ -f "$(cd "$(dirname "$SELF")" && pwd)/CMakeLists.txt" ]; then
    SRC="$(cd "$(dirname "$SELF")" && pwd)"
    say "Building from this checkout: $SRC"
else
    command -v git >/dev/null 2>&1 || die "git is required to fetch the source.  Try:  $(install_hint)"
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    say "Cloning $REPO_URL"
    git clone --depth 1 "$REPO_URL" "$TMP/splice" >/dev/null 2>&1 || die "git clone failed"
    SRC="$TMP/splice"
fi

# --- 2. check the build prerequisites (Rust is handled separately below) ---
missing=()
for tool in cc c++ cmake ninja pkg-config git; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if ! pkg-config --exists openssl 2>/dev/null; then
    missing+=("openssl-dev")
elif ! pkg-config --atleast-version=3 openssl 2>/dev/null; then
    warn "OpenSSL < 3 detected; splice needs OpenSSL 3 (EVP_EC_gen). Build may fail."
fi
if [ "${#missing[@]}" -gt 0 ]; then
    warn "missing build tools: ${missing[*]}"
    die "install them first, then re-run.  Try:\n      $(install_hint)"
fi

# macOS specifics.
if [ "$(uname -s)" = "Darwin" ]; then
    # Pin one deployment target for the whole build so the Rust (cc) objects and
    # the C++ objects agree — otherwise the linker warns "built for newer macOS
    # version" once per object in the crypto staticlib.
    export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-$(sw_vers -productVersion 2>/dev/null)}"
    # Point CMake at Homebrew's OpenSSL 3 instead of the system LibreSSL.
    if command -v brew >/dev/null 2>&1; then
        brew_ssl="$(brew --prefix openssl@3 2>/dev/null || true)"
        [ -n "$brew_ssl" ] && export OPENSSL_ROOT_DIR="$brew_ssl"
    fi
fi

# --- 3. ensure an up-to-date Rust (no sudo; rustup installs under ~/.cargo) ---
# Our Cargo.lock is format v4, which needs Cargo >= 1.78. Distro packages (e.g.
# Debian's /usr/bin/cargo) are often older, so check the version, not just that a
# cargo exists. ~/.cargo/bin goes first on PATH so rustup's toolchain wins.
export PATH="$HOME/.cargo/bin:$PATH"
MIN_CARGO_MINOR=78
cargo_ok() {
    command -v cargo >/dev/null 2>&1 || return 1
    local v major minor
    v="$(cargo --version 2>/dev/null | awk '{print $2}')"   # e.g. 1.78.0
    major="${v%%.*}"; minor="${v#*.}"; minor="${minor%%.*}"
    [ "${major:-0}" -gt 1 ] && return 0
    [ "${major:-0}" -eq 1 ] && [ "${minor:-0}" -ge "$MIN_CARGO_MINOR" ] && return 0
    return 1
}
if ! cargo_ok; then
    command -v cargo >/dev/null 2>&1 &&
        warn "found $(cargo --version 2>/dev/null), but splice needs Cargo >= 1.$MIN_CARGO_MINOR (Cargo.lock v4)."
    if command -v rustup >/dev/null 2>&1; then
        say "Updating the Rust toolchain via rustup"
        rustup update stable >/dev/null && rustup default stable >/dev/null
    else
        say "Installing an up-to-date Rust toolchain via rustup (to ~/.cargo)"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    fi
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    export PATH="$HOME/.cargo/bin:$PATH"
    cargo_ok || die "could not obtain Cargo >= 1.$MIN_CARGO_MINOR (have: $(cargo --version 2>/dev/null || echo none)). Update Rust and re-run."
fi

# --- 4. build (Release, no tests) ---
say "Fetching submodules"
git -C "$SRC" submodule update --init --recursive >/dev/null 2>&1 || die "submodule init failed"
say "Configuring"
cmake -S "$SRC" -B "$SRC/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DSPL_BUILD_TESTS=OFF >/dev/null
say "Compiling (this takes a minute)"
cmake --build "$SRC/build"

# --- 5. install ---
mkdir -p "$PREFIX"
install -m 0755 "$SRC/build/spl" "$PREFIX/spl"
say "Installed: $PREFIX/spl"

# --- 6. PATH hint ---
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) warn "$PREFIX is not on your PATH. Add this to your shell profile:"
       printf '         export PATH="%s:$PATH"\n' "$PREFIX" >&2 ;;
esac

say "Done. Run 'spl pair' to get started (uses splice.kussowski.dev:443 by default)."
