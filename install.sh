#!/usr/bin/env bash
# splice client installer.
#
# By default it downloads a prebuilt `spl` binary for your platform from the
# project's GitHub releases and drops it in ~/.local/bin (no root, no toolchain).
# If no prebuilt binary fits your system — or it can't run here — it falls back to
# building from source, which needs Rust (bootstrapped automatically) plus a C/C++
# toolchain, CMake, Ninja, pkg-config and OpenSSL 3 headers.
#
#   From a checkout:  bash install.sh
#   One-liner:        curl -fsSL https://raw.githubusercontent.com/m4teuk/splice/main/install.sh | bash
#
# Environment overrides:
#   SPL_PREFIX=/somewhere/bin   install location (default: ~/.local/bin)
#   SPL_FROM_SOURCE=1           skip the prebuilt binary and build from source
#   SPL_VERSION=<tag>           pull binaries from a specific release tag
#                               (default: the rolling "nightly" release built from main)
set -euo pipefail

REPO_SLUG="m4teuk/splice"
REPO_URL="https://github.com/${REPO_SLUG}.git"
PREFIX="${SPL_PREFIX:-$HOME/.local/bin}"
REL_TAG="${SPL_VERSION:-nightly}"

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

# --- platform -> release asset name (spl-<os>-<arch>), or empty if unsupported ---
# Matches the names produced by .github/workflows/release.yml. Linux uses the kernel's
# "aarch64"; macOS uses "arm64" — exactly what `uname -m` reports on each.
asset_name() {
    local os arch
    case "$(uname -s)" in
        Linux)  os=linux ;;
        Darwin) os=macos ;;
        *)      return 1 ;;
    esac
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  arch=x86_64 ;;
        aarch64|arm64) [ "$os" = macos ] && arch=arm64 || arch=aarch64 ;;
        *)             return 1 ;;
    esac
    printf 'spl-%s-%s' "$os" "$arch"
}

# --- sha256 of a file, using whichever tool exists; empty if neither does ---
sha256_of() {
    if   command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum    >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# --- try to install a prebuilt binary; return 0 on success, 1 to fall back to source ---
# (No `trap ... RETURN` for cleanup: a RETURN trap persists and re-fires on later
# function returns, so we remove the temp dir explicitly on each soft exit instead.)
try_prebuilt() {
    command -v curl >/dev/null 2>&1 || { warn "curl not found; will build from source."; return 1; }

    local asset
    asset="$(asset_name)" || { warn "no prebuilt binary for $(uname -s)/$(uname -m); building from source."; return 1; }

    local base="https://github.com/${REPO_SLUG}/releases/download/${REL_TAG}"
    local tmp; tmp="$(mktemp -d)"

    say "Downloading prebuilt $asset ($REL_TAG)"
    if ! curl -fSL --proto '=https' --tlsv1.2 -o "$tmp/spl" "$base/$asset" 2>/dev/null; then
        warn "no prebuilt binary at $base/$asset; building from source."
        rm -rf "$tmp"; return 1
    fi

    # Verify the checksum when we can compute one and the release ships a sidecar.
    # A present-but-mismatched checksum is fatal — we don't silently fall back.
    if curl -fSL --proto '=https' --tlsv1.2 -o "$tmp/spl.sha256" "$base/$asset.sha256" 2>/dev/null; then
        local got want
        got="$(sha256_of "$tmp/spl")"
        want="$(awk '{print $1}' "$tmp/spl.sha256")"
        if [ -z "$got" ]; then
            warn "no sha256 tool found; skipping checksum verification."
        elif [ "$got" != "$want" ]; then
            rm -rf "$tmp"
            die "checksum mismatch for $asset (got $got, expected $want). Refusing to install."
        else
            say "Checksum verified"
        fi
    else
        warn "no checksum published for $asset; skipping verification."
    fi

    chmod +x "$tmp/spl"

    # Smoke test: does it actually load and run here? Catches a missing/incompatible
    # libc, etc. `--version` is offline and exercises the native (Rust) FFI link.
    if ! "$tmp/spl" --version >/dev/null 2>&1; then
        warn "prebuilt binary doesn't run on this system; building from source."
        rm -rf "$tmp"; return 1
    fi

    mkdir -p "$PREFIX"
    install -m 0755 "$tmp/spl" "$PREFIX/spl"
    local ver; ver="$("$PREFIX/spl" --version 2>/dev/null || true)"
    rm -rf "$tmp"
    say "Installed prebuilt: $PREFIX/spl  ($ver)"
    return 0
}

# --- build from source: locate source, check tools, bootstrap Rust, compile, install ---
build_from_source() {
    # 1. locate the source: a checkout next to us, or a throwaway clone.
    local self src tmp
    self="${BASH_SOURCE[0]:-}"
    if [ -n "$self" ] && [ -f "$(cd "$(dirname "$self")" && pwd)/CMakeLists.txt" ]; then
        src="$(cd "$(dirname "$self")" && pwd)"
        say "Building from this checkout: $src"
    else
        command -v git >/dev/null 2>&1 || die "git is required to fetch the source.  Try:  $(install_hint)"
        tmp="$(mktemp -d)"
        trap 'rm -rf "$tmp"' EXIT
        say "Cloning $REPO_URL"
        git clone --depth 1 "$REPO_URL" "$tmp/splice" >/dev/null 2>&1 || die "git clone failed"
        src="$tmp/splice"
    fi

    # 2. check the build prerequisites (Rust is handled separately below).
    local missing=()
    local tool
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
            local brew_ssl
            brew_ssl="$(brew --prefix openssl@3 2>/dev/null || true)"
            [ -n "$brew_ssl" ] && export OPENSSL_ROOT_DIR="$brew_ssl"
        fi
    fi

    # 3. ensure an up-to-date Rust (no sudo; rustup installs under ~/.cargo).
    # Our Cargo.lock is format v4, which needs Cargo >= 1.78. Distro packages (e.g.
    # Debian's /usr/bin/cargo) are often older, so check the version, not just that a
    # cargo exists. ~/.cargo/bin goes first on PATH so rustup's toolchain wins.
    export PATH="$HOME/.cargo/bin:$PATH"
    local MIN_CARGO_MINOR=78
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

    # 4. build (Release, no tests).
    say "Fetching submodules"
    git -C "$src" submodule update --init --recursive >/dev/null 2>&1 || die "submodule init failed"
    say "Configuring"
    cmake -S "$src" -B "$src/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DSPL_BUILD_TESTS=OFF >/dev/null
    say "Compiling (this takes a minute)"
    cmake --build "$src/build"

    # 5. install.
    mkdir -p "$PREFIX"
    install -m 0755 "$src/build/spl" "$PREFIX/spl"
    say "Installed: $PREFIX/spl"
}

# --- main: prebuilt first (unless forced to source), then source as fallback ---
if [ "${SPL_FROM_SOURCE:-0}" = "1" ] || ! try_prebuilt; then
    build_from_source
fi

# --- PATH hint ---
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) warn "$PREFIX is not on your PATH. Add this to your shell profile:"
       printf '         export PATH="%s:$PATH"\n' "$PREFIX" >&2 ;;
esac

say "Done. Run 'spl pair' to get started (or 'spl --help')"
