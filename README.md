# splice (`spl`)

Peer-to-peer byte/file sharing over an **untrusted relay**. Two peers pair once
with a short code, then talk over a WireGuard tunnel that hole-punches a direct
path when it can and relays through the server when it can't. The server can only
deny service — never read, inject, or MITM traffic (see [docs/DESIGN.md](docs/DESIGN.md)).

A single binary `spl` is the server *and* the peer.

## Build

Prerequisites: a C++20 compiler, **CMake ≥ 3.22**, Ninja, a **Rust toolchain**
(for the WireGuard/SPAKE2 shim), and **OpenSSL** dev headers.

```sh
# Debian/Ubuntu
sudo apt-get install -y cmake ninja-build libssl-dev pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y   # if no rust yet

git submodule update --init                 # vendored lwIP

# cargo must be on PATH for the build:
. "$HOME/.cargo/env"

cmake -S . -B build -G Ninja
cmake --build build
```

### macOS

Install the toolchain with Homebrew (Apple Clang from the Xcode command-line
tools provides the C++20 compiler):

```sh
xcode-select --install          # if you don't have the command-line tools yet
brew install cmake ninja openssl@3 pkg-config rust

git submodule update --init     # vendored lwIP

# Homebrew's OpenSSL isn't on the default search path, so point CMake at it:
cmake -S . -B build -G Ninja -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
cmake --build build
```

The linker may print harmless `was built for newer 'macOS' version` warnings for
the vendored BoringSSL objects; they don't affect the build.

The binary is `build/spl`. lwIP is built from source; OpenSSL is taken from the
system (Homebrew on macOS). The Rust shim is built and linked automatically via
Corrosion.

## Use

Run a relay server (uses an ephemeral self-signed TLS cert in dev; pass
`--cert`/`--key` for a real one):

```sh
spl server --bind :: --port 7777
```

Pair two devices against that server. On the first:

```sh
$ spl pair --server relay.example --port 7777
Pairing code:  3-481922
On the other device run:  spl pair 3-481922
```

On the second, paste the code (each side names the other for later):

```sh
spl pair 3-481922 --server relay.example --port 7777 --name laptop
```

Then pipe bytes over the tunnel (nc-style):

```sh
# on the receiver
spl receive laptop --server relay.example --port 7777 > out.txt
# on the sender
spl send phone --server relay.example --port 7777 < in.txt
```

`--name NAME` on `pair` accepts non-interactively; without it you get an
accept / decline / verify-by-pasting-the-peer-key prompt. Connection records live
under `$SPL_CONFIG_DIR` (else `$XDG_CONFIG_HOME/spl`, else `~/.config/spl`), mode 0600.

## Test

```sh
ctest --test-dir build
```

Unit tests cover the wire codecs, server logic (code allocator / relay table /
rate limiter), crypto (HKDF/HMAC/AEAD/SPAKE2), the WireGuard FFI, and the lwIP
stack. Integration tests boot a real server and drive the server protocols,
pairing (including a tamper-abort), the data path (relay → direct → fallback), and
the full nc pipe.

## Layout

```
native/        Rust shim: boringtun (WireGuard) + spake2, over a small C ABI
src/proto/     wire codecs (pairing, relay, whereami)
src/crypto/    HKDF/HMAC/AEAD (OpenSSL) + SPAKE2 wrapper
src/net/       sockets + TLS
src/server/    rendezvous + relay + entrypoint
src/peer/      pairing, store, WireGuard, path manager, lwIP netstack, nc app
src/lwip_port/ lwIP NO_SYS port (lwipopts.h, arch, sys_now)
third_party/   lwIP submodule
tests/         gtest unit tests + Python integration tests
```

## Status

v1: pairing, the relay/direct WireGuard data path, and an nc-style byte pipe, all
without root. Not yet: file-transfer framing, a TUN backend for system-wide use,
and non-Linux path-manager backends. MIT licensed.
