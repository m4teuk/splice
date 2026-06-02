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

Run a relay server. The first run with no config walks you through setup (bind
address, port, rate limits, TLS) — suggesting a default for each that you accept
with Enter or override — then saves a config file and prints what clients need to
connect:

```sh
$ spl server
Let's configure your splice relay server.
Bind address (interface to listen on) [::]:
Port (TCP for pairing + UDP for relay) [7777]:
  ... clients reach this server at the address below; put it in their [peer] config
...
```

Re-run setup any time with `spl server --setup`; afterwards a bare `spl server`
uses the saved config. Flags like `--bind`/`--port`/`--cert`/`--key` still override
and skip the walkthrough. TLS uses an ephemeral self-signed cert in dev unless you
supply `--cert`/`--key`.

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

If the server's TLS certificate doesn't verify (e.g. the dev self-signed cert),
`pair` warns and prompts before continuing; pass `--insecure` to skip the prompt
(required when pairing non-interactively with `--name`).

Then talk over the tunnel. Send a file (optionally renaming it for the receiver),
chat interactively, or manage connections:

```sh
spl receive laptop                 # waits for incoming files (writes under cwd)
spl send phone ./report.pdf docs/  # one or more files/dirs; report.pdf:newname renames
spl chat laptop                    # bidirectional stdin<->stdout pipe

spl peer ls                        # list paired connections
spl peer rename laptop work        # rename
spl peer remove work               # delete
```

You can send several files and directories in one command; directories are sent
recursively with their subdirectory structure. The receiver never silently
overwrites: a name collision prompts `[o]verwrite / [s]kip / [r]ename / [c]ancel`,
and incoming paths are confined to the current directory (`..` and absolute paths
are stripped). Add `-v` to any command for verbose logging (the peer shows
throughput by path — direct vs relay — and the server shows a live relay summary).

### Config file

The config lives in the config dir (`$SPL_CONFIG_DIR`, else `$XDG_CONFIG_HOME/spl`,
else `~/.config/spl`). `spl server` setup writes the `[server]` section; add a
`[peer]` section yourself so the peer commands don't need `--server`/`--port`:

```ini
[server]                 # written by `spl server` setup
addr = ::
port = 7777
per_ip_rate = 500
per_ip_burst = 1000
global_rate = 100000
global_burst = 200000
# cert = /etc/spl/cert.pem
# key  = /etc/spl/key.pem

[peer]                   # default relay for pair / chat / send / receive
addr = relay.example     # for now this defaults to 127.0.0.1
port = 7777
```

CLI flags override the config. Connection records live in the same dir, mode 0600.

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
