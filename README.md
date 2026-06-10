# splice (`spl`)

Peer-to-peer byte/file sharing over an **untrusted relay**. Two peers pair once
with a short code, then talk over a WireGuard tunnel that hole-punches a direct
path when it can and relays through the server when it can't. The server can only
deny service — never read, inject, or MITM traffic (see [docs/DESIGN.md](docs/DESIGN.md)).

A single binary `spl` is the server *and* the peer.

## Install

Drop `spl` into `~/.local/bin` — no root:

```sh
curl -fsSL https://raw.githubusercontent.com/m4teuk/splice/main/install.sh | bash
```

or from a checkout:

```sh
git clone https://github.com/m4teuk/splice.git
bash splice/install.sh
rm -rf splice          # the binary now lives in ~/.local/bin
```

By default the script **downloads a prebuilt `spl`** for your platform (Linux/macOS,
x86_64/arm64), verifies its checksum, and installs it — no toolchain needed. The
prebuilt binaries link OpenSSL statically, so they only need the system C runtime.

If no prebuilt binary fits your system (or it won't run there), the script
**falls back to building from source**: Rust is bootstrapped automatically, while a
C++ toolchain, CMake, Ninja, pkg-config and OpenSSL 3 headers must already be present
— it prints the one `apt`/`brew`/`dnf` command to install them if not (it never runs
`sudo` itself).

Overrides: `SPL_FROM_SOURCE=1` always builds from source; `SPL_VERSION=<tag>` pulls a
specific release instead of the rolling `nightly` build; `SPL_PREFIX=<dir>` changes the
install location. Ensure `~/.local/bin` is on your `PATH`; then `spl pair` works against
the default relay. To develop, or to run a server, build manually (below).

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

Pair two devices. Clients default to the public relay
`splice.kussowski.dev:443`; pass `--server`/`--port` (or a `[peer]` config) to use
your own. On the first device:

```sh
$ spl pair
Pairing code:  3-481922
On the other device run:  spl pair 3-481922
```

On the second, paste the code (each side names the other for later):

```sh
spl pair 3-481922 --name laptop
```

If the server's TLS certificate doesn't verify (e.g. the dev self-signed cert),
`pair` warns and prompts before continuing; pass `--insecure` to skip the prompt
(required when pairing non-interactively with `--name`).

Before accepting, each side shows **both** public keys (yours and the peer's) so
you can compare them out of band; the prompt accepts `[v]erify` (paste the peer's
key to check it) and `[c]opy` (copy your own key to the clipboard) alongside
`[a]ccept`/`[d]ecline`.

Then talk over the tunnel. A per-user **daemon** keeps one warm connection per
paired peer and splices named byte **pipes** over it (see
[docs/PIPES.md](docs/PIPES.md)); the commands are thin clients of it and start
it on demand:

```sh
spl serve laptop report.pdf        # host a file; the peer fetches it when it wants
spl get phone report.pdf           # fetch (writes ./report.pdf; -o DIR/FILE, -f, -b)
spl chat laptop                    # talk: a terminal on each end of a pipe

spl peer status                    # all peers: path (direct/relay), pipes, progress
spl peer start | stop              # daemon lifecycle (auto-started otherwise)
spl peer ls | rename | remove      # manage paired connections
spl peer register | open | close   # raw pipe plumbing (ECHO, SHARE_FILE, PIPE, …)
```

Serving is durable: registrations survive daemon restarts (`spl peer reset`
clears them), so you can `spl serve` on a server once and fetch whenever. The
receiver never silently overwrites (`-f` to allow) and incoming names are
reduced to a safe filename. `spl get` shows progress on a TTY; everything else
shows its progress in `spl peer status`.

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

[peer]                   # relay for pair / chat / serve / get / the daemon
addr = splice.kussowski.dev   # defaults to this public relay
port = 443
```

CLI flags override the config. Connection records live in the same dir, mode 0600.

## Test

```sh
ctest --test-dir build
```

Unit tests cover the wire codecs, server logic (code allocator / relay table /
rate limiter), crypto (HKDF/HMAC/AEAD/SPAKE2), the WireGuard FFI, and the lwIP
stack. Integration tests boot a real server and drive the server protocols,
pairing (including a tamper-abort), the daemon (pipes, persistence, reset), the
data path (relay → direct → fallback), file serving (including a lossy path),
and chat.

## Layout

```
native/        Rust shim: boringtun (WireGuard) + spake2, over a small C ABI
src/proto/     wire codecs (pairing, relay, whereami)
src/crypto/    HKDF/HMAC/AEAD (OpenSSL) + SPAKE2 wrapper
src/net/       sockets + TLS
src/server/    rendezvous + relay + entrypoint
src/peer/      pairing, store, WireGuard, path manager, lwIP netstack, daemon + pipes
src/lwip_port/ lwIP NO_SYS port (lwipopts.h, arch, sys_now)
third_party/   lwIP submodule
tests/         gtest unit tests + Python integration tests
```

## Status

v2: pairing, the relay/direct WireGuard data path, and a per-user daemon serving
named byte pipes (files, chat, anything — [docs/PIPES.md](docs/PIPES.md)), all
without root. Not yet: directory transfer (a future pipe-type pair), a TUN
backend for system-wide use, and non-Linux path-manager backends. MIT licensed.
