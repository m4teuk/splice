# splice (`spl`)

**Send files and bytes straight to another machine you trust — no accounts, no
cloud, no root.** Pair two devices once with a short code; from then on either
can serve, fetch, push, or pipe data to the other over an encrypted peer-to-peer
link. A relay server helps the two find each other and forwards traffic when a
direct connection isn't possible, but it can never read, alter, or inject your
data — only you and your peer hold the keys.

One small binary, `spl`, is everything: the thing you run on your laptop *and*
the relay server.

## What you can do with it

- **Share a file or a whole folder** and let the other side grab it whenever:
  `spl serve laptop report.pdf` → `spl get phone report.pdf`.
- **Push files to someone** who opted in: `spl send laptop ./photos`.
- **Pipe anything** between two terminals: `spl chat laptop`, or wire up your own
  byte streams.
- **Get a shell on a machine you own** — `spl revshell laptop` offers one,
  `spl shell laptop` attaches; it feels like ssh (raw terminal, live resize), with
  no server and no open port.
- **Resume interrupted transfers** automatically, with per-file checksums, over
  directories of any depth.
- All of it **end-to-end encrypted** (WireGuard), **without root** (no TUN
  device, no `sudo`), going **directly** between the two machines whenever the
  network allows and falling back to the relay only when it must.

## Install

Drop `spl` into `~/.local/bin` — no root:

```sh
curl -fsSL https://raw.githubusercontent.com/m4teuk/splice/main/install.sh | bash
```

This downloads a prebuilt binary for your platform (Linux/macOS, x86_64/arm64),
verifies its checksum, and installs it — no toolchain needed. If no prebuilt
binary fits, it falls back to building from source (see
[Building from source](#building-from-source)). Make sure `~/.local/bin` is on
your `PATH`.

Later, `spl update` re-runs this installer to upgrade in place.

## Quickstart

**1. Pair the two devices** (once). On the first:

```sh
$ spl pair
Pairing code:  3-481922
On the other device run:  spl pair 3-481922
```

On the second, paste the code and give the first device a name:

```sh
spl pair 3-481922 --name laptop
```

Each side names the other, then compares public keys before accepting (the
prompt can verify a pasted key or copy yours to the clipboard). By default both
use the public relay `splice.kussowski.dev:443`; point them at your own with
`--server`/`--port` or a config file (below).

**2. Move data.** Pull, push, or talk:

```sh
spl serve laptop report.pdf        # host a file/dir; the peer fetches when it wants
spl get phone report.pdf           # fetch it (writes ./report.pdf)

spl inbox phone ~/Downloads        # opt in to receiving pushes from a peer
spl send laptop report.pdf docs/   # push files/dirs into the peer's inbox

spl chat laptop                    # a terminal on each end of a pipe
```

**3. See what's happening.**

```sh
spl status                         # every peer: link (direct/relay), pipes, live transfers
spl ping laptop                    # is the peer reachable right now?
spl ls                             # paired peers;  spl ls <peer> = what they serve you
```

That's the whole day-to-day. Transfers show live progress; add `-b` to a
`get`/`send` to detach and watch it in `spl status` instead.

## Command reference

```
spl serve <peer> [--name n] <path>    host a file/dir for the peer to fetch (--limit N)
spl get   <peer> <pipe> [-o p] [-f] [-b]   fetch a served file/dir (-o DIR/FILE, -f force, -b background)
spl inbox <peer> <dir> [--name n] [--limit N]   let a peer push files to you (--name for several inboxes; --limit N pushes then close)
spl send  <peer> <path>… [--name n] [-b]        push files/dirs into the peer's inbox (--name picks which one)
spl chat  <peer>                      talk: a terminal on each end of a pipe

spl revshell <peer> [--name n] [--limit N]   offer a shell on this machine to a peer
spl shell    <peer> [--name n]               open a shell on the peer (feels like ssh)

spl status [-v]                       all peers: path, pipes, progress (-v: addresses, bytes, candidates)
spl ping  <peer>                      reachability + rough RTT
spl ls [<peer>]                       list paired peers; with a peer, what they serve you

spl start | stop                      run the daemon explicitly / shut it down
spl reset                             drop every registered pipe everywhere
spl config                            show the config file path and current values
spl rename <old> <new> | remove <peer>   manage paired connections
spl update                            re-run the installer to get the latest spl

spl register | unregister | open | close   raw pipe plumbing (ECHO, SHARE_FILE, GET_FILE, PIPE)
```

**Transfers are robust by default.** They handle directories recursively, verify
a per-file checksum, and **resume** an interrupted `get`/`send` from the kept
`.part` — and a file that *changed* since the interruption restarts on its own,
because its checksum won't match. The receiver never silently overwrites (pass
`-f` to allow it).

**Serving is durable.** Registrations survive daemon restarts, so you can
`spl serve` a file on a server once and fetch it whenever; `spl reset` clears
them.

**The daemon stays out of your way.** It starts on demand and **auto-stops when
idle** — unless you ran `spl start` (which keeps it up until `spl stop`) or
something is registered (an active `serve`/`inbox` keeps it alive on its own).

## Config

The config lives in `$SPL_CONFIG_DIR`, else `$XDG_CONFIG_HOME/spl`, else
`~/.config/spl`; `spl config` prints its path and current values. Add a `[peer]`
section so the client commands don't need `--server`/`--port`:

```ini
[peer]                   # relay for pair / chat / serve / get / the daemon
addr = splice.kussowski.dev   # defaults to this public relay
port = 443
```

(Running your own relay? `spl server` setup writes a `[server]` section — see
[docs/DEPLOY.md](docs/DEPLOY.md).) CLI flags override the config. Connection
records live in the same dir, mode 0600.

## Shell completion

`install.sh` offers to install completion wrappers for bash/zsh/fish (set
`SPL_COMPLETIONS=0`/`1` to skip the prompt, or `SPL_COMPLETIONS_ONLY=1 bash
install.sh` to (re)install just them). They're thin: all the logic lives in
`spl __complete`, so completion covers commands, peer names, pipe types, your
registered pipe names, live instance ids, flags, and file paths. To enable
manually, source `completions/spl.bash`, put `completions/spl.zsh` (as `_spl`) on
your `$fpath`, or copy `completions/spl.fish` to `~/.config/fish/completions/`.

## How it works under the hood

The interesting part is that the **relay is untrusted**. Pairing runs a SPAKE2
password exchange over the short code and exchanges fresh WireGuard keys inside
that authenticated channel, so the server only ever sees opaque ciphertext — it
can drop your packets but never read or forge them.

After pairing, a per-user **daemon** keeps one warm connection per peer. It
starts every session on the relay, learns each side's address, then probes for a
**direct** path (NAT hole-punching, plus any shared LAN/overlay address) and
upgrades to the lowest-latency one it finds — falling back to the relay if the
direct path goes quiet. All paths are WireGuard-encrypted regardless. The TCP/IP
stack runs **in-process** (userspace lwIP), which is why no TUN device or root is
needed.

Over that link the daemon splices named byte **pipes**: `serve`/`get`,
`send`/`inbox`, and `chat` are all thin clients of a small local control socket.
The byte-pipe model is deliberately tiny — the daemon resolves names and pumps
bytes; everything with an opinion (file framing, resume, progress) lives in the
pipe endpoints, not the daemon.

The two reference docs:

- **[docs/DESIGN.md](docs/DESIGN.md)** — threat model, pairing protocol, the
  relay/direct WireGuard data path, the userspace network stack.
- **[docs/PIPES.md](docs/PIPES.md)** — the daemon's pipe model, control API, wire
  handshake, and type catalogue.

To run your own relay server, see **[docs/DEPLOY.md](docs/DEPLOY.md)**.

## Building from source

Prerequisites: a C++20 compiler, **CMake ≥ 3.22**, Ninja, a **Rust toolchain**
(for the WireGuard/SPAKE2 shim), and **OpenSSL** dev headers.

```sh
# Debian/Ubuntu
sudo apt-get install -y cmake ninja-build libssl-dev pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y   # if no rust yet
. "$HOME/.cargo/env"                         # cargo must be on PATH

git submodule update --init                  # vendored lwIP
cmake -S . -B build -G Ninja
cmake --build build                          # -> build/spl
```

On **macOS**, install the toolchain with Homebrew (`brew install cmake ninja
openssl@3 pkg-config rust`) and point CMake at OpenSSL:
`cmake -S . -B build -G Ninja -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"`.
lwIP is built from source; OpenSSL comes from the system; the Rust shim is built
and linked automatically via Corrosion.

`SPL_FROM_SOURCE=1 bash install.sh` forces the from-source path of the installer
(it bootstraps Rust and prints the one package-manager command for the C++
toolchain if anything is missing — it never runs `sudo` itself).

## Test

```sh
ctest --test-dir build
```

Unit tests cover the wire codecs, server logic (code allocator / relay table /
rate limiter), crypto (HKDF/HMAC/AEAD/SPAKE2), the WireGuard FFI, and the lwIP
stack. Integration tests boot a real server and drive pairing (including a
tamper-abort), the daemon lifecycle, the pipe model, the data path (relay →
direct → fallback), file transfer (directories, resume, checksums, push), and
chat.

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

MIT licensed.
