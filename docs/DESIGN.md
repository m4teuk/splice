# splice — design & protocol

`splice` is a peer-to-peer byte/file sharing tool built around an **untrusted
relay server**. A single binary `spl` runs as the `server`, as a per-user peer
**daemon**, or as one of its thin clients (`pair` / `serve` / `get` / `send` /
`inbox` / `chat` / `status` / …). Two peers pair once, then their daemons talk
over a WireGuard tunnel whose packets travel either **directly** (NAT
hole-punched) or **relayed** through the server.

## Threat model

The relay server is **untrusted**. Its only capability against paired peers is
**denial of service** (dropping/withholding packets). It can never read, inject,
or MITM peer traffic because:

- **SPAKE2** authenticates pairing from a short human code. A PAKE limits an
  active attacker (including a malicious server) to one online guess per attempt;
  a wrong guess fails key confirmation and aborts before anything is trusted.
- The **WireGuard public keys are exchanged inside an AEAD channel keyed from the
  SPAKE2 secret**, binding them to the PAKE — the server cannot substitute its own
  key. All subsequent data is WireGuard-encrypted/authenticated.

A fresh WireGuard keypair is generated per pairing so the server cannot build a
social graph by correlating keys.

## The two phases

### 1. Pairing (one-shot, TCP + TLS to the server)

The server is a rendezvous point. TLS only protects against passive observers;
security comes from SPAKE2, so the client does **not** verify the server cert.

```
leader  --INIT-->        server          (allocates a short code, holds the conn)
leader  <--CODE{id,ttl}-- server
                                          follower --JOIN{id}--> server
both    <--PAIRED--       server          (server now relays frames opaquely)
```

The code shown to the user is `<rendezvous-id>-<6-digit-spake2>`. The id is the
server handle; the 6 digits are the SPAKE2 password. Over the bridged channel the
peers run a strictly **turn-based, leader-first** exchange (so the server's bridge
is a trivial single-threaded relay with no concurrent-SSL hazards):

```
F1 leader -> Spake2(msg_L)            F2 follower -> Spake2(msg_F)      # -> shared key K
F3 leader -> KeyConfirm(HMAC_L)       F4 follower -> KeyConfirm(HMAC_F) # mismatch => abort
F5 leader -> Sealed(Offer)            F6 follower -> Sealed(Reply)      # WG pubkeys, inside AEAD
```

`Offer` carries the leader's ULA subnet, the 256-bit session `uid`, and the
leader's WG pubkey; `Reply` carries the follower's WG pubkey (or, on the
astronomically rare ULA collision, a counter-proposal — retried up to 10×). Keys
are HKDF-derived from K with the SPAKE2 transcript as salt. Each peer stores
`{name, uid, side, ula_base, own_wg_priv, peer_wg_pub}` 0600 under the config dir.

#### Local pairing (no server)

After `PAIRED` the server only passes frames, so the same exchange runs over a
plain TCP connection between the two devices. `spl pair --local` — and plain
`spl pair` when the relay can't be reached — makes the leader listen on the LAN
and print a code of the form **`L<id>-<6 digits>`** (`L37-481922`): `<id>` is a
random rendezvous id that travels in clear, the digits are the SPAKE2 password
that never does. (`L`, not `#`: a `#` would start a shell comment and silently
turn the joining device into a leader.)

```
follower  --UDP broadcast, discovery port-->  "SPLP" ‖ id[4] ‖ nonce[8]
leader    --UDP, to the asker-->              "SPLR" ‖ id[4] ‖ nonce[8] ‖ tcp_port[2]
follower  --TCP-->  leader:   frame JOIN{id}  ->  frame PAIRED | ERR
          then F1…F6 exactly as above, over the same framing
```

With `--at <host[:port]>` the follower skips the broadcast and connects straight
to the leader's TCP port (7702 by default; the leader prints one `--at` line per
interface address, so this covers Tailscale, a VPN, another subnet). The
rendezvous is unauthenticated and the channel has no TLS, on purpose: SPAKE2 is
what authenticates, and the LAN is in exactly the position the (equally
untrusted) server is in — one guess at the code, and a wrong one aborts at key
confirmation. A code is joined on one path only: `L…` codes locally, others at
the relay. Whatever address the pairing found the other device at is saved as an
address hint on both sides, so they find each other afterwards even where
broadcast doesn't reach.

### 2. Usage (UDP, the WireGuard data path)

The daemon keeps one warm session per paired peer — path manager, WireGuard
tunnel, and a userspace lwIP netif each. Inner addressing is IPv6 **ULA**
(`fd00::/8`, a random /64 per pair): leader = `…::1`, follower = `…::2`; the
disjoint /64s let one lwIP instance route between any number of peer netifs.

## Server data plane (UDP)

All peer↔server packets carry a 1-byte type tag; direct peer↔peer packets are raw
(demuxed by source address ≠ server).

- **relay**: upstream `0x01 ‖ uid[32] ‖ payload`. The server records `(uid)→addr`,
  forwards `payload` to the peer found by **flipping the uid's low (side) bit**, and
  drops if that peer is unknown. Entries expire after ~2 min of inactivity — the
  server holds no long-lived state. An empty payload is a registration keepalive.
- **whereami**: `0x02 ‖ token[4]` → reply `0x02 ‖ token ‖ ip[16] ‖ port[2]` (the
  server-observed source), used for hole punching.
- Rate limited per source IP + globally (cost control, not security).

## Path manager (the magic socket)

Owns the single UDP socket and runs WireGuard (boringtun `Tunn`) over whichever
path is best. Peer↔peer datagrams are `[channel:1][body]`: channel `0x00` =
WireGuard, `0x01` = disco (path control).

```
start on RELAY  (works once both peers register)
  -> whereami learns our external address
  -> CALLME (over relay) tells the peer our external + interface addresses
  -> disco PING/PONG probes every candidate directly, measuring per-candidate RTT
  -> UPGRADE to DIRECT once a round-trip is confirmed (lowest-RTT candidate wins)
  -> FALL BACK to RELAY if the direct path goes quiet (no packets for 3s)
```

WireGuard's endpoint roaming means the session migrates between paths seamlessly.

The relay is optional. The daemon resolves it in the background and runs without
it (offline, DNS down), and **LAN discovery** (below) finds a paired peer on the
local network with no server involved — so two paired machines on one network
work with no internet at all.

## Userspace networking (no root)

Inner IP packets are produced/consumed by an in-process **lwIP** stack
(`NO_SYS=1`, IPv6-only), so only *our* process uses the tunnel — no TUN device,
no privileges. lwIP's `output_ip6` hands packets to the path manager (WireGuard
encapsulate); decrypted inner packets are fed back via `ip6_input`. lwIP is
initialized once per process; each peer session owns one netif, and the daemon
splices its pipes over lwIP's raw TCP API.

## Disco (path-control) wire format

Peer↔peer datagrams (relayed or direct) are `[channel:1][body]`: channel `0x00`
is WireGuard, `0x01` is disco. Disco messages:

- `CALLME` `0x01 ‖ ip[16] ‖ port[2] ‖ count[1] ‖ count×(ip[16] ‖ port[2])` —
  "reach me here": our external address (the whereami result) followed by our
  interface addresses, sent over the relay until a direct path is confirmed.
- `PING` `0x02 ‖ txid[8]` — sent at each candidate address to punch.
- `PONG` `0x03 ‖ txid[8]` — reply to a PING; one that echoes our latest token, from
  a candidate we are probing, marks that candidate alive and samples its RTT.
- `HERE` `0x04`, `PORTQ` `0x05`, `PORTA` `0x06` — LAN discovery's answer and the
  LAN-port question/answer; each carries a nonce and a per-pair MAC (see "LAN
  discovery" below).

Each peer adopts **all** of the other's advertised interface addresses as direct
candidates — no same-NAT gate and no address range is special-cased. A same-LAN
address is reachable directly; an overlay address (e.g. Tailscale) is reachable if
the peers share that overlay; an unreachable one (a private LAN address seen across
different networks) simply never answers and is ignored. `choose_direct` then picks
the **lowest-RTT alive** candidate (with hysteresis to avoid flapping), so the
fastest reachable path wins on its own merits — the real LAN over an overlay hop,
an overlay over the relay — without us trusting or blacklisting any address. Every
path is WireGuard-encrypted, so a failed or stray probe costs nothing.

### LAN discovery (no server)

While a session is active it asks the local networks whether its peer is there —
a few quick queries when a search starts (activation, a lost direct path, an
edited address hint, our own interfaces changing), then one every 30 s for as
long as it stays active, **also with a direct path up**:

```
query   raw UDP, from the asking session's own socket, to every interface's
        broadcast address (and every address hint) on the peer's LAN port:
          "SPLQ" ‖ nonce[16] ‖ HMAC(k_pair, "who" ‖ side ‖ nonce)[:16]
answer  disco, from the answering session's own socket, unicast to the asker:
          HERE 0x04 ‖ nonce[16] ‖ HMAC(k_pair, "here" ‖ side ‖ nonce)[:16]
```

`k_pair = HKDF(X25519(own_priv, peer_pub), "spl/lan-discovery/v1")` — a secret
both sides derive from the keys they already store, so discovery needs no pairing
change and reveals nothing to bystanders (a fresh random nonce makes every query
unlinkable). The daemon listens on the shared discovery port (`SO_REUSEPORT`, so
several users' daemons on one machine all hear broadcasts), checks a query's MAC
against each *active* session's key, and lets the match answer. Neither packet
carries an address: the **source** of a verified packet is the candidate, so one
exchange gives each side the other's. The `side` byte keeps a peer from accepting
its own looped-back packet, the two labels keep a query from being replayed as an
answer, and answered nonces are remembered against replays. Verification only
earns a candidate a probe — PING/PONG and WireGuard still decide what's alive.

**Address hints** (`spl peer add-address <peer> <host[:port]>`) are extra unicast
targets for the same query — for networks with no broadcast between the peers
(Tailscale, another subnet, a VPN). They are resolved off the event loop and are
never authoritative: just one more place to ask. One side having the hint is
enough. (Two daemons on *one* machine can't both receive a unicast query on the
shared port — hints address a machine, broadcasts reach every daemon on it.)

**Remembered addresses.** With a peer's `remember-address` setting on, the
daemon notes the direct address in use (newest first, up to four) in
`<config>/<peer>.seen`. On the next start each is offered as an exact candidate
(the peer's socket may still be there) and its host becomes one more query
target (the peer's daemon may have restarted on a new port). Because one side may
then reach the other at an address the other hasn't learned, a WireGuard reply
produced for a packet that arrived direct goes back to **that packet's source**
(as WireGuard itself does), not to whatever path is currently chosen.

**Per-peer settings** (`spl peer set <peer> <setting> on|off`, all on by
default, stored in the peer's record and applied live through `RELOAD`):

- `relay` — off: nothing is sent to, or accepted from, the relay for this peer;
  only direct paths can work. It is a local switch, but the relay only forwards
  when both sides register, so it disables the relay for the pair.
- `lan-discovery` — off: no broadcasts for this peer (queries still go to its
  address hints, and we still answer the peer's own queries).
- `remember-address` — off: nothing is saved or reused, and what was remembered
  is forgotten.

`spl peer ls`, `spl peer show` and `spl status` all show the settings and how
many addresses are known for the peer.

**The LAN port.** Discovery (UDP) and local pairing (TCP) use one port number,
**7702** by default — unassigned in the IANA registry and below the ranges
systems pick outgoing ports from, so it is rarely taken. Two different things
are configurable:

- *where this machine listens*: `[peer] lan_port` in the config file;
- *where to ask for a given peer*: that peer's `lan-port`, stored in its record.
  Each side sends its own listening port inside the encrypted pairing
  negotiation (`Offer`/`Reply` carry it), so it is learned automatically;
  `spl peer set <peer> lan-port <N|default>` changes it by hand. A local pairing
  with a leader on a non-default port needs it once up front: the leader prints
  `--lan-port N` (and ports in its `--at` lines) for the follower to use.

The daemon's discovery socket is **open only while some peer is active**
(something offered, a connection running, or the warm window after) — an idle
daemon holds no port. It answers a query only when the query's MAC verifies
under that specific pairing's key; anything else gets no reply at all.

**Following a peer that moves its port.** A peer can change `lan_port` after
pairing; the other side would keep asking the old one. So each active session
asks its peer, over whatever path works (the relay included):

```
PORTQ 0x05 ‖ nonce[16] ‖ HMAC(k_pair, "portq" ‖ side ‖ nonce)[:16]
PORTA 0x06 ‖ nonce[16] ‖ port[2] ‖ HMAC(k_pair, "porta" ‖ side ‖ nonce ‖ port)[:16]
```

It asks every 5 s until answered (six tries — an older peer never answers), then
every 5 minutes, and again at once whenever the direct path is lost or moves to
a different address (the peer's socket changing is what a restart of its daemon
looks like, and a restart is the only time its port can change). An answer is
accepted only for a nonce we sent in the last 30 s, only once, and only with the
pair's MAC over that nonce and the port — so only the peer can change what we
store, only to the port it has *now*, and a recorded or delayed answer can't
roll it back. Freshness comes from the asker's nonce, so no clocks or counters
are involved. A query is answered only if it carries the pair's MAC, each nonce
once, and only by an active session.

The learned port is kept by the daemon in `<config>/<peer>.lanport`, separate
from the peer's record (which only the CLI writes, so the two never overwrite
each other's changes), and takes precedence over the record's value.
`spl peer show` marks it "(told by the peer)"; setting the port by hand clears
it, until the peer says otherwise again.

Test hooks: `SPL_LAN_PORT` moves the discovery port and
`SPL_LAN_TARGETS=host:port,…` replaces broadcasting with explicit targets.

**A working path is never the end of the search.** With a direct path up the
manager still pings every known candidate each second (so a faster one takes
over), keeps sending the slow LAN query, re-sends CALLME every 30 s, and
re-reads its own interface addresses every 10 s — a change there (or in the
external address whereami reports) advertises the new set at once and restarts
the quick search. So two machines talking across the internet move to the LAN
shortly after they join the same network. Candidates that neither answer nor are
re-reported for 2 minutes are dropped, so old networks' addresses don't
accumulate.

The path manager keeps the relay mapping and (once known) the direct path warm
with keepalives, and reverts to the relay if no direct packet arrives for ~3 s;
WireGuard endpoint roaming migrates the session between paths transparently. For
tests, `SPL_LOSS=<frac>` drops that fraction of egress UDP packets to exercise
loss recovery.

## Apps over the tunnel: the daemon and its pipes

Everything above raw TCP lives in the **daemon** and its **pipe** model — named,
durable byte pipes registered per peer, spliced over a single well-known tunnel
TCP port (7700), with a one-line `OK`/`UNKNOWN` handshake. `spl serve`/`get` and
`spl send`/`inbox` (pull and push file transfer via the `SHARE_FILE`/`GET_FILE`
type pair, with directories, checksums, and resume), `spl chat` (a `PIPE` pair),
and `spl status`/`open`/`register`/… (status and plumbing) are thin clients of
the daemon's unix control socket. The contract — the model, API verbs, wire
handshake, type catalogue, and rules — is [PIPES.md](PIPES.md).

## Crypto & dependency stack

- **Rust shim (`native/`)**: WireGuard via `boringtun`, SPAKE2 via the `spake2`
  crate, X25519 keygen, CSPRNG — exposed over a small C ABI (the two
  security-critical primitives not in OpenSSL, with zero hand-rolled crypto).
- **OpenSSL**: TLS to the server, HKDF, HMAC, ChaCha20-Poly1305.
- **lwIP** (submodule): userspace TCP/IP.

## Out of scope (roadmap)

A TUN backend for system-wide use, ULA address GC, macOS/Windows path-manager
backends, and Let's Encrypt automation for the server (dev runs use an ephemeral
self-signed cert). Directory/recursive transfer, resume, and push (`send`/`inbox`)
are **done** — they live in the `SHARE_FILE`/`GET_FILE` type pair (see
[PIPES.md](PIPES.md)), no kernel change required, exactly as this model intended.
