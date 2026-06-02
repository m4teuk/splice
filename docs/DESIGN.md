# splice — design & protocol

`splice` is a peer-to-peer byte/file sharing tool built around an **untrusted
relay server**. A single binary `spl` runs as the `server` or as a peer
(`pair` / `send` / `receive`). Two peers pair once, then talk over a WireGuard
tunnel whose packets travel either **directly** (NAT hole-punched) or **relayed**
through the server.

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

### 2. Usage (UDP, the WireGuard data path)

`spl receive <name>` listens; `spl send <name>` dials. Inner addressing is IPv6
**ULA** (`fd00::/8`, a random /64 per pair): leader = `…::1`, follower = `…::2`.

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
  -> CALLME (over relay) tells the peer where to reach us
  -> disco PING/PONG probes the peer's address directly
  -> UPGRADE to DIRECT once a round-trip is confirmed
  -> FALL BACK to RELAY if the direct path goes quiet (no packets for 3s)
```

WireGuard's endpoint roaming means the session migrates between paths seamlessly.

## Userspace networking (no root)

Inner IP packets are produced/consumed by an in-process **lwIP** stack
(`NO_SYS=1`, IPv6-only), so only *our* process uses the tunnel — no TUN device,
no privileges. lwIP's `output_ip6` hands packets to the path manager (WireGuard
encapsulate); decrypted inner packets are fed back via `ip6_input`. The app uses
lwIP's raw TCP API; `spl send`/`receive` are an nc-style byte pipe over it.

## Disco (path-control) wire format

Peer↔peer datagrams (relayed or direct) are `[channel:1][body]`: channel `0x00`
is WireGuard, `0x01` is disco. Disco messages:

- `CALLME` `0x01 ‖ ip[16] ‖ port[2]` — "reach me here" (the whereami result), sent
  over the relay until a direct path is confirmed.
- `PING` `0x02 ‖ txid[8]` — sent at the peer's candidate address to punch.
- `PONG` `0x03 ‖ txid[8]` — reply to a PING; receiving one confirms a working
  round-trip and upgrades the active path to DIRECT.

The path manager keeps the relay mapping and (once known) the direct path warm
with keepalives, and reverts to the relay if no direct packet arrives for ~3 s;
WireGuard endpoint roaming migrates the session between paths transparently. For
tests, `SPL_LOSS=<frac>` drops that fraction of egress UDP packets to exercise
loss recovery.

## Apps over the tunnel

The app side speaks lwIP TCP to the peer's ULA address. Two apps ship today:

- **`spl chat`** — a bidirectional stdin↔stdout pipe (tunnel TCP port 7771);
  either side closing tears the whole connection down. Roles come from the stored
  side: the leader listens, the follower dials.
- **`spl send` / `receive`** — one-or-more-file transfer (tunnel TCP port 7772).
  Control messages are `[u32 length][payload]` frames; between an `ACCEPT` and the
  next frame the sender streams exactly `size` raw bytes:

  ```
  sender   → receiver   OFFER{relpath, size}      (one per file)
  receiver → sender     ACCEPT | SKIP | CANCEL
  sender   → receiver   <size bytes of data>      (only after ACCEPT)
  ...                   (repeat per file)
  sender   → receiver   END
  receiver → sender     DONE                       (whole transfer written)
  ```

  Directories are expanded recursively into `dir/sub/file` relpaths. The receiver
  reduces each relpath to a safe path **under the current directory** (`..`,
  absolute, and empty components stripped; subdirectories created) and never
  overwrites without a prompt (overwrite / skip / rename / cancel). Streaming is
  flow-controlled by the lwIP send buffer, and the explicit `DONE` (rather than a
  FIN) signals success so a close/FIN race can't lose the result.

## Crypto & dependency stack

- **Rust shim (`native/`)**: WireGuard via `boringtun`, SPAKE2 via the `spake2`
  crate, X25519 keygen, CSPRNG — exposed over a small C ABI (the two
  security-critical primitives not in OpenSSL, with zero hand-rolled crypto).
- **OpenSSL**: TLS to the server, HKDF, HMAC, ChaCha20-Poly1305.
- **lwIP** (submodule): userspace TCP/IP.

## Out of scope for v1 (roadmap)

File-transfer framing/progress (the path is an nc-style pipe today), a TUN backend
for system-wide use, ULA address GC, macOS/Windows path-manager backends, and
Let's Encrypt automation for the server (dev runs use an ephemeral self-signed cert).
