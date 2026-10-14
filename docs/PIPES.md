# splice pipes — the daemon abstraction

> This is the contract for the daemon (`spl start`) and its pipe model, and
> it is what the code implements. [DESIGN.md](DESIGN.md) covers the layers
> underneath (pairing, the relay, WireGuard, the path manager).

## The model

A **pipe** is a bidirectional byte stream. That is the whole abstraction: bytes
in, bytes out, no framing, no meaning. Endpoints interpret the bytes however
they want.

Every connection between peers is exactly **two pipes spliced together** — one
on each side. Once two pipes are connected, everything below (WireGuard, path
selection, relay vs direct) is invisible: from this point on, forget the
network.

The **daemon** is deliberately dumb. It does three things and nothing else:

1. **resolve names** — map `<peer, pipe_id>` to a registered pipe,
2. **splice bytes** — pump data between the two ends,
3. **aggregate status** — report what exists and what each end says about itself.

It never inspects, frames, limits, or interprets traffic. Anything with an
opinion — completion, refusal, progress, concurrency — is a pipe's
responsibility, not the daemon's.

## Named and anonymous pipes

- **Named (listening) pipes** are registered toward a specific peer and wait for
  that peer to connect. A registration is a **template, not an instance**: each
  incoming connection spawns a fresh instance of the pipe, so one
  `SHARE_FILE` registration can serve any number of concurrent connections.
- **Anonymous (active) pipes** are created on our side by `OPEN`: we name the
  *remote* pipe to connect to and the *local* type to handle our end. They are
  never named — they are not hosted.

Every **live instance** — whether spawned by an inbound connection to a named
pipe or created by `OPEN` — gets an instance id (`#0`, `#1`, …) from a single
per-peer id space. The id is how an instance is shown in `STATUS` and how it is
killed with `CLOSE`; a named registration additionally keeps simple counters
(finished, active) across the instances it has spawned.

**A registration is only an offer; instances are independent of it.** The daemon
consults the registration table when the peer connects (and to answer `LIST`),
and that's all. Each instance records the name it was reached by and the type +
args offered *at that moment*, and shows those. `UNREGISTER` (or a `LIMIT`
retiring) stops new connections but never touches live ones — the reply notes
any that are still running and how to `CLOSE` them. A new registration under a
reused name is a different registration: it starts at 0/0 and never adopts the
old one's instances.

Both kinds are daemon-owned: the daemon runs them, so the process that created
them may exit (the one exception is the `PIPE` type, whose backing socket is the
creating process — see below).

## Daemon API

Clients (the `spl` CLI, scripts, and **pipe implementations themselves**) talk
to the daemon over a per-user unix socket (`$XDG_RUNTIME_DIR/spl/daemon.sock`,
else `${TMPDIR:-/tmp}/spl-<uid>/daemon.sock`; no root anywhere). The directory
must be a real 0700 directory owned by you — spl refuses a planted symlink or
another user's directory — and both ends check the other's uid with the kernel.
The verbs:

```
REGISTER   <peer> <pipe_id> [LIMIT <n>] <type> <args…> -> OK | error (e.g. collision)
UNREGISTER <peer> <pipe_id>                  -> OK | error
OPEN       <peer> <peer_pipe_id> [WAIT] [FOLLOW] [EXPECT <kind>] <type> <args…> -> <local_id> | error
CLOSE      <peer> <local_id>                 -> OK | error   (forceful)
STATUS                                       -> the state of everything
RESET                                        -> drop every registered pipe everywhere
```

`LIMIT <n>` makes a registration **N-shot**: it serves at most `n` instances over
its lifetime, and is retired as soon as the `n`-th has started (no longer offered;
a daemon-owned one's stored file is deleted) while those instances run on. A
`PIPE`'s owner socket *is* its byte stream, so it stays open until neither a
registration nor a live instance uses it; then it closes and the host process
exits — this is how `chat` ends a session symmetrically (it registers with
`LIMIT 1`, so the single conversation closing from *either* side tears down both
ends). `LIMIT` applies to **any** type: `spl inbox --limit N`
is just a `GET_FILE` registration with `LIMIT N`, accepting exactly N pushes then
retiring. Without `LIMIT` a registration serves connections indefinitely until
explicitly removed.

(Plus housekeeping verbs: `PING` -> `OK` (aliveness, used by auto-start),
`VERSION`, `STOP` (shut the daemon down), `RELOAD` (re-read the peer files and
reconcile: a peer is identified by its uid, so a removed one's session and
connections are dropped at once, a renamed one keeps its session, offers and
live connections under the new name, and a new one gets a session — `spl pair`
and `spl peer rename/remove` send it for you; `spl reload` is for hand edits), `STICKY` (mark a running daemon
no-auto-stop, sent by `spl start`), `LIST <peer>` / `REACH <peer>` (a meta
round-trip to the peer — the served names, or a reachability ping — backing
`spl ls <peer>` and `spl ping`), and `FORCE_RELAY <peer> <0|1>`, a debug/test
hook that pins a session to the relay to simulate losing the direct path. The
env hooks `SPL_FORCE_RELAY=1` and `SPL_LOSS=<frac>` — drop that fraction of
egress UDP packets — apply at daemon start.)

**Registrations are durable.** A daemon-owned registration is a fact, recorded
like pairings are: one file per pipe under `<config>/pipes/<peer>/<name>`. The
daemon resolves incoming names against these files on demand, so a restarted
daemon serves exactly what was registered before — register once on a server
and it keeps working. `PIPE` registrations are the exception: their local end
is a living process, so they exist only while that process holds its socket.
Live instances are never persisted. `RESET` wipes the stored registrations,
drops live ones, and kills running instances.

- `REGISTER` makes a named pipe available to `<peer>` (and only that peer).
- `OPEN` connects to a pipe the peer has registered; `<type> <args…>` describe
  the local end (e.g. `GET_FILE /tmp/out.pdf` connected to Alice's `mypdf`,
  which we happen to know is a `SHARE_FILE` — the daemon neither knows nor
  cares about the *type* on the other side, only its *kind*: see the handshake
  below). An optional `WAIT` token before the type treats `UNKNOWN` as "not
  registered *yet*": the daemon keeps re-dialing until the pipe appears or the
  instance is closed. Chat uses it (whoever starts first just waits); `get` does
  not (a typo'd name should fail fast). `EXPECT <kind>` (one encoded token)
  names the kind the offer must be; without it the local type's own need
  applies (`GET_FILE` needs `file/1 send`, `SHARE_FILE` needs `file/1 recv`,
  the others take anything).
- An `OPEN … PIPE` client gets a second line once the connection is settled,
  before the first byte of the stream: `READY <kind>` (what the peer announced)
  or `ERR <why>` (not offered, the wrong kind, or the peer unreachable) — then
  the socket closes. A `FOLLOW`ing client gets the same failures as `E <why>`.
- `CLOSE` kills any live instance by id — `OPEN`-created ones and instances
  spawned by our own named pipes alike (the registration itself stays and keeps
  listening; it is removed with `UNREGISTER`, which conversely leaves live
  instances running). `RESET` is the big hammer: it removes every registration
  *and* ends the instances they spawned.
- Pipes may call these verbs too. A future coordinator pipe (e.g. directory
  transfer) registers ephemeral named pipes and `OPEN`s connections exactly
  like any other client. **Built-in types get no private interface** — this is
  what keeps the kernel closed and the type catalogue open.

## Wire handshake (tunnel side)

Daemon-to-daemon traffic rides one constant TCP port inside the tunnel's ULA
address space. The active side connects and sends the pipe id it wants; the
passive daemon replies:

- `UNKNOWN` — no such pipe registered for this peer; connection closed.
- `OK <kind>` — a new instance of the named pipe is spawned and from the next
  byte the connection *is* the spliced pipe pair. Raw bytes, both directions,
  until either end closes.

The **kind** says what the offer is, from the offering side: a protocol with its
version, then words about this end.

| kind | offered by | the opener needs |
|---|---|---|
| `file/1 send` | `SHARE_FILE` (serve) | `GET_FILE` (get) |
| `file/1 recv` | `GET_FILE` (inbox) | `SHARE_FILE` (send) |
| `exec/1` | `EXEC` (expose) | the exec client (`spl run`) |
| `exec/1 pty` | `EXEC PTY`, `SHELL` (expose --pty, revshell) | the exec client (`spl shell`, or `spl run`) |
| `raw` | `ECHO`, `PIPE` | anything |

It is announced by the daemon from the registration — not by the pipe, and not
in-band — so the opener knows what it reached before a byte of any protocol
moves, and the opening daemon refuses a mismatch itself (an inbox answered by
`spl get` would otherwise leave both ends waiting to receive). A kind *matches*
an expectation when the protocol (with version) is the same and every expected
word is present. A bare `OK` (an older peer) is an unknown kind and is accepted.

Still no BUSY and no error detail: if a pipe wants to refuse, negotiate, or
report, it does so in-band in its own protocol after `OK`.

One meta-request rides the same channel: a connection whose first line is
`__LIST__` gets back one `<name>\t<kind>` line per pipe this peer serves the
caller (then the connection closes). It's how `spl ls <peer>` (each offer, what
it is, and the command that uses it) and remote-pipe TAB completion discover
what's available — introspection built from the same handshake, no special
socket.

## Pipe types

The initial catalogue. Adding a type touches only the catalogue — the daemon
kernel, API, and wire format never change.

| type | input | output |
|---|---|---|
| `ECHO` | anything | a copy of the input (diagnostics) |
| `SHARE_FILE <path>` | RESUME offsets | the file (or directory) content |
| `GET_FILE <target> [OVERWRITE]` | the stream → written under `<target>` | RESUME offsets |
| `EXEC [PTY] <program> [args…]` | framed stdin, end of input, window size | framed stdout, stderr, then the exit status |
| `SHELL` | (`EXEC PTY` of the host user's login shell) | |
| `PIPE` | from the creating process | to the creating process |

`ECHO` is handy as a diagnostic target — register one explicitly with
`spl pipe register <peer> diagnostic ECHO` (the name is not special).

`PIPE` is the escape hatch to the outside world: the unix-socket connection
that issued the `REGISTER`/`OPEN` itself becomes the byte stream after the
reply (mirroring the tunnel handshake). The creating process bridges its own
stdin/stdout (or anything else) to that socket; when the process dies, the
pipe dies. `spl chat` is nothing more than a `PIPE` opened against the peer's
registered `PIPE`, with the terminal on both outer ends.

### Type pairs may speak protocols — above the pipe layer

A pipe carries raw bytes, but two *consenting* types may layer a protocol over
them. `SHARE_FILE`/`GET_FILE` are such a matched pair speaking **SPLF2**, a
multi-entry, resumable file protocol (one path may be a single file or a whole
directory, streamed recursively):

```
sender → "SPLF2 <size> <crc32hex> <relpath>\n"
recv   → "RESUME <offset>\n"          (offset bytes of a matching .part it kept)
sender → <size - offset> raw bytes
...                                   (one OFFER/RESUME/bytes per file)
sender → "SPLF2-END\n"
```

The receiver writes each entry to `<dest>.part` (plus a `.part.meta` recording
size/crc/relpath) and renames to `<dest>` once the crc verifies — so an
interrupted transfer **resumes**, a same-named-but-changed file **restarts**
(its crc won't match the kept `.part`), and corruption is caught. The `SPLF2`
magic also lets the receiver tell a real `SHARE_FILE` apart from any other pipe
(getting, say, a `chat` reports "not a SHARE_FILE pipe" rather than a vague
failure). None of this leaks downward — the daemon still splices opaque bytes.

`EXEC` is another matched pair: each inbound connection runs a program, fixed
by the registration (the connecting peer supplies input, never the command
line), as the host user, in their home directory, in its own session, with
`SPL_PEER` set to the peer's name. Both directions are framed
(`[type:1][len:2][payload]`, see `src/peer/exec.h`): to the program DATA, WINSZ
(a `TIOCSWINSZ`) and EOF (its stdin closes, while its output keeps coming); from
it OUT, ERR and finally EXIT (exited with a code, or killed by a signal). A
stream that ends without EXIT means the run was cut off. With `PTY` the program
runs on a terminal (`forkpty`): its output is one stream and EOF types the
terminal's end-of-file character. Whether there's a PTY is in the kind
(`exec/1 pty`), so the client knows before the first byte whether to hand over
its terminal (raw mode, size changes forwarded). `SHELL` is the `EXEC PTY`
preset for the host user's login shell.

`spl expose <peer> <program> [args…]` offers a program (`--pty` on a terminal);
`spl run <peer> <name>` runs it and exits with its status — its exit code, or
128 + the signal — and with 255 when spl itself fails (unreachable, not offered,
the wrong kind, the connection lost), as ssh does. `spl revshell`/`spl shell`
are the same for the login shell, and feel like `ssh`. When a connection goes
away first, the program's session is sent SIGHUP, and SIGKILL 5 s later.
Offering a program is a deliberate, named, revocable grant to one peer — and
one that reads commands from its input (a shell, an interpreter) is a shell.

Ends like `EXEC` don't fit "the daemon pumps one fd": a `LocalEnd` names the
descriptors it wants polled, each for reading or writing (`watches()`), and the
daemon re-asks after every call into it, so an end leaves its read fds out while
the tunnel is full and its write fd out while it has nothing to write. And an
end that hands data on at its consumer's pace (`manual_flow()`) reports bytes
as consumed only once they're taken; until then they hold the sender's TCP
window, so a program that reads its input slowly slows the sender down instead
of growing a buffer in the daemon.

`spl serve`/`get` are the pull form; `spl inbox`/`send` are the push form (the
receiver opts in with a `GET_FILE` registration, then the sender opens it with
`SHARE_FILE`). Like any registration the inbox has a **name** — `inbox` by
default, or anything via `inbox --name <n>`, so one peer can offer several inboxes
(say `downloads` and `media` into different directories); the sender picks one
with `send --name <n>` (no `--name` means the default `inbox`, and an unknown name
gets the usual "not served" error). `inbox --limit N` uses the N-shot LIMIT to
accept exactly N pushes. Foreground `get`/`send` stream live progress over the
control connection (an `OPEN … FOLLOW`); `-b` detaches and the transfer shows in
`spl status`.

## Rules

- **Close is just close.** The pipe layer does not distinguish "finished" from
  "broke". If an endpoint needs to know it received everything, that knowledge
  must come from its own protocol (see `SHARE_FILE`/`GET_FILE`). Receiving a
  clean close tells you nothing the bytes didn't.
- **A silent peer is a gone peer.** Every connection runs TCP keepalive: one
  that hears nothing from the other side for ~3 minutes (no data, no ACKs, no
  keepalive replies) is closed — so a peer that vanished without closing (lost
  network, crashed, asleep) doesn't leave a shell or transfer hanging on either
  end. A healthy idle connection answers the probes and stays up.
  (`SPL_KEEPALIVE_MS` overrides the window for tests.)
- **No concurrency limits.** Any number of connections may hit a named pipe;
  each gets its own instance. Where instances share a backing resource the
  behavior is defined by mechanics, not policy: two connections to a
  `SHARE_FILE` each read the file independently; two connections to one `PIPE`
  interleave on its single socket — the user asked for that.
- **One introspection hook.** The daemon never looks inside a pipe; instead
  every live instance must answer `describe()` with one human-readable line
  (`GET_FILE` says `receiving out.pdf 61% (3.2/5.1 MB)`; a raw `PIPE` can only
  say what the splice counters know, e.g. `up 1.2 MB / down 40 B, 34s`).
  `STATUS` is purely an aggregation of the registry, the instances'
  `describe()` lines, and the per-peer path state.

## Status

`spl status` renders the `STATUS` verb (send `STATUS VERBOSE` for `spl status -v`,
which adds the peer's side, both ULA addresses, the session uid, our
relay-observed external address, the tx/rx byte split per path, and the full
candidate table — every probed address with alive/rtt/last-reply). Per peer: the link state (relay or
direct, RTT, liveness — the path manager's snapshot), then what we offer (with
counters only), then every live connection:

```
PEER alice: DIRECT via 192.168.1.20:41641 ~3ms | tx 2.4 MB rx 1.1 MB
  OFFERED
    mypdf  SHARE_FILE /home/user/file_to_share.pdf  (0 finished, 1 active)
    chat  PIPE  (1 finished, 0 active)
  CONNECTIONS
    #0  out  alice:notes  GET_FILE /tmp/notes.md  up 40 B down 1.1 MB | receiving 92% (1.1/1.2 MB)
    #1  in   mypdf  SHARE_FILE /home/user/file_to_share.pdf  up 2.4 MB down 12 B | sending 48% (2.4/5.1 MB)
```

Each connection shows the name it used and the type it got *when it connected*
(`in` = the peer reached our offer, `out` = we opened theirs), so it stays
truthful after an unregister or a same-named re-registration. Instance ids are
unique per peer, so `CLOSE alice 1` kicks the inbound `mypdf` transfer just as
`CLOSE alice 0` aborts our own fetch.

## Lifecycle

- `spl start` / `spl stop` run and kill the daemon explicitly; any client
  command auto-starts it when the socket is absent. A daemon started implicitly
  is **non-sticky**: it auto-stops once it has been idle (nothing registered and
  no instance running) for a couple of minutes, so a casual `spl get` leaves
  nothing behind. `spl start` marks it **sticky** (runs until `spl stop`), and a
  live registration (`serve`/`inbox`) keeps even a non-sticky daemon alive on its
  own. (`SPL_IDLE_STOP_MS` overrides the idle window for tests.)
- **Per-peer activity gating.** A peer session is *active* — registering with the
  relay, running whereami/CALLME, probing direct paths — only while it has a pipe
  listening (a live `PIPE` registration or a persisted one) or a running
  instance, plus a ~5-minute warm window after the last one goes away (so a
  follow-up command reconnects instantly). Otherwise the session is **dormant**:
  it sends nothing at all — no relay traffic, no probing, lwIP frozen — so an
  idle daemon with several paired-but-unused peers is silent. A local
  `REGISTER`/`OPEN` wakes it on the next tick. There is no implicit `diagnostic`
  pipe; register one yourself (`spl pipe register <peer> diagnostic ECHO`) if you want
  an echo target.
- CLI commands are thin sugar over the verbs: `spl serve alice --name x f` ≈
  `REGISTER alice x SHARE_FILE f`; `spl get alice x -o f` ≈
  `OPEN alice x GET_FILE f`; `spl chat alice` ≈ `OPEN alice chat PIPE` with the
  terminal bridged; `spl drop alice x` ≈ `UNREGISTER alice x`. The verbs
  themselves are reachable as `spl pipe register|unregister|open|close`.

## Later (explicitly out of scope now)

Background presence pings to idle peers, syncing, and richer coordinator types.
All of these are new pipe types or new instances of existing verbs — none require
touching the kernel. (Directory/recursive transfer, resume, and push were on this
list and are now done, all inside the `SHARE_FILE`/`GET_FILE` pair — proof the
model holds.)
