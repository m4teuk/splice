# splice pipes — the daemon abstraction

> **Status: target design.** This describes the daemon (`spl peer start`) and its
> pipe model. The current code still runs one process per command
> ([DESIGN.md](DESIGN.md) describes what is implemented today); this document is
> the contract the refactor works toward.

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

Both kinds are daemon-owned: the daemon runs them, so the process that created
them may exit (the one exception is the `PIPE` type, whose backing socket is the
creating process — see below).

## Daemon API

Clients (the `spl` CLI, scripts, and **pipe implementations themselves**) talk
to the daemon over a per-user unix socket (`$XDG_RUNTIME_DIR/spl/daemon.sock`,
no root anywhere). The verbs:

```
REGISTER   <peer> <pipe_id> <type> <args…>   -> OK | error (e.g. name collision)
UNREGISTER <peer> <pipe_id>                  -> OK | error
OPEN       <peer> <peer_pipe_id> <type> <args…> -> <local_id> | error
CLOSE      <peer> <local_id>                 -> OK | error   (forceful)
STATUS                                       -> the state of everything
```

- `REGISTER` makes a named pipe available to `<peer>` (and only that peer).
- `OPEN` connects to a pipe the peer has registered; `<type> <args…>` describe
  the local end (e.g. `GET_FILE /tmp/out.pdf` connected to Alice's `mypdf`,
  which we happen to know is a `SHARE_FILE` — the daemon neither knows nor
  cares whether the two types match).
- `CLOSE` kills any live instance by id — `OPEN`-created ones and instances
  spawned by our own named pipes alike (the registration itself stays and keeps
  listening; it is removed with `UNREGISTER`).
- Pipes may call these verbs too. A future coordinator pipe (e.g. directory
  transfer) registers ephemeral named pipes and `OPEN`s connections exactly
  like any other client. **Built-in types get no private interface** — this is
  what keeps the kernel closed and the type catalogue open.

## Wire handshake (tunnel side)

Daemon-to-daemon traffic rides one constant TCP port inside the tunnel's ULA
address space. The active side connects and sends the pipe id it wants; the
passive daemon replies:

- `UNKNOWN` — no such pipe registered for this peer; connection closed.
- `OK` — a new instance of the named pipe is spawned and from the next byte the
  connection *is* the spliced pipe pair. Raw bytes, both directions, until
  either end closes.

Two-word vocabulary, by design. There is no BUSY, no error detail: if a pipe
wants to refuse, negotiate, or report, it does so in-band in its own protocol
after `OK`.

## Pipe types

The initial catalogue. Adding a type touches only the catalogue — the daemon
kernel, API, and wire format never change.

| type | input | output |
|---|---|---|
| `PONG` | anything | a copy of the input (diagnostics) |
| `SHARE_FILE <path>` | ignored | the file's content, like a symlink to the bytes |
| `GET_FILE <path>` | written to `<path>` | nothing |
| `PIPE` | from the creating process | to the creating process |

`PIPE` is the escape hatch to the outside world: the unix-socket connection
that issued the `REGISTER`/`OPEN` itself becomes the byte stream after the
reply (mirroring the tunnel handshake). The creating process bridges its own
stdin/stdout (or anything else) to that socket; when the process dies, the
pipe dies. `spl chat` is nothing more than a `PIPE` opened against the peer's
registered `PIPE`, with the terminal on both outer ends.

### Type pairs may speak protocols — above the pipe layer

A pipe carries raw bytes, but two *consenting* types may layer a protocol over
them. `SHARE_FILE`/`GET_FILE` are such a matched pair: a small header (at
minimum the byte count) precedes the content, which is how `GET_FILE` knows the
transfer completed and how far along it is. This never leaks downward: the
daemon splices opaque bytes, and connecting `SHARE_FILE` to a raw `PIPE` simply
delivers header-plus-content to whatever reads it — reasonable use is the
user's job.

## Rules

- **Close is just close.** The pipe layer does not distinguish "finished" from
  "broke". If an endpoint needs to know it received everything, that knowledge
  must come from its own protocol (see `SHARE_FILE`/`GET_FILE`). Receiving a
  clean close tells you nothing the bytes didn't.
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

`spl peer status` renders the `STATUS` verb. Per peer: the link state (relay or
direct, RTT, liveness — the path manager's snapshot), then the pipes:

```
PEER alice:                          direct 3ms (relay fallback armed)
  LISTENING
    diagnostic  PONG                                      (12 finished, 0 active)
    mypdf       SHARE_FILE /home/user/file_to_share.pdf   (0 finished, 1 active)
      #1          sending 48% (2.4/5.1 MB)
    chat        PIPE                                      (1 finished, 0 active)
  RUNNING
    #0          GET_FILE /tmp/notes.md <- alice:notes     receiving 92% (1.1/1.2 MB)

PEER bob:                            unreachable (last seen 2d ago)
  LISTENING
    diagnostic  PONG                                      (0 finished, 0 active)
```

Instance ids (`#0`, `#1`, …) are unique per peer across both sections, so
`CLOSE alice 1` kicks the inbound `mypdf` transfer just as `CLOSE alice 0`
aborts our own fetch.

## Lifecycle

- `spl peer start` / `spl peer stop` run and kill the daemon explicitly; any
  client command auto-starts it when the socket is absent and the daemon
  auto-stops after a quiet period with nothing registered and nothing running.
- CLI commands are thin sugar over the verbs: `spl serve alice --name x f` ≈
  `REGISTER alice x SHARE_FILE f`; `spl get alice x -o f` ≈
  `OPEN alice x GET_FILE f`; `spl chat alice` ≈ `OPEN alice chat PIPE` with the
  terminal bridged.

## Later (explicitly out of scope now)

Directory/recursive transfer (a coordinator type pair built from ephemeral
`SHARE_FILE`/`GET_FILE` registrations), background presence pings to idle
peers, syncing. All of these are new pipe types or new instances of existing
verbs — none require touching the kernel.
