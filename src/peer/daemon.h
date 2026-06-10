// The spl daemon: keeps one warm session (path manager + WG + lwIP netif) per
// paired peer and splices pipes over them (docs/PIPES.md). Clients drive it
// over a per-user unix socket with newline-delimited commands:
//
//   REGISTER <peer> <id> <TYPE> [args…]   -> OK | ERR <why>
//   UNREGISTER <peer> <id>                -> OK | ERR
//   OPEN <peer> <peer_pipe_id> <TYPE> [args…] -> OK <local_id> | ERR
//   CLOSE <peer> <id>                     -> OK | ERR
//   STATUS | PING | STOP                  -> OK [body]
//
// One command per connection. A PIPE-typed REGISTER/OPEN keeps its connection:
// after the OK line it becomes the byte stream (the client process is the local
// end of the pipe; it dies, the pipe dies).
#pragma once

#include <cstdint>
#include <string>

namespace spl::peer {

struct DaemonOpts {
    std::string server;  // rendezvous/relay host
    uint16_t port = 443;
};

// Resolved per-user runtime dir ($SPL_RUNTIME_DIR, else $XDG_RUNTIME_DIR/spl,
// else /tmp/spl-<uid>), created 0700 on first use.
std::string runtime_dir();
std::string daemon_socket_path();

// Control-line token encoding: '%', space and newlines are %-escaped so that
// arguments (e.g. file paths) survive the whitespace-split protocol.
std::string ctl_encode(const std::string& s);
std::string ctl_decode(const std::string& s);

// Run the daemon in this process; blocks until STOP/SIGTERM. Returns exit code.
int daemon_run(const DaemonOpts& opts);

}  // namespace spl::peer
