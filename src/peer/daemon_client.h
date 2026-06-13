// Client side of the daemon control socket: connect, one-shot requests,
// auto-start (fork a daemon when none is running), and the stdio<->socket
// bridge used by PIPE-typed commands.
#pragma once

#include <string>

#include "peer/daemon.h"

namespace spl::peer {

// Verbose client trace, always on, to stderr — blue and "[spl] "-prefixed when
// stderr is a TTY, plain otherwise (so logs/pipes stay clean). printf-style.
void clog(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

// Connect to the daemon socket; -1 if it isn't running.
int daemon_connect();

// Send one command line; returns the first reply line (without the newline) or
// "" on I/O failure. Closes the connection.
std::string daemon_request(const std::string& line);

// Make sure a daemon is running (fork one if needed). True on success.
bool ensure_daemon(const DaemonOpts& opts, std::string* err);

// Send `line` on `fd` and read the first reply line (fd stays open: used for
// PIPE-typed commands whose connection becomes the byte stream).
std::string send_command(int fd, const std::string& line);

// Pump stdin -> fd and fd -> stdout until the daemon side closes (or SIGINT).
// On stdin EOF: keep receiving (default), or return — closing the pipe — when
// exit_on_stdin_eof is set (chat semantics). Returns an exit code.
int bridge_stdio(int fd, bool exit_on_stdin_eof = false);

}  // namespace spl::peer
