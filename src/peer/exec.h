// EXEC: a pipe whose far end is a program run on this machine, one run per
// connection — the type behind `spl run`/`spl expose` and (as the SHELL preset)
// `spl shell`/`spl revshell`.
//
// The program is fixed by whoever offers it: the peer that connects supplies
// input, never the command line. It runs as the offering user, in their home
// directory, in a session of its own, with SPL_PEER set to the connecting
// peer's name. Hanging up the connection hangs the program up (SIGHUP to its
// process group, SIGKILL a few seconds later if it's still there).
//
// Both directions are framed as [type:1][len:2 BE][payload], so input can end
// while output continues, stderr stays apart from stdout, and the result
// travels at the end:
//
//   to the program:    DATA (stdin bytes) · WINSZ (rows:2 cols:2) · EOF (stdin ended)
//   from the program:  OUT (stdout) · ERR (stderr) · EXIT (how:1 code:1), always last
//
// EXIT says how it ended: how 0 = exited with `code`, how 1 = killed by signal
// `code`. A stream that ends without EXIT means the run was cut off.
//
// With PTY the program gets a terminal instead of pipes: its stdout and stderr
// are one stream (sent as OUT), WINSZ resizes it, and EOF types the terminal's
// end-of-file character. Whether an offer has a PTY is part of its kind
// ("exec/1 pty" vs "exec/1"), so a client knows before the first byte whether
// to hand the program its terminal.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "common/time.h"
#include "peer/pipes.h"

namespace spl::peer {

namespace execproto {
constexpr uint8_t kData = 0, kWinsz = 1, kEof = 2;   // client -> program
constexpr uint8_t kOut = 16, kErr = 17, kExit = 18;  // program -> client
constexpr uint8_t kExited = 0, kSignaled = 1;        // EXIT's `how`
constexpr size_t kMaxPayload = 0xffff;
}  // namespace execproto

// EXEC [PTY] <program> [args...]   or   SHELL (EXEC PTY of the user's login shell).
// Null + *err for bad arguments.
std::unique_ptr<LocalEnd> make_exec_end(const std::string& type,
                                        const std::vector<std::string>& args, std::string* err);

// Does this EXEC/SHELL registration run its program on a terminal?
bool exec_has_pty(const std::string& type, const std::vector<std::string>& args);

// Programs whose connection ended before they did: hung up, then killed if
// they linger, and reaped. The daemon calls this every tick.
void reap_orphans(Millis now);

// The daemon is exiting: give the programs it hung up up to `grace_ms` to end,
// then SIGKILL whatever is left (one that ignores SIGHUP mustn't outlive it).
void stop_orphans(Millis grace_ms);

}  // namespace spl::peer
