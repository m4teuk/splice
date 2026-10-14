// Commands on EXEC pipes (peer/exec.h):
//
//   spl expose   <peer> [--name n] [--pty] [--limit N] <program> [args...]   offer a program
//   spl revshell <peer> [--name n] [--limit N]    offer the login shell (EXEC PTY preset)
//   spl run      <peer> <name>                    run an offered program; its status is ours
//   spl shell    <peer> [--name n]                the same, on our terminal (needs a PTY offer)
//
// `run` and `shell` exit with the program's status (128 + signal if it was
// killed), and 255 when spl itself fails (unreachable, not offered, the wrong
// kind, the connection lost mid-run). See docs/PIPES.md.
#pragma once

namespace spl::peer {

int expose_main(int argc, char** argv);
int revshell_main(int argc, char** argv);
int run_main(int argc, char** argv);
int shell_main(int argc, char** argv);

}  // namespace spl::peer
