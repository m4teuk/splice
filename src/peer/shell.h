// SHELL pipe type + its two CLI commands.
//
//   spl revshell <peer> [--name n] [--limit N]   host: offer a shell on this box
//   spl shell    <peer> [--name n]                client: attach to the peer's shell
//
// The host side is a daemon-owned, durable registration (like SHARE_FILE): each
// inbound connection forkpty's the host's $SHELL and splices the PTY ↔ tunnel,
// so the peer gets a fresh shell per attach, any number at once, until it is
// unregistered. The client side bridges the local terminal in raw mode and
// forwards window-size changes — so it feels like ssh. See docs/PIPES.md.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "peer/pipes.h"

namespace spl::peer {

// Factory for the daemon-owned SHELL end (called by make_local_end). Takes no
// args; the actual forkpty happens in start(), so REGISTER-time validation is
// cheap and one shell is spawned per connection.
std::unique_ptr<LocalEnd> make_shell_end(const std::vector<std::string>& args, std::string* err);

int revshell_main(int argc, char** argv);  // host
int shell_main(int argc, char** argv);     // client

}  // namespace spl::peer
