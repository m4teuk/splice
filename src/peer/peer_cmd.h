// The daemon (start/stop/reset/status), pipe plumbing (register/open/close/…)
// and stored connections (ls/rename/remove, `add` = pair).
#pragma once

namespace spl::peer {

int peer_cmd_main(int argc, char** argv);  // argv[0] == "spl", argv[1] == subcommand

}  // namespace spl::peer
