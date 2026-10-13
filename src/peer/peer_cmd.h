// The daemon (start/stop/reset/status) and pipe plumbing (register/open/close/…),
// plus the `spl peer` group that manages paired peers (ls/show/rename/remove).
#pragma once

namespace spl::peer {

int peer_cmd_main(int argc, char** argv);  // argv[0] == "spl", argv[1] == subcommand
int peer_group_main(int argc, char** argv);  // argv[0] == "peer", argv[1] == its subcommand

}  // namespace spl::peer
