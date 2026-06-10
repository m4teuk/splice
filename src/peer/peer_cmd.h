// `spl peer` — the daemon (start/stop/reset), pipe plumbing (register/open/…)
// and stored connections (list/rename/remove, `add` = pair).
#pragma once

namespace spl::peer {

int peer_cmd_main(int argc, char** argv);  // argv[0] == "peer"
int status_main();                         // `spl status` (alias: `spl peer status`)

}  // namespace spl::peer
