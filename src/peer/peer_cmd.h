// `spl peer` — manage stored connections (list/rename/remove) and `add` (= pair).
#pragma once

namespace spl::peer {

int peer_cmd_main(int argc, char** argv);  // argv[0] == "peer"

}  // namespace spl::peer
