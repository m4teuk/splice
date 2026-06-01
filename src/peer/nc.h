// `spl send <name>` and `spl receive <name>`: an nc-style byte pipe over the
// tunnel. Both copy stdin -> peer and peer -> stdout.
#pragma once

namespace spl::peer {

int nc_main(bool is_send, int argc, char** argv);

}  // namespace spl::peer
