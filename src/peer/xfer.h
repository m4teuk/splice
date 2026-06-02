// `spl send <name> <path[:newname]>` and `spl receive <name>`: one-file transfer
// over the tunnel.
#pragma once

namespace spl::peer {

int send_main(int argc, char** argv);
int receive_main(int argc, char** argv);

}  // namespace spl::peer
