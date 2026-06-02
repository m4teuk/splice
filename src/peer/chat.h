// `spl chat <name>`: a bidirectional stdin<->stdout pipe over the tunnel. Unlike
// file transfer, closing either end tears the whole connection down.
#pragma once

namespace spl::peer {

int chat_main(int argc, char** argv);

}  // namespace spl::peer
