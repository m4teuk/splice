#pragma once

namespace spl::peer {
int serve_main(int argc, char** argv);  // spl serve <peer> [--name n] [--limit N] <path>
int get_main(int argc, char** argv);    // spl get <peer> <pipe> [-o path] [-f] [-b]
int send_main(int argc, char** argv);   // spl send <peer> <path…>  (push into the peer's inbox)
int inbox_main(int argc, char** argv);  // spl inbox <peer> <dir> [--limit N] [-f]
}  // namespace spl::peer
