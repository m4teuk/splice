#pragma once

namespace spl::peer {
int serve_main(int argc, char** argv);  // spl serve <peer> [--name n] <path>
int get_main(int argc, char** argv);    // spl get <peer> <pipe> [-o path] [-f] [--background]
}  // namespace spl::peer
