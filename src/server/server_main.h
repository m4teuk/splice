// Entry point for `spl server`.
#pragma once

namespace spl::server {

// argv[0] is "server"; parses flags, binds sockets, runs until SIGINT/SIGTERM.
int server_main(int argc, char** argv);

}  // namespace spl::server
