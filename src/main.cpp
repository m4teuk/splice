// spl — splice peer/server binary.
//
// Dispatches on the first argument into one of the four roles. Phase 0 wires up
// argument handling and proves the Rust(native) <-> C++ FFI link; the role
// implementations are filled in by later phases.

#include <cstdio>
#include <cstring>
#include <string_view>

#include "native/native.h"
#include "peer/chat.h"
#include "peer/pairing.h"
#include "peer/peer_cmd.h"
#include "peer/serve_get.h"
#include "server/server_main.h"

namespace {

// SPL_GIT_SHA is defined by CMake (target_compile_definitions); default keeps
// non-CMake/standalone builds compiling.
#ifndef SPL_GIT_SHA
#define SPL_GIT_SHA "unknown"
#endif
constexpr const char* kVersion = "spl 0.1.0 (" SPL_GIT_SHA ")";

int cmd_server(int argc, char** argv) {
    return spl::server::server_main(argc, argv);
}
int cmd_pair(int argc, char** argv) {
    return spl::peer::pair_main(argc, argv);
}
int cmd_chat(int argc, char** argv) { return spl::peer::chat_main(argc, argv); }
int cmd_peer(int argc, char** argv) { return spl::peer::peer_cmd_main(argc, argv); }

void print_usage() {
    std::puts(
        "usage: spl <command> [args]\n"
        "\n"
        "commands:\n"
        "  server                              run the rendezvous + relay server\n"
        "  pair [code]                         pair with another peer\n"
        "  peer <sub>                          daemon, pipes + connections (see spl peer)\n"
        "  serve <peer> [--name n] <path>      host a file for the peer to fetch\n"
        "  get <peer> <pipe> [-o p] [-b]       fetch a served file\n"
        "  chat <name>                         talk to the peer (a PIPE pair)\n"
        "\n"
        "  --version   print version\n"
        "  --selftest  verify the native (Rust) FFI link\n"
        "  --help      show this help");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 2;
    }

    const std::string_view cmd = argv[1];

    if (cmd == "--version" || cmd == "-V") {
        unsigned char nbuf[64];
        const int n = spl_native_version(nbuf, sizeof(nbuf));
        std::printf("%s (native: %s)\n", kVersion,
                    n > 0 ? reinterpret_cast<const char*>(nbuf) : "?");
        return 0;
    }
    if (cmd == "--selftest") {
        const int r = spl_native_selftest(41);
        const bool ok = (r == 42);
        std::printf("native FFI self-test: %s (spl_native_selftest(41) = %d)\n",
                    ok ? "OK" : "FAIL", r);
        return ok ? 0 : 1;
    }
    if (cmd == "--help" || cmd == "-h") {
        print_usage();
        return 0;
    }

    if (cmd == "server") return cmd_server(argc - 1, argv + 1);
    if (cmd == "pair") return cmd_pair(argc - 1, argv + 1);
    if (cmd == "peer") return cmd_peer(argc - 1, argv + 1);
    if (cmd == "serve") return spl::peer::serve_main(argc - 1, argv + 1);
    if (cmd == "get") return spl::peer::get_main(argc - 1, argv + 1);
    if (cmd == "chat") return cmd_chat(argc - 1, argv + 1);

    std::fprintf(stderr, "spl: unknown command '%.*s'\n",
                 static_cast<int>(cmd.size()), cmd.data());
    print_usage();
    return 2;
}
