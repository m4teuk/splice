// spl — splice peer/server binary.
//
// Dispatches on the first argument into one of the four roles. Phase 0 wires up
// argument handling and proves the Rust(native) <-> C++ FFI link; the role
// implementations are filled in by later phases.

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string_view>

#include "native/native.h"
#include "peer/datatest.h"
#include "peer/nc.h"
#include "peer/pairing.h"
#include "server/server_main.h"

namespace {

constexpr const char* kVersion = "spl 0.1.0";

int cmd_server(int argc, char** argv) {
    return spl::server::server_main(argc, argv);
}
int cmd_pair(int argc, char** argv) {
    return spl::peer::pair_main(argc, argv);
}
int cmd_send(int argc, char** argv) {
    return spl::peer::nc_main(/*is_send=*/true, argc, argv);
}
int cmd_receive(int argc, char** argv) {
    return spl::peer::nc_main(/*is_send=*/false, argc, argv);
}

void print_usage() {
    std::puts(
        "usage: spl <command> [args]\n"
        "\n"
        "commands:\n"
        "  server      run the rendezvous + relay server\n"
        "  pair        pair with another peer (`spl pair` or `spl pair <code>`)\n"
        "  send        connect to a paired peer and send\n"
        "  receive     wait for a paired peer and receive\n"
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
    if (cmd == "send") return cmd_send(argc - 1, argv + 1);
    if (cmd == "receive") return cmd_receive(argc - 1, argv + 1);
    if (cmd == "__datatest") return spl::peer::datatest_main(argc - 1, argv + 1);

    std::fprintf(stderr, "spl: unknown command '%.*s'\n",
                 static_cast<int>(cmd.size()), cmd.data());
    print_usage();
    return 2;
}
