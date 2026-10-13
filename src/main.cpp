// spl — splice peer/server binary.
//
// Dispatches on the first argument into one of the four roles. Phase 0 wires up
// argument handling and proves the Rust(native) <-> C++ FFI link; the role
// implementations are filled in by later phases.

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#include "native/native.h"
#include "peer/chat.h"
#include "peer/commands.h"
#include "peer/complete.h"
#include "peer/pairing.h"
#include "peer/peer_cmd.h"
#include "peer/serve_get.h"
#include "peer/shell.h"
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

// Re-run the installer one-liner — the same `curl … | bash` the README documents,
// which downloads the latest prebuilt binary (or builds from source) and replaces
// this one in place. SPL_INSTALL_URL overrides the source (forks / testing). We
// exec the shell so spl hands its terminal straight to the installer.
int cmd_update() {
    const char* url = std::getenv("SPL_INSTALL_URL");
    if (!url || !*url)
        url = "https://raw.githubusercontent.com/m4teuk/splice/main/install.sh";
    const std::string sh = "curl -fsSL '" + std::string(url) + "' | bash";
    std::fprintf(stderr, "updating spl from %s\n", url);
    ::execl("/bin/sh", "sh", "-c", sh.c_str(), static_cast<char*>(nullptr));
    std::perror("spl update: could not exec /bin/sh");
    return 1;
}

void print_usage() {
    std::puts(
        "usage: spl <command> [args]\n"
        "\n"
        "pairing:\n"
        "  pair [code]                         pair with another device\n"
        "  peer ls | show | rename | remove    manage paired peers (see: spl peer)\n"
        "\n"
        "moving data:\n"
        "  serve <peer> [--name n] <path>      host a file/dir for the peer to fetch\n"
        "  get <peer> <pipe> [-o p] [-b]       fetch a served file/dir\n"
        "  inbox <peer> <dir> [--limit N]      let the peer push files to you\n"
        "  send <peer> <path...>               push files into the peer's inbox\n"
        "  chat <name>                         talk to the peer (a PIPE pair)\n"
        "  revshell <peer> [--name n]          offer a shell on this machine to the peer\n"
        "  shell <peer> [--name n]             open a shell on the peer\n"
        "  ls <peer>                           what the peer offers you\n"
        "\n"
        "seeing what's happening:\n"
        "  status [-v]                         every peer: link, offers, live connections\n"
        "  ping <peer>                         is the peer reachable right now?\n"
        "\n"
        "daemon and plumbing:\n"
        "  start | stop | reset | config       daemon lifecycle / drop all offers / config\n"
        "  reload                              make the daemon re-read the peer files\n"
        "  register | unregister | open | close   raw pipes (ECHO, SHARE_FILE, GET_FILE, SHELL, PIPE)\n"
        "  server                              run your own rendezvous + relay server\n"
        "  update                              re-run the installer to get the latest spl\n"
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
    if (cmd == "serve") return spl::peer::serve_main(argc - 1, argv + 1);
    if (cmd == "get") return spl::peer::get_main(argc - 1, argv + 1);
    if (cmd == "send") return spl::peer::send_main(argc - 1, argv + 1);
    if (cmd == "inbox") return spl::peer::inbox_main(argc - 1, argv + 1);
    if (cmd == "chat") return cmd_chat(argc - 1, argv + 1);
    if (cmd == "revshell") return spl::peer::revshell_main(argc - 1, argv + 1);
    if (cmd == "shell") return spl::peer::shell_main(argc - 1, argv + 1);
    if (cmd == "update") return cmd_update();
    if (cmd == "peer") return spl::peer::peer_group_main(argc - 1, argv + 1);
    if (cmd == "__complete") return spl::peer::complete_main(argc - 1, argv + 1);

    // The daemon / pipe plumbing commands (start, stop, status, ls, register,
    // open, …) are all handled by peer_cmd_main.
    if (spl::peer::is_managed_command(cmd)) return cmd_peer(argc, argv);

    // Managing peers has one home; point there instead of a bare "unknown command".
    if (cmd == "rename" || cmd == "remove" || cmd == "rm" || cmd == "list") {
        std::fprintf(stderr, "spl: managing peers is under `spl peer` — try: spl peer %s\n",
                     cmd == "list" ? "ls" : cmd == "rm" ? "remove" : std::string(cmd).c_str());
        return 2;
    }
    std::fprintf(stderr, "spl: unknown command '%.*s'\n",
                 static_cast<int>(cmd.size()), cmd.data());
    print_usage();
    return 2;
}
