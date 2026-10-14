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
#include "peer/help.h"
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

// `spl help [topic…]`: the overview, or one page ("help peer set" -> "peer set").
int cmd_help(int argc, char** argv) {
    std::string topic;  // the words, minus any -h/--help ("spl help get --help" = get)
    bool flag = false;
    for (int i = 2; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "-h" || a == "--help") flag = true;
        else topic += (topic.empty() ? "" : " ") + std::string(a);
    }
    if (topic.empty()) {
        if (flag) spl::peer::print_help("help");
        else spl::peer::print_overview();
        return 0;
    }
    if (spl::peer::print_help(topic)) return 0;
    std::fprintf(stderr, "spl help: no command '%s' (see: spl help)\n", topic.c_str());
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        spl::peer::print_overview();
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
        spl::peer::print_overview();
        return 0;
    }
    if (cmd == "help") return cmd_help(argc, argv);
    // `spl <command> … --help` shows that command's page and never runs it.
    if (auto topic = spl::peer::help_request(argc, argv)) {
        spl::peer::print_help(*topic);
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
    if (cmd == "update") return argc == 2 ? cmd_update() : spl::peer::usage_error("update");
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
    std::fprintf(stderr, "spl: unknown command '%.*s' (see: spl help)\n",
                 static_cast<int>(cmd.size()), cmd.data());
    return 2;
}
