// spl chat: a terminal on each end of a PIPE pair (docs/PIPES.md).
//
// The stored side decides the roles: the leader REGISTERs a `chat` PIPE and
// hosts it (it keeps listening if the peer hangs up; ^D/^C ends hosting); the
// follower OPENs it. Both then just bridge their stdio to the daemon.
#include "peer/chat.h"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#include "common/log.h"
#include "peer/daemon.h"
#include "peer/daemon_client.h"
#include "peer/store.h"

namespace spl::peer {

int chat_main(int argc, char** argv) {
    DaemonOpts opts = default_daemon_opts();
    std::string name;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--server" && i + 1 < argc) {
            opts.server = argv[++i];
        } else if (a == "--port" && i + 1 < argc) {
            opts.port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (!a.empty() && a[0] != '-') {
            name = a;
        } else {
            spl::logf("spl chat: unexpected argument '%s'", a.c_str());
            return 2;
        }
    }
    if (name.empty()) {
        spl::logf("usage: spl chat <name> [--server H --port N]");
        return 2;
    }

    std::string err;
    auto store = Store::open(&err);
    auto rec = store ? store->load(name) : std::nullopt;
    if (!rec) {
        spl::logf("spl chat: no connection named '%s' (pair first)", name.c_str());
        return 1;
    }

    if (!ensure_daemon(opts, &err)) {
        spl::logf("spl chat: %s", err.c_str());
        return 1;
    }
    int fd = daemon_connect();
    if (fd < 0) {
        spl::logf("spl chat: cannot reach the daemon");
        return 1;
    }

    const bool leader = !rec->side;
    // The follower WAITs: the leader's chat may not be registered yet (whoever
    // starts first just sits until the other side shows up).
    const std::string verb = leader ? "REGISTER " + ctl_encode(name) + " chat PIPE"
                                    : "OPEN " + ctl_encode(name) + " chat WAIT PIPE";
    clog("%s chat with %s...", leader ? "hosting" : "joining", name.c_str());
    const std::string r = send_command(fd, verb);
    if (r.rfind("OK", 0) != 0) {
        spl::logf("spl chat: %s", r.empty() ? "no reply from daemon" : r.c_str());
        ::close(fd);
        return 1;
    }
    clog(leader ? "hosting; waiting for %s (^D to end)" : "waiting for %s (^D to end)",
         name.c_str());

    const int rc = bridge_stdio(fd, /*exit_on_stdin_eof=*/true);
    ::close(fd);
    clog("chat closed");
    return rc;
}

}  // namespace spl::peer
