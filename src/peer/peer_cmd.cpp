#include "peer/peer_cmd.h"

#include <unistd.h>

#include <cstdio>
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

#include "common/base64.h"
#include "common/log.h"
#include "peer/daemon.h"
#include "peer/daemon_client.h"
#include "peer/pairing.h"
#include "peer/store.h"

namespace spl::peer {

namespace {

void usage() {
    spl::logf(
        "usage:\n"
        "  spl ls [peer]                 list paired peers (or what <peer> serves you)\n"
        "  spl rename <old> <new>        rename a connection\n"
        "  spl remove <name>             delete a connection\n"
        "  spl add [pair options]        pair with a new peer (alias for `spl pair`)\n"
        "\n"
        "  spl start [--foreground] [--server H --port N]   run the daemon (stays up)\n"
        "  spl stop                      stop the daemon\n"
        "  spl status [-v]               show sessions and pipes\n"
        "  spl reset                     drop all registered pipes\n"
        "\n"
        "  spl register <peer> <pipe> [LIMIT n] <TYPE> [args…]   host a named pipe\n"
        "  spl unregister <peer> <pipe>\n"
        "  spl open [--wait] <peer> <pipe>   connect; stdio becomes the pipe\n"
        "  spl close <peer> <#id>        kill a running instance");
}

DaemonOpts daemon_opts_from(int argc, char** argv) {
    DaemonOpts o = default_daemon_opts();
    apply_daemon_opts(argc, argv, 2, o);
    return o;
}

int do_start(int argc, char** argv) {
    bool foreground = false;
    for (int i = 2; i < argc; ++i)
        if (std::string(argv[i]) == "--foreground") foreground = true;
    const DaemonOpts opts = daemon_opts_from(argc, argv);
    if (foreground) return daemon_run(opts);
    if (daemon_request("PING") == "OK") {
        std::printf("daemon already running (%s)\n", daemon_socket_path().c_str());
        return 0;
    }
    std::string err;
    if (!ensure_daemon(opts, &err)) {
        spl::logf("spl start: %s", err.c_str());
        return 1;
    }
    std::printf("daemon started (%s)\n", daemon_socket_path().c_str());
    return 0;
}

int do_stop() {
    clog("-> STOP");
    const std::string r = daemon_request("STOP");
    if (r.empty()) {
        std::printf("daemon not running\n");
        return 1;
    }
    std::printf("daemon stopped\n");
    return 0;
}

int do_status(bool verbose) {
    int fd = daemon_connect();
    if (fd < 0) {
        std::printf("daemon not running\n");
        return 1;
    }
    const std::string first = send_command(fd, verbose ? "STATUS VERBOSE" : "STATUS");
    if (!ok_reply(first)) {
        daemon_fail("spl status", first);
        ::close(fd);
        return 1;
    }
    const std::string body = read_to_eof(fd);
    ::close(fd);
    fwrite(body.data(), 1, body.size(), stdout);
    return 0;
}

// One-line verbs (REGISTER/UNREGISTER/CLOSE/RESET) after auto-starting the daemon.
int do_verb(int argc, char** argv, const std::string& line) {
    std::string err;
    if (!ensure_daemon(daemon_opts_from(argc, argv), &err)) {
        spl::logf("spl: %s", err.c_str());
        return 1;
    }
    clog("-> %s", line.c_str());
    const std::string r = daemon_request(line);
    if (!ok_reply(r)) {
        daemon_fail("spl", r);
        return 1;
    }
    clog("<- %s", r.c_str());
    if (r.size() > 3) std::printf("%s\n", r.substr(3).c_str());
    return 0;
}

// PIPE-typed verbs: issue the command, then this process is the pipe.
int do_pipe_verb(int argc, char** argv, const std::string& line) {
    std::string err;
    if (!ensure_daemon(daemon_opts_from(argc, argv), &err)) {
        spl::logf("spl: %s", err.c_str());
        return 1;
    }
    int fd = daemon_connect();
    if (fd < 0) {
        spl::logf("spl: cannot reach the daemon");
        return 1;
    }
    clog("-> %s", line.c_str());
    const std::string r = send_command(fd, line);
    if (!ok_reply(r)) {
        daemon_fail("spl", r);
        ::close(fd);
        return 1;
    }
    clog("connected; bridging stdin/stdout (^D to end)");
    int rc = bridge_stdio(fd);
    ::close(fd);
    return rc;
}

// Collect non-flag args after the subcommand (skipping --server/--port values).
std::vector<std::string> plain_args(int argc, char** argv) {
    std::vector<std::string> out;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--server" || a == "--port") {
            ++i;
            continue;
        }
        if (a == "--foreground" || a == "--wait") continue;
        out.push_back(a);
    }
    return out;
}

bool has_flag(int argc, char** argv, const char* flag) {
    for (int i = 2; i < argc; ++i)
        if (std::string(argv[i]) == flag) return true;
    return false;
}

// Joins args as encoded control-protocol tokens (paths may contain spaces).
std::string join(const std::vector<std::string>& v, size_t from) {
    std::string s;
    for (size_t i = from; i < v.size(); ++i) {
        if (!s.empty()) s += " ";
        s += ctl_encode(v[i]);
    }
    return s;
}

// `spl ls <peer>`: ask that peer (via the daemon's LIST verb) what it serves us.
int do_list_remote(int argc, char** argv, const std::string& peer) {
    std::string err;
    if (!ensure_daemon(daemon_opts_from(argc, argv), &err)) {
        spl::logf("spl ls: %s", err.c_str());
        return 1;
    }
    const std::string body = daemon_list(peer, 4500);
    if (body.empty()) {
        std::printf("%s offers no pipes (or is unreachable).\n", peer.c_str());
        return 0;
    }
    std::printf("%s offers:\n", peer.c_str());
    std::string line;
    std::istringstream is(body);
    while (std::getline(is, line))
        if (!line.empty()) std::printf("  %s\n", line.c_str());
    return 0;
}

int do_list() {
    std::string err;
    auto store = Store::open(&err);
    if (!store) {
        spl::logf("%s", err.c_str());
        return 1;
    }
    auto names = store->list();
    if (names.empty()) {
        std::printf("No paired connections.\n");
        return 0;
    }
    for (const auto& n : names) {
        auto r = store->load(n);
        if (!r) continue;
        char date[32] = "?";
        time_t t = static_cast<time_t>(r->created_unix);
        struct tm tm;
        if (localtime_r(&t, &tm)) std::strftime(date, sizeof(date), "%Y-%m-%d", &tm);
        std::printf("%-20s  %-8s  %s  (paired %s)\n", n.c_str(), r->side ? "follower" : "leader",
                    base64_encode(as_span(r->peer_pub)).c_str(), date);
    }
    return 0;
}

int do_rename(const std::string& from, const std::string& to) {
    std::string err;
    auto store = Store::open(&err);
    if (!store) {
        spl::logf("%s", err.c_str());
        return 1;
    }
    if (!store->rename(from, to, &err)) {
        spl::logf("rename failed: %s", err.c_str());
        return 1;
    }
    std::printf("renamed '%s' -> '%s'\n", from.c_str(), to.c_str());
    return 0;
}

int do_remove(const std::string& name) {
    std::string err;
    auto store = Store::open(&err);
    if (!store) {
        spl::logf("%s", err.c_str());
        return 1;
    }
    if (!store->remove(name)) {
        spl::logf("no connection named '%s'", name.c_str());
        return 1;
    }
    std::printf("removed '%s'\n", name.c_str());
    return 0;
}

}  // namespace


int peer_cmd_main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 2;
    }
    std::string sub = argv[1];
    if (sub == "list" || sub == "ls") {
        const auto a = plain_args(argc, argv);
        return a.empty() ? do_list() : do_list_remote(argc, argv, a[0]);
    }
    if (sub == "rename") {
        if (argc < 4) {
            usage();
            return 2;
        }
        return do_rename(argv[2], argv[3]);
    }
    if (sub == "remove" || sub == "rm") {
        if (argc < 3) {
            usage();
            return 2;
        }
        return do_remove(argv[2]);
    }
    if (sub == "add") return pair_main(argc - 1, argv + 1);  // argv+1[0] == "add"

    if (sub == "start") return do_start(argc, argv);
    if (sub == "stop") return do_stop();
    if (sub == "status") return do_status(has_flag(argc, argv, "-v") || has_flag(argc, argv, "--verbose"));
    if (sub == "reset") return do_verb(argc, argv, "RESET");

    const auto a = plain_args(argc, argv);
    if (sub == "register") {
        if (a.size() < 3) {
            usage();
            return 2;
        }
        const std::string line = "REGISTER " + join(a, 0);
        return a[2] == "PIPE" ? do_pipe_verb(argc, argv, line) : do_verb(argc, argv, line);
    }
    if (sub == "unregister") {
        if (a.size() != 2) {
            usage();
            return 2;
        }
        return do_verb(argc, argv, "UNREGISTER " + join(a, 0));
    }
    if (sub == "open") {
        if (a.size() < 2) {
            usage();
            return 2;
        }
        const std::string wait = has_flag(argc, argv, "--wait") ? " WAIT" : "";
        if (a.size() == 2)  // default local end: this process via PIPE
            return do_pipe_verb(argc, argv, "OPEN " + join(a, 0) + wait + " PIPE");
        const std::string line = "OPEN " + ctl_encode(a[0]) + " " + ctl_encode(a[1]) + wait +
                                 " " + join(a, 2);
        return a[2] == "PIPE" ? do_pipe_verb(argc, argv, line) : do_verb(argc, argv, line);
    }
    if (sub == "close") {
        if (a.size() != 2) {
            usage();
            return 2;
        }
        return do_verb(argc, argv, "CLOSE " + join(a, 0));
    }
    usage();
    return 2;
}

}  // namespace spl::peer
