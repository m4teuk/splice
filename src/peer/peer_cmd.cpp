#include "peer/peer_cmd.h"

#include <unistd.h>

#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include "common/base64.h"
#include "common/log.h"
#include "peer/daemon.h"
#include "peer/daemon_client.h"
#include "peer/pairing.h"
#include "peer/runtime.h"
#include "peer/store.h"

namespace spl::peer {

namespace {

void usage() {
    spl::logf(
        "usage:\n"
        "  spl peer list | ls            list paired connections\n"
        "  spl peer rename <old> <new>   rename a connection\n"
        "  spl peer remove <name>        delete a connection\n"
        "  spl peer add [pair options]   pair with a new peer (alias for `spl pair`)\n"
        "\n"
        "  spl peer start [--foreground] [--server H --port N]   run the daemon\n"
        "  spl peer stop                 stop the daemon\n"
        "  spl peer status               show sessions and pipes\n"
        "  spl peer reset                drop all pipes (diagnostic stays)\n"
        "\n"
        "  spl peer register <peer> <pipe> <TYPE> [args…]   host a named pipe\n"
        "  spl peer unregister <peer> <pipe>\n"
        "  spl peer open <peer> <pipe>   connect; stdin/stdout become the pipe\n"
        "  spl peer close <peer> <#id>   kill a running instance");
}

DaemonOpts daemon_opts_from(int argc, char** argv) {
    PeerOpts o = default_peer_opts();
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--server" && i + 1 < argc) o.server = argv[++i];
        if (a == "--port" && i + 1 < argc) o.port = static_cast<uint16_t>(std::atoi(argv[++i]));
    }
    return DaemonOpts{o.server, o.port};
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
        spl::logf("spl peer start: %s", err.c_str());
        return 1;
    }
    std::printf("daemon started (%s)\n", daemon_socket_path().c_str());
    return 0;
}

int do_stop() {
    const std::string r = daemon_request("STOP");
    if (r.empty()) {
        std::printf("daemon not running\n");
        return 1;
    }
    std::printf("daemon stopped\n");
    return 0;
}

int do_status() {
    int fd = daemon_connect();
    if (fd < 0) {
        std::printf("daemon not running\n");
        return 1;
    }
    std::string first = send_command(fd, "STATUS");
    if (first != "OK") {
        spl::logf("spl peer status: %s", first.empty() ? "no reply" : first.c_str());
        ::close(fd);
        return 1;
    }
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0) fwrite(buf, 1, static_cast<size_t>(n), stdout);
    ::close(fd);
    return 0;
}

// One-line verbs (REGISTER/UNREGISTER/CLOSE/RESET) after auto-starting the daemon.
int do_verb(int argc, char** argv, const std::string& line) {
    std::string err;
    if (!ensure_daemon(daemon_opts_from(argc, argv), &err)) {
        spl::logf("spl peer: %s", err.c_str());
        return 1;
    }
    const std::string r = daemon_request(line);
    if (r.rfind("OK", 0) == 0) {
        if (r.size() > 3) std::printf("%s\n", r.substr(3).c_str());
        return 0;
    }
    spl::logf("spl peer: %s", r.empty() ? "no reply from daemon" : r.c_str());
    return 1;
}

// PIPE-typed verbs: issue the command, then this process is the pipe.
int do_pipe_verb(int argc, char** argv, const std::string& line) {
    std::string err;
    if (!ensure_daemon(daemon_opts_from(argc, argv), &err)) {
        spl::logf("spl peer: %s", err.c_str());
        return 1;
    }
    int fd = daemon_connect();
    if (fd < 0) {
        spl::logf("spl peer: cannot reach the daemon");
        return 1;
    }
    const std::string r = send_command(fd, line);
    if (r.rfind("OK", 0) != 0) {
        spl::logf("spl peer: %s", r.empty() ? "no reply from daemon" : r.c_str());
        ::close(fd);
        return 1;
    }
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
        if (a == "--foreground") continue;
        out.push_back(a);
    }
    return out;
}

std::string join(const std::vector<std::string>& v, size_t from) {
    std::string s;
    for (size_t i = from; i < v.size(); ++i) {
        if (!s.empty()) s += " ";
        s += v[i];
    }
    return s;
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
    if (sub == "list" || sub == "ls") return do_list();
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
    if (sub == "status") return do_status();
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
        if (a.size() == 2)  // default local end: this process via PIPE
            return do_pipe_verb(argc, argv, "OPEN " + join(a, 0) + " PIPE");
        const std::string line = "OPEN " + join(a, 0);
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
