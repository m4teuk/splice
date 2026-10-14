#include "peer/peer_cmd.h"

#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

#include "common/base64.h"
#include "common/config.h"
#include "common/log.h"
#include "peer/commands.h"
#include "peer/daemon.h"
#include "peer/daemon_client.h"
#include "peer/help.h"
#include "peer/pairing.h"
#include "peer/pathman.h"
#include "peer/pipes.h"
#include "peer/store.h"

namespace spl::peer {

namespace {

DaemonOpts daemon_opts_from(int argc, char** argv) {
    DaemonOpts o = default_daemon_opts();
    apply_daemon_opts(argc, argv, 2, o);
    return o;
}

int do_start(int argc, char** argv) {
    bool foreground = false;
    for (int i = 2; i < argc; ++i)
        if (std::string(argv[i]) == "--foreground") foreground = true;
    DaemonOpts opts = daemon_opts_from(argc, argv);
    opts.sticky = true;  // an explicitly-started daemon stays up until `spl stop`
    if (foreground) return daemon_run(opts);
    if (daemon_request("PING") == "OK") {
        // Already running (perhaps auto-started); make sure it won't auto-stop.
        daemon_request("STICKY");
        std::printf("daemon already running, kept up (%s)\n", daemon_socket_path().c_str());
        return 0;
    }
    std::string err;
    if (!ensure_daemon(opts, &err)) {
        spl::logf("spl start: %s", err.c_str());
        return 1;
    }
    std::printf("daemon started, stays up until `spl stop` (%s)\n", daemon_socket_path().c_str());
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
    if (line.rfind("OPEN ", 0) == 0) {  // an OPEN connects first; a REGISTER just listens
        std::string kind;
        if (!await_ready(fd, &kind, &err)) {
            spl::logf("spl: %s", err.c_str());
            ::close(fd);
            return 1;
        }
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
    // One "<name>\t<kind>" line per offer (an older peer sends just the name).
    struct Row { std::string name, label, use; };
    std::vector<Row> rows;
    size_t w0 = 0, w1 = 0;
    std::string line;
    std::istringstream is(body);
    while (std::getline(is, line)) {
        if (line.empty()) continue;
        const size_t tab = line.find('\t');
        // Both come from the peer: never let them drive our terminal.
        const std::string name = printable(line.substr(0, tab));
        const std::string kind = printable(tab == std::string::npos ? "" : line.substr(tab + 1));
        rows.push_back({name, kind_label(kind), kind_usage(kind, peer, name)});
        w0 = std::max(w0, name.size());
        w1 = std::max(w1, rows.back().label.size());
    }
    std::printf("%s offers you:\n", peer.c_str());
    for (const auto& r : rows)
        std::printf("  %-*s  %-*s  %s\n", static_cast<int>(w0), r.name.c_str(),
                    static_cast<int>(w1), r.label.c_str(), r.use.c_str());
    return 0;
}

// The peers we offer `name` to: stored offers, plus live PIPE ones a running
// daemon holds (never starts one just to ask).
std::vector<std::string> peers_offered(const std::string& name) {
    std::vector<std::string> out;
    auto add = [&](const std::string& p) {
        if (std::find(out.begin(), out.end(), p) == out.end()) out.push_back(p);
    };
    if (auto store = Store::open(nullptr))
        for (const auto& peer : store->list())
            for (const auto& r : store->list_pipes(peer))
                if (r.name == name) add(peer);
    if (int fd = daemon_connect(); fd >= 0) {
        if (ok_reply(send_command(fd, "STATUS RAW"))) {
            std::istringstream is(read_to_eof(fd));
            std::string line;
            while (std::getline(is, line)) {  // reg\t<peer>\t<name>\t<type>
                std::vector<std::string> f;
                std::istringstream ls(line);
                for (std::string x; std::getline(ls, x, '\t');) f.push_back(x);
                if (f.size() >= 3 && f[0] == "reg" && f[2] == name) add(f[1]);
            }
        }
        ::close(fd);
    }
    return out;
}

// `spl drop [<peer>] <name>`: stop offering something. The peer can be left
// out when only one peer is offered that name.
int do_drop(int argc, char** argv) {
    const auto a = plain_args(argc, argv);
    if (a.empty() || a.size() > 2) return usage_error("drop");
    const std::string name = a.back();
    std::string peer = a.size() == 2 ? a[0] : "";
    if (peer.empty()) {
        const auto peers = peers_offered(name);
        if (peers.empty()) {
            spl::logf("spl drop: you don't offer anything called '%s' (see: spl status)",
                      name.c_str());
            return 1;
        }
        if (peers.size() > 1) {
            std::string list;
            for (const auto& p : peers) list += (list.empty() ? "" : ", ") + p;
            spl::logf("spl drop: '%s' is offered to %s; say which: spl drop <peer> %s",
                      name.c_str(), list.c_str(), name.c_str());
            return 1;
        }
        peer = peers[0];
    }
    std::string err;
    if (!ensure_daemon(daemon_opts_from(argc, argv), &err)) {
        spl::logf("spl drop: %s", err.c_str());
        return 1;
    }
    const std::string r = daemon_request("UNREGISTER " + ctl_encode(peer) + " " + ctl_encode(name));
    if (!ok_reply(r)) {
        daemon_fail("spl drop", r);
        return 1;
    }
    std::printf("no longer offering '%s' to %s\n", name.c_str(), peer.c_str());
    if (r.size() > 3) std::printf("%s\n", r.substr(3).c_str());  // live connections carry on
    return 0;
}

// "just now", "5 min ago", "3 h ago", "2 d ago"
std::string ago(int64_t secs) {
    if (secs < 60) return "just now";
    if (secs < 3600) return std::to_string(secs / 60) + " min ago";
    if (secs < 86400) return std::to_string(secs / 3600) + " h ago";
    return std::to_string(secs / 86400) + " d ago";
}

std::string paired_date(int64_t unix_s) {
    char date[32] = "?";
    time_t t = static_cast<time_t>(unix_s);
    struct tm tm;
    if (localtime_r(&t, &tm)) std::strftime(date, sizeof(date), "%Y-%m-%d", &tm);
    return date;
}

int do_show(const std::string& name) {
    std::string err;
    auto store = Store::open(&err);
    if (!store) {
        spl::logf("%s", err.c_str());
        return 1;
    }
    auto r = store->load(name);
    if (!r) {
        spl::logf("no peer named '%s' (see: spl peer ls)", name.c_str());
        return 1;
    }
    std::printf("%s\n", r->name.c_str());
    std::printf("  your role  %s\n", r->side ? "follower (you entered the code)"
                                             : "leader (you showed the code)");
    std::printf("  their key  %s\n", base64_encode(as_span(r->peer_pub)).c_str());
    std::printf("  your key   %s\n", base64_encode(as_span(r->own_pub)).c_str());
    std::printf("  paired     %s\n", paired_date(r->created_unix).c_str());
    const uint16_t told = store->load_learned_port(name);
    const uint16_t lan = told ? told : r->lan_port ? r->lan_port : kLanDiscoPort;
    r->lan_port = lan == kLanDiscoPort ? 0 : lan;  // show what's in effect
    std::printf("  settings   %s\n", settings_summary(*r).c_str());
    std::printf("  lan port   %u%s\n", lan,
                told ? " (told by the peer)" : lan == kLanDiscoPort ? " (default)" : "");
    bool first = true;
    auto row = [&](const std::string& addr, const std::string& note) {
        std::printf("  %s  %-28s (%s)\n", first ? "addresses" : "         ", addr.c_str(),
                    note.c_str());
        first = false;
    };
    for (const auto& a : r->addresses) row(a, "added");
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    for (const auto& s : store->load_seen(name)) row(s.addr, "seen " + ago(now - s.when_unix));
    return 0;
}

int do_set(const std::string& name, const std::string& setting, const std::string& value) {
    std::string err;
    auto store = Store::open(&err);
    if (!store) {
        spl::logf("%s", err.c_str());
        return 1;
    }
    auto r = store->load(name);
    if (!r) {
        spl::logf("no peer named '%s' (see: spl peer ls)", name.c_str());
        return 1;
    }
    if (setting == "lan-port") {
        const int n = value == "default" ? kLanDiscoPort : std::atoi(value.c_str());
        if (n < 1 || n > 65535) {
            spl::logf("lan-port is a port number (1-65535) or 'default', not '%s'", value.c_str());
            return 2;
        }
        r->lan_port = n == kLanDiscoPort ? 0 : static_cast<uint16_t>(n);
        // A hand-set value replaces whatever the peer told the daemon before
        // (if the peer says otherwise again later, its word wins again).
        store->save_learned_port(name, 0);
    } else {
        if (value != "on" && value != "off") {
            spl::logf("a setting is 'on' or 'off', not '%s'", value.c_str());
            return 2;
        }
        const PeerSetting* st = nullptr;
        for (const auto& s : kPeerSettings)
            if (setting == s.name) st = &s;
        if (!st) {
            spl::logf("no setting '%s' — settings: relay, lan-discovery, remember-address, lan-port",
                      setting.c_str());
            return 2;
        }
        (*r).*(st->field) = value == "on";
    }
    if (!store->save(*r, &err)) {
        spl::logf("could not save: %s", err.c_str());
        return 1;
    }
    // Turning remembering off also forgets what was remembered.
    if (!r->remember_address) store->save_seen(name, {});
    std::printf("%s: %s\n", name.c_str(), settings_summary(*r).c_str());
    notify_peers_changed();
    return 0;
}

int do_address(const std::string& name, const std::string& addr, bool add) {
    std::string err;
    auto store = Store::open(&err);
    if (!store) {
        spl::logf("%s", err.c_str());
        return 1;
    }
    auto r = store->load(name);
    if (!r) {
        spl::logf("no peer named '%s' (see: spl peer ls)", name.c_str());
        return 1;
    }
    auto it = std::find(r->addresses.begin(), r->addresses.end(), addr);
    if (add) {
        if (!parse_address_hint(addr, nullptr, nullptr)) {
            spl::logf("'%s' is not an address — use a host or IP, optionally with a port: "
                      "10.0.0.5, laptop.example.net, 10.0.0.5:7701, [fd00::5]:7701",
                      addr.c_str());
            return 2;
        }
        if (it != r->addresses.end()) {
            std::printf("'%s' already has address %s\n", name.c_str(), addr.c_str());
            return 0;
        }
        r->addresses.push_back(addr);
    } else if (it != r->addresses.end()) {
        r->addresses.erase(it);
    } else {
        // Not a hint: maybe a remembered address — by its full form or just its host.
        auto seen = store->load_seen(name);
        const size_t before = seen.size();
        std::erase_if(seen, [&](const SeenAddress& s) {
            std::string host;
            parse_address_hint(s.addr, &host, nullptr);
            return s.addr == addr || host == addr;
        });
        if (seen.size() == before) {
            spl::logf("'%s' has no address %s (see: spl peer show %s)", name.c_str(), addr.c_str(),
                      name.c_str());
            return 1;
        }
        store->save_seen(name, seen);
        std::printf("forgot remembered address %s of '%s'\n", addr.c_str(), name.c_str());
        notify_peers_changed();
        return 0;
    }
    if (!store->save(*r, &err)) {
        spl::logf("could not save: %s", err.c_str());
        return 1;
    }
    std::printf("%s address %s %s '%s'\n", add ? "added" : "removed", addr.c_str(),
                add ? "to" : "from", name.c_str());
    notify_peers_changed();
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
        std::printf("No paired peers. Pair with one: spl pair\n");
        return 0;
    }
    for (const auto& n : names) {
        auto r = store->load(n);
        if (!r) continue;
        std::printf("%-20s  paired %s", n.c_str(), paired_date(r->created_unix).c_str());
        if (const uint16_t told = store->load_learned_port(n))  // show what's in effect
            r->lan_port = told == kLanDiscoPort ? 0 : told;
        const size_t known = r->addresses.size() + store->load_seen(n).size();
        std::printf("  %s · %zu address%s\n", settings_summary(*r).c_str(), known,
                    known == 1 ? "" : "es");
    }
    return 0;
}

// `spl ping <peer>`: probe whether the peer is reachable right now (and rough RTT).
int do_ping(int argc, char** argv, const std::string& peer) {
    std::string err;
    if (!ensure_daemon(daemon_opts_from(argc, argv), &err)) {
        spl::logf("spl ping: %s", err.c_str());
        return 1;
    }
    const long rtt = daemon_reach(peer, 5000);
    if (rtt < 0) {
        std::printf("%s is unreachable (offline, or not running spl)\n", peer.c_str());
        return 1;
    }
    std::printf("%s is reachable (~%ldms)\n", peer.c_str(), rtt);
    return 0;
}

// `spl config`: show where the config lives and the current values (edit by hand).
int do_config() {
    Config c = load_config();
    std::printf("config file: %s%s\n", config_path().c_str(),
                config_exists() ? "" : "  (does not exist yet)");
    std::printf("[peer]   addr = %s   port = %u   (relay for pair/serve/get/chat/…)\n",
                c.peer.addr.empty() ? "(default: splice.kussowski.dev)" : c.peer.addr.c_str(),
                c.peer.port ? c.peer.port : 443);
    std::printf("         lan_port = %u%s   (LAN discovery + local pairing listen here)\n",
                c.lan_port ? c.lan_port : kLanDiscoPort, c.lan_port ? "" : " (default)");
    std::printf("[server] addr = %s   port = %u   (only when running `spl server`)\n",
                c.server.addr.empty() ? "(unset)" : c.server.addr.c_str(), c.server.port);
    std::printf("edit the file by hand to change these; CLI flags override per-command.\n");
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
    notify_peers_changed();
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
        spl::logf("no peer named '%s' (see: spl peer ls)", name.c_str());
        return 1;
    }
    std::printf("removed '%s'\n", name.c_str());
    notify_peers_changed();  // a running daemon drops the peer's session right away
    return 0;
}

}  // namespace


int peer_cmd_main(int argc, char** argv) {
    if (argc < 2) return usage_error("help");
    std::string sub = argv[1];
    if (sub == "ls") {  // what a peer offers us (paired peers are `spl peer ls`)
        const auto a = plain_args(argc, argv);
        if (a.size() != 1) {
            return usage_error("ls", a.empty() ? "which peer? (your paired peers: spl peer ls)"
                                                : "too many arguments");
        }
        return do_list_remote(argc, argv, a[0]);
    }

    // These take no arguments; refuse extra words rather than act on a typo
    // (`spl reset desk` must not wipe every peer's offers).
    if (sub == "start" || sub == "stop" || sub == "status" || sub == "reset" ||
        sub == "reload" || sub == "config") {
        for (const auto& w : plain_args(argc, argv))
            if (!(sub == "status" && (w == "-v" || w == "--verbose")))
                return usage_error(sub, "unexpected '" + w + "'");
    }
    if (sub == "start") return do_start(argc, argv);
    if (sub == "stop") return do_stop();
    if (sub == "status") return do_status(has_flag(argc, argv, "-v") || has_flag(argc, argv, "--verbose"));
    if (sub == "reset") return do_verb(argc, argv, "RESET");
    if (sub == "reload") {  // never starts a daemon: a fresh one reads the files anyway
        const std::string r = daemon_request("RELOAD");
        if (r.empty()) {
            std::printf("daemon not running (it reads the peer files when it starts)\n");
            return 0;
        }
        if (!ok_reply(r)) {
            daemon_fail("spl reload", r);
            return 1;
        }
        std::printf("reloaded — %s\n", r.size() > 3 ? r.substr(3).c_str() : "ok");
        return 0;
    }
    if (sub == "config") return do_config();
    if (sub == "drop") return do_drop(argc, argv);
    if (sub == "ping") {
        const auto a = plain_args(argc, argv);
        if (a.size() != 1) {
            return usage_error(sub);
        }
        return do_ping(argc, argv, a[0]);
    }

    const auto a = plain_args(argc, argv);
    if (sub == "register") {
        if (a.size() < 3) {
            return usage_error("pipe " + sub);
        }
        const std::string line = "REGISTER " + join(a, 0);
        return a[2] == "PIPE" ? do_pipe_verb(argc, argv, line) : do_verb(argc, argv, line);
    }
    if (sub == "unregister") {
        if (a.size() != 2) {
            return usage_error("pipe " + sub);
        }
        return do_verb(argc, argv, "UNREGISTER " + join(a, 0));
    }
    if (sub == "open") {
        if (a.size() < 2) {
            return usage_error("pipe " + sub);
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
            return usage_error("pipe " + sub);
        }
        return do_verb(argc, argv, "CLOSE " + join(a, 0));
    }
    return usage_error(sub);
}

// `spl peer <sub> …`: manage paired peers.
int peer_group_main(int argc, char** argv) {
    if (argc < 2) {  // the group alone: show what's in it
        print_help("peer");
        return 2;
    }
    const std::string sub = argv[1];
    if (sub == "ls" || sub == "list") {
        if (argc != 2) {
            return usage_error("peer " + sub);
        }
        return do_list();
    }
    if (sub == "show") {
        if (argc != 3) {
            return usage_error("peer " + sub);
        }
        return do_show(argv[2]);
    }
    if (sub == "rename") {
        if (argc != 4) {
            return usage_error("peer " + sub);
        }
        return do_rename(argv[2], argv[3]);
    }
    if (sub == "remove" || sub == "rm") {
        if (argc != 3) {
            return usage_error("peer " + sub);
        }
        return do_remove(argv[2]);
    }
    if (sub == "set") {
        if (argc != 5) {
            return usage_error("peer " + sub);
        }
        return do_set(argv[2], argv[3], argv[4]);
    }
    if (sub == "add-address" || sub == "remove-address") {
        if (argc != 4) {
            return usage_error("peer " + sub);
        }
        return do_address(argv[2], argv[3], sub == "add-address");
    }
    return usage_error("peer", "unknown command '" + sub + "'");
}

// `spl pipe <sub> …`: the raw plumbing (register/unregister/open/close). Same
// handlers as before they moved here; argv already has the subcommand at [1].
int pipe_group_main(int argc, char** argv) {
    if (argc < 2) {  // the group alone: show what's in it
        print_help("pipe");
        return 2;
    }
    const std::string sub = argv[1];
    for (const auto& c : kPipeSubcommands)
        if (c == sub) return peer_cmd_main(argc, argv);
    return usage_error("pipe", "unknown command '" + sub + "'");
}

}  // namespace spl::peer
