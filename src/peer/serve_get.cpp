// File-transfer commands — thin clients of the daemon's SHARE_FILE/GET_FILE
// pipes (docs/PIPES.md). The transfer protocol lives entirely in the daemon
// (peer/pipes.cpp); these commands just register/open and, in the foreground,
// FOLLOW the daemon's progress on the control connection.
//
//   serve <peer> [--name n] <path>      REGISTER <peer> <n> SHARE_FILE <path>
//   get   <peer> <pipe> [-o p] [-f] [-b]   OPEN .. GET_FILE <target>
//   send  <peer> <path…>                OPEN <peer> inbox SHARE_FILE <path>   (push)
//   inbox <peer> <dir> [--limit N] [-f] REGISTER <peer> inbox [LIMIT N] GET_FILE <dir>
#include "peer/serve_get.h"

#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "common/log.h"
#include "peer/daemon.h"
#include "peer/daemon_client.h"

namespace spl::peer {

namespace {

constexpr const char* kInbox = "inbox";  // the well-known push target name

struct Opts {
    DaemonOpts daemon;
    std::vector<std::string> pos;
    std::string name, out;
    uint32_t limit = 0;
    bool overwrite = false, background = false, ok = true;
};

Opts parse(int argc, char** argv) {
    Opts o;
    o.daemon = default_daemon_opts();
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto val = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        if (a == "--server") { if (auto v = val()) o.daemon.server = v; }
        else if (a == "--port") { if (auto v = val()) o.daemon.port = (uint16_t)std::atoi(v); }
        else if (a == "--name") { if (auto v = val()) o.name = v; }
        else if (a == "-o" || a == "--out") { if (auto v = val()) o.out = v; }
        else if (a == "--limit") { if (auto v = val()) o.limit = (uint32_t)std::atoi(v); }
        else if (a == "-f" || a == "--force") o.overwrite = true;
        else if (a == "-b" || a == "--background") o.background = true;
        else if (!a.empty() && a[0] == '-') { spl::logf("unexpected option '%s'", a.c_str()); o.ok = false; }
        else o.pos.push_back(a);
    }
    return o;
}

std::string abspath(const std::string& p) {
    if (!p.empty() && p[0] == '/') return p;
    char cwd[PATH_MAX];
    if (!::getcwd(cwd, sizeof(cwd))) return p;
    return std::string(cwd) + "/" + p;
}
std::string basename_of(const std::string& p) {
    const size_t s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

// Follow a FOLLOW-opened control fd: render "P <progress>" lines and return the
// exit code from the final "D" (done) / "E <msg>" (error) line.
int follow(int fd, const char* ctx) {
    const bool tty = ::isatty(STDERR_FILENO);
    std::string buf;
    char rb[4096];
    for (;;) {
        size_t nl;
        while ((nl = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            if (line.empty()) continue;
            if (line[0] == 'P') {
                if (tty) std::fprintf(stderr, "\r\033[K%s", line.c_str() + 2);
            } else if (line[0] == 'D') {
                if (tty) std::fputc('\n', stderr);
                return 0;
            } else if (line[0] == 'E') {
                if (tty) std::fputc('\n', stderr);
                spl::logf("%s: %s", ctx, line.size() > 2 ? line.c_str() + 2 : "failed");
                return 1;
            }
        }
        ssize_t n = ::read(fd, rb, sizeof(rb));
        if (n <= 0) {
            spl::logf("%s: lost contact with the daemon", ctx);
            return 1;
        }
        buf.append(rb, static_cast<size_t>(n));
    }
}

// OPEN a daemon-owned end and, unless backgrounded, FOLLOW it to completion.
int open_and_follow(const Opts& o, const std::string& peer, const std::string& pipe,
                    const std::string& local_type_args, const char* ctx, const char* bg_noun) {
    std::string err;
    if (!ensure_daemon(o.daemon, &err)) {
        spl::logf("%s: %s", ctx, err.c_str());
        return 1;
    }
    if (o.background) {
        const std::string r = daemon_request("OPEN " + ctl_encode(peer) + " " + ctl_encode(pipe) +
                                             " " + local_type_args);
        if (!ok_reply(r)) {
            daemon_fail(ctx, r);
            return 1;
        }
        std::printf("%s in the background as instance #%s (see `spl status`)\n", bg_noun,
                    r.size() > 3 ? r.c_str() + 3 : "?");
        return 0;
    }
    int fd = daemon_connect();
    if (fd < 0) {
        spl::logf("%s: cannot reach the daemon", ctx);
        return 1;
    }
    const std::string r = send_command(fd, "OPEN " + ctl_encode(peer) + " " + ctl_encode(pipe) +
                                           " FOLLOW " + local_type_args);
    if (!ok_reply(r)) {
        daemon_fail(ctx, r);
        ::close(fd);
        return 1;
    }
    int rc = follow(fd, ctx);
    ::close(fd);
    return rc;
}

}  // namespace

int serve_main(int argc, char** argv) {
    Opts o = parse(argc, argv);
    if (!o.ok || o.pos.size() != 2) {
        spl::logf("usage: spl serve <peer> [--name <pipe>] [--limit N] <path>   (path may be a dir)");
        return 2;
    }
    const std::string& peer = o.pos[0];
    const std::string path = abspath(o.pos[1]);
    const std::string name = o.name.empty() ? basename_of(o.pos[1]) : o.name;

    std::string err;
    if (!ensure_daemon(o.daemon, &err)) {
        spl::logf("spl serve: %s", err.c_str());
        return 1;
    }
    std::string line = "REGISTER " + ctl_encode(peer) + " " + ctl_encode(name) + " ";
    if (o.limit) line += "LIMIT " + std::to_string(o.limit) + " ";
    line += "SHARE_FILE " + ctl_encode(path);
    const std::string r = daemon_request(line);
    if (!ok_reply(r)) {
        daemon_fail("spl serve", r);
        return 1;
    }
    std::printf("serving '%s' to %s as '%s'\n", path.c_str(), peer.c_str(), name.c_str());
    std::printf("  the peer fetches it with:  spl get <you> %s\n", name.c_str());
    return 0;
}

int get_main(int argc, char** argv) {
    Opts o = parse(argc, argv);
    if (!o.ok || o.pos.size() != 2) {
        spl::logf("usage: spl get <peer> <pipe> [-o <path>] [-f] [-b]");
        return 2;
    }
    const std::string target = o.out.empty() ? abspath(".") : abspath(o.out);
    std::string args = "GET_FILE " + ctl_encode(target);
    if (o.overwrite) args += " OVERWRITE";
    return open_and_follow(o, o.pos[0], o.pos[1], args, "spl get", "receiving");
}

int send_main(int argc, char** argv) {
    Opts o = parse(argc, argv);
    if (!o.ok || o.pos.size() < 2) {
        spl::logf("usage: spl send <peer> <path>…   (each path may be a directory)");
        return 2;
    }
    const std::string& peer = o.pos[0];
    int rc = 0;
    for (size_t i = 1; i < o.pos.size(); ++i) {  // one SHARE_FILE connection per path
        const std::string path = abspath(o.pos[i]);
        if (open_and_follow(o, peer, kInbox, "SHARE_FILE " + ctl_encode(path), "spl send",
                            "sending") != 0)
            rc = 1;
    }
    return rc;
}

int inbox_main(int argc, char** argv) {
    Opts o = parse(argc, argv);
    if (!o.ok || o.pos.size() != 2) {
        spl::logf("usage: spl inbox <peer> <dir> [--limit N] [-f]");
        return 2;
    }
    const std::string& peer = o.pos[0];
    const std::string dir = abspath(o.pos[1]);
    ::mkdir(dir.c_str(), 0755);  // GET_FILE needs the directory to exist (dir-mode)

    std::string err;
    if (!ensure_daemon(o.daemon, &err)) {
        spl::logf("spl inbox: %s", err.c_str());
        return 1;
    }
    std::string line = "REGISTER " + ctl_encode(peer) + " " + kInbox + " ";
    if (o.limit) line += "LIMIT " + std::to_string(o.limit) + " ";
    line += "GET_FILE " + ctl_encode(dir);
    if (o.overwrite) line += " OVERWRITE";
    const std::string r = daemon_request(line);
    if (!ok_reply(r)) {
        daemon_fail("spl inbox", r);
        return 1;
    }
    std::printf("inbox open: %s can `spl send <you> <path>` into %s\n", peer.c_str(), dir.c_str());
    return 0;
}

}  // namespace spl::peer
