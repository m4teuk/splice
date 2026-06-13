// spl serve / spl get: thin sugar over the daemon verbs (docs/PIPES.md).
//
//   serve <peer> [--name n] <path>   == REGISTER <peer> <n|basename> SHARE_FILE <abspath>
//   get <peer> <pipe> --background   == OPEN <peer> <pipe> GET_FILE <target>
//   get <peer> <pipe>                == OPEN <peer> <pipe> PIPE, with this process
//                                       speaking the SHARE_FILE/GET_FILE protocol
//                                       itself: progress on a TTY, real exit code.
#include "peer/serve_get.h"

#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "common/log.h"
#include "common/time.h"
#include "peer/daemon.h"
#include "peer/daemon_client.h"
#include "peer/pipes.h"

namespace spl::peer {

namespace {

struct CommonOpts {
    DaemonOpts daemon;
    std::vector<std::string> pos;
    std::string name, out;
    bool overwrite = false, background = false;
    bool ok = true;
};

CommonOpts parse(int argc, char** argv) {
    CommonOpts o;
    o.daemon = default_daemon_opts();
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto val = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        if (a == "--server") {
            const char* v = val();
            if (v) o.daemon.server = v;
        } else if (a == "--port") {
            const char* v = val();
            if (v) o.daemon.port = static_cast<uint16_t>(std::atoi(v));
        } else if (a == "--name") {
            const char* v = val();
            if (v) o.name = v;
        } else if (a == "-o" || a == "--out") {
            const char* v = val();
            if (v) o.out = v;
        } else if (a == "-f" || a == "--force") {
            o.overwrite = true;
        } else if (a == "--background" || a == "-b") {
            o.background = true;
        } else if (!a.empty() && a[0] == '-') {
            spl::logf("unexpected option '%s'", a.c_str());
            o.ok = false;
        } else {
            o.pos.push_back(a);
        }
    }
    return o;
}

std::string abspath(const std::string& p) {
    if (!p.empty() && p[0] == '/') return p;
    char cwd[PATH_MAX];
    if (!::getcwd(cwd, sizeof(cwd))) return p;
    return std::string(cwd) + (p.empty() ? "" : "/" + p);
}

std::string basename_of(const std::string& p) {
    const size_t s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

bool is_dir(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}
bool exists(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0;
}

void progress(bool tty, Millis* last, const std::string& name, uint64_t got, uint64_t total) {
    if (!tty) return;
    const Millis now = mono_ms();
    if (got < total && now - *last < 100) return;
    *last = now;
    std::fprintf(stderr, "\r%s  %3llu%%  %s / %s   ", name.c_str(),
                 total ? static_cast<unsigned long long>(got * 100 / total) : 0,
                 human_bytes(got).c_str(), human_bytes(total).c_str());
    if (got >= total) std::fprintf(stderr, "\n");
}

}  // namespace

int serve_main(int argc, char** argv) {
    CommonOpts o = parse(argc, argv);
    if (!o.ok || o.pos.size() != 2) {
        spl::logf("usage: spl serve <peer> [--name <pipe>] <path>");
        return 2;
    }
    const std::string& peer = o.pos[0];
    const std::string path = abspath(o.pos[1]);
    const std::string name = o.name.empty() ? basename_of(path) : o.name;

    std::string err;
    if (!ensure_daemon(o.daemon, &err)) {
        spl::logf("spl serve: %s", err.c_str());
        return 1;
    }
    clog("registering '%s' (SHARE_FILE %s) for %s...", name.c_str(), path.c_str(), peer.c_str());
    const std::string r = daemon_request("REGISTER " + ctl_encode(peer) + " " + ctl_encode(name) +
                                         " SHARE_FILE " + ctl_encode(path));
    if (r != "OK") {
        spl::logf("spl serve: %s", r.empty() ? "no reply from daemon" : r.c_str());
        return 1;
    }
    clog("registered; the daemon serves this until `spl peer unregister %s %s`", peer.c_str(),
         name.c_str());
    std::printf("serving '%s' to %s as '%s'\n", path.c_str(), peer.c_str(), name.c_str());
    return 0;
}

int get_main(int argc, char** argv) {
    CommonOpts o = parse(argc, argv);
    if (!o.ok || o.pos.size() != 2) {
        spl::logf("usage: spl get <peer> <pipe> [-o <path>] [-f] [--background]");
        return 2;
    }
    const std::string& peer = o.pos[0];
    const std::string& pipe = o.pos[1];

    std::string err;
    if (!ensure_daemon(o.daemon, &err)) {
        spl::logf("spl get: %s", err.c_str());
        return 1;
    }

    if (o.background) {  // daemon-owned GET_FILE; watch it in `spl status`
        const std::string target = abspath(o.out);  // "" -> cwd (a directory)
        clog("opening '%s' on %s as a background GET_FILE -> %s", pipe.c_str(), peer.c_str(),
             target.empty() ? "(cwd)" : target.c_str());
        std::string line = "OPEN " + ctl_encode(peer) + " " + ctl_encode(pipe) + " GET_FILE " +
                           ctl_encode(target);
        if (o.overwrite) line += " OVERWRITE";
        const std::string r = daemon_request(line);
        if (r.rfind("OK ", 0) != 0) {
            spl::logf("spl get: %s", r.empty() ? "no reply from daemon" : r.c_str());
            return 1;
        }
        clog("started as instance #%s; watch it with `spl status`", r.substr(3).c_str());
        std::printf("receiving in the background as instance #%s (see `spl status`)\n",
                    r.substr(3).c_str());
        return 0;
    }

    // Foreground: we are the local end — read the pair protocol ourselves.
    int fd = daemon_connect();
    if (fd < 0) {
        spl::logf("spl get: cannot reach the daemon");
        return 1;
    }
    clog("opening '%s' on %s...", pipe.c_str(), peer.c_str());
    const std::string r =
        send_command(fd, "OPEN " + ctl_encode(peer) + " " + ctl_encode(pipe) + " PIPE");
    if (r.rfind("OK", 0) != 0) {
        spl::logf("spl get: %s", r.empty() ? "no reply from daemon" : r.c_str());
        ::close(fd);
        return 1;
    }
    clog("connected; waiting for the file header...");

    const bool tty = ::isatty(STDERR_FILENO);
    std::string hdr, path, name;
    uint64_t size = 0, got = 0;
    FILE* f = nullptr;
    Millis last = 0;
    bool done = false;
    uint8_t buf[8192];
    ssize_t n;
    while (!done && (n = ::read(fd, buf, sizeof(buf))) > 0) {
        size_t off = 0;
        if (!f) {  // header phase
            while (off < static_cast<size_t>(n) && hdr.size() < 512 && buf[off] != '\n')
                hdr += static_cast<char>(buf[off++]);
            if (off < static_cast<size_t>(n) && buf[off] == '\n') {
                ++off;
                if (!parse_file_header(hdr, &size, &name)) {
                    spl::logf("spl get: malformed stream (is '%s' a SHARE_FILE pipe?)",
                              pipe.c_str());
                    break;
                }
                path = o.out.empty() ? safe_file_name(name)
                                     : (is_dir(o.out) ? o.out + "/" + safe_file_name(name) : o.out);
                if (!o.overwrite && exists(path)) {
                    spl::logf("spl get: '%s' exists (use -f to overwrite)", path.c_str());
                    break;
                }
                f = std::fopen((path + ".part").c_str(), "wb");
                if (!f) {
                    spl::logf("spl get: cannot write '%s.part'", path.c_str());
                    break;
                }
                clog("receiving '%s' (%s) -> %s", name.c_str(), human_bytes(size).c_str(),
                     path.c_str());
            } else {
                if (hdr.size() >= 512) {
                    spl::logf("spl get: malformed stream");
                    break;
                }
                continue;
            }
        }
        const size_t keep =
            static_cast<size_t>(std::min<uint64_t>(static_cast<size_t>(n) - off, size - got));
        if (keep && std::fwrite(buf + off, 1, keep, f) != keep) {
            spl::logf("spl get: write failed for '%s.part'", path.c_str());
            break;
        }
        got += keep;
        progress(tty, &last, name, got, size);
        done = (got == size);
    }
    ::close(fd);
    if (f) std::fclose(f);
    if (done) {
        if (std::rename((path + ".part").c_str(), path.c_str()) != 0) {
            spl::logf("spl get: rename failed for '%s'", path.c_str());
            return 1;
        }
        std::printf("received '%s' (%s)\n", path.c_str(), human_bytes(size).c_str());
        return 0;
    }
    if (!path.empty()) ::remove((path + ".part").c_str());
    spl::logf("spl get: transfer incomplete");
    return 1;
}

}  // namespace spl::peer
