// Commands on EXEC pipes (peer/exec.h): offering a program (`expose`, and
// `revshell` for the login shell) and running one (`run`, and `shell` for one
// on a terminal). Both client commands are one bridge: frames to and from the
// program, our terminal handed over when the offer has a PTY, and the program's
// exit status as ours.
#include "peer/shell.h"

#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "common/log.h"
#include "peer/daemon.h"
#include "peer/daemon_client.h"
#include "peer/exec.h"
#include "peer/help.h"
#include "peer/store.h"

namespace spl::peer {

namespace {

using namespace execproto;

constexpr size_t kChunk = 4096;
constexpr int kSplFailed = 255;  // spl itself failed (as ssh): never a program's code

volatile sig_atomic_t g_winch = 0;
void on_winch(int) { g_winch = 1; }

bool write_full(int fd, const char* p, size_t n) {
    while (n > 0) {
        const ssize_t w = ::write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

bool send_frame(int fd, uint8_t type, const char* p, size_t len) {
    const char h[3] = {static_cast<char>(type), static_cast<char>(len >> 8),
                       static_cast<char>(len & 0xff)};
    return write_full(fd, h, 3) && (len == 0 || write_full(fd, p, len));
}

void send_winsize(int fd) {
    winsize ws{};
    if (::ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) != 0) return;
    const char b[4] = {static_cast<char>(ws.ws_row >> 8), static_cast<char>(ws.ws_row & 0xff),
                       static_cast<char>(ws.ws_col >> 8), static_cast<char>(ws.ws_col & 0xff)};
    send_frame(fd, kWinsz, b, 4);
}

// Our terminal in raw mode for as long as this lives (when there is one).
struct RawTerminal {
    bool on = false;
    termios saved{};
    explicit RawTerminal(bool want) {
        if (!want || !::isatty(STDIN_FILENO) || ::tcgetattr(STDIN_FILENO, &saved) != 0) return;
        termios raw = saved;
        ::cfmakeraw(&raw);
        on = ::tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0;
    }
    ~RawTerminal() {
        if (on) ::tcsetattr(STDIN_FILENO, TCSANOW, &saved);
    }
};

// Bridge stdin/stdout/stderr to the connected EXEC pipe `fd` until the program's
// EXIT arrives; returns its status (exit code, or 128 + signal), or 255 if the
// connection ended without one. With `pty` our terminal is handed over (raw
// mode, size changes forwarded).
int run_exec_client(int fd, bool pty, const std::string& peer) {
    ::signal(SIGPIPE, SIG_IGN);
    int status = -1;
    std::string why;
    {
        RawTerminal term(pty);
        if (term.on) {
            ::signal(SIGWINCH, on_winch);
            send_winsize(fd);  // before the program draws anything
        }
        bool stdin_open = true;
        std::string buf;
        while (status < 0 && why.empty()) {
            if (g_winch) {
                g_winch = 0;
                send_winsize(fd);
            }
            pollfd p[2] = {{fd, POLLIN, 0}, {STDIN_FILENO, POLLIN, 0}};
            if (::poll(p, stdin_open ? 2 : 1, -1) < 0) {
                if (errno == EINTR) continue;  // a SIGWINCH
                why = "poll failed";
                break;
            }
            if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
                char rb[kChunk + 3];
                const ssize_t n = ::read(fd, rb, sizeof(rb));
                if (n <= 0) {
                    why = "connection to " + peer + " lost; the program was stopped";
                    break;
                }
                buf.append(rb, static_cast<size_t>(n));
                size_t off = 0;
                while (buf.size() - off >= 3) {
                    const uint8_t type = static_cast<uint8_t>(buf[off]);
                    const size_t len = (static_cast<uint8_t>(buf[off + 1]) << 8) |
                                       static_cast<uint8_t>(buf[off + 2]);
                    if (buf.size() - off - 3 < len) break;
                    const char* d = buf.data() + off + 3;
                    if (type == kOut || type == kErr) {
                        if (!write_full(type == kErr ? STDERR_FILENO : STDOUT_FILENO, d, len) &&
                            type == kOut) {
                            // Our output is gone (`spl run … | head`): stop, as a
                            // local program would on SIGPIPE; hanging up stops it there.
                            status = 128 + SIGPIPE;
                            break;
                        }
                    } else if (type == kExit && len == 2) {
                        const int how = static_cast<uint8_t>(d[0]), code = static_cast<uint8_t>(d[1]);
                        status = how == kSignaled ? 128 + code : code;
                        break;
                    }
                    off += 3 + len;
                }
                buf.erase(0, std::min(off, buf.size()));
            }
            if (stdin_open && (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
                char ib[kChunk];
                const ssize_t n = ::read(STDIN_FILENO, ib, sizeof(ib));
                if (n <= 0) {  // our input ended: the program's does too; keep its output coming
                    send_frame(fd, kEof, nullptr, 0);
                    stdin_open = false;
                } else {
                    send_frame(fd, kData, ib, static_cast<size_t>(n));
                }
            }
        }
        if (term.on) ::signal(SIGWINCH, SIG_DFL);
    }  // terminal restored before we print anything
    if (status >= 0) return status;
    spl::logf("spl: %s", why.c_str());
    return kSplFailed;
}

// OPEN an EXEC offer and run the bridge. `expect` is the kind it must be.
int open_exec(const DaemonOpts& dopts, const std::string& ctx, const std::string& peer,
              const std::string& name, const std::string& expect) {
    if (auto store = Store::open(nullptr); !store || !store->load(peer)) {
        spl::logf("%s: no peer named '%s' (see: spl peer ls)", ctx.c_str(), peer.c_str());
        return kSplFailed;
    }
    std::string err;
    if (!ensure_daemon(dopts, &err)) {
        spl::logf("%s: %s", ctx.c_str(), err.c_str());
        return kSplFailed;
    }
    const int fd = daemon_connect();
    if (fd < 0) {
        spl::logf("%s: cannot reach the daemon", ctx.c_str());
        return kSplFailed;
    }
    const std::string r = send_command(fd, "OPEN " + ctl_encode(peer) + " " + ctl_encode(name) +
                                               " EXPECT " + ctl_encode(expect) + " PIPE");
    std::string kind;
    if (!ok_reply(r)) {
        daemon_fail(ctx.c_str(), r);
        ::close(fd);
        return kSplFailed;
    }
    if (!await_ready(fd, &kind, &err)) {
        spl::logf("%s: %s", ctx.c_str(), err.c_str());
        ::close(fd);
        return kSplFailed;
    }
    // The offer's kind says whether the program has a terminal (an older peer
    // says nothing: it can only be a shell, which has one).
    const bool pty = kind.empty() || kind_matches(kind, "exec/1 pty");
    const int rc = run_exec_client(fd, pty, peer);
    ::close(fd);
    return rc;
}

// <peer> plus --name/--limit and the relay flags.
struct ShOpts {
    DaemonOpts daemon;
    std::vector<std::string> pos;
    std::string name;
    uint32_t limit = 0;
    bool pty = false;
    std::string bad;  // why parsing failed
};
// Options, then positionals. With `command_after`, the n-th positional starts
// the program's command line: it and everything after it are the program's
// (so `spl expose desk ls -la` passes -la to ls).
ShOpts parse(int argc, char** argv, bool allow_limit, size_t command_after = 0) {
    ShOpts o;
    o.daemon = default_daemon_opts();
    bool rest = false;  // after `--`, or once the program's command line started
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (rest) {
            o.pos.push_back(a);
            continue;
        }
        auto val = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        if (a == "--server") { if (auto v = val()) o.daemon.server = v; }
        else if (a == "--port") { if (auto v = val()) o.daemon.port = (uint16_t)std::atoi(v); }
        else if (a == "--name") { if (auto v = val()) o.name = v; }
        else if (allow_limit && a == "--limit") { if (auto v = val()) o.limit = (uint32_t)std::atoi(v); }
        else if (command_after && a == "--pty") o.pty = true;
        else if (a == "--") rest = true;
        else if (!a.empty() && a[0] == '-') o.bad = "unknown option '" + a + "'";
        else {
            o.pos.push_back(a);
            if (command_after && o.pos.size() > command_after) rest = true;  // the program
        }
    }
    return o;
}

// REGISTER an EXEC/SHELL offer; prints what was offered and how to stop it.
int offer(const ShOpts& o, const char* ctx, const std::string& peer, const std::string& name,
          const std::string& type_args) {
    if (auto store = Store::open(nullptr); !store || !store->load(peer)) {
        spl::logf("%s: no peer named '%s' (see: spl peer ls)", ctx, peer.c_str());
        return 1;
    }
    std::string err;
    if (!ensure_daemon(o.daemon, &err)) {
        spl::logf("%s: %s", ctx, err.c_str());
        return 1;
    }
    std::string line = "REGISTER " + ctl_encode(peer) + " " + ctl_encode(name) + " ";
    if (o.limit) line += "LIMIT " + std::to_string(o.limit) + " ";
    const std::string r = daemon_request(line + type_args);
    if (!ok_reply(r)) {
        daemon_fail(ctx, r);
        return 1;
    }
    return 0;
}

std::string basename_of(const std::string& p) {
    const size_t s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

}  // namespace

int revshell_main(int argc, char** argv) {
    const ShOpts o = parse(argc, argv, /*allow_limit=*/true);
    if (!o.bad.empty() || o.pos.size() != 1)
        return usage_error("revshell", o.bad.empty() && o.pos.size() > 1 ? "too many arguments" : o.bad);
    const std::string& peer = o.pos[0];
    const std::string name = o.name.empty() ? "shell" : o.name;
    if (const int rc = offer(o, "spl revshell", peer, name, "SHELL")) return rc;
    const std::string suffix = name == "shell" ? "" : " --name " + name;
    std::printf("offering a shell on this machine to %s as '%s'\n", peer.c_str(), name.c_str());
    std::printf("  they attach with:  spl shell <you>%s\n", suffix.c_str());
    std::printf("  this lets %s run commands as you until you stop it: spl drop %s %s\n",
                peer.c_str(), peer.c_str(), name.c_str());
    return 0;
}

int expose_main(int argc, char** argv) {
    const ShOpts o = parse(argc, argv, /*allow_limit=*/true, /*command_after=*/1);
    if (!o.bad.empty() || o.pos.size() < 2)
        return usage_error("expose", o.bad.empty() && o.pos.size() == 1 ? "which program?" : o.bad);
    const std::string& peer = o.pos[0];
    const std::vector<std::string> cmd(o.pos.begin() + 1, o.pos.end());
    const std::string name = o.name.empty() ? basename_of(cmd[0]) : o.name;
    std::string type_args = "EXEC";
    if (o.pty) type_args += " PTY";
    std::string shown;
    for (const auto& a : cmd) {
        type_args += " " + ctl_encode(a);
        shown += (shown.empty() ? "" : " ") + a;
    }
    if (const int rc = offer(o, "spl expose", peer, name, type_args)) return rc;
    std::printf("offering `%s` to %s as '%s'%s\n", shown.c_str(), peer.c_str(), name.c_str(),
                o.pty ? " (on a terminal)" : "");
    if (o.pty)
        std::printf("  they run it with:  spl shell <you> --name %s\n", name.c_str());
    else
        std::printf("  they run it with:  spl run <you> %s\n", name.c_str());
    std::printf("  stop offering it:  spl drop %s %s\n", peer.c_str(), name.c_str());
    return 0;
}

int shell_main(int argc, char** argv) {
    const ShOpts o = parse(argc, argv, /*allow_limit=*/false);
    if (!o.bad.empty() || o.pos.size() != 1) {
        usage_error("shell", o.bad.empty() && o.pos.size() > 1 ? "too many arguments" : o.bad);
        return kSplFailed;
    }
    return open_exec(o.daemon, "spl shell", o.pos[0], o.name.empty() ? "shell" : o.name,
                     "exec/1 pty");
}

int run_main(int argc, char** argv) {
    const ShOpts o = parse(argc, argv, /*allow_limit=*/false);
    if (!o.bad.empty() || o.pos.size() != 2 || !o.name.empty()) {
        usage_error("run", !o.bad.empty() ? o.bad
                           : o.pos.size() > 2 ? "the program's arguments are fixed by the peer "
                                                "that offers it"
                                              : "");
        return kSplFailed;
    }
    return open_exec(o.daemon, "spl run", o.pos[0], o.pos[1], "exec/1");
}

}  // namespace spl::peer
