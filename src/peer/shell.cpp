#include "peer/shell.h"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <util.h>  // forkpty
#else
#include <pty.h>   // forkpty
#endif

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "common/io.h"
#include "common/log.h"
#include "peer/daemon.h"
#include "peer/daemon_client.h"
#include "peer/store.h"

namespace spl::peer {

namespace {

// --- the client→host frame protocol -------------------------------------
// Keystrokes and window-size changes share the one pipe, so the client→host
// direction is framed: [type:1][len:2 BE][payload]. The host→client direction
// is a raw byte stream (the shell's output), so the client just writes it to
// its terminal — no framing needed there.
constexpr uint8_t kData = 0;   // payload = terminal bytes -> the PTY
constexpr uint8_t kWinsz = 1;  // payload = rows:2 BE, cols:2 BE -> TIOCSWINSZ
constexpr size_t kChunk = 4096;

std::string basename_of(const std::string& p) {
    const size_t s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

// Close every inherited fd above the PTY (0/1/2) before exec'ing the shell, so
// it can't touch the daemon's sockets/poller. Done in the forked child only.
// close_range is one syscall; the /proc walk only touches actually-open fds —
// either way we avoid a blind loop to _SC_OPEN_MAX (~1M fds = seconds, the bug
// that made the shell appear dead).
void close_inherited_fds() {
#if defined(__linux__) && defined(SYS_close_range)
    if (::syscall(SYS_close_range, 3u, ~0u, 0) == 0) return;
#endif
    if (DIR* d = ::opendir("/proc/self/fd")) {
        int fds[1024];
        int n = 0;
        for (dirent* e; (e = ::readdir(d)) && n < 1024;) {
            const int fd = ::atoi(e->d_name);
            if (fd > 2) fds[n++] = fd;
        }
        ::closedir(d);
        for (int i = 0; i < n; ++i) ::close(fds[i]);
        return;
    }
    for (int i = 3; i < 1024; ++i) ::close(i);  // last resort
}

// ===================== host side: the daemon SHELL end =====================

class ShellEnd : public LocalEnd {
 public:
    ~ShellEnd() override {
        if (pid_ > 0) {  // hang up the shell and reap it (no zombies)
            ::kill(pid_, SIGHUP);
            ::waitpid(pid_, nullptr, 0);
        }
        if (master_ >= 0) ::close(master_);
    }

    void start() override {  // splice begins: spawn the shell on its own PTY
        struct winsize ws = {24, 80, 0, 0};  // until the client sends its real size
        int master = -1;
        const pid_t pid = ::forkpty(&master, nullptr, nullptr, &ws);
        if (pid < 0) {
            err_ = "forkpty failed";
            if (shutdown) shutdown();
            return;
        }
        if (pid == 0) {  // child: become a clean interactive shell
            // forkpty already gave us a controlling tty on fds 0/1/2; drop every
            // other inherited daemon fd so the shell can't touch them.
            close_inherited_fds();
            ::signal(SIGPIPE, SIG_DFL);
            ::signal(SIGINT, SIG_DFL);
            ::signal(SIGTERM, SIG_DFL);
            ::signal(SIGCHLD, SIG_DFL);
            const char* sh = ::getenv("SHELL");
            if (!sh || !*sh) sh = "/bin/sh";
            if (!::getenv("TERM")) ::setenv("TERM", "xterm-256color", 1);
            const std::string arg0 = "-" + basename_of(sh);  // login shell
            ::execl(sh, arg0.c_str(), static_cast<char*>(nullptr));
            ::_exit(127);
        }
        pid_ = pid;
        master_ = master;
        const int fl = ::fcntl(master_, F_GETFL, 0);
        ::fcntl(master_, F_SETFL, fl | O_NONBLOCK);
        ::fcntl(master_, F_SETFD, FD_CLOEXEC);
    }

    int watch_fd() const override { return master_; }

    // PTY output -> peer, raw (the client writes it straight to its terminal).
    void on_fd_data(ByteSpan b) override {
        if (to_tunnel) to_tunnel(b);
    }

    // Framed client input -> the PTY (keystrokes) or a resize ioctl.
    void on_tunnel_data(ByteSpan b) override {
        ibuf_.append(reinterpret_cast<const char*>(b.data()), b.size());
        size_t off = 0;
        while (ibuf_.size() - off >= 3) {
            const uint8_t type = static_cast<uint8_t>(ibuf_[off]);
            const size_t len = (static_cast<uint8_t>(ibuf_[off + 1]) << 8) |
                               static_cast<uint8_t>(ibuf_[off + 2]);
            if (ibuf_.size() - off - 3 < len) break;  // frame not all here yet
            const char* p = ibuf_.data() + off + 3;
            if (type == kData && master_ >= 0) {
                spl::write_all(master_, p, len);
            } else if (type == kWinsz && len == 4 && master_ >= 0) {
                struct winsize ws{};
                ws.ws_row = (static_cast<uint8_t>(p[0]) << 8) | static_cast<uint8_t>(p[1]);
                ws.ws_col = (static_cast<uint8_t>(p[2]) << 8) | static_cast<uint8_t>(p[3]);
                ::ioctl(master_, TIOCSWINSZ, &ws);
            }
            off += 3 + len;
        }
        ibuf_.erase(0, off);
    }

    std::string describe() const override { return "shell"; }
    std::string error() const override { return err_; }

 private:
    pid_t pid_ = -1;
    int master_ = -1;
    std::string ibuf_;  // accumulates partial client frames
    std::string err_;
};

// ===================== client side: the terminal bridge =====================

volatile sig_atomic_t g_winch = 0;
void on_winch(int) { g_winch = 1; }

void send_frame(int fd, uint8_t type, const char* p, uint16_t len) {
    uint8_t h[3] = {type, static_cast<uint8_t>(len >> 8), static_cast<uint8_t>(len & 0xff)};
    spl::write_all(fd, h, 3);
    if (len) spl::write_all(fd, p, len);
}

void send_winsize(int fd) {
    struct winsize ws{};
    if (::ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) != 0) return;
    const uint8_t b[4] = {static_cast<uint8_t>(ws.ws_row >> 8), static_cast<uint8_t>(ws.ws_row),
                          static_cast<uint8_t>(ws.ws_col >> 8), static_cast<uint8_t>(ws.ws_col)};
    send_frame(fd, kWinsz, reinterpret_cast<const char*>(b), 4);
}

// Bridge our terminal to the shell pipe `fd`: stdin -> DATA frames, SIGWINCH ->
// WINSZ frames, and the raw pipe output -> stdout. Returns when the shell/peer
// closes the pipe.
int run_shell_client(int fd, const std::string& peer, const std::string& name) {
    ::signal(SIGPIPE, SIG_IGN);
    const bool tty = ::isatty(STDIN_FILENO);
    termios saved{};
    if (tty) {
        ::tcgetattr(STDIN_FILENO, &saved);
        termios raw = saved;
        ::cfmakeraw(&raw);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        ::signal(SIGWINCH, on_winch);
        send_winsize(fd);  // tell the host our size before the shell draws anything
    }

    bool stdin_open = true, got_bytes = false;
    for (;;) {
        if (g_winch) {
            g_winch = 0;
            send_winsize(fd);
        }
        pollfd p[2];
        p[0] = {fd, POLLIN, 0};
        int n = 1;
        if (stdin_open) {
            p[1] = {STDIN_FILENO, POLLIN, 0};
            n = 2;
        }
        if (::poll(p, n, -1) < 0) {
            if (errno == EINTR) continue;  // a SIGWINCH interrupted us
            break;
        }
        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            char buf[kChunk];
            const ssize_t r = ::read(fd, buf, sizeof(buf));
            if (r <= 0) break;  // shell exited / peer closed
            got_bytes = true;
            spl::write_all(STDOUT_FILENO, buf, static_cast<size_t>(r));
        }
        if (n == 2 && (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            char buf[kChunk];
            const ssize_t r = ::read(STDIN_FILENO, buf, sizeof(buf));
            if (r <= 0) {
                // Our stdin ended (piped input, or the terminal closed). Send a
                // ^D so the remote shell sees EOF and exits, then stop reading
                // stdin but keep draining its output until it does — closing our
                // write side here would instead tear the whole pipe down and race
                // away that final output.
                const char eot = 0x04;
                send_frame(fd, kData, &eot, 1);
                stdin_open = false;
            } else {
                send_frame(fd, kData, buf, static_cast<uint16_t>(r));
            }
        }
    }

    if (tty) {
        ::tcsetattr(STDIN_FILENO, TCSANOW, &saved);
        ::signal(SIGWINCH, SIG_DFL);
    }
    // Never received a byte: almost always the peer isn't offering this shell.
    if (!got_bytes)
        spl::logf("spl shell: %s isn't offering '%s' (try: spl ls %s)", peer.c_str(), name.c_str(),
                  peer.c_str());
    return got_bytes ? 0 : 1;
}

// Shared arg parsing for the two commands: <peer> plus --name/--limit/server.
struct ShOpts {
    DaemonOpts daemon;
    std::string peer, name = "shell";
    uint32_t limit = 0;
    bool ok = true;
};
ShOpts parse(const char* ctx, int argc, char** argv, bool allow_limit) {
    ShOpts o;
    o.daemon = default_daemon_opts();
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto val = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        if (a == "--server") { if (auto v = val()) o.daemon.server = v; }
        else if (a == "--port") { if (auto v = val()) o.daemon.port = (uint16_t)std::atoi(v); }
        else if (a == "--name") { if (auto v = val()) o.name = v; }
        else if (allow_limit && a == "--limit") { if (auto v = val()) o.limit = (uint32_t)std::atoi(v); }
        else if (!a.empty() && a[0] == '-') { spl::logf("%s: unexpected option '%s'", ctx, a.c_str()); o.ok = false; }
        else if (o.peer.empty()) o.peer = a;
        else { spl::logf("%s: too many arguments", ctx); o.ok = false; }
    }
    return o;
}

}  // namespace

std::unique_ptr<LocalEnd> make_shell_end(const std::vector<std::string>& args, std::string* err) {
    if (!args.empty()) {
        if (err) *err = "SHELL takes no arguments";
        return nullptr;
    }
    return std::make_unique<ShellEnd>();
}

int revshell_main(int argc, char** argv) {
    ShOpts o = parse("spl revshell", argc, argv, /*allow_limit=*/true);
    if (!o.ok || o.peer.empty()) {
        spl::logf("usage: spl revshell <peer> [--name <n>] [--limit N]");
        return 2;
    }
    if (auto store = Store::open(nullptr); !store || !store->load(o.peer)) {
        spl::logf("spl revshell: no connection named '%s' (pair first)", o.peer.c_str());
        return 1;
    }
    std::string err;
    if (!ensure_daemon(o.daemon, &err)) {
        spl::logf("spl revshell: %s", err.c_str());
        return 1;
    }
    std::string line = "REGISTER " + ctl_encode(o.peer) + " " + ctl_encode(o.name) + " ";
    if (o.limit) line += "LIMIT " + std::to_string(o.limit) + " ";
    line += "SHELL";
    const std::string r = daemon_request(line);
    if (!ok_reply(r)) {
        daemon_fail("spl revshell", r);
        return 1;
    }
    const std::string suffix = o.name == "shell" ? "" : " --name " + o.name;
    std::printf("offering a shell on this machine to %s as '%s'\n", o.peer.c_str(), o.name.c_str());
    std::printf("  they attach with:  spl shell <you>%s\n", suffix.c_str());
    std::printf("  this lets %s run commands as you until you stop it: spl unregister %s %s\n",
                o.peer.c_str(), o.peer.c_str(), o.name.c_str());
    return 0;
}

int shell_main(int argc, char** argv) {
    ShOpts o = parse("spl shell", argc, argv, /*allow_limit=*/false);
    if (!o.ok || o.peer.empty()) {
        spl::logf("usage: spl shell <peer> [--name <n>]");
        return 2;
    }
    if (auto store = Store::open(nullptr); !store || !store->load(o.peer)) {
        spl::logf("spl shell: no connection named '%s' (pair first)", o.peer.c_str());
        return 1;
    }
    std::string err;
    if (!ensure_daemon(o.daemon, &err)) {
        spl::logf("spl shell: %s", err.c_str());
        return 1;
    }
    int fd = daemon_connect();
    if (fd < 0) {
        spl::logf("spl shell: cannot reach the daemon");
        return 1;
    }
    const std::string r =
        send_command(fd, "OPEN " + ctl_encode(o.peer) + " " + ctl_encode(o.name) + " PIPE");
    if (!ok_reply(r)) {
        daemon_fail("spl shell", r);
        ::close(fd);
        return 1;
    }
    const int rc = run_shell_client(fd, o.peer, o.name);
    ::close(fd);
    return rc;
}

}  // namespace spl::peer
