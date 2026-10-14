#include "peer/exec.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <util.h>  // forkpty
#else
#include <pty.h>   // forkpty
#endif

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern char** environ;

namespace spl::peer {

namespace {

using namespace execproto;

constexpr size_t kChunk = 4096;       // bytes per OUT/ERR frame read
constexpr Millis kKillAfterMs = 5000;  // a hung-up program gets this long, then SIGKILL

std::string basename_of(const std::string& p) {
    const size_t s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

void nonblock_cloexec(int fd) {
    ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
}

void close_fd(int& fd) {
    if (fd >= 0) ::close(fd);
    fd = -1;
}

// `file` as execve needs it: as given if it has a '/', else found on $PATH.
// Empty if there's no such executable. (Done before fork: the child of a
// multithreaded daemon may only make async-signal-safe calls.)
std::string resolve(const std::string& file) {
    if (file.find('/') != std::string::npos) return ::access(file.c_str(), X_OK) == 0 ? file : "";
    const char* path = std::getenv("PATH");
    std::string p = path && *path ? path : "/usr/local/bin:/usr/bin:/bin";
    size_t i = 0;
    for (;;) {
        const size_t j = p.find(':', i);
        std::string dir = p.substr(i, j == std::string::npos ? std::string::npos : j - i);
        if (dir.empty()) dir = ".";
        const std::string cand = dir + "/" + file;
        if (::access(cand.c_str(), X_OK) == 0) return cand;
        if (j == std::string::npos) return "";
        i = j + 1;
    }
}

std::string home_dir() {
    const char* h = std::getenv("HOME");
    return h && *h ? h : "/";
}

// Everything the child needs, built before fork: it then only calls
// async-signal-safe functions (no malloc) until execve.
struct ChildPlan {
    std::string path, home;
    std::vector<std::string> argv_s, env_s;
    std::vector<char*> argv, env;
    int max_fd = 1024;

    ChildPlan(const std::string& resolved, const std::vector<std::string>& args,
              const std::string& peer, bool pty)
        : path(resolved), home(home_dir()), argv_s(args) {
        bool has_term = false;
        for (char** e = environ; e && *e; ++e) {
            const std::string kv = *e;
            if (kv.rfind("SPL_PEER=", 0) == 0) continue;
            has_term = has_term || kv.rfind("TERM=", 0) == 0;
            env_s.push_back(kv);
        }
        env_s.push_back("SPL_PEER=" + peer);
        if (pty && !has_term) env_s.push_back("TERM=xterm-256color");
        for (auto& a : argv_s) argv.push_back(a.data());
        argv.push_back(nullptr);
        for (auto& e : env_s) env.push_back(e.data());
        env.push_back(nullptr);
        rlimit rl{};
        if (::getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
            max_fd = static_cast<int>(std::min<rlim_t>(rl.rlim_cur, 65536));
    }

    // In the child, with 0/1/2 in place: drop every other inherited fd (the
    // daemon's sockets), restore default signal handling, and exec.
    [[noreturn]] void exec() const {
#if defined(__linux__) && defined(SYS_close_range)
        if (::syscall(SYS_close_range, 3u, ~0u, 0) != 0)
#endif
            for (int fd = 3; fd < max_fd; ++fd) ::close(fd);
        sigset_t none;
        sigemptyset(&none);
        ::sigprocmask(SIG_SETMASK, &none, nullptr);
        for (int sig : {SIGPIPE, SIGINT, SIGTERM, SIGCHLD, SIGHUP, SIGQUIT})
            ::signal(sig, SIG_DFL);
        if (::chdir(home.c_str()) != 0) (void)::chdir("/");
        ::execve(path.c_str(), argv.data(), env.data());
        static const char msg[] = "spl: exec failed\n";
        (void)::write(2, msg, sizeof(msg) - 1);
        ::_exit(127);
    }
};

struct Orphan {
    pid_t pid;
    Millis kill_at;
    bool killed;
};
// The program's session (it's a session leader) and the program itself: right
// after fork it may not have called setsid yet, and then only the pid reaches it.
void signal_run(pid_t pid, int sig) {
    ::kill(-pid, sig);
    ::kill(pid, sig);
}

std::vector<Orphan>& orphans() {
    static std::vector<Orphan> v;
    return v;
}

class ExecEnd : public LocalEnd {
 public:
    ExecEnd(std::string file, std::vector<std::string> argv, bool pty)
        : file_(std::move(file)), argv_(std::move(argv)), pty_(pty) {}

    ~ExecEnd() override {
        close_fd(out_);
        close_fd(err_);
        close_fd(in_);
        if (pid_ > 0 && !reaped_) {  // the connection ended first: hang the program up
            signal_run(pid_, SIGHUP);
            if (::waitpid(pid_, nullptr, WNOHANG) != pid_)
                orphans().push_back({pid_, mono_ms() + kKillAfterMs, false});
        }
    }

    bool manual_flow() const override { return true; }

    void start() override {
        const std::string path = resolve(file_);
        if (path.empty()) {  // report it the way a shell would, and end like one
            frame(kErr, "spl: " + file_ + ": command not found\n");
            finish(kExited, 127);
            return;
        }
        const ChildPlan plan(path, argv_, peer, pty_);
        if (pty_ ? !spawn_pty(plan) : !spawn_pipes(plan)) {
            frame(kErr, std::string("spl: couldn't start ") + file_ + ": " + std::strerror(errno) + "\n");
            finish(kExited, 126);
        }
    }

    std::vector<Watch> watches() const override {
        std::vector<Watch> w;
        // Read output only while the tunnel can take a full frame (backpressure).
        const bool room = tunnel_space && tunnel_space() >= kChunk + 3;
        if (room && out_ >= 0) w.push_back({out_, false});
        if (room && err_ >= 0) w.push_back({err_, false});
        if (in_ >= 0 && !inbuf_.empty()) w.push_back({in_, true});
        return w;
    }

    void on_fd_ready(int fd) override {
        if (fd == in_) {
            flush_input();
        } else if (fd == out_ || fd == err_) {
            char buf[kChunk];
            const ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n > 0) {
                frame(fd == err_ ? kErr : kOut, std::string(buf, static_cast<size_t>(n)));
            } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
                // EOF (or, on a PTY, EIO: the program and its children are gone)
                if (fd == out_) close_fd(out_);
                else close_fd(err_);
                if (pty_) drop_input();  // nobody left to type to
            }
        }
        maybe_finish();
    }

    void on_tunnel_data(ByteSpan b) override {
        ibuf_.append(reinterpret_cast<const char*>(b.data()), b.size());
        size_t done = 0, now_consumed = 0;
        while (ibuf_.size() - done >= 3) {
            const uint8_t type = static_cast<uint8_t>(ibuf_[done]);
            const size_t len = (static_cast<uint8_t>(ibuf_[done + 1]) << 8) |
                               static_cast<uint8_t>(ibuf_[done + 2]);
            if (ibuf_.size() - done - 3 < len) break;  // not all here yet
            const char* p = ibuf_.data() + done + 3;
            now_consumed += 3;
            if (type == kData && in_ >= 0 && !eof_) {
                inbuf_.append(p, len);  // consumed once the program has read it
            } else {
                now_consumed += len;
                if (type == kWinsz && len == 4 && pty_ && out_ >= 0) {
                    winsize ws{};
                    ws.ws_row = static_cast<unsigned short>((static_cast<uint8_t>(p[0]) << 8) |
                                                            static_cast<uint8_t>(p[1]));
                    ws.ws_col = static_cast<unsigned short>((static_cast<uint8_t>(p[2]) << 8) |
                                                            static_cast<uint8_t>(p[3]));
                    ::ioctl(out_, TIOCSWINSZ, &ws);
                } else if (type == kEof && !eof_) {
                    eof_ = true;
                    if (pty_ && in_ >= 0) {  // a terminal's EOF is a keystroke
                        termios t{};
                        const char veof = ::tcgetattr(out_, &t) == 0 ? static_cast<char>(t.c_cc[VEOF])
                                                                     : '\x04';
                        inbuf_ += veof;
                        ++synthetic_;
                    }
                }
            }
            done += 3 + len;
        }
        ibuf_.erase(0, done);
        if (consumed && now_consumed) consumed(now_consumed);
        flush_input();
    }

    void tick(Millis) override { maybe_finish(); }

    std::string describe() const override {
        if (!reaped_) return pid_ > 0 ? "running " + basename_of(file_) : "starting";
        return how_ == kSignaled ? "killed by signal " + std::to_string(code_)
                                 : "exited " + std::to_string(code_);
    }
    bool done() const override { return reaped_ && how_ == kExited && code_ == 0; }

 private:
    bool spawn_pipes(const ChildPlan& plan) {
        int in[2] = {-1, -1}, out[2] = {-1, -1}, err[2] = {-1, -1};
        if (::pipe(in) != 0 || ::pipe(out) != 0 || ::pipe(err) != 0) {
            for (int fd : {in[0], in[1], out[0], out[1], err[0], err[1]})
                if (fd >= 0) ::close(fd);
            return false;
        }
        const pid_t pid = ::fork();
        if (pid < 0) {
            for (int fd : {in[0], in[1], out[0], out[1], err[0], err[1]}) ::close(fd);
            return false;
        }
        if (pid == 0) {  // child
            ::setsid();  // its own session: hanging up reaches everything it starts
            ::dup2(in[0], 0);
            ::dup2(out[1], 1);
            ::dup2(err[1], 2);
            plan.exec();
        }
        ::close(in[0]);
        ::close(out[1]);
        ::close(err[1]);
        pid_ = pid;
        in_ = in[1];
        out_ = out[0];
        err_ = err[0];
        for (int fd : {in_, out_, err_}) nonblock_cloexec(fd);
        return true;
    }

    bool spawn_pty(const ChildPlan& plan) {
        winsize ws = {24, 80, 0, 0};  // until the client sends its real size
        int master = -1;
        const pid_t pid = ::forkpty(&master, nullptr, nullptr, &ws);  // setsid + ctty in the child
        if (pid < 0) return false;
        if (pid == 0) plan.exec();
        pid_ = pid;
        out_ = master;           // the program's output (stdout and stderr, as a terminal has)
        in_ = ::dup(master);     // its input: a second fd so reads and writes are polled apart
        nonblock_cloexec(out_);
        if (in_ >= 0) nonblock_cloexec(in_);
        return true;
    }

    // Write what we hold for the program's input, as far as it takes it.
    void flush_input() {
        while (in_ >= 0 && !inbuf_.empty()) {
            const ssize_t w = ::write(in_, inbuf_.data(), inbuf_.size());
            if (w > 0) {
                account(static_cast<size_t>(w));
                inbuf_.erase(0, static_cast<size_t>(w));
            } else if (w < 0 && (errno == EAGAIN || errno == EINTR)) {
                return;  // full: the daemon polls in_ for room
            } else {     // it stopped reading (closed stdin, or exited)
                drop_input();
                return;
            }
        }
        if (in_ >= 0 && inbuf_.empty() && eof_ && !pty_) close_fd(in_);  // the program sees EOF
    }

    // Report `n` bytes written to the program as consumed (the EOF keystroke we
    // added ourselves never came from the tunnel, so it doesn't count).
    void account(size_t n) {
        const size_t real = inbuf_.size() - synthetic_;
        const size_t k = std::min(n, real);
        synthetic_ -= std::min(synthetic_, n - k);
        if (consumed && k) consumed(k);
    }

    void drop_input() {
        account(inbuf_.size());
        inbuf_.clear();
        close_fd(in_);
    }

    // Once its output is closed, wait for the program to exit, then send EXIT
    // and end the connection.
    void maybe_finish() {
        if (reaped_ || pid_ <= 0 || out_ >= 0 || err_ >= 0) return;
        int st = 0;
        const pid_t r = ::waitpid(pid_, &st, WNOHANG);
        if (r == 0) return;  // closed its output but still running
        if (r != pid_) {     // can't learn how it ended: end without EXIT ("cut off")
            reaped_ = true;
            if (shutdown) shutdown();
            return;
        }
        if (WIFSIGNALED(st)) finish(kSignaled, WTERMSIG(st));
        else finish(kExited, WEXITSTATUS(st));
    }

    void finish(uint8_t how, int code) {
        reaped_ = true;
        how_ = how;
        code_ = code;
        const char e[2] = {static_cast<char>(how), static_cast<char>(code)};
        frame(kExit, std::string(e, 2));
        drop_input();
        if (shutdown) shutdown();
    }

    void frame(uint8_t type, const std::string& payload) {
        if (!to_tunnel) return;
        std::string f;
        f.reserve(payload.size() + 3);
        f += static_cast<char>(type);
        f += static_cast<char>(payload.size() >> 8);
        f += static_cast<char>(payload.size() & 0xff);
        f += payload;
        to_tunnel(ByteSpan(reinterpret_cast<const uint8_t*>(f.data()), f.size()));
    }

    std::string file_;
    std::vector<std::string> argv_;
    bool pty_;
    pid_t pid_ = -1;
    int in_ = -1, out_ = -1, err_ = -1;  // PTY: out_ is the master, in_ a dup of it
    std::string ibuf_;    // incoming frames not yet complete
    std::string inbuf_;   // bytes for the program's input, not yet written
    size_t synthetic_ = 0;  // trailing bytes of inbuf_ we added (the EOF keystroke)
    bool eof_ = false;
    bool reaped_ = false;
    uint8_t how_ = kExited;
    int code_ = 0;
};

}  // namespace

bool exec_has_pty(const std::string& type, const std::vector<std::string>& args) {
    return type == "SHELL" || (type == "EXEC" && !args.empty() && args[0] == "PTY");
}

std::unique_ptr<LocalEnd> make_exec_end(const std::string& type,
                                        const std::vector<std::string>& args, std::string* err) {
    if (type == "SHELL") {
        if (!args.empty()) {
            if (err) *err = "SHELL takes no arguments";
            return nullptr;
        }
        const char* sh = std::getenv("SHELL");
        const std::string file = sh && *sh ? sh : "/bin/sh";
        return std::make_unique<ExecEnd>(file, std::vector<std::string>{"-" + basename_of(file)},
                                         true);  // "-bash": a login shell
    }
    const bool pty = exec_has_pty(type, args);
    std::vector<std::string> argv(args.begin() + (pty ? 1 : 0), args.end());
    if (argv.empty() || argv[0].empty()) {
        if (err) *err = "usage: EXEC [PTY] <program> [args...]";
        return nullptr;
    }
    const std::string file = argv[0];
    return std::make_unique<ExecEnd>(file, std::move(argv), pty);
}

void reap_orphans(Millis now) {
    auto& v = orphans();
    for (auto it = v.begin(); it != v.end();) {
        if (::waitpid(it->pid, nullptr, WNOHANG) != 0) {  // reaped (or not ours any more)
            it = v.erase(it);
            continue;
        }
        if (!it->killed && now >= it->kill_at) {
            signal_run(it->pid, SIGKILL);
            it->killed = true;
        }
        ++it;
    }
}

}  // namespace spl::peer
