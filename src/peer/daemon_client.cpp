#include "peer/daemon_client.h"

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstring>

#include "common/time.h"

namespace spl::peer {

namespace {

void write_all(int fd, const void* p, size_t n) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    size_t off = 0;
    while (off < n) {
        ssize_t w = ::write(fd, b + off, n - off);
        if (w <= 0) return;
        off += static_cast<size_t>(w);
    }
}

std::string read_line(int fd) {
    std::string out;
    char c;
    while (out.size() < 4096) {
        ssize_t n = ::read(fd, &c, 1);
        if (n <= 0) return "";
        if (c == '\n') return out;
        out += c;
    }
    return "";
}

}  // namespace

int daemon_connect() {
    const std::string path = daemon_socket_path();
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_un sa{};
    sa.sun_family = AF_UNIX;
    if (path.size() >= sizeof(sa.sun_path)) {
        ::close(fd);
        return -1;
    }
    std::strncpy(sa.sun_path, path.c_str(), sizeof(sa.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

std::string send_command(int fd, const std::string& line) {
    const std::string out = line + "\n";
    write_all(fd, out.data(), out.size());
    return read_line(fd);
}

std::string daemon_request(const std::string& line) {
    int fd = daemon_connect();
    if (fd < 0) return "";
    std::string r = send_command(fd, line);
    ::close(fd);
    return r;
}

bool ensure_daemon(const DaemonOpts& opts, std::string* err) {
    if (daemon_request("PING") == "OK") return true;

    pid_t pid = ::fork();
    if (pid < 0) {
        if (err) *err = "fork failed";
        return false;
    }
    if (pid == 0) {  // child: become the daemon (single-threaded; fork is safe)
        ::setsid();
        const std::string log = runtime_dir() + "/daemon.log";
        if (!std::freopen("/dev/null", "r", stdin)) {}
        if (!std::freopen(log.c_str(), "a", stdout)) {}
        if (!std::freopen(log.c_str(), "a", stderr)) {}
        _exit(daemon_run(opts));
    }
    // parent: wait for the socket to come up
    const Millis deadline = mono_ms() + 5000;
    while (mono_ms() < deadline) {
        if (daemon_request("PING") == "OK") return true;
        struct timespec ts {0, 50 * 1000 * 1000};
        ::nanosleep(&ts, nullptr);
    }
    if (err) *err = "daemon did not come up (see " + runtime_dir() + "/daemon.log)";
    return false;
}

int bridge_stdio(int fd) {
    std::signal(SIGPIPE, SIG_IGN);
    bool stdin_open = true;
    for (;;) {
        pollfd p[2];
        p[0] = {fd, POLLIN, 0};
        int n = 1;
        if (stdin_open) {
            p[1] = {STDIN_FILENO, POLLIN, 0};
            n = 2;
        }
        if (::poll(p, n, -1) < 0) return 1;
        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            char buf[4096];
            ssize_t r = ::read(fd, buf, sizeof(buf));
            if (r <= 0) return 0;  // pipe closed by the other side
            write_all(STDOUT_FILENO, buf, static_cast<size_t>(r));
        }
        if (n == 2 && (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            char buf[4096];
            ssize_t r = ::read(STDIN_FILENO, buf, sizeof(buf));
            if (r <= 0) {
                stdin_open = false;  // keep draining the pipe side
            } else {
                write_all(fd, buf, static_cast<size_t>(r));
            }
        }
    }
}

}  // namespace spl::peer
