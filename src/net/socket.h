// Thin socket helpers. All listening sockets are dual-stack IPv6 (V6ONLY off),
// so a single socket serves IPv4 (v4-mapped) and IPv6 peers.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "net/endpoint.h"

namespace spl::net {

// Owning file-descriptor wrapper (move-only, closes on destruction).
class Fd {
 public:
    Fd() = default;
    explicit Fd(int fd) : fd_(fd) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    Fd& operator=(Fd&& o) noexcept {
        if (this != &o) {
            reset();
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }
    ~Fd() { reset(); }

    int get() const { return fd_; }
    int release() {
        int f = fd_;
        fd_ = -1;
        return f;
    }
    void reset();
    explicit operator bool() const { return fd_ >= 0; }

 private:
    int fd_ = -1;
};

// Bind a dual-stack IPv6 TCP listener. host empty/"*"/"::" => any.
Fd tcp_listen(const std::string& host, uint16_t port, int backlog, std::string* err);
// Accept a connection; fills *peer if non-null. Invalid Fd on error/EINTR.
Fd tcp_accept(int listen_fd, Endpoint* peer);
// Connect to host:port (numeric or DNS).
Fd tcp_connect(const std::string& host, uint16_t port, std::string* err);
// Bind a dual-stack IPv6 UDP socket.
Fd udp_bind(const std::string& host, uint16_t port, std::string* err);

// Resolve host:port (numeric or DNS) to an Endpoint.
std::optional<Endpoint> resolve(const std::string& host, uint16_t port);

// The local UDP/TCP port a bound socket is using, in host byte order (0 on error).
uint16_t local_port(int fd);

// The host's own unicast interface addresses, each paired with `port`, for
// advertising LAN candidates (same-NAT direct connectivity). Loopback and
// link-local addresses are skipped. Best-effort: empty if enumeration fails.
std::vector<Endpoint> local_interface_endpoints(uint16_t port);

bool set_nonblocking(int fd, bool nb);
bool set_recv_timeout(int fd, int ms);

}  // namespace spl::net
