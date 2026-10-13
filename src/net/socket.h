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
// Connect to host:port (numeric or DNS). timeout_ms > 0 bounds each connect
// attempt (the returned socket is blocking either way); 0 = the OS default.
Fd tcp_connect(const std::string& host, uint16_t port, std::string* err, int timeout_ms = 0);
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

// The same addresses with their interface names ("eth0", "tailscale0", …), as
// printable hosts — for telling the user where this machine can be reached.
struct InterfaceAddress {
    std::string ifname;
    std::string host;
};
std::vector<InterfaceAddress> local_interface_addresses();

// The IPv4 broadcast address of every up, non-loopback interface, with `port` —
// where a LAN discovery query goes to reach everyone on each attached network.
std::vector<Endpoint> broadcast_endpoints(uint16_t port);

// Dual-stack UDP socket on [::]:port that other processes may bind too
// (SO_REUSEPORT): broadcasts reach every socket sharing the port, so several
// users' daemons on one machine can all listen for LAN discovery.
Fd udp_bind_shared(uint16_t port, std::string* err);

bool set_broadcast(int fd);  // allow sending to broadcast addresses

bool set_nonblocking(int fd, bool nb);
bool set_recv_timeout(int fd, int ms);

}  // namespace spl::net
