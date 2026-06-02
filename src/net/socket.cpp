#include "net/socket.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace spl::net {

void Fd::reset() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool set_nonblocking(int fd, bool nb) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return false;
    fl = nb ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK);
    return fcntl(fd, F_SETFL, fl) == 0;
}

bool set_recv_timeout(int fd, int ms) {
    timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}

namespace {

Fd make_v6_socket(int type) {
    int fd = ::socket(AF_INET6, type, 0);
    if (fd < 0) return Fd{};
    int off = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));  // dual-stack
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    return Fd{fd};
}

bool parse_bind_addr(const std::string& host, uint16_t port, sockaddr_in6* sa) {
    std::memset(sa, 0, sizeof(*sa));
    sa->sin6_family = AF_INET6;
    sa->sin6_port = htons(port);
    if (host.empty() || host == "*" || host == "::" || host == "0.0.0.0") {
        sa->sin6_addr = in6addr_any;
        return true;
    }
    if (inet_pton(AF_INET6, host.c_str(), &sa->sin6_addr) == 1) return true;
    in_addr v4{};
    if (inet_pton(AF_INET, host.c_str(), &v4) == 1) {
        uint8_t* p = sa->sin6_addr.s6_addr;
        p[10] = 0xff;
        p[11] = 0xff;
        std::memcpy(p + 12, &v4, 4);
        return true;
    }
    return false;
}

}  // namespace

Fd tcp_listen(const std::string& host, uint16_t port, int backlog, std::string* err) {
    Fd fd = make_v6_socket(SOCK_STREAM);
    if (!fd) {
        if (err) *err = "socket failed";
        return Fd{};
    }
    sockaddr_in6 sa{};
    if (!parse_bind_addr(host, port, &sa)) {
        if (err) *err = "bad bind address: " + host;
        return Fd{};
    }
    if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        if (err) *err = std::string("bind: ") + std::strerror(errno);
        return Fd{};
    }
    if (::listen(fd.get(), backlog) != 0) {
        if (err) *err = std::string("listen: ") + std::strerror(errno);
        return Fd{};
    }
    return fd;
}

Fd udp_bind(const std::string& host, uint16_t port, std::string* err) {
    Fd fd = make_v6_socket(SOCK_DGRAM);
    if (!fd) {
        if (err) *err = "socket failed";
        return Fd{};
    }
    sockaddr_in6 sa{};
    if (!parse_bind_addr(host, port, &sa)) {
        if (err) *err = "bad bind address: " + host;
        return Fd{};
    }
    if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        if (err) *err = std::string("bind: ") + std::strerror(errno);
        return Fd{};
    }
    return fd;
}

Fd tcp_accept(int listen_fd, Endpoint* peer) {
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    int fd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&ss), &len);
    if (fd < 0) return Fd{};
    // BSD/macOS accept() inherits the listener's O_NONBLOCK; Linux does not. The
    // pairing handshake/bridge assume blocking sockets, so normalize here.
    set_nonblocking(fd, false);
    if (peer) *peer = endpoint_from_sockaddr(ss);
    return Fd{fd};
}

std::optional<Endpoint> resolve(const std::string& host, uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        return std::nullopt;
    }
    std::optional<Endpoint> out;
    if (res) {
        sockaddr_storage ss{};
        std::memcpy(&ss, res->ai_addr, res->ai_addrlen);
        out = endpoint_from_sockaddr(ss);
    }
    freeaddrinfo(res);
    return out;
}

uint16_t local_port(int fd) {
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0) return 0;
    if (ss.ss_family == AF_INET6) return ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port);
    if (ss.ss_family == AF_INET) return ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
    return 0;
}

std::vector<Endpoint> local_interface_endpoints(uint16_t port) {
    std::vector<Endpoint> out;
    ifaddrs* ifs = nullptr;
    if (::getifaddrs(&ifs) != 0) return out;
    for (ifaddrs* p = ifs; p; p = p->ifa_next) {
        if (!p->ifa_addr || !(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
        sockaddr_storage ss{};
        if (p->ifa_addr->sa_family == AF_INET) {
            const auto* s = reinterpret_cast<const sockaddr_in*>(p->ifa_addr);
            const uint8_t* b = reinterpret_cast<const uint8_t*>(&s->sin_addr);
            if (b[0] == 127) continue;                 // loopback 127.0.0.0/8
            if (b[0] == 169 && b[1] == 254) continue;  // link-local 169.254.0.0/16
            std::memcpy(&ss, s, sizeof(*s));
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            const auto* s = reinterpret_cast<const sockaddr_in6*>(p->ifa_addr);
            const uint8_t* b = s->sin6_addr.s6_addr;
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) continue;  // link-local fe80::/10
            bool loop = (b[15] == 1);
            for (int i = 0; i < 15 && loop; ++i) loop = (b[i] == 0);
            if (loop) continue;  // loopback ::1
            std::memcpy(&ss, s, sizeof(*s));
        } else {
            continue;
        }
        Endpoint e = endpoint_from_sockaddr(ss);
        e.port = port;
        if (std::find(out.begin(), out.end(), e) == out.end()) out.push_back(e);
    }
    ::freeifaddrs(ifs);
    return out;
}

Fd tcp_connect(const std::string& host, uint16_t port, std::string* err) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string ports = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), ports.c_str(), &hints, &res);
    if (rc != 0) {
        if (err) *err = std::string("getaddrinfo: ") + gai_strerror(rc);
        return Fd{};
    }
    Fd out;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            out = Fd{fd};
            break;
        }
        ::close(fd);
    }
    freeaddrinfo(res);
    if (!out && err) *err = "connect failed to " + host + ":" + ports;
    return out;
}

}  // namespace spl::net
