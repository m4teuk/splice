#include "net/endpoint.h"

#include <arpa/inet.h>
#include <cstring>
#include <sys/socket.h>

namespace spl {

namespace {
constexpr std::array<uint8_t, 12> kV4Prefix = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
}

bool is_v4_mapped(const std::array<uint8_t, 16>& ip) {
    return std::memcmp(ip.data(), kV4Prefix.data(), kV4Prefix.size()) == 0;
}

Endpoint endpoint_from_sockaddr(const sockaddr_storage& ss) {
    Endpoint ep;
    if (ss.ss_family == AF_INET) {
        const auto* s = reinterpret_cast<const sockaddr_in*>(&ss);
        ep.ip[10] = 0xff;
        ep.ip[11] = 0xff;
        std::memcpy(ep.ip.data() + 12, &s->sin_addr, 4);
        ep.port = ntohs(s->sin_port);
    } else if (ss.ss_family == AF_INET6) {
        const auto* s = reinterpret_cast<const sockaddr_in6*>(&ss);
        std::memcpy(ep.ip.data(), &s->sin6_addr, 16);
        ep.port = ntohs(s->sin6_port);
    }
    return ep;
}

void sockaddr_from_endpoint(const Endpoint& ep, sockaddr_storage* ss, socklen_t* len) {
    std::memset(ss, 0, sizeof(*ss));
    auto* s = reinterpret_cast<sockaddr_in6*>(ss);
    s->sin6_family = AF_INET6;
    std::memcpy(&s->sin6_addr, ep.ip.data(), 16);
    s->sin6_port = htons(ep.port);
    *len = sizeof(sockaddr_in6);
}

std::string Endpoint::to_string() const {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (is_v4_mapped(ip)) {
        inet_ntop(AF_INET, ip.data() + 12, buf, sizeof(buf));
        return std::string(buf) + ":" + std::to_string(port);
    }
    inet_ntop(AF_INET6, ip.data(), buf, sizeof(buf));
    return "[" + std::string(buf) + "]:" + std::to_string(port);
}

}  // namespace spl
