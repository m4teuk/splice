// A transport address (IP + UDP/TCP port). IPv4 is stored IPv4-mapped
// (::ffff:a.b.c.d) so a single representation and a single dual-stack IPv6
// socket cover both families.
#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <netinet/in.h>
#include <string>

namespace spl {

struct Endpoint {
    std::array<uint8_t, 16> ip{};
    uint16_t port = 0;

    friend bool operator==(const Endpoint&, const Endpoint&) = default;
    friend std::strong_ordering operator<=>(const Endpoint&, const Endpoint&) = default;

    bool valid() const { return port != 0; }
    std::string to_string() const;
};

bool is_v4_mapped(const std::array<uint8_t, 16>& ip);

// Converts a kernel sockaddr (AF_INET or AF_INET6) into an Endpoint.
Endpoint endpoint_from_sockaddr(const sockaddr_storage& ss);

// Fills an AF_INET6 sockaddr from an Endpoint (always v6; v4 is v4-mapped), so
// it can be used directly with a dual-stack IPv6 socket.
void sockaddr_from_endpoint(const Endpoint& ep, sockaddr_storage* ss, socklen_t* len);

}  // namespace spl
