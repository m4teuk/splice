#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

#include "net/endpoint.h"
#include "net/socket.h"

using namespace spl;

TEST(Endpoint, V4MappedRoundTrip) {
    sockaddr_storage ss{};
    auto* s = reinterpret_cast<sockaddr_in*>(&ss);
    s->sin_family = AF_INET;
    s->sin_port = htons(12345);
    inet_pton(AF_INET, "203.0.113.7", &s->sin_addr);

    Endpoint ep = endpoint_from_sockaddr(ss);
    EXPECT_TRUE(is_v4_mapped(ep.ip));
    EXPECT_EQ(ep.port, 12345);
    EXPECT_EQ(ep.to_string(), "203.0.113.7:12345");

    sockaddr_storage out{};
    socklen_t len = 0;
    sockaddr_from_endpoint(ep, &out, &len);
    EXPECT_EQ(static_cast<int>(out.ss_family), AF_INET6);  // always dual-stack v6
    EXPECT_EQ(len, static_cast<socklen_t>(sizeof(sockaddr_in6)));
}

TEST(Endpoint, V6RoundTrip) {
    sockaddr_storage ss{};
    auto* s = reinterpret_cast<sockaddr_in6*>(&ss);
    s->sin6_family = AF_INET6;
    s->sin6_port = htons(51820);
    inet_pton(AF_INET6, "2001:db8::1", &s->sin6_addr);

    Endpoint ep = endpoint_from_sockaddr(ss);
    EXPECT_FALSE(is_v4_mapped(ep.ip));
    EXPECT_EQ(ep.port, 51820);
    EXPECT_EQ(ep.to_string(), "[2001:db8::1]:51820");
}

TEST(Endpoint, Ordering) {
    Endpoint a{};
    a.port = 1;
    Endpoint b{};
    b.port = 2;
    EXPECT_LT(a, b);
    Endpoint c = a;
    EXPECT_EQ(a, c);
}

TEST(LocalAddr, PortFromBoundSocket) {
    std::string err;
    net::Fd fd = net::udp_bind("", 0, &err);
    ASSERT_TRUE(static_cast<bool>(fd)) << err;
    EXPECT_NE(net::local_port(fd.get()), 0);  // an ephemeral port was assigned
}

// LAN-candidate enumeration must tag every address with the requested port and
// never surface loopback or link-local addresses (a peer can't reach those).
TEST(LocalAddr, InterfaceEndpointsAreUsable) {
    const uint16_t port = 51820;
    auto eps = net::local_interface_endpoints(port);
    EXPECT_LT(eps.size(), 64u);  // sanity bound
    for (const auto& e : eps) {
        EXPECT_TRUE(e.valid());
        EXPECT_EQ(e.port, port);
        EXPECT_NE(e.to_string(), "127.0.0.1:" + std::to_string(port));
        EXPECT_NE(e.to_string(), "[::1]:" + std::to_string(port));
        if (is_v4_mapped(e.ip)) {
            EXPECT_NE(e.ip[12], 127);                              // not 127.0.0.0/8
            EXPECT_FALSE(e.ip[12] == 169 && e.ip[13] == 254);      // not 169.254.0.0/16
        } else {
            EXPECT_FALSE(e.ip[0] == 0xfe && (e.ip[1] & 0xc0) == 0x80);  // not fe80::/10
        }
    }
}
