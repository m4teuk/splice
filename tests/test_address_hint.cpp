#include <gtest/gtest.h>

#include <string>

#include "peer/store.h"

using spl::peer::parse_address_hint;

namespace {
struct Parsed {
    bool ok;
    std::string host;
    uint16_t port;
};
Parsed parse(const std::string& s) {
    Parsed p{false, "", 0};
    p.ok = parse_address_hint(s, &p.host, &p.port);
    return p;
}
}  // namespace

TEST(AddressHint, HostsWithoutPort) {
    for (const char* h : {"10.0.0.5", "laptop.tailnet.ts.net", "my-box_2", "fd00::5", "::1"}) {
        const Parsed p = parse(h);
        EXPECT_TRUE(p.ok) << h;
        EXPECT_EQ(p.host, h);
        EXPECT_EQ(p.port, 0);
    }
}

TEST(AddressHint, HostsWithPort) {
    Parsed p = parse("10.0.0.5:7701");
    EXPECT_TRUE(p.ok);
    EXPECT_EQ(p.host, "10.0.0.5");
    EXPECT_EQ(p.port, 7701);
    p = parse("laptop.example.net:9");
    EXPECT_TRUE(p.ok);
    EXPECT_EQ(p.host, "laptop.example.net");
    EXPECT_EQ(p.port, 9);
    p = parse("[fd00::5]:7701");
    EXPECT_TRUE(p.ok);
    EXPECT_EQ(p.host, "fd00::5");
    EXPECT_EQ(p.port, 7701);
    p = parse("[fd00::5]");
    EXPECT_TRUE(p.ok);
    EXPECT_EQ(p.host, "fd00::5");
    EXPECT_EQ(p.port, 0);
}

TEST(AddressHint, RejectsMalformed) {
    for (const char* h : {"", "host:", ":7701", "host:0", "host:70000", "host:12ab", "a b",
                          "[fd00::5", "[fd00::5]7701", "[fd00::5]:", "host/path", "host;rm"})
        EXPECT_FALSE(parse(h).ok) << h;
}
