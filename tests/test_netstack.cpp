#include <gtest/gtest.h>

#include <string>

#include "peer/netstack.h"

using namespace spl;
using namespace spl::peer;

// Drives a TCP connection within a single lwIP stack via internal loopback
// (packets to our own tunnel address are looped back). Validates the netstack +
// TCP path without sockets or threads.
TEST(Netstack, TcpLoopback) {
    Netstack ns;
    proto::Ip6 addr{};
    addr[0] = 0xfd;
    addr[15] = 1;  // fd00::1
    ns.configure(addr);

    std::string received;
    bool connected = false;
    ns.listen(7777, [&](TcpConn* c) {
        c->on_recv = [&](ByteSpan b) {
            received.append(reinterpret_cast<const char*>(b.data()), b.size());
        };
    });
    ns.connect(
        addr, 7777,
        [&](TcpConn* c) {
            connected = true;
            std::string msg = "hello tunnel";
            c->send(as_span(msg));
        },
        [&]() {});

    for (int i = 0; i < 5000 && received.size() < 12; ++i) ns.check_timeouts();

    EXPECT_TRUE(connected);
    EXPECT_EQ(received, "hello tunnel");
}
