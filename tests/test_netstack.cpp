#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>

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

// Regression: lwIP's IPv6 reassembly timer fires ~1s in and used to abort on
// 64-bit hosts (struct ip6_reass_helper > IP6_FRAG_HLEN). Drive the stack past
// the cyclic-timer interval with real time elapsing — reaching the end without
// aborting is the test.
TEST(Netstack, RunsPastCyclicTimers) {
    Netstack ns;
    proto::Ip6 addr{};
    addr[0] = 0xfd;
    addr[15] = 1;
    ns.configure(addr);

    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(1300)) {
        ns.check_timeouts();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    SUCCEED();
}
