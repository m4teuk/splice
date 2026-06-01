#include <gtest/gtest.h>

#include "server/rate_limit.h"

using namespace spl;
using namespace spl::server;

namespace {
std::array<uint8_t, 16> ip(uint8_t last) {
    std::array<uint8_t, 16> a{};
    a[15] = last;
    return a;
}
}  // namespace

TEST(RateLimit, BurstThenDeny) {
    RateLimiter rl(/*ip_rate=*/1, /*ip_burst=*/3, /*g_rate=*/1000, /*g_burst=*/1000);
    auto a = ip(1);
    EXPECT_TRUE(rl.allow(a, 0));
    EXPECT_TRUE(rl.allow(a, 0));
    EXPECT_TRUE(rl.allow(a, 0));
    EXPECT_FALSE(rl.allow(a, 0));    // burst exhausted
    EXPECT_TRUE(rl.allow(a, 1000));  // +1 token after a second
    EXPECT_FALSE(rl.allow(a, 1000));
}

TEST(RateLimit, PerIpIsolation) {
    RateLimiter rl(1, 1, 1000, 1000);
    EXPECT_TRUE(rl.allow(ip(1), 0));
    EXPECT_FALSE(rl.allow(ip(1), 0));
    EXPECT_TRUE(rl.allow(ip(2), 0));  // a different IP is independent
}

TEST(RateLimit, GlobalCap) {
    RateLimiter rl(/*ip_rate=*/1000, /*ip_burst=*/1000, /*g_rate=*/1, /*g_burst=*/2);
    EXPECT_TRUE(rl.allow(ip(1), 0));
    EXPECT_TRUE(rl.allow(ip(2), 0));
    EXPECT_FALSE(rl.allow(ip(3), 0));  // global burst of 2 exhausted
}

TEST(RateLimit, EvictIdle) {
    RateLimiter rl(1, 1, 1000, 1000);
    rl.allow(ip(1), 0);
    EXPECT_EQ(rl.tracked_ips(), 1u);
    rl.evict_idle(10000, 1000);
    EXPECT_EQ(rl.tracked_ips(), 0u);
}
