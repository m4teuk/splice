#include <gtest/gtest.h>

#include "server/code_alloc.h"

using namespace spl;
using namespace spl::server;

TEST(CodeAlloc, SmallestFirstAndUnique) {
    CodeAllocator a;
    auto c0 = a.allocate(0, 10000);
    auto c1 = a.allocate(0, 10000);
    auto c2 = a.allocate(0, 10000);
    ASSERT_TRUE(c0 && c1 && c2);
    EXPECT_EQ(*c0, 0u);
    EXPECT_EQ(*c1, 1u);
    EXPECT_EQ(*c2, 2u);
}

TEST(CodeAlloc, ActiveAndTtlExpiry) {
    CodeAllocator a;
    auto c = a.allocate(0, 1000);
    ASSERT_TRUE(c);
    EXPECT_TRUE(a.active(*c, 500));
    EXPECT_FALSE(a.active(*c, 2000));  // past TTL

    a.expire(2000);                    // moves code 0 into cooldown
    auto c2 = a.allocate(2000, 1000);  // 0 is cooling down -> next smallest
    ASSERT_TRUE(c2);
    EXPECT_NE(*c2, *c);
}

TEST(CodeAlloc, ReuseCooldown) {
    CodeAllocator a;  // cooldown 3000ms
    auto c0 = a.allocate(0, 10000);
    ASSERT_TRUE(c0);
    EXPECT_EQ(*c0, 0u);

    a.release(0, 0);                      // 0 cools down until t=3000
    auto c = a.allocate(0, 10000);        // can't reuse 0 yet -> 1
    ASSERT_TRUE(c);
    EXPECT_EQ(*c, 1u);

    a.release(1, 100);                    // 1 cools down until t=3100
    auto c2 = a.allocate(4000, 10000);    // both cooldowns elapsed -> smallest 0
    ASSERT_TRUE(c2);
    EXPECT_EQ(*c2, 0u);
}

TEST(CodeAlloc, GrowsOnExhaustion) {
    CodeAllocator a({/*initial_max=*/2, /*hard_max=*/1'000'000, /*cooldown=*/3000});
    auto c0 = a.allocate(0, 10000);
    auto c1 = a.allocate(0, 10000);
    ASSERT_TRUE(c0 && c1);
    EXPECT_EQ(a.pool_max(), 2);
    auto c2 = a.allocate(0, 10000);  // pool full -> grows to 20
    ASSERT_TRUE(c2);
    EXPECT_EQ(*c2, 2u);
    EXPECT_EQ(a.pool_max(), 20);
}

TEST(CodeAlloc, FailsWhenHardCapExhausted) {
    CodeAllocator a({/*initial_max=*/2, /*hard_max=*/2, /*cooldown=*/100000});
    ASSERT_TRUE(a.allocate(0, 10000));
    ASSERT_TRUE(a.allocate(0, 10000));
    EXPECT_FALSE(a.allocate(0, 10000).has_value());  // full and cannot grow
}
