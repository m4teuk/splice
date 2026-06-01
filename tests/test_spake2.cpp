#include <gtest/gtest.h>

#include "crypto/spake2.h"

using namespace spl;
using namespace spl::crypto;

TEST(Spake2, MatchingPasswordsAgree) {
    Bytes pw = {'4', '8', '1', '9', '2', '2'};
    Bytes msg_a, msg_b;
    auto a = Spake2::start(as_span(pw), &msg_a);
    auto b = Spake2::start(as_span(pw), &msg_b);
    ASSERT_TRUE(a && b);
    EXPECT_FALSE(msg_a.empty());

    auto key_a = a->finish(as_span(msg_b));
    auto key_b = b->finish(as_span(msg_a));
    ASSERT_TRUE(key_a && key_b);
    EXPECT_FALSE(key_a->empty());
    EXPECT_EQ(*key_a, *key_b);  // same password -> same shared key
}

TEST(Spake2, MismatchedPasswordsDiverge) {
    Bytes pw1 = {'1', '1', '1', '1', '1', '1'};
    Bytes pw2 = {'2', '2', '2', '2', '2', '2'};
    Bytes msg_a, msg_b;
    auto a = Spake2::start(as_span(pw1), &msg_a);
    auto b = Spake2::start(as_span(pw2), &msg_b);
    ASSERT_TRUE(a && b);

    auto key_a = a->finish(as_span(msg_b));
    auto key_b = b->finish(as_span(msg_a));
    ASSERT_TRUE(key_a && key_b);
    EXPECT_NE(*key_a, *key_b);  // wrong password -> keys differ (detected at confirmation)
}
