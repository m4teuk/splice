#include <gtest/gtest.h>

#include "server/relay_table.h"

using namespace spl;
using namespace spl::server;

namespace {
proto::Uid mk(uint8_t fill, uint8_t side) {
    proto::Uid u;
    u.fill(fill);
    u[proto::kUidLen - 1] = (u[proto::kUidLen - 1] & 0xfe) | (side & 1);
    return u;
}
Endpoint ep(uint16_t port) {
    Endpoint e{};
    e.ip[15] = 1;
    e.port = port;
    return e;
}
}  // namespace

TEST(RelayTable, PeerUidFlipsLowBit) {
    proto::Uid a = mk(0x11, 0);
    proto::Uid b = RelayTable::peer_uid(a);
    EXPECT_EQ(b[proto::kUidLen - 1] & 1, 1);
    EXPECT_EQ(RelayTable::peer_uid(b), a);  // involution
}

TEST(RelayTable, ForwardsWhenPeerKnown) {
    RelayTable t(1000);
    proto::Uid a = mk(0x22, 0), b = mk(0x22, 1);

    // A registers first; its peer (B) is unknown -> drop.
    EXPECT_FALSE(t.on_packet(a, ep(1001), 0).has_value());
    // B registers; peer A is known -> forward to A.
    auto d = t.on_packet(b, ep(1002), 10);
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->port, 1001);
    // A sends again -> forward to B's (updated) address.
    auto d2 = t.on_packet(a, ep(1003), 20);
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(d2->port, 1002);
}

TEST(RelayTable, StalePeerDropped) {
    RelayTable t(1000);
    proto::Uid a = mk(1, 0), b = mk(1, 1);
    t.on_packet(a, ep(1), 0);
    // B arrives long after A's last-seen -> A is stale -> drop.
    EXPECT_FALSE(t.on_packet(b, ep(2), 5000).has_value());
}

TEST(RelayTable, EvictExpired) {
    RelayTable t(1000);
    t.on_packet(mk(1, 0), ep(1), 0);
    EXPECT_EQ(t.size(), 1u);
    t.evict_expired(5000);
    EXPECT_EQ(t.size(), 0u);
}
