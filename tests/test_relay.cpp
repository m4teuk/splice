#include <gtest/gtest.h>

#include "proto/relay.h"

using namespace spl;
using namespace spl::proto;

TEST(Relay, UpRoundTrip) {
    Uid uid{};
    uid.fill(0x5A);
    Bytes payload = {1, 2, 3, 4};
    Bytes pkt = encode_relay_up(uid, as_span(payload));

    EXPECT_EQ(peek_udp_type(as_span(pkt)), UdpType::kRelay);
    auto d = decode_relay_up(as_span(pkt));
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->uid, uid);
    EXPECT_EQ(d->payload, payload);
}

TEST(Relay, UpEmptyPayloadIsRegistration) {
    Uid uid{};
    uid.fill(1);
    auto d = decode_relay_up(as_span(encode_relay_up(uid, {})));
    ASSERT_TRUE(d.has_value());
    EXPECT_TRUE(d->payload.empty());
}

TEST(Relay, UpTooShortUid) {
    Bytes pkt(11, 0);  // 0x01 tag + only 10 uid bytes
    pkt[0] = 0x01;
    EXPECT_FALSE(decode_relay_up(as_span(pkt)).has_value());
}

TEST(Relay, DownRoundTrip) {
    Bytes payload = {7, 7, 7};
    auto p = decode_relay_down(as_span(encode_relay_down(as_span(payload))));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(*p, payload);
}

TEST(Relay, WhereamiReqRoundTrip) {
    Bytes pkt = encode_whereami_req(0xCAFEBABE);
    EXPECT_EQ(peek_udp_type(as_span(pkt)), UdpType::kWhereami);
    auto t = decode_whereami_req(as_span(pkt));
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(*t, 0xCAFEBABEu);
}

TEST(Relay, WhereamiReplyRoundTrip) {
    WhereamiReply m{};
    m.token = 0x11223344;
    m.ip.fill(0);
    // ::ffff:192.168.0.7
    m.ip[10] = 0xff;
    m.ip[11] = 0xff;
    m.ip[12] = 192;
    m.ip[13] = 168;
    m.ip[14] = 0;
    m.ip[15] = 7;
    m.port = 51820;

    auto d = decode_whereami_reply(as_span(encode_whereami_reply(m)));
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->token, m.token);
    EXPECT_EQ(d->ip, m.ip);
    EXPECT_EQ(d->port, m.port);
}

TEST(Relay, PeekUnknownType) {
    EXPECT_FALSE(peek_udp_type(as_span(Bytes{})).has_value());
    EXPECT_FALSE(peek_udp_type(as_span(Bytes{0x09})).has_value());
}

TEST(Relay, WrongTypeRejected) {
    Bytes w = encode_whereami_req(1);
    EXPECT_FALSE(decode_relay_up(as_span(w)).has_value());  // 0x02 is not relay

    Bytes r = encode_relay_down(as_span(Bytes{1}));
    EXPECT_FALSE(decode_whereami_req(as_span(r)).has_value());  // 0x01 is not whereami
}
