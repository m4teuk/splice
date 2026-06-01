#include <gtest/gtest.h>

#include "proto/pairing.h"

using namespace spl;
using namespace spl::proto;

namespace {
Bytes reencode_ctrl(const Bytes& payload) {
    auto m = decode_ctrl(as_span(payload));
    EXPECT_TRUE(m.has_value());
    return m ? encode_ctrl(*m) : Bytes{};
}
}  // namespace

TEST(Pairing, CtrlRoundTrip) {
    EXPECT_EQ(reencode_ctrl(encode(Init{0x0102})), encode(Init{0x0102}));
    EXPECT_EQ(reencode_ctrl(encode(Code{7, 30})), encode(Code{7, 30}));
    EXPECT_EQ(reencode_ctrl(encode(Join{7})), encode(Join{7}));
    EXPECT_EQ(reencode_ctrl(encode(Paired{})), encode(Paired{}));
    EXPECT_EQ(reencode_ctrl(encode(Error{2, "bad code"})), encode(Error{2, "bad code"}));
}

TEST(Pairing, CtrlFields) {
    auto m = decode_ctrl(as_span(encode(Code{42, 30})));
    ASSERT_TRUE(m.has_value());
    ASSERT_TRUE(std::holds_alternative<Code>(*m));
    EXPECT_EQ(std::get<Code>(*m).code, 42u);
    EXPECT_EQ(std::get<Code>(*m).ttl_seconds, 30u);
}

TEST(Pairing, CtrlRejectsGarbage) {
    EXPECT_FALSE(decode_ctrl(as_span(Bytes{})).has_value());      // empty
    EXPECT_FALSE(decode_ctrl(as_span(Bytes{0xff})).has_value());  // unknown type
    EXPECT_FALSE(decode_ctrl(as_span(Bytes{0x01})).has_value());  // Init missing version

    Bytes code_extra = encode(Code{1, 2});
    code_extra.push_back(0);  // trailing byte
    EXPECT_FALSE(decode_ctrl(as_span(code_extra)).has_value());
}

TEST(Pairing, PeerRoundTrip) {
    Spake2Msg s{Bytes{1, 2, 3, 4, 5}};
    EXPECT_EQ(encode_peer(*decode_peer(as_span(encode(s)))), encode(s));

    Mac mac{};
    mac.fill(0xAB);
    KeyConfirm kc{mac};
    EXPECT_EQ(encode_peer(*decode_peer(as_span(encode(kc)))), encode(kc));

    Sealed sl{Bytes{9, 9, 9}};
    EXPECT_EQ(encode_peer(*decode_peer(as_span(encode(sl)))), encode(sl));
}

TEST(Pairing, PeerKeyConfirmExactLen) {
    Bytes short_kc = {0x11, 1, 2, 3};  // tag + only 3 of 32 MAC bytes
    EXPECT_FALSE(decode_peer(as_span(short_kc)).has_value());
}

TEST(Pairing, PeerSpake2AllowsEmpty) {
    Spake2Msg s{Bytes{}};
    auto d = decode_peer(as_span(encode(s)));
    ASSERT_TRUE(d.has_value());
    EXPECT_TRUE(std::holds_alternative<Spake2Msg>(*d));
    EXPECT_TRUE(std::get<Spake2Msg>(*d).msg.empty());
}

TEST(Pairing, NegRoundTrip) {
    Offer o{};
    o.ula_base.fill(0);
    o.ula_base[0] = 0xfd;
    o.ula_prefix = 64;
    o.uid.fill(0x11);
    o.uid[kUidLen - 1] &= 0xfe;  // side bit clear (leader)
    o.leader_pubkey.fill(0x22);
    EXPECT_EQ(encode_neg(*decode_neg(as_span(encode(o)))), encode(o));

    Reply r{};
    r.status = ReplyStatus::kAccept;
    r.follower_pubkey.fill(0x33);
    EXPECT_EQ(encode_neg(*decode_neg(as_span(encode(r)))), encode(r));
}

TEST(Pairing, NegFields) {
    Offer o{};
    o.uid.fill(0xAA);
    o.uid[kUidLen - 1] = 0xAA;  // low bit set
    auto m = decode_neg(as_span(encode(o)));
    ASSERT_TRUE(m.has_value());
    ASSERT_TRUE(std::holds_alternative<Offer>(*m));
    EXPECT_EQ(std::get<Offer>(*m).uid[kUidLen - 1] & 1, 0);  // 0xAA low bit is 0
}

TEST(Pairing, NegRejectsBadStatus) {
    Bytes bad = encode(Reply{});  // status byte at index 1
    bad[1] = 9;                   // out of range (> kAbort)
    EXPECT_FALSE(decode_neg(as_span(bad)).has_value());
}
