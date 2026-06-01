#include <gtest/gtest.h>

#include "proto/frame.h"

using namespace spl;
using namespace spl::proto;

TEST(Frame, RoundTrip) {
    Bytes payload = {1, 2, 3, 4, 5};
    Bytes f = encode_frame(as_span(payload));
    EXPECT_EQ(f.size(), 4u + payload.size());

    bool err = true;
    auto p = try_parse_frame(as_span(f), &err);
    ASSERT_TRUE(p.has_value());
    EXPECT_FALSE(err);
    EXPECT_EQ(p->payload, payload);
    EXPECT_EQ(p->consumed, f.size());
}

TEST(Frame, EmptyPayload) {
    Bytes f = encode_frame({});
    EXPECT_EQ(f.size(), 4u);
    bool err = true;
    auto p = try_parse_frame(as_span(f), &err);
    ASSERT_TRUE(p.has_value());
    EXPECT_FALSE(err);
    EXPECT_TRUE(p->payload.empty());
    EXPECT_EQ(p->consumed, 4u);
}

TEST(Frame, NeedsMoreBytes) {
    Bytes f = encode_frame(as_span(Bytes{1, 2, 3}));
    bool err = false;

    Bytes partial(f.begin(), f.end() - 1);  // payload truncated by one
    EXPECT_FALSE(try_parse_frame(as_span(partial), &err).has_value());
    EXPECT_FALSE(err);

    Bytes header_only = {0, 0};  // not even a full length header
    EXPECT_FALSE(try_parse_frame(as_span(header_only), &err).has_value());
    EXPECT_FALSE(err);
}

TEST(Frame, OversizedIsProtocolError) {
    ByteWriter w;
    w.u32(kMaxFrameLen + 1);
    Bytes f = w.take();
    bool err = false;
    EXPECT_FALSE(try_parse_frame(as_span(f), &err).has_value());
    EXPECT_TRUE(err);
}

TEST(Frame, TwoFramesConsumedOffset) {
    Bytes f1 = encode_frame(as_span(Bytes{1, 2}));
    Bytes f2 = encode_frame(as_span(Bytes{3, 4, 5}));
    Bytes buf = f1;
    buf.insert(buf.end(), f2.begin(), f2.end());

    bool err = false;
    auto p1 = try_parse_frame(as_span(buf), &err);
    ASSERT_TRUE(p1.has_value());
    EXPECT_EQ(p1->payload, (Bytes{1, 2}));

    ByteSpan rest(buf.data() + p1->consumed, buf.size() - p1->consumed);
    auto p2 = try_parse_frame(rest, &err);
    ASSERT_TRUE(p2.has_value());
    EXPECT_EQ(p2->payload, (Bytes{3, 4, 5}));
    EXPECT_EQ(p2->consumed, f2.size());
}
