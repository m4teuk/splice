#include <gtest/gtest.h>

#include "common/bytes.h"

using namespace spl;

TEST(Bytes, IntRoundTrip) {
    ByteWriter w;
    w.u8(0x12);
    w.u16(0x3456);
    w.u32(0x789abcde);
    w.u64(0x0102030405060708ull);
    Bytes b = w.take();
    ASSERT_EQ(b.size(), 1u + 2 + 4 + 8);

    ByteReader r(as_span(b));
    EXPECT_EQ(r.u8(), 0x12);
    EXPECT_EQ(r.u16(), 0x3456);
    EXPECT_EQ(r.u32(), 0x789abcdeu);
    EXPECT_EQ(r.u64(), 0x0102030405060708ull);
    EXPECT_TRUE(r.done());
}

TEST(Bytes, BigEndianLayout) {
    ByteWriter w;
    w.u32(0x01020304);
    Bytes b = w.take();
    EXPECT_EQ(b[0], 1);
    EXPECT_EQ(b[1], 2);
    EXPECT_EQ(b[2], 3);
    EXPECT_EQ(b[3], 4);
}

TEST(Bytes, UnderflowLatches) {
    Bytes b = {0x00, 0x01};  // only two bytes
    ByteReader r(as_span(b));
    (void)r.u32();
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.u8(), 0);  // keeps failing, returns zero
    EXPECT_FALSE(r.ok());
    EXPECT_FALSE(r.done());
}

TEST(Bytes, ArrayAndLp16) {
    ByteWriter w;
    std::array<uint8_t, 4> a = {9, 8, 7, 6};
    w.array(a);
    w.lp16(as_span(std::string("hi")));
    Bytes b = w.take();

    ByteReader r(as_span(b));
    EXPECT_EQ(r.array<4>(), a);
    Bytes blob = r.lp16();
    EXPECT_EQ(std::string(blob.begin(), blob.end()), "hi");
    EXPECT_TRUE(r.done());
}

TEST(Bytes, RestReturnsRemaining) {
    Bytes b = {1, 2, 3, 4, 5};
    ByteReader r(as_span(b));
    EXPECT_EQ(r.u8(), 1);
    EXPECT_EQ(r.rest(), (Bytes{2, 3, 4, 5}));
    EXPECT_TRUE(r.done());
}

TEST(Bytes, ExhaustedVsFailed) {
    Bytes b = {7};
    ByteReader r(as_span(b));
    EXPECT_FALSE(r.exhausted());
    EXPECT_EQ(r.u8(), 7);
    EXPECT_TRUE(r.exhausted());
    EXPECT_TRUE(r.done());
}
