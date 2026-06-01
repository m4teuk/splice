#include <gtest/gtest.h>

#include "common/base64.h"
#include "crypto/aead.h"

using namespace spl;
using namespace spl::crypto;

TEST(Hkdf, DeterministicAndLength) {
    Bytes ikm = {1, 2, 3, 4};
    Bytes salt = {9, 9};
    Bytes info = {7};
    Bytes a = hkdf_sha256(as_span(ikm), as_span(salt), as_span(info), 32);
    Bytes b = hkdf_sha256(as_span(ikm), as_span(salt), as_span(info), 32);
    EXPECT_EQ(a.size(), 32u);
    EXPECT_EQ(a, b);
    Bytes c = hkdf_sha256(as_span(ikm), as_span(salt), as_span(Bytes{8}), 32);
    EXPECT_NE(a, c);  // different info -> different key
}

TEST(Hmac, DeterministicAndKeySensitive) {
    Bytes k1 = {1, 2, 3};
    Bytes k2 = {1, 2, 4};
    Bytes data = {5, 6, 7, 8};
    auto a = hmac_sha256(as_span(k1), as_span(data));
    auto b = hmac_sha256(as_span(k1), as_span(data));
    auto c = hmac_sha256(as_span(k2), as_span(data));
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(Aead, SealOpenRoundTrip) {
    Bytes key(32, 0x11);
    Bytes nonce(12, 0x22);
    Bytes pt = {'h', 'e', 'l', 'l', 'o'};
    Bytes aad = {0xAA, 0xBB};
    Bytes ct = aead_seal(as_span(key), as_span(nonce), as_span(pt), as_span(aad));
    EXPECT_EQ(ct.size(), pt.size() + 16);
    auto out = aead_open(as_span(key), as_span(nonce), as_span(ct), as_span(aad));
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, pt);
}

TEST(Aead, RejectsTamperingAndWrongKey) {
    Bytes key(32, 0x11);
    Bytes nonce(12, 0x22);
    Bytes pt = {1, 2, 3, 4};
    Bytes ct = aead_seal(as_span(key), as_span(nonce), as_span(pt), {});

    Bytes tampered = ct;
    tampered[0] ^= 0x01;
    EXPECT_FALSE(aead_open(as_span(key), as_span(nonce), as_span(tampered), {}).has_value());

    Bytes wrong_key(32, 0x33);
    EXPECT_FALSE(aead_open(as_span(wrong_key), as_span(nonce), as_span(ct), {}).has_value());

    Bytes wrong_aad = {0x01};
    EXPECT_FALSE(aead_open(as_span(key), as_span(nonce), as_span(ct), as_span(wrong_aad)).has_value());
}

TEST(Base64, RoundTrip) {
    for (Bytes in : {Bytes{}, Bytes{0}, Bytes{1, 2}, Bytes{1, 2, 3}, Bytes{0xde, 0xad, 0xbe, 0xef}}) {
        auto dec = base64_decode(base64_encode(as_span(in)));
        ASSERT_TRUE(dec.has_value());
        EXPECT_EQ(*dec, in);
    }
}
