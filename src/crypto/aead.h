// Crypto primitives for the post-SPAKE2 channel, backed by OpenSSL:
// HKDF-SHA256 (key derivation), HMAC-SHA256 (key confirmation), and
// ChaCha20-Poly1305 (the AEAD that the WG pubkeys are exchanged inside).
#pragma once

#include <array>
#include <optional>

#include "common/bytes.h"

namespace spl::crypto {

Bytes hkdf_sha256(ByteSpan ikm, ByteSpan salt, ByteSpan info, size_t out_len);

std::array<uint8_t, 32> hmac_sha256(ByteSpan key, ByteSpan data);

// ChaCha20-Poly1305. `nonce` must be 12 bytes. seal returns ciphertext||tag(16);
// open returns the plaintext, or nullopt if authentication fails.
Bytes aead_seal(ByteSpan key32, ByteSpan nonce12, ByteSpan plaintext, ByteSpan aad);
std::optional<Bytes> aead_open(ByteSpan key32, ByteSpan nonce12, ByteSpan ciphertext, ByteSpan aad);

}  // namespace spl::crypto
