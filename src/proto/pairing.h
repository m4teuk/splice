// Pairing-channel message codecs (carried as frame payloads, see frame.h).
//
// Three layers travel over the TCP+TLS rendezvous bridge:
//   1. Control (peer <-> server): INIT / CODE / JOIN / PAIRED / ERR. The server
//      consumes these until it bridges the two peers.
//   2. Peer envelope (peer <-> peer, relayed opaquely by the server):
//      SPAKE2 message, key-confirmation MAC, and AEAD-sealed blobs.
//   3. Negotiation (peer <-> peer, the plaintext sealed inside #2): the leader's
//      Offer (ULA subnet + session uid + WG pubkey) and the follower's Reply.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>

#include "common/bytes.h"

namespace spl::proto {

inline constexpr size_t kUidLen = 32;    // 256 bits; low bit encodes the side
inline constexpr size_t kWgKeyLen = 32;  // X25519 public key
inline constexpr size_t kMacLen = 32;    // HMAC-SHA256 key-confirmation tag
inline constexpr size_t kIpLen = 16;     // IPv6 address bytes

using Uid = std::array<uint8_t, kUidLen>;
using WgKey = std::array<uint8_t, kWgKeyLen>;
using Mac = std::array<uint8_t, kMacLen>;
using Ip6 = std::array<uint8_t, kIpLen>;

// ---- Layer 1: control (peer <-> server) ----

enum class CtrlType : uint8_t {
    kInit = 0x01,    // peer -> server: request a pairing code
    kCode = 0x02,    // server -> peer: assigned code + TTL
    kJoin = 0x03,    // peer -> server: present a code
    kPaired = 0x04,  // server -> both: both present, begin peer exchange
    kError = 0x05,   // server -> peer: error
};

struct Init {
    uint16_t proto_version;
};
struct Code {
    uint64_t code;
    uint32_t ttl_seconds;
};
struct Join {
    uint64_t code;
};
struct Paired {};
struct Error {
    uint16_t code;
    std::string message;
};

using CtrlMessage = std::variant<Init, Code, Join, Paired, Error>;

Bytes encode(const Init&);
Bytes encode(const Code&);
Bytes encode(const Join&);
Bytes encode(const Paired&);
Bytes encode(const Error&);
Bytes encode_ctrl(const CtrlMessage&);
std::optional<CtrlMessage> decode_ctrl(ByteSpan payload);

// ---- Layer 2: peer envelope (relayed opaquely by the server) ----

enum class PeerType : uint8_t {
    kSpake2 = 0x10,      // a SPAKE2 message (symmetric mode: each side sends one)
    kKeyConfirm = 0x11,  // HMAC over the SPAKE2 transcript
    kSealed = 0x12,      // AEAD-sealed negotiation blob (nonce is an implicit counter)
};

struct Spake2Msg {
    Bytes msg;
};
struct KeyConfirm {
    Mac mac;
};
struct Sealed {
    Bytes ciphertext;  // AEAD ciphertext including the auth tag
};

using PeerMessage = std::variant<Spake2Msg, KeyConfirm, Sealed>;

Bytes encode(const Spake2Msg&);
Bytes encode(const KeyConfirm&);
Bytes encode(const Sealed&);
Bytes encode_peer(const PeerMessage&);
std::optional<PeerMessage> decode_peer(ByteSpan payload);

// ---- Layer 3: negotiation (plaintext sealed inside a Sealed envelope) ----

enum class NegType : uint8_t {
    kOffer = 0x01,
    kReply = 0x02,
};

enum class ReplyStatus : uint8_t {
    kAccept = 0,    // follower accepts; follower_pubkey is valid
    kRejectIp = 1,  // ULA collision (rare); counter_ula is valid, leader retries
    kAbort = 2,     // follower declined entirely
};

// Leader -> follower: proposes the whole connection in one shot. ULA makes IP
// collisions astronomically unlikely, so this is normally a single round-trip.
struct Offer {
    Ip6 ula_base;       // /prefix network base, host bits zero
    uint8_t ula_prefix;  // e.g. 64
    Uid uid;             // low bit = side; leader holds the bit clear, follower set
    WgKey leader_pubkey;
};

// Follower -> leader: accept (with its WG pubkey) or counter/abort.
struct Reply {
    ReplyStatus status;
    WgKey follower_pubkey;     // valid iff status == kAccept
    Ip6 counter_ula_base;      // valid iff status == kRejectIp
    uint8_t counter_ula_prefix;
};

using NegMessage = std::variant<Offer, Reply>;

Bytes encode(const Offer&);
Bytes encode(const Reply&);
Bytes encode_neg(const NegMessage&);
std::optional<NegMessage> decode_neg(ByteSpan plaintext);

}  // namespace spl::proto
