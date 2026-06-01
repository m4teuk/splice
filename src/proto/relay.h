// UDP codecs for the relay + whereami protocols (the server's data plane).
//
// All peer<->server packets carry a 1-byte type tag. Direct peer<->peer packets
// are raw WireGuard (no tag) and are demuxed by source address (!= server).
//
//   relay   upstream (peer->server):   0x01 | uid[32] | wg_payload
//           downstream (server->peer): 0x01 | wg_payload
//   whereami request  (peer->server):  0x02 | token[4]
//           reply     (server->peer):  0x02 | token[4] | ip[16] | port[2]
//
// The server forwards a relay packet to the peer found by flipping the low
// (side) bit of `uid`, updating the sender's address as it goes.
#pragma once

#include <cstdint>
#include <optional>

#include "common/bytes.h"
#include "proto/pairing.h"  // Uid, Ip6

namespace spl::proto {

enum class UdpType : uint8_t {
    kRelay = 0x01,
    kWhereami = 0x02,
};

// First-byte demux for an incoming UDP packet (nullopt if empty/unknown).
std::optional<UdpType> peek_udp_type(ByteSpan pkt);

// ---- relay ----

Bytes encode_relay_up(const Uid& uid, ByteSpan wg_payload);
struct RelayUp {
    Uid uid;
    Bytes payload;  // may be empty (registration keepalive)
};
std::optional<RelayUp> decode_relay_up(ByteSpan pkt);

Bytes encode_relay_down(ByteSpan wg_payload);
// Returns the wg_payload (the bytes after the 0x01 tag), or nullopt if malformed.
std::optional<Bytes> decode_relay_down(ByteSpan pkt);

// ---- whereami ----

Bytes encode_whereami_req(uint32_t token);
std::optional<uint32_t> decode_whereami_req(ByteSpan pkt);

struct WhereamiReply {
    uint32_t token;
    Ip6 ip;        // IPv4-mapped (::ffff:a.b.c.d) for v4 sources
    uint16_t port;
};
Bytes encode_whereami_reply(const WhereamiReply&);
std::optional<WhereamiReply> decode_whereami_reply(ByteSpan pkt);

}  // namespace spl::proto
