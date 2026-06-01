#include "proto/relay.h"

namespace spl::proto {

std::optional<UdpType> peek_udp_type(ByteSpan pkt) {
    if (pkt.empty()) return std::nullopt;
    switch (static_cast<UdpType>(pkt[0])) {
        case UdpType::kRelay:
            return UdpType::kRelay;
        case UdpType::kWhereami:
            return UdpType::kWhereami;
    }
    return std::nullopt;
}

// ---- relay ----

Bytes encode_relay_up(const Uid& uid, ByteSpan wg_payload) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(UdpType::kRelay));
    w.array(uid);
    w.raw(wg_payload);
    return w.take();
}

std::optional<RelayUp> decode_relay_up(ByteSpan pkt) {
    ByteReader r(pkt);
    if (r.u8() != static_cast<uint8_t>(UdpType::kRelay)) return std::nullopt;
    RelayUp out;
    out.uid = r.array<kUidLen>();
    if (!r.ok()) return std::nullopt;
    out.payload = r.rest();
    return out;
}

Bytes encode_relay_down(ByteSpan wg_payload) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(UdpType::kRelay));
    w.raw(wg_payload);
    return w.take();
}

std::optional<Bytes> decode_relay_down(ByteSpan pkt) {
    ByteReader r(pkt);
    if (r.u8() != static_cast<uint8_t>(UdpType::kRelay)) return std::nullopt;
    return r.rest();
}

// ---- whereami ----

Bytes encode_whereami_req(uint32_t token) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(UdpType::kWhereami));
    w.u32(token);
    return w.take();
}

std::optional<uint32_t> decode_whereami_req(ByteSpan pkt) {
    ByteReader r(pkt);
    if (r.u8() != static_cast<uint8_t>(UdpType::kWhereami)) return std::nullopt;
    const uint32_t token = r.u32();
    if (!r.done()) return std::nullopt;
    return token;
}

Bytes encode_whereami_reply(const WhereamiReply& m) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(UdpType::kWhereami));
    w.u32(m.token);
    w.array(m.ip);
    w.u16(m.port);
    return w.take();
}

std::optional<WhereamiReply> decode_whereami_reply(ByteSpan pkt) {
    ByteReader r(pkt);
    if (r.u8() != static_cast<uint8_t>(UdpType::kWhereami)) return std::nullopt;
    WhereamiReply m{};
    m.token = r.u32();
    m.ip = r.array<kIpLen>();
    m.port = r.u16();
    if (!r.done()) return std::nullopt;
    return m;
}

}  // namespace spl::proto
