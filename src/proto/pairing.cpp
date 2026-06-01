#include "proto/pairing.h"

namespace spl::proto {

// ---- Layer 1: control ----

Bytes encode(const Init& m) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(CtrlType::kInit));
    w.u16(m.proto_version);
    return w.take();
}
Bytes encode(const Code& m) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(CtrlType::kCode));
    w.u64(m.code);
    w.u32(m.ttl_seconds);
    return w.take();
}
Bytes encode(const Join& m) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(CtrlType::kJoin));
    w.u64(m.code);
    return w.take();
}
Bytes encode(const Paired&) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(CtrlType::kPaired));
    return w.take();
}
Bytes encode(const Error& m) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(CtrlType::kError));
    w.u16(m.code);
    w.lp16(as_span(m.message));
    return w.take();
}
Bytes encode_ctrl(const CtrlMessage& m) {
    return std::visit([](const auto& v) { return encode(v); }, m);
}

std::optional<CtrlMessage> decode_ctrl(ByteSpan payload) {
    ByteReader r(payload);
    const uint8_t t = r.u8();
    if (!r.ok()) return std::nullopt;
    switch (static_cast<CtrlType>(t)) {
        case CtrlType::kInit: {
            Init m{};
            m.proto_version = r.u16();
            if (!r.done()) return std::nullopt;
            return CtrlMessage{m};
        }
        case CtrlType::kCode: {
            Code m{};
            m.code = r.u64();
            m.ttl_seconds = r.u32();
            if (!r.done()) return std::nullopt;
            return CtrlMessage{m};
        }
        case CtrlType::kJoin: {
            Join m{};
            m.code = r.u64();
            if (!r.done()) return std::nullopt;
            return CtrlMessage{m};
        }
        case CtrlType::kPaired: {
            if (!r.done()) return std::nullopt;
            return CtrlMessage{Paired{}};
        }
        case CtrlType::kError: {
            Error m{};
            m.code = r.u16();
            const Bytes s = r.lp16();
            if (!r.done()) return std::nullopt;
            m.message.assign(s.begin(), s.end());
            return CtrlMessage{m};
        }
    }
    return std::nullopt;
}

// ---- Layer 2: peer envelope ----

Bytes encode(const Spake2Msg& m) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(PeerType::kSpake2));
    w.raw(as_span(m.msg));
    return w.take();
}
Bytes encode(const KeyConfirm& m) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(PeerType::kKeyConfirm));
    w.array(m.mac);
    return w.take();
}
Bytes encode(const Sealed& m) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(PeerType::kSealed));
    w.raw(as_span(m.ciphertext));
    return w.take();
}
Bytes encode_peer(const PeerMessage& m) {
    return std::visit([](const auto& v) { return encode(v); }, m);
}

std::optional<PeerMessage> decode_peer(ByteSpan payload) {
    ByteReader r(payload);
    const uint8_t t = r.u8();
    if (!r.ok()) return std::nullopt;
    switch (static_cast<PeerType>(t)) {
        case PeerType::kSpake2: {
            Spake2Msg m{};
            m.msg = r.rest();
            if (!r.ok()) return std::nullopt;
            return PeerMessage{m};
        }
        case PeerType::kKeyConfirm: {
            KeyConfirm m{};
            m.mac = r.array<kMacLen>();
            if (!r.done()) return std::nullopt;
            return PeerMessage{m};
        }
        case PeerType::kSealed: {
            Sealed m{};
            m.ciphertext = r.rest();
            if (!r.ok()) return std::nullopt;
            return PeerMessage{m};
        }
    }
    return std::nullopt;
}

// ---- Layer 3: negotiation ----

Bytes encode(const Offer& m) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(NegType::kOffer));
    w.array(m.ula_base);
    w.u8(m.ula_prefix);
    w.array(m.uid);
    w.array(m.leader_pubkey);
    return w.take();
}
Bytes encode(const Reply& m) {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(NegType::kReply));
    w.u8(static_cast<uint8_t>(m.status));
    w.array(m.follower_pubkey);
    w.array(m.counter_ula_base);
    w.u8(m.counter_ula_prefix);
    return w.take();
}
Bytes encode_neg(const NegMessage& m) {
    return std::visit([](const auto& v) { return encode(v); }, m);
}

std::optional<NegMessage> decode_neg(ByteSpan plaintext) {
    ByteReader r(plaintext);
    const uint8_t t = r.u8();
    if (!r.ok()) return std::nullopt;
    switch (static_cast<NegType>(t)) {
        case NegType::kOffer: {
            Offer m{};
            m.ula_base = r.array<kIpLen>();
            m.ula_prefix = r.u8();
            m.uid = r.array<kUidLen>();
            m.leader_pubkey = r.array<kWgKeyLen>();
            if (!r.done()) return std::nullopt;
            return NegMessage{m};
        }
        case NegType::kReply: {
            Reply m{};
            const uint8_t st = r.u8();
            if (st > static_cast<uint8_t>(ReplyStatus::kAbort)) return std::nullopt;
            m.status = static_cast<ReplyStatus>(st);
            m.follower_pubkey = r.array<kWgKeyLen>();
            m.counter_ula_base = r.array<kIpLen>();
            m.counter_ula_prefix = r.u8();
            if (!r.done()) return std::nullopt;
            return NegMessage{m};
        }
    }
    return std::nullopt;
}

}  // namespace spl::proto
