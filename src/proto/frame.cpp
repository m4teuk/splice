#include "proto/frame.h"

namespace spl::proto {

Bytes encode_frame(ByteSpan payload) {
    ByteWriter w;
    w.u32(static_cast<uint32_t>(payload.size()));
    w.raw(payload);
    return w.take();
}

std::optional<FrameParse> try_parse_frame(ByteSpan buf, bool* protocol_error) {
    if (protocol_error) *protocol_error = false;
    if (buf.size() < 4) return std::nullopt;  // need the length header

    ByteReader r(buf);
    const uint32_t len = r.u32();
    if (len > kMaxFrameLen) {
        if (protocol_error) *protocol_error = true;
        return std::nullopt;
    }
    if (buf.size() < 4u + len) return std::nullopt;  // payload not fully arrived

    FrameParse out;
    out.payload = r.take(len);
    out.consumed = 4u + len;
    return out;
}

}  // namespace spl::proto
