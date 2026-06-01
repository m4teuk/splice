// Length-prefixed framing for the TCP pairing channel: [u32 length][payload].
//
// Both the server control messages (INIT/CODE/JOIN/PAIRED/ERR) and the
// peer-to-peer pairing messages (SPAKE2 / key-confirm / sealed negotiation) are
// carried as frame payloads. The server parses frames only until PAIRED, after
// which it relays raw bytes; the peers keep using the same framing underneath.
#pragma once

#include <cstdint>
#include <optional>

#include "common/bytes.h"

namespace spl::proto {

// Upper bound on a single frame payload. Pairing/negotiation frames are tiny
// (tens of bytes); this cap just bounds memory against a hostile/garbled stream.
inline constexpr uint32_t kMaxFrameLen = 64 * 1024;

// Encodes payload as [u32 length][payload].
Bytes encode_frame(ByteSpan payload);

struct FrameParse {
    Bytes payload;
    size_t consumed;  // total bytes consumed from the input (header + payload)
};

// Attempts to parse one frame from the front of `buf`.
//   * returns the frame and bytes consumed if a complete frame is present;
//   * returns nullopt if more bytes are needed (incomplete header/payload);
//   * returns nullopt AND sets *protocol_error=true if the declared length
//     exceeds kMaxFrameLen (caller should drop the connection).
std::optional<FrameParse> try_parse_frame(ByteSpan buf, bool* protocol_error);

}  // namespace spl::proto
