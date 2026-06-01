// Standard base64 (RFC 4648). Header-only; used for storing/printing key material.
#pragma once

#include <optional>
#include <string>

#include "common/bytes.h"

namespace spl {

inline std::string base64_encode(ByteSpan in) {
    static constexpr char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        uint32_t n = (uint32_t(in[i]) << 16) | (uint32_t(in[i + 1]) << 8) | in[i + 2];
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];
        out += T[n & 63];
    }
    const size_t rem = in.size() - i;
    if (rem == 1) {
        uint32_t n = uint32_t(in[i]) << 16;
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (uint32_t(in[i]) << 16) | (uint32_t(in[i + 1]) << 8);
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];
        out += "=";
    }
    return out;
}

inline std::optional<Bytes> base64_decode(const std::string& s) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    Bytes out;
    int buf = 0, bits = 0;
    for (char c : s) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int v = val(c);
        if (v < 0) return std::nullopt;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xff));
        }
    }
    return out;
}

}  // namespace spl
