// Big-endian (network order) byte cursor utilities used by all wire codecs.
//
// ByteWriter appends; ByteReader consumes with bounds checking. A ByteReader
// never reads out of bounds: on underflow it latches a failure flag and returns
// zeroed values, so decoders can run a sequence of reads and check ok() once at
// the end.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace spl {

using Bytes = std::vector<uint8_t>;
using ByteSpan = std::span<const uint8_t>;

inline ByteSpan as_span(const Bytes& b) { return ByteSpan(b.data(), b.size()); }
inline ByteSpan as_span(const std::string& s) {
    return ByteSpan(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
template <size_t N>
inline ByteSpan as_span(const std::array<uint8_t, N>& a) {
    return ByteSpan(a.data(), a.size());
}

class ByteWriter {
 public:
    void u8(uint8_t v) { buf_.push_back(v); }
    void u16(uint16_t v) {
        buf_.push_back(static_cast<uint8_t>(v >> 8));
        buf_.push_back(static_cast<uint8_t>(v));
    }
    void u32(uint32_t v) {
        for (int s = 24; s >= 0; s -= 8) buf_.push_back(static_cast<uint8_t>(v >> s));
    }
    void u64(uint64_t v) {
        for (int s = 56; s >= 0; s -= 8) buf_.push_back(static_cast<uint8_t>(v >> s));
    }
    void raw(ByteSpan b) { buf_.insert(buf_.end(), b.begin(), b.end()); }
    template <size_t N>
    void array(const std::array<uint8_t, N>& a) {
        buf_.insert(buf_.end(), a.begin(), a.end());
    }
    // Length-prefixed (u16) blob: [u16 len][bytes].
    void lp16(ByteSpan b) {
        u16(static_cast<uint16_t>(b.size()));
        raw(b);
    }

    const Bytes& data() const { return buf_; }
    Bytes take() { return std::move(buf_); }
    size_t size() const { return buf_.size(); }

 private:
    Bytes buf_;
};

class ByteReader {
 public:
    explicit ByteReader(ByteSpan b) : buf_(b) {}

    uint8_t u8() {
        if (remaining() < 1) return fail0();
        return buf_[pos_++];
    }
    uint16_t u16() {
        if (remaining() < 2) return fail0();
        uint16_t v = (static_cast<uint16_t>(buf_[pos_]) << 8) | buf_[pos_ + 1];
        pos_ += 2;
        return v;
    }
    uint32_t u32() {
        if (remaining() < 4) return fail0();
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | buf_[pos_ + i];
        pos_ += 4;
        return v;
    }
    uint64_t u64() {
        if (remaining() < 8) return fail0();
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | buf_[pos_ + i];
        pos_ += 8;
        return v;
    }
    // Reads exactly n bytes; on underflow fails and returns empty.
    Bytes take(size_t n) {
        if (remaining() < n) {
            failed_ = true;
            return {};
        }
        Bytes out(buf_.begin() + pos_, buf_.begin() + pos_ + n);
        pos_ += n;
        return out;
    }
    template <size_t N>
    std::array<uint8_t, N> array() {
        std::array<uint8_t, N> a{};
        if (remaining() < N) {
            failed_ = true;
            return a;
        }
        std::memcpy(a.data(), buf_.data() + pos_, N);
        pos_ += N;
        return a;
    }
    // Length-prefixed (u16) blob.
    Bytes lp16() {
        uint16_t n = u16();
        return take(n);
    }
    // Remaining bytes (the rest of the buffer).
    Bytes rest() { return take(remaining()); }

    size_t remaining() const { return failed_ ? 0 : buf_.size() - pos_; }
    bool ok() const { return !failed_; }
    bool exhausted() const { return !failed_ && pos_ == buf_.size(); }
    // True iff every read so far succeeded and the whole input was consumed.
    bool done() const { return ok() && exhausted(); }
    void fail() { failed_ = true; }

 private:
    uint8_t fail0() {
        failed_ = true;
        return 0;
    }
    ByteSpan buf_;
    size_t pos_ = 0;
    bool failed_ = false;
};

}  // namespace spl
