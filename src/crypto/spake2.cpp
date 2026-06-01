#include "crypto/spake2.h"

#include "native/native.h"

namespace spl::crypto {

std::optional<Spake2> Spake2::start(ByteSpan password, Bytes* out_msg) {
    uint8_t buf[64];
    size_t len = 0;
    void* st = spl_spake2_start(password.data(), password.size(), buf, sizeof(buf), &len);
    if (!st) return std::nullopt;
    out_msg->assign(buf, buf + len);
    return Spake2(st);
}

std::optional<Bytes> Spake2::finish(ByteSpan peer_msg) {
    if (!state_) return std::nullopt;
    uint8_t key[64];
    size_t klen = 0;
    int rc = spl_spake2_finish(state_, peer_msg.data(), peer_msg.size(), key, sizeof(key), &klen);
    state_ = nullptr;  // finish consumes/frees the state in Rust
    if (rc != 0) return std::nullopt;
    return Bytes(key, key + klen);
}

Spake2::~Spake2() {
    if (state_) spl_spake2_free(state_);
}

Spake2& Spake2::operator=(Spake2&& o) noexcept {
    if (this != &o) {
        if (state_) spl_spake2_free(state_);
        state_ = o.state_;
        o.state_ = nullptr;
    }
    return *this;
}

}  // namespace spl::crypto
