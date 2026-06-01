// RAII wrapper over the Rust shim's symmetric SPAKE2 (native/src/lib.rs).
#pragma once

#include <optional>

#include "common/bytes.h"

namespace spl::crypto {

class Spake2 {
 public:
    // Starts a symmetric exchange with `password`; writes the outbound message
    // into *out_msg. Returns nullopt on error.
    static std::optional<Spake2> start(ByteSpan password, Bytes* out_msg);

    // Finishes with the peer's message; returns the shared key (or nullopt on a
    // malformed message). Consumes the state — do not call twice.
    std::optional<Bytes> finish(ByteSpan peer_msg);

    Spake2(Spake2&& o) noexcept : state_(o.state_) { o.state_ = nullptr; }
    Spake2& operator=(Spake2&& o) noexcept;
    Spake2(const Spake2&) = delete;
    ~Spake2();

 private:
    explicit Spake2(void* s) : state_(s) {}
    void* state_ = nullptr;
};

}  // namespace spl::crypto
