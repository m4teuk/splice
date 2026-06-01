// Monotonic millisecond clock used for TTLs, rate limiting and keepalives.
// Times are passed explicitly into the pure components so tests can inject them.
#pragma once

#include <chrono>
#include <cstdint>

namespace spl {

using Millis = int64_t;

inline Millis mono_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

}  // namespace spl
