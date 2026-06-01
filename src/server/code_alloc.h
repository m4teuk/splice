// Allocates short human-friendly pairing codes (smallest free integer first),
// each with a TTL, and holds freed codes in a brief cooldown before reuse so a
// late follower can't land on a recycled code. The pool starts tiny (<10) and
// grows by orders of magnitude only when exhausted.
#pragma once

#include <cstdint>
#include <map>
#include <optional>

#include "common/time.h"

namespace spl::server {

class CodeAllocator {
 public:
    struct Config {
        int initial_max = 10;          // first pool: codes [0, 10)
        int hard_max = 1'000'000;      // grow up to 6 digits, then give up
        Millis cooldown_ms = 3'000;    // reuse buffer after a code is freed
    };

    CodeAllocator();  // uses default Config
    explicit CodeAllocator(Config cfg);

    // Allocates the smallest free code valid for ttl_ms; grows the pool if full;
    // nullopt only if the hard cap is also exhausted.
    std::optional<uint64_t> allocate(Millis now, Millis ttl_ms);

    bool active(uint64_t code, Millis now) const;
    void release(uint64_t code, Millis now);  // move to cooldown
    void expire(Millis now);                  // expire stale actives + clear old cooldowns

    size_t active_count() const { return active_.size(); }
    int pool_max() const { return max_; }

 private:
    Config cfg_;
    int max_;
    std::map<uint64_t, Millis> active_;    // code -> expiry time
    std::map<uint64_t, Millis> cooldown_;  // code -> available-after time
};

}  // namespace spl::server
