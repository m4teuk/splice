#include "server/code_alloc.h"

namespace spl::server {

CodeAllocator::CodeAllocator() : CodeAllocator(Config{}) {}

CodeAllocator::CodeAllocator(Config cfg) : cfg_(cfg), max_(cfg.initial_max) {}

void CodeAllocator::expire(Millis now) {
    for (auto it = active_.begin(); it != active_.end();) {
        if (it->second <= now) {
            cooldown_[it->first] = now + cfg_.cooldown_ms;
            it = active_.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = cooldown_.begin(); it != cooldown_.end();) {
        if (it->second <= now) {
            it = cooldown_.erase(it);
        } else {
            ++it;
        }
    }
}

std::optional<uint64_t> CodeAllocator::allocate(Millis now, Millis ttl_ms) {
    expire(now);
    for (;;) {
        for (uint64_t c = 0; c < static_cast<uint64_t>(max_); ++c) {
            if (active_.count(c) || cooldown_.count(c)) continue;
            active_[c] = now + ttl_ms;
            return c;
        }
        if (max_ >= cfg_.hard_max) return std::nullopt;
        long grown = static_cast<long>(max_) * 10;
        max_ = static_cast<int>(grown > cfg_.hard_max ? cfg_.hard_max : grown);
    }
}

bool CodeAllocator::active(uint64_t code, Millis now) const {
    auto it = active_.find(code);
    return it != active_.end() && it->second > now;
}

void CodeAllocator::release(uint64_t code, Millis now) {
    active_.erase(code);
    cooldown_[code] = now + cfg_.cooldown_ms;
}

}  // namespace spl::server
