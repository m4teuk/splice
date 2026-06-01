#include "server/rate_limit.h"

#include <algorithm>

namespace spl::server {

bool TokenBucket::allow(Millis now, double cost) {
    const double elapsed = static_cast<double>(now - last) / 1000.0;
    if (elapsed > 0) {
        tokens = std::min(burst, tokens + elapsed * rate);
        last = now;
    }
    if (tokens >= cost) {
        tokens -= cost;
        return true;
    }
    return false;
}

bool RateLimiter::allow(const std::array<uint8_t, 16>& ip, Millis now) {
    auto it = ip_.find(ip);
    if (it == ip_.end()) {
        it = ip_.emplace(ip, TokenBucket{ip_burst_, ip_rate_, ip_burst_, now}).first;
    }
    if (!it->second.allow(now)) return false;  // per-IP empty: charge nothing else
    return global_.allow(now);
}

void RateLimiter::evict_idle(Millis now, Millis idle_ms) {
    for (auto it = ip_.begin(); it != ip_.end();) {
        if (now - it->second.last > idle_ms) {
            it = ip_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace spl::server
