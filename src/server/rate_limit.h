// Token-bucket rate limiting for the UDP data plane: a per-source-IP bucket plus
// a global bucket. This is a cost-control safeguard, not a security boundary.
#pragma once

#include <array>
#include <cstdint>
#include <map>

#include "common/time.h"

namespace spl::server {

struct TokenBucket {
    double tokens;
    double rate;   // tokens per second
    double burst;  // max tokens
    Millis last;

    bool allow(Millis now, double cost = 1.0);
};

class RateLimiter {
 public:
    RateLimiter(double per_ip_rate, double per_ip_burst, double global_rate, double global_burst)
        : ip_rate_(per_ip_rate),
          ip_burst_(per_ip_burst),
          global_{global_burst, global_rate, global_burst, 0} {}

    // Charges one token to the source IP's bucket and one to the global bucket.
    // Returns false (and charges nothing further) if either is empty.
    bool allow(const std::array<uint8_t, 16>& ip, Millis now);

    // Drops per-IP buckets not touched within idle_ms, to bound memory.
    void evict_idle(Millis now, Millis idle_ms);
    size_t tracked_ips() const { return ip_.size(); }

 private:
    std::map<std::array<uint8_t, 16>, TokenBucket> ip_;
    TokenBucket global_;
    double ip_rate_;
    double ip_burst_;
};

}  // namespace spl::server
