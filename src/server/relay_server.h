// UDP data plane: relays opaque WireGuard payloads between the two sides of a
// uid, answers whereami, and rate-limits. Holds only short-lived address state.
#pragma once

#include <atomic>
#include <cstdint>
#include <map>

#include "common/time.h"
#include "net/socket.h"
#include "proto/pairing.h"
#include "server/rate_limit.h"
#include "server/relay_table.h"

namespace spl::server {

struct RelayConfig {
    Millis entry_ttl_ms = 120'000;  // idle uid->addr eviction (~2 min)
    double per_ip_rate = 500;       // packets/sec/IP (token bucket)
    double per_ip_burst = 1000;
    double global_rate = 100'000;
    double global_burst = 200'000;
    bool verbose = false;
};

class RelayServer {
 public:
    RelayServer(net::Fd udp, RelayConfig cfg);
    void run(std::atomic<bool>& stop);  // blocks until stop

 private:
    net::Fd udp_;
    RelayConfig cfg_;
    RelayTable table_;
    RateLimiter limiter_;

    // verbose stats
    uint64_t stat_pkts_ = 0, stat_bytes_ = 0, stat_dropped_ = 0, stat_whereami_ = 0;
    std::map<proto::Uid, uint64_t> flow_;  // bytes relayed per uid, current interval
    Millis t_stats_ = 0;
};

}  // namespace spl::server
