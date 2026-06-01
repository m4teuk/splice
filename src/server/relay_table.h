// The relay's address table: maps a 256-bit session uid to the last source
// address seen for it, and forwards to the peer found by flipping the uid's low
// (side) bit. Idle entries expire so the server holds no long-lived state.
#pragma once

#include <map>
#include <optional>

#include "common/time.h"
#include "net/endpoint.h"
#include "proto/pairing.h"  // proto::Uid

namespace spl::server {

class RelayTable {
 public:
    explicit RelayTable(Millis ttl_ms) : ttl_ms_(ttl_ms) {}

    // Records that `uid` was just seen at `src`, then returns the peer endpoint
    // to forward this packet to — i.e. the address of `peer_uid(uid)` if it is
    // known and not expired. Returns nullopt (drop) if the peer is unknown/stale.
    std::optional<Endpoint> on_packet(const proto::Uid& uid, const Endpoint& src, Millis now);

    void evict_expired(Millis now);
    size_t size() const { return map_.size(); }

    // The peer's uid is this uid with its low (side) bit flipped.
    static proto::Uid peer_uid(proto::Uid uid);

 private:
    struct Entry {
        Endpoint ep;
        Millis last;
    };
    std::map<proto::Uid, Entry> map_;
    Millis ttl_ms_;
};

}  // namespace spl::server
