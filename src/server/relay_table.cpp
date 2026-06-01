#include "server/relay_table.h"

namespace spl::server {

proto::Uid RelayTable::peer_uid(proto::Uid uid) {
    uid[proto::kUidLen - 1] ^= 0x01;  // flip the side bit
    return uid;
}

std::optional<Endpoint> RelayTable::on_packet(const proto::Uid& uid, const Endpoint& src,
                                              Millis now) {
    map_[uid] = Entry{src, now};

    const proto::Uid peer = peer_uid(uid);
    auto it = map_.find(peer);
    if (it == map_.end()) return std::nullopt;
    if (now - it->second.last > ttl_ms_) return std::nullopt;  // stale
    return it->second.ep;
}

void RelayTable::evict_expired(Millis now) {
    for (auto it = map_.begin(); it != map_.end();) {
        if (now - it->second.last > ttl_ms_) {
            it = map_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace spl::server
