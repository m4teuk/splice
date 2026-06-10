#include "peer/pathwatch.h"

#include <string>

#include "common/log.h"

namespace spl::peer {

namespace {

const PathStatus::Cand* find(const PathStatus& s, const Endpoint& ep) {
    for (const auto& c : s.cands)
        if (c.ep == ep) return &c;
    return nullptr;
}

}  // namespace

void PathWatch::render(const PathStatus& cur, Millis now) {
    if (!first_) {
        if (cur.external && (!prev_.external || !(*prev_.external == *cur.external)))
            spl::logf("[path] external address %s", cur.external->to_string().c_str());
        for (const auto& c : cur.cands) {
            const PathStatus::Cand* old = find(prev_, c.ep);
            if (!old)
                spl::logf("[path] candidate %s%s", c.ep.to_string().c_str(),
                          c.lan ? " (LAN)" : "");
            if (c.alive && (!old || !old->alive))
                spl::logf("[disco] <- PONG from %s: candidate now ALIVE (rtt %lldms)",
                          c.ep.to_string().c_str(), static_cast<long long>(c.rtt));
            if (c.in_use && (!old || !old->in_use))
                spl::logf("[path] direct via %s%s (~%lldms)", c.ep.to_string().c_str(),
                          c.lan ? " LAN" : "", static_cast<long long>(c.rtt));
        }
        if (prev_.direct_confirmed && !cur.direct_confirmed)
            spl::logf("[path] direct path lost");
        if (cur.active != prev_.active)
            spl::logf("[path] switched to %s", path_name(cur.active));
    }
    first_ = false;
    prev_ = cur;

    if (now - t_stats_ < 2000) return;
    t_stats_ = now;
    spl::logf("[stats] path=%s | tx: direct %s / relay %s | rx: direct %s / relay %s",
              path_name(cur.active), human_bytes(cur.tx_direct).c_str(),
              human_bytes(cur.tx_relay).c_str(), human_bytes(cur.rx_direct).c_str(),
              human_bytes(cur.rx_relay).c_str());
    spl::logf("[path] active=%s | our external=%s | %zu candidate(s):", path_name(cur.active),
              cur.external ? cur.external->to_string().c_str() : "(unknown)", cur.cands.size());
    for (const auto& c : cur.cands) {
        const std::string rtt = c.rtt ? std::to_string(static_cast<long long>(c.rtt)) + "ms" : "?";
        const std::string seen =
            c.reply_age >= 0 ? std::to_string(c.reply_age) + "ms ago" : "no reply yet";
        spl::logf("[path]   %s %s [%s] %s rtt=%s, last reply %s", c.in_use ? "USE->" : "     ",
                  c.ep.to_string().c_str(), c.lan ? "iface" : "ext ", c.alive ? "ALIVE" : "dead ",
                  rtt.c_str(), seen.c_str());
    }
}

}  // namespace spl::peer
