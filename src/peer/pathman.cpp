#include "peer/pathman.h"

#include <poll.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "common/bytes.h"
#include "common/log.h"
#include "native/native.h"
#include "proto/relay.h"

namespace spl::peer {

namespace {

constexpr uint8_t CH_WG = 0x00;
constexpr uint8_t CH_DISCO = 0x01;
constexpr uint8_t DISCO_CALLME = 0x01;
constexpr uint8_t DISCO_PING = 0x02;
constexpr uint8_t DISCO_PONG = 0x03;

constexpr Millis kTickMs = 250;
constexpr Millis kRegisterMs = 4000;
constexpr Millis kWhereamiMs = 1000;
constexpr Millis kCallmeMs = 1000;
constexpr Millis kPingProbeMs = 300;       // probe rate while no direct path is up (recover fast)
constexpr Millis kPingKeepaliveMs = 1000;  // probe rate once a direct path is established
constexpr Millis kDirectDeadMs = 3000;

constexpr size_t kMaxAdvertise = 8;  // LAN candidates we put in one CALLME
constexpr size_t kMaxCands = 16;     // direct-path candidates we track at once

void send_to(int fd, const Endpoint& ep, ByteSpan d) {
    sockaddr_storage ss{};
    socklen_t len = 0;
    sockaddr_from_endpoint(ep, &ss, &len);
    ::sendto(fd, d.data(), d.size(), 0, reinterpret_cast<sockaddr*>(&ss), len);
}

Bytes build_inner(uint8_t ch, ByteSpan body) {
    Bytes b;
    b.reserve(1 + body.size());
    b.push_back(ch);
    b.insert(b.end(), body.begin(), body.end());
    return b;
}

// CALLME = [type][external ip:16][external port:2][count:1] then `count` LAN
// candidates, each [ip:16][port:2]. The external address (first) is what the peer
// compares against its own to detect a shared NAT; the LAN list is what it then
// probes. Old/truncated encodings (no count) decode as zero LAN candidates.
Bytes build_callme(const Endpoint& ext, const std::vector<Endpoint>& locals) {
    ByteWriter w;
    w.u8(DISCO_CALLME);
    w.array(ext.ip);
    w.u16(ext.port);
    const uint8_t n = static_cast<uint8_t>(std::min(locals.size(), kMaxAdvertise));
    w.u8(n);
    for (uint8_t i = 0; i < n; ++i) {
        w.array(locals[i].ip);
        w.u16(locals[i].port);
    }
    return w.take();
}
Bytes build_ping(uint64_t tx) {
    ByteWriter w;
    w.u8(DISCO_PING);
    w.u64(tx);
    return w.take();
}
Bytes build_pong(uint64_t tx) {
    ByteWriter w;
    w.u8(DISCO_PONG);
    w.u64(tx);
    return w.take();
}

}  // namespace

const char* path_name(Path p) { return p == Path::Direct ? "DIRECT" : "RELAY"; }

PathManager::PathManager(net::Fd udp, PathConfig cfg)
    : udp_(std::move(udp)),
      cfg_(cfg),
      wg_(WgTunnel::create(cfg.own_priv, cfg.peer_pub, 1)) {
    if (const char* l = std::getenv("SPL_LOSS")) {
        loss_ = std::atof(l);
        if (!(loss_ > 0.0)) loss_ = 0.0;  // NaN / negative / garbage -> disabled
        if (loss_ > 1.0) loss_ = 1.0;
    }
    spl_random_bytes(reinterpret_cast<uint8_t*>(&rng_), sizeof(rng_));

    // Enumerate our own LAN addresses once. We reach peers from a single socket,
    // so a peer on the same network reaches us at <interface ip>:<our local port>.
    const uint16_t lp = net::local_port(udp_.get());
    local_eps_ = net::local_interface_endpoints(lp);
    if (cfg_.verbose && !local_eps_.empty()) {
        std::string s;
        for (const auto& e : local_eps_) s += " " + e.to_string();
        spl::logf("[path] advertising %zu local iface candidate(s) on port %u:%s",
                  local_eps_.size(), lp, s.c_str());
    }
}

void PathManager::emit_udp(const Endpoint& ep, ByteSpan data) {
    if (loss_ > 0.0) {
        rng_ = rng_ * 6364136223846793005ull + 1442695040888963407ull;  // LCG
        if (static_cast<double>(rng_ >> 32) / 4294967296.0 < loss_) return;  // drop
    }
    send_to(udp_.get(), ep, data);
}

void PathManager::send_payload(Path path, const Endpoint* direct_to, ByteSpan payload) {
    if (path == Path::Relay) {
        tx_relay_ += payload.size();
        Bytes pkt = proto::encode_relay_up(cfg_.uid, payload);
        emit_udp(cfg_.server, as_span(pkt));
    } else if (direct_to) {
        tx_direct_ += payload.size();
        emit_udp(*direct_to, payload);
    }
}

void PathManager::send_wg(ByteSpan wg) {
    Bytes payload = build_inner(CH_WG, wg);
    if (!force_relay_ && tx_path_ == Path::Direct && chosen_) {
        send_payload(Path::Direct, &*chosen_, as_span(payload));
    } else {
        send_payload(Path::Relay, nullptr, as_span(payload));
    }
}

void PathManager::send_register() {
    Bytes pkt = proto::encode_relay_up(cfg_.uid, {});  // empty payload = registration
    emit_udp(cfg_.server, as_span(pkt));
}

bool PathManager::send_inner(ByteSpan ip_packet) {
    WgResult r = wg_.encapsulate(ip_packet);
    if (r.op == WgOp::WriteToNetwork) send_wg(as_span(r.data));
    return r.op != WgOp::Err;
}

void PathManager::pump_wg(WgResult r, Path via, const Endpoint* from, Millis now) {
    while (r.op == WgOp::WriteToNetwork) {
        send_wg(as_span(r.data));
        r = wg_.decapsulate({});
    }
    if (r.op == WgOp::WriteToTunnel) {
        // Real decrypted data is authenticated, so it is a trustworthy liveness
        // signal (and may reveal a NAT rebind from a new address).
        if (via == Path::Direct && from) touch_cand(*from, now);
        if (on_inner) on_inner(as_span(r.data), via);
    }
}

void PathManager::handle_wg(ByteSpan body, Path via, const Endpoint* from, Millis now) {
    pump_wg(wg_.decapsulate(body), via, from, now);
}

void PathManager::handle_disco(ByteSpan body, Path via, const Endpoint* from, Millis now) {
    ByteReader r(body);
    const uint8_t dt = r.u8();
    if (!r.ok()) return;
    if (dt == DISCO_CALLME) {
        if (via != Path::Relay) return;  // candidates are advertised over the relay only
        Endpoint ext{r.array<16>(), r.u16()};
        if (!r.ok()) return;
        add_cand(ext, /*lan=*/false);
        // Adopt every interface address the peer advertised, regardless of whether we
        // share a NAT: a same-LAN address is reachable directly, an overlay address
        // (e.g. Tailscale) is reachable if we share that overlay, and an unreachable
        // one simply never goes alive. RTT selection then picks the best reachable
        // path — no address range is special-cased.
        const uint8_t n = r.u8();  // absent in a truncated/old CALLME -> !r.ok() -> no locals
        std::string adv;
        for (uint8_t i = 0; r.ok() && i < n; ++i) {
            Endpoint le{r.array<16>(), r.u16()};
            if (!r.ok()) break;
            add_cand(le, /*lan=*/true);
            adv += " " + le.to_string();
        }
        if (cfg_.verbose)
            spl::logf("[disco] <- CALLME: peer external %s, %u iface addr(s):%s",
                      ext.to_string().c_str(), n, adv.empty() ? " (none)" : adv.c_str());
    } else if (dt == DISCO_PING) {
        const uint64_t tx = r.u64();
        if (!r.ok() || !from) return;
        Bytes pong = build_inner(CH_DISCO, as_span(build_pong(tx)));
        send_payload(Path::Direct, from, as_span(pong));
    } else if (dt == DISCO_PONG) {
        const uint64_t tx = r.u64();
        // Mark a candidate alive only if the PONG echoes our latest PING token and
        // comes from a candidate we are actually probing — a sprayed packet from an
        // unknown source can neither add itself nor keep the direct path alive.
        if (!r.ok() || tx != ping_txid_ || !from) return;
        if (DirectCand* c = find_cand(*from)) {
            const bool was_alive = c->last_rx && now - c->last_rx < kDirectDeadMs;
            c->last_rx = now;
            Millis rtt = now - t_ping_;  // this token went out at t_ping_
            if (rtt < 1) rtt = 1;
            c->srtt = c->srtt ? (c->srtt * 3 + rtt) / 4 : rtt;  // EWMA toward the latest sample
            if (cfg_.verbose && !was_alive)
                spl::logf("[disco] <- PONG from %s: candidate now ALIVE (rtt %lldms)",
                          from->to_string().c_str(), static_cast<long long>(rtt));
        }
    }
}

void PathManager::dispatch_inner(ByteSpan inner, Path via, const Endpoint* from, Millis now) {
    if (inner.empty()) return;
    const uint8_t ch = inner[0];
    ByteSpan body = inner.subspan(1);
    if (ch == CH_WG) {
        handle_wg(body, via, from, now);
    } else if (ch == CH_DISCO) {
        handle_disco(body, via, from, now);
    }
}

void PathManager::process(const Endpoint& src, ByteSpan raw, Millis now) {
    if (force_relay_ && !(src == cfg_.server)) return;  // pretend the direct path is gone
    (src == cfg_.server ? rx_relay_ : rx_direct_) += raw.size();
    if (src == cfg_.server) {
        auto t = proto::peek_udp_type(raw);
        if (t == proto::UdpType::kWhereami) {
            auto rep = proto::decode_whereami_reply(raw);
            if (rep && rep->token == whereami_token_) {
                Endpoint e{rep->ip, rep->port};
                if (!external_ || *external_ != e) {
                    external_ = e;
                    if (cfg_.verbose) spl::logf("[path] external address %s", e.to_string().c_str());
                }
            }
        } else if (t == proto::UdpType::kRelay) {
            auto inner = proto::decode_relay_down(raw);
            if (inner) dispatch_inner(as_span(*inner), Path::Relay, nullptr, now);
        }
    } else {
        dispatch_inner(raw, Path::Direct, &src, now);
    }
}

void PathManager::update_tx_path(Millis now) {
    choose_direct(now);
    const Path want = (!force_relay_ && direct_confirmed_) ? Path::Direct : Path::Relay;
    if (want != tx_path_) {
        tx_path_ = want;
        if (cfg_.verbose) spl::logf("[path] switched to %s", path_name(want));
    }
}

PathManager::DirectCand* PathManager::find_cand(const Endpoint& ep) {
    for (auto& c : cands_)
        if (c.ep == ep) return &c;
    return nullptr;
}

void PathManager::add_cand(const Endpoint& ep, bool lan) {
    if (!ep.valid()) return;
    if (DirectCand* c = find_cand(ep)) {
        if (lan) c->lan = true;  // a candidate can be both reported and LAN-reachable
        return;
    }
    if (cands_.size() >= kMaxCands) return;
    cands_.push_back({ep, lan, 0});
    if (cfg_.verbose)
        spl::logf("[path] candidate %s%s", ep.to_string().c_str(), lan ? " (LAN)" : "");
}

void PathManager::touch_cand(const Endpoint& from, Millis now) {
    if (DirectCand* c = find_cand(from)) {
        c->last_rx = now;
        return;
    }
    if (cands_.size() >= kMaxCands) return;
    cands_.push_back({from, false, now});  // learned from traffic (e.g. a NAT rebind)
}

// Pick the active direct path: the lowest-RTT *alive* candidate, with hysteresis so
// we converge on the fastest path instead of flapping. No address range is
// special-cased — RTT decides, so a real LAN address naturally beats a Tailscale or
// other overlay hop (which has a higher round-trip), without a blacklist.
void PathManager::choose_direct(Millis now) {
    auto alive = [&](const DirectCand& c) { return c.last_rx && now - c.last_rx < kDirectDeadMs; };
    auto score = [](const DirectCand& c) -> Millis { return c.srtt ? c.srtt : 1'000'000; };

    const DirectCand* best = nullptr;
    for (const auto& c : cands_)
        if (alive(c) && (!best || score(c) < score(*best))) best = &c;

    // Stick with the current path while it stays alive and is within ~25% of the
    // best candidate's RTT, so comparable paths don't cause churn.
    if (chosen_)
        if (DirectCand* cur = find_cand(*chosen_))
            if (alive(*cur) && best && score(*cur) <= score(*best) + score(*best) / 4) best = cur;

    const bool was = direct_confirmed_;
    if (best) {
        if (!chosen_ || *chosen_ != best->ep)
            if (cfg_.verbose)
                spl::logf("[path] direct via %s%s (~%lldms)", best->ep.to_string().c_str(),
                          best->lan ? " LAN" : "", static_cast<long long>(best->srtt));
        chosen_ = best->ep;
        chosen_lan_ = best->lan;
        direct_confirmed_ = true;
    } else {
        chosen_.reset();
        chosen_lan_ = false;
        direct_confirmed_ = false;
        if (was && cfg_.verbose) spl::logf("[path] direct path lost");
    }
}

// Verbose: one glance at the whole path state — every candidate, whether it has
// answered, its RTT, and which one we are using.
void PathManager::dump_paths(Millis now) {
    spl::logf("[path] active=%s | our external=%s | %zu candidate(s):", path_name(tx_path_),
              external_ ? external_->to_string().c_str() : "(unknown)", cands_.size());
    for (const auto& c : cands_) {
        const bool live = c.last_rx && now - c.last_rx < kDirectDeadMs;
        const bool using_it = chosen_ && *chosen_ == c.ep;
        const std::string rtt = c.srtt ? std::to_string(static_cast<long long>(c.srtt)) + "ms" : "?";
        const std::string seen =
            c.last_rx ? std::to_string(now - c.last_rx) + "ms ago" : "no reply yet";
        spl::logf("[path]   %s %s [%s] %s rtt=%s, last reply %s", using_it ? "USE->" : "     ",
                  c.ep.to_string().c_str(), c.lan ? "iface" : "ext ", live ? "ALIVE" : "dead ",
                  rtt.c_str(), seen.c_str());
    }
}

void PathManager::run(std::atomic<bool>& stop) {
    net::set_nonblocking(udp_.get(), true);
    send_register();
    start_ = mono_ms();

    std::vector<uint8_t> buf(4096);
    while (!stop.load()) {
        pollfd pfds[2];
        pfds[0] = pollfd{udp_.get(), POLLIN, 0};
        int nfds = 1;
        if (extra_fd_ >= 0) {
            pfds[1] = pollfd{extra_fd_, POLLIN, 0};
            nfds = 2;
        }
        ::poll(pfds, nfds, 100);
        const Millis now = mono_ms();

        if (pfds[0].revents & POLLIN) {
            for (;;) {
                sockaddr_storage ss{};
                socklen_t slen = sizeof(ss);
                ssize_t n = ::recvfrom(udp_.get(), buf.data(), buf.size(), 0,
                                       reinterpret_cast<sockaddr*>(&ss), &slen);
                if (n < 0) break;
                process(endpoint_from_sockaddr(ss), ByteSpan(buf.data(), static_cast<size_t>(n)),
                        now);
            }
        }
        if (nfds == 2 && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) && on_extra_readable_) {
            on_extra_readable_();
        }

        if (now - t_tick_ >= kTickMs) {
            t_tick_ = now;
            WgResult r = wg_.tick();
            if (r.op == WgOp::WriteToNetwork) send_wg(as_span(r.data));
        }
        if (now - t_register_ >= kRegisterMs) {
            t_register_ = now;
            send_register();
        }
        // Hole-punching (disco) — optionally delayed so the relay phase is observable.
        if (now - start_ >= cfg_.disco_delay_ms) {
            if (!external_ && now - t_whereami_ >= kWhereamiMs) {
                t_whereami_ = now;
                spl_random_bytes(reinterpret_cast<uint8_t*>(&whereami_token_),
                                 sizeof(whereami_token_));
                Bytes q = proto::encode_whereami_req(whereami_token_);
                emit_udp(cfg_.server, as_span(q));
            }
            if (external_ && !direct_confirmed_ && now - t_callme_ >= kCallmeMs) {
                t_callme_ = now;
                Bytes inner = build_inner(CH_DISCO, as_span(build_callme(*external_, local_eps_)));
                send_payload(Path::Relay, nullptr, as_span(inner));
            }
            // Probe faster while no direct path is up (to get off the rate-limited
            // relay sooner), slower once one is established (keepalive + RTT refresh).
            const Millis ping_iv = direct_confirmed_ ? kPingKeepaliveMs : kPingProbeMs;
            if (!force_relay_ && !cands_.empty() && now - t_ping_ >= ping_iv) {
                t_ping_ = now;
                // Probe every candidate so each keeps a fresh RTT and choose_direct can
                // pick (and re-pick) the fastest reachable one.
                Bytes inner = build_inner(CH_DISCO, as_span(build_ping(++ping_txid_)));
                for (const auto& c : cands_) send_payload(Path::Direct, &c.ep, as_span(inner));
            }
        }

        update_tx_path(now);
        if (cfg_.verbose && now - t_stats_ >= 2000) {
            t_stats_ = now;
            spl::logf("[stats] path=%s | tx: direct %s / relay %s | rx: direct %s / relay %s",
                      path_name(tx_path_), human_bytes(tx_direct_).c_str(),
                      human_bytes(tx_relay_).c_str(), human_bytes(rx_direct_).c_str(),
                      human_bytes(rx_relay_).c_str());
            dump_paths(now);
        }
        if (on_tick) on_tick(now);
    }
}

}  // namespace spl::peer
