#include "peer/pathman.h"

#include <poll.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
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
constexpr Millis kPingMs = 700;
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
    if (const char* l = std::getenv("SPL_LOSS")) loss_ = std::atof(l);
    spl_random_bytes(reinterpret_cast<uint8_t*>(&rng_), sizeof(rng_));

    // Enumerate our own LAN addresses once. We reach peers from a single socket,
    // so a peer on the same network reaches us at <interface ip>:<our local port>.
    const uint16_t lp = net::local_port(udp_.get());
    local_eps_ = net::local_interface_endpoints(lp);
    if (cfg_.verbose && !local_eps_.empty())
        spl::logf("[path] %zu local LAN candidate(s) on port %u", local_eps_.size(), lp);
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

void PathManager::pump_wg(WgResult r, Path via) {
    while (r.op == WgOp::WriteToNetwork) {
        send_wg(as_span(r.data));
        r = wg_.decapsulate({});
    }
    if (r.op == WgOp::WriteToTunnel && on_inner) on_inner(as_span(r.data), via);
}

void PathManager::handle_wg(ByteSpan body, Path via, Millis /*now*/) {
    pump_wg(wg_.decapsulate(body), via);
}

void PathManager::handle_disco(ByteSpan body, const Endpoint* from, Millis /*now*/) {
    ByteReader r(body);
    const uint8_t dt = r.u8();
    if (!r.ok()) return;
    if (dt == DISCO_CALLME) {
        Endpoint ext{r.array<16>(), r.u16()};
        if (!r.ok()) return;
        std::vector<Endpoint> locals;
        const uint8_t n = r.u8();  // absent in a truncated/old CALLME -> !r.ok() -> no locals
        for (uint8_t i = 0; r.ok() && i < n; ++i) {
            Endpoint le{r.array<16>(), r.u16()};
            if (r.ok()) locals.push_back(le);
        }
        peer_ext_ = ext;
        peer_locals_ = std::move(locals);
        add_cand(ext, /*lan=*/false);
        maybe_adopt_lan();
    } else if (dt == DISCO_PING) {
        const uint64_t tx = r.u64();
        if (!r.ok() || !from) return;
        Bytes pong = build_inner(CH_DISCO, as_span(build_pong(tx)));
        send_payload(Path::Direct, from, as_span(pong));
    }
    // PONG (and any other direct datagram) registers liveness in dispatch_inner;
    // choose_direct() then promotes the best live candidate to the active path.
}

void PathManager::dispatch_inner(ByteSpan inner, Path via, const Endpoint* from, Millis now) {
    if (inner.empty()) return;
    if (via == Path::Direct && from) touch_cand(*from, now);
    const uint8_t ch = inner[0];
    ByteSpan body = inner.subspan(1);
    if (ch == CH_WG) {
        handle_wg(body, via, now);
    } else if (ch == CH_DISCO) {
        handle_disco(body, from, now);
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
                    lan_adopted_ = false;  // re-evaluate same-NAT against the new external
                    if (cfg_.verbose) spl::logf("[path] external address %s", e.to_string().c_str());
                    maybe_adopt_lan();
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

// Pick the active direct path: the best *alive* candidate, preferring a LAN
// address over the NAT'd external one. Sets chosen_/direct_confirmed_.
void PathManager::choose_direct(Millis now) {
    const DirectCand* best = nullptr;
    for (const auto& c : cands_) {
        if (c.last_rx == 0 || now - c.last_rx >= kDirectDeadMs) continue;  // not alive
        if (!best || (c.lan && !best->lan)) best = &c;
    }
    const bool was = direct_confirmed_;
    if (best) {
        if (!chosen_ || *chosen_ != best->ep || chosen_lan_ != best->lan) {
            if (cfg_.verbose)
                spl::logf("[path] direct via %s%s", best->ep.to_string().c_str(),
                          best->lan ? " (LAN)" : "");
        }
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

// If the peer reports the same external IP as ours, we share a NAT and our
// private LAN addresses are mutually routable — adopt the peer's as candidates.
void PathManager::maybe_adopt_lan() {
    if (lan_adopted_ || !external_ || !peer_ext_) return;
    // Compare IP only: one NAT typically maps each peer to a different public port.
    if (external_->ip != peer_ext_->ip) return;
    lan_adopted_ = true;
    if (cfg_.verbose)
        spl::logf("[path] same-NAT peer (%s); trying %zu LAN candidate(s)",
                  external_->to_string().c_str(), peer_locals_.size());
    for (const auto& e : peer_locals_) add_cand(e, /*lan=*/true);
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
            if (!force_relay_ && !cands_.empty() && now - t_ping_ >= kPingMs) {
                t_ping_ = now;
                // Once a LAN path is alive, probe only LAN candidates so we converge
                // on the LAN address and let the NAT'd external path go stale.
                bool lan_alive = false;
                for (const auto& c : cands_)
                    if (c.lan && c.last_rx && now - c.last_rx < kDirectDeadMs) {
                        lan_alive = true;
                        break;
                    }
                Bytes inner = build_inner(CH_DISCO, as_span(build_ping(++ping_txid_)));
                for (const auto& c : cands_) {
                    if (lan_alive && !c.lan) continue;
                    send_payload(Path::Direct, &c.ep, as_span(inner));
                }
            }
        }

        update_tx_path(now);
        if (cfg_.verbose && now - t_stats_ >= 2000) {
            t_stats_ = now;
            spl::logf("[stats] path=%s | tx: direct %s / relay %s | rx: direct %s / relay %s",
                      path_name(tx_path_), human_bytes(tx_direct_).c_str(),
                      human_bytes(tx_relay_).c_str(), human_bytes(rx_direct_).c_str(),
                      human_bytes(rx_relay_).c_str());
        }
        if (on_tick) on_tick(now);
    }
}

}  // namespace spl::peer
