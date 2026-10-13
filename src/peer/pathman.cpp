#include "peer/pathman.h"

#include <sys/socket.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <openssl/crypto.h>

#include "common/bytes.h"
#include "crypto/aead.h"
#include "native/native.h"
#include "proto/relay.h"

namespace spl::peer {

namespace {

constexpr uint8_t CH_WG = 0x00;
constexpr uint8_t CH_DISCO = 0x01;
constexpr uint8_t DISCO_CALLME = 0x01;
constexpr uint8_t DISCO_PING = 0x02;
constexpr uint8_t DISCO_PONG = 0x03;
constexpr uint8_t DISCO_HERE = 0x04;  // answer to a LAN discovery query: [nonce:16][mac:16]

// LAN discovery query, broadcast raw (no channel byte) to the discovery port:
//   "SPLQ" | nonce[16] | HMAC(k_pair, "who" | sender_side | nonce)[:16]
// answered direct, on the disco channel, with
//   DISCO_HERE | nonce[16] | HMAC(k_pair, "here" | sender_side | nonce)[:16]
// The side byte means a peer never accepts its own (looped-back) packet, and the
// different labels mean a query can't be replayed as an answer.
constexpr char kLanMagic[4] = {'S', 'P', 'L', 'Q'};
constexpr size_t kLanNonce = 16, kLanMac = 16;
constexpr size_t kLanQueryLen = sizeof(kLanMagic) + kLanNonce + kLanMac;
constexpr Millis kLanFastMs = 2000;   // while a search is fresh…
constexpr int kLanFastQueries = 5;    // …for this many queries,
constexpr Millis kLanSlowMs = 30000;  // then every once in a while — also with a direct path up
constexpr size_t kLanRemember = 64;   // nonces kept (ours sent / theirs answered)

constexpr Millis kTickMs = 250;
constexpr Millis kRegisterMs = 4000;
constexpr Millis kWhereamiMs = 1000;         // until our external address is learned
constexpr Millis kWhereamiRefreshMs = 10000; // refresh after, to catch a NAT/network change
constexpr Millis kCallmeMs = 1000;
// Once a direct path is up we keep looking for a better one, just slowly: the
// peer's addresses (and ours) can change, and a faster route may appear — e.g.
// two machines talking across the internet that later join the same Wi-Fi.
constexpr Millis kCallmeDirectMs = 30000;
constexpr Millis kHousekeepMs = 10000;   // re-read our interfaces, prune stale candidates
constexpr Millis kCandStaleMs = 120000;  // a dead candidate nobody re-reported is dropped
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

std::array<uint8_t, kLanMac> lan_mac(const Bytes& key, const char* label, bool sender_side,
                                     ByteSpan nonce) {
    Bytes m(label, label + std::strlen(label));
    m.push_back(sender_side ? 1 : 0);
    m.insert(m.end(), nonce.begin(), nonce.end());
    const auto full = crypto::hmac_sha256(as_span(key), as_span(m));
    std::array<uint8_t, kLanMac> out{};
    std::memcpy(out.data(), full.data(), kLanMac);
    return out;
}

template <typename V, typename T>
void remember(V& v, const T& x) {
    if (v.size() >= kLanRemember) v.erase(v.begin());
    v.push_back(x);
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
    local_eps_ = net::local_interface_endpoints(net::local_port(udp_.get()));

    // The per-pair discovery key: both sides derive the same value from keys they
    // already hold (their own private key + the other's public key).
    uint8_t dh[32];
    spl_x25519(cfg_.own_priv.data(), cfg_.peer_pub.data(), dh);
    static const char kInfo[] = "spl/lan-discovery/v1";
    lan_key_ = crypto::hkdf_sha256(ByteSpan(dh, sizeof(dh)), {},
                                   ByteSpan(reinterpret_cast<const uint8_t*>(kInfo),
                                            sizeof(kInfo) - 1),
                                   32);
    OPENSSL_cleanse(dh, sizeof(dh));
    side_ = (cfg_.uid[proto::kUidLen - 1] & 1) != 0;
    if (cfg_.lan_port == 0) cfg_.lan_port = kLanDiscoPort;
    net::set_broadcast(udp_.get());

    net::set_nonblocking(udp_.get(), true);
    // No traffic until the owner marks us active (set_active): a dormant peer
    // session sits silent. The daemon registers the moment something listens or
    // a pipe runs.
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
        if (!relay_ok()) return;  // relay unknown (yet) or disabled for this peer
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

// ---- LAN discovery ----

bool PathManager::is_lan_query(ByteSpan pkt) {
    return pkt.size() == kLanQueryLen && std::memcmp(pkt.data(), kLanMagic, sizeof(kLanMagic)) == 0;
}

void PathManager::send_lan_query() {
    std::array<uint8_t, kLanNonce> nonce{};
    spl_random_bytes(nonce.data(), nonce.size());
    remember(lan_sent_, nonce);
    Bytes pkt(kLanMagic, kLanMagic + sizeof(kLanMagic));
    pkt.insert(pkt.end(), nonce.begin(), nonce.end());
    const auto mac = lan_mac(lan_key_, "who", side_, as_span(nonce));
    pkt.insert(pkt.end(), mac.begin(), mac.end());
    // Interfaces come and go (Wi-Fi roaming, a cable, a VPN): look them up each time.
    if (lan_broadcast_) {
        const std::vector<Endpoint> targets =
            cfg_.lan_targets.empty() ? net::broadcast_endpoints(cfg_.lan_port) : cfg_.lan_targets;
        for (const auto& t : targets) emit_udp(t, as_span(pkt));
    }
    for (const auto& t : lan_hints_) emit_udp(t, as_span(pkt));
    ++lan_queries_;
}

bool PathManager::lan_query_from_peer(ByteSpan pkt) const {
    if (!is_lan_query(pkt)) return false;
    const ByteSpan nonce = pkt.subspan(sizeof(kLanMagic), kLanNonce);
    const auto want = lan_mac(lan_key_, "who", !side_, nonce);  // sent by the *other* side
    return CRYPTO_memcmp(want.data(), pkt.data() + sizeof(kLanMagic) + kLanNonce, kLanMac) == 0;
}

void PathManager::answer_lan_query(const Endpoint& src, ByteSpan pkt, Millis now) {
    if (force_relay_) return;
    std::array<uint8_t, kLanNonce> nonce{};
    std::memcpy(nonce.data(), pkt.data() + sizeof(kLanMagic), kLanNonce);
    // A captured query replayed later (perhaps from a forged source) earns nothing.
    if (std::find(lan_seen_.begin(), lan_seen_.end(), nonce) != lan_seen_.end()) return;
    remember(lan_seen_, nonce);
    add_cand(src, /*lan=*/true, now);  // the asker's own socket: our candidate for them
    ByteWriter w;
    w.u8(DISCO_HERE);
    w.array(nonce);
    w.array(lan_mac(lan_key_, "here", side_, as_span(nonce)));
    Bytes inner = build_inner(CH_DISCO, as_span(w.take()));
    send_payload(Path::Direct, &src, as_span(inner));
    t_ping_.rearm();  // probe the new candidate right away
}

void PathManager::send_register() {
    if (!relay_ok()) return;
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
        // A reply WireGuard produced for a packet that arrived direct (a handshake
        // response, typically) goes back to that packet's source — as WireGuard
        // itself does. Otherwise a peer that reaches us at an address we haven't
        // learned yet (it remembered ours; we don't know its new one) could never
        // finish the handshake: our answer would head for the relay instead.
        if (via == Path::Direct && from && !force_relay_) {
            Bytes payload = build_inner(CH_WG, as_span(r.data));
            send_payload(Path::Direct, from, as_span(payload));
        } else {
            send_wg(as_span(r.data));
        }
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
        add_cand(ext, /*lan=*/false, now);
        // Adopt every interface address the peer advertised, regardless of whether we
        // share a NAT: a same-LAN address is reachable directly, an overlay address
        // (e.g. Tailscale) is reachable if we share that overlay, and an unreachable
        // one simply never goes alive. RTT selection then picks the best reachable
        // path — no address range is special-cased.
        const uint8_t n = r.u8();  // absent in a truncated/old CALLME -> !r.ok() -> no locals
        for (uint8_t i = 0; r.ok() && i < n; ++i) {
            Endpoint le{r.array<16>(), r.u16()};
            if (!r.ok()) break;
            add_cand(le, /*lan=*/true, now);
        }
    } else if (dt == DISCO_HERE) {
        // The peer answering one of our LAN queries, from its own socket.
        if (via != Path::Direct || !from) return;
        const auto nonce = r.array<kLanNonce>();
        const auto mac = r.array<kLanMac>();
        if (!r.ok()) return;
        if (std::find(lan_sent_.begin(), lan_sent_.end(), nonce) == lan_sent_.end()) return;
        const auto want = lan_mac(lan_key_, "here", !side_, as_span(nonce));
        if (CRYPTO_memcmp(want.data(), mac.data(), kLanMac) != 0) return;
        add_cand(*from, /*lan=*/true, now);
        t_ping_.rearm();
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
            c->last_rx = now;
            Millis rtt = now - t_ping_.last;  // this token went out at the last ping
            if (rtt < 1) rtt = 1;
            c->srtt = c->srtt ? (c->srtt * 3 + rtt) / 4 : rtt;  // EWMA toward the latest sample
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
        if (!relay_on_) return;
        auto t = proto::peek_udp_type(raw);
        if (t == proto::UdpType::kWhereami) {
            auto rep = proto::decode_whereami_reply(raw);
            if (rep && rep->token == whereami_token_) {
                const Endpoint ext{rep->ip, rep->port};
                // A new external address (NAT rebind, new network): tell the peer now.
                if (!external_ || !(*external_ == ext)) t_callme_.rearm();
                external_ = ext;
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
    const bool was_direct = direct_confirmed_;
    choose_direct(now);
    if (was_direct && !direct_confirmed_) restart_lan_search();  // lost it: look again now
    tx_path_ = (!force_relay_ && direct_confirmed_) ? Path::Direct : Path::Relay;
}

PathManager::DirectCand* PathManager::find_cand(const Endpoint& ep) {
    for (auto& c : cands_)
        if (c.ep == ep) return &c;
    return nullptr;
}

void PathManager::add_cand(const Endpoint& ep, bool lan, Millis now) {
    if (!ep.valid()) return;
    if (DirectCand* c = find_cand(ep)) {
        if (lan) c->lan = true;  // a candidate can be both reported and LAN-reachable
        c->learned = now;
        return;
    }
    if (cands_.size() >= kMaxCands) {
        // Full: make room by dropping a candidate that never answered a probe, so
        // junk can't lock a real address out. (All proven? Then keep what we have.)
        auto dead = std::find_if(cands_.begin(), cands_.end(), [&](const DirectCand& c) {
            return c.last_rx == 0 && !(chosen_ && *chosen_ == c.ep);
        });
        if (dead == cands_.end()) return;
        cands_.erase(dead);
    }
    cands_.push_back({ep, lan, 0, 0, now});
}

// Drop candidates that are neither answering nor being reported any more (an old
// network's addresses), so we don't ping them forever. Anything still valid is
// re-learned by the next CALLME / discovery answer.
void PathManager::prune_cands(Millis now) {
    std::erase_if(cands_, [&](const DirectCand& c) {
        if (chosen_ && *chosen_ == c.ep) return false;
        return now - std::max(c.last_rx, c.learned) > kCandStaleMs;
    });
}

void PathManager::refresh_local_addrs() {
    auto eps = net::local_interface_endpoints(net::local_port(udp_.get()));
    if (eps == local_eps_) return;
    // We joined or left a network: advertise the new set and look around again,
    // even if a direct path is currently up (a better one may now exist).
    local_eps_ = std::move(eps);
    t_callme_.rearm();
    restart_lan_search();
}

void PathManager::touch_cand(const Endpoint& from, Millis now) {
    if (DirectCand* c = find_cand(from)) {
        c->last_rx = now;
        return;
    }
    if (cands_.size() >= kMaxCands) return;
    cands_.push_back({from, false, now, 0, now});  // learned from traffic (e.g. a NAT rebind)
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

    if (best) {
        chosen_ = best->ep;
        direct_confirmed_ = true;
    } else {
        chosen_.reset();
        direct_confirmed_ = false;
    }
}

void PathManager::handle_io(Millis now) {
    uint8_t buf[4096];
    for (;;) {
        sockaddr_storage ss{};
        socklen_t slen = sizeof(ss);
        ssize_t n = ::recvfrom(udp_.get(), buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&ss),
                               &slen);
        if (n < 0) break;
        process(endpoint_from_sockaddr(ss), ByteSpan(buf, static_cast<size_t>(n)), now);
    }
}

void PathManager::tick(Millis now) {
    // Inactive (the owner has no pipe listening/running and the warm window has
    // lapsed): stay completely silent — no relay registration, no whereami, no
    // CALLME, no probing, no WG keepalive. handle_io still runs, so a stray reply
    // is processed harmlessly. We just stop initiating traffic.
    if (!active_) return;

    if (t_tick_.due(now, kTickMs)) {
        WgResult r = wg_.tick();
        if (r.op == WgOp::WriteToNetwork) send_wg(as_span(r.data));
    }
    if (t_register_.due(now, kRegisterMs)) send_register();
    // whereami: fast until our external address is known, then a slow refresh so
    // a NAT rebind / network change is noticed and re-advertised via CALLME.
    if (relay_ok() &&
        t_whereami_.due(now, external_ ? kWhereamiRefreshMs : kWhereamiMs)) {
        spl_random_bytes(reinterpret_cast<uint8_t*>(&whereami_token_), sizeof(whereami_token_));
        Bytes q = proto::encode_whereami_req(whereami_token_);
        emit_udp(cfg_.server, as_span(q));
    }
    if (t_housekeep_.due(now, kHousekeepMs)) {
        refresh_local_addrs();
        prune_cands(now);
    }
    // CALLME: every second until a direct path is up, then an occasional refresh
    // (and at once when our addresses change — the timer is re-armed for that).
    if (relay_ok() && external_ &&
        t_callme_.due(now, direct_confirmed_ ? kCallmeDirectMs : kCallmeMs)) {
        Bytes inner = build_inner(CH_DISCO, as_span(build_callme(*external_, local_eps_)));
        send_payload(Path::Relay, nullptr, as_span(inner));
    }
    // LAN discovery: a few quick queries when a search starts, then an occasional
    // one for as long as the session is active — with a direct path up too, since
    // a better one may have appeared.
    const bool lan_fast = !direct_confirmed_ && lan_queries_ < kLanFastQueries;
    if (!force_relay_ && t_lan_.due(now, lan_fast ? kLanFastMs : kLanSlowMs)) send_lan_query();
    // Probe faster while no direct path is up (to get off the rate-limited
    // relay sooner), slower once one is established (keepalive + RTT refresh).
    const Millis ping_iv = direct_confirmed_ ? kPingKeepaliveMs : kPingProbeMs;
    if (!force_relay_ && !cands_.empty() && t_ping_.due(now, ping_iv)) {
        // Probe every candidate so each keeps a fresh RTT and choose_direct can
        // pick (and re-pick) the fastest reachable one.
        Bytes inner = build_inner(CH_DISCO, as_span(build_ping(++ping_txid_)));
        for (const auto& c : cands_) send_payload(Path::Direct, &c.ep, as_span(inner));
    }
    update_tx_path(now);
}

PathStatus PathManager::status(Millis now) const {
    PathStatus s;
    s.active = tx_path_;
    s.direct_confirmed = direct_confirmed_;
    s.external = external_;
    s.tx_direct = tx_direct_;
    s.tx_relay = tx_relay_;
    s.rx_direct = rx_direct_;
    s.rx_relay = rx_relay_;
    for (const auto& c : cands_) {
        PathStatus::Cand out;
        out.ep = c.ep;
        out.lan = c.lan;
        out.alive = c.last_rx && now - c.last_rx < kDirectDeadMs;
        out.in_use = chosen_ && *chosen_ == c.ep;
        out.rtt = c.srtt;
        out.reply_age = c.last_rx ? now - c.last_rx : -1;
        s.cands.push_back(out);
    }
    return s;
}

}  // namespace spl::peer
