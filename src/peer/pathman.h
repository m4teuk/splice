// Path manager: owns the single UDP socket and runs the WireGuard data path over
// whichever path is currently best.
//
//   start on RELAY (works as soon as both peers register with the server)
//     -> learn own external address via whereami
//     -> tell the peer our external + LAN addresses (CALLME over the relay)
//     -> probe every candidate directly (disco PING/PONG)
//     -> UPGRADE to DIRECT once a round-trip is confirmed
//     -> FALL BACK to RELAY if the direct path goes quiet
//
// CALLME advertises this peer's LAN addresses alongside its external one. When
// both peers report the same external IP (they sit behind one NAT) each adopts
// the other's LAN addresses as extra candidates and prefers a working LAN path —
// so two machines on the same network talk over the LAN instead of hairpinning
// through the router or the relay. A LAN probe that goes nowhere is harmless: the
// data plane stays WireGuard-encrypted and the relay/external paths still apply.
//
// All peer<->peer datagrams (relayed or direct) are [channel:1][body]:
//   channel 0x00 = WireGuard, 0x01 = disco (path control).
//
// The manager performs no event loop of its own: the owner polls fd() and calls
// handle_io() when it is readable and tick() once per loop round. It also does
// no logging — observers read the status() snapshot.
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "common/bytes.h"
#include "common/time.h"
#include "net/endpoint.h"
#include "net/socket.h"
#include "peer/wg.h"
#include "proto/pairing.h"

namespace spl::peer {

enum class Path { Relay, Direct };
const char* path_name(Path p);

// A periodic gate: due(now, interval) returns true at most once per interval and
// stamps the time; rearm() makes the next due() fire immediately.
struct Timer {
    Millis last = 0;
    bool due(Millis now, Millis interval) {
        if (now - last < interval) return false;
        last = now;
        return true;
    }
    void rearm() { last = 0; }
};

struct PathConfig {
    proto::Uid uid;        // this side's uid (low bit = side)
    proto::WgKey own_priv;
    proto::WgKey peer_pub;
    Endpoint server;       // resolved rendezvous/relay server address
    // LAN discovery: the port queries are broadcast to, and (tests) explicit
    // targets replacing the per-interface broadcast addresses.
    uint16_t lan_port = 0;
    std::vector<Endpoint> lan_targets;
};

// The well-known UDP port daemons listen on for LAN discovery queries.
inline constexpr uint16_t kLanDiscoPort = 7701;

// Read-only snapshot of the path state, for status displays. The path manager
// never renders or logs; this is its single observation surface.
struct PathStatus {
    struct Cand {
        Endpoint ep;
        bool lan = false;     // advertised as a peer interface address
        bool alive = false;
        bool in_use = false;  // the currently chosen direct path
        Millis rtt = 0;       // smoothed PONG round-trip; 0 = not yet measured
        Millis reply_age = -1;  // ms since last inbound from this address; -1 = never
    };
    Path active = Path::Relay;
    bool direct_confirmed = false;
    std::optional<Endpoint> external;  // our address as seen by the server
    uint64_t tx_direct = 0, tx_relay = 0, rx_direct = 0, rx_relay = 0;  // bytes
    std::vector<Cand> cands;
};

class PathManager {
 public:
    // Sends the initial relay registration; the owner must start polling fd().
    PathManager(net::Fd udp, PathConfig cfg);

    // Invoked for each decrypted inner IP packet, tagged with the path it arrived on.
    std::function<void(ByteSpan inner, Path via)> on_inner;

    int fd() const { return udp_.get(); }
    void handle_io(Millis now);  // drain + process readable datagrams
    void tick(Millis now);       // drive WG timers, registration, disco, path choice

    bool send_inner(ByteSpan ip_packet);  // encapsulate + send over the active path

    bool active() const { return active_; }
    PathStatus status(Millis now) const;  // full snapshot (path, candidates, byte counters)

    // Activity gate: when inactive, tick() initiates no traffic at all (the peer
    // session goes dormant). The daemon sets this from whether the peer has a
    // pipe listening/running or was active recently. A false->true edge re-arms
    // the timers so registration + probing fire on the very next tick.
    void set_active(bool a) {
        if (a && !active_) {
            t_register_.rearm();
            t_whereami_.rearm();
            t_callme_.rearm();
            t_ping_.rearm();
            restart_lan_search();
        }
        active_ = a;
    }

    // The relay's address may be unknown at start (offline, DNS down) and learned
    // later; until then nothing is sent to it and only direct paths can work.
    void set_server(const Endpoint& ep) {
        cfg_.server = ep;
        t_register_.rearm();
        t_whereami_.rearm();
    }

    // --- LAN discovery (no server involved) ---
    // While no direct path is up we broadcast "is my peer here?" queries from our
    // own socket; the peer's daemon hears them on the shared discovery port and
    // hands them to its matching session, which answers from *its* socket. Both
    // packets are MACed with a key only the two paired peers can derive, and the
    // address to use is simply the packet's source — so one verified exchange
    // gives each side the other's direct candidate. Verification only earns a
    // candidate a probe: the usual PING/PONG + WireGuard still decide liveness.
    // Per-peer settings. Relay off: nothing is sent to or accepted from the relay
    // for this peer (only direct paths can work). Broadcast off: LAN queries go
    // to the address hints only. We still *answer* the peer's own queries.
    void set_relay_enabled(bool on) {
        if (on && !relay_on_) {
            t_register_.rearm();
            t_whereami_.rearm();
            t_callme_.rearm();
        }
        relay_on_ = on;
    }
    void set_lan_broadcast(bool on) { lan_broadcast_ = on; }
    // A direct address worth probing (e.g. one that worked last time).
    void add_candidate(const Endpoint& ep, Millis now) { add_cand(ep, /*lan=*/true, now); }

    // Extra places to send the query (address hints), besides the broadcasts.
    void set_lan_hints(std::vector<Endpoint> hints) {
        if (hints == lan_hints_) return;
        lan_hints_ = std::move(hints);
        restart_lan_search();
    }
    static bool is_lan_query(ByteSpan pkt);
    bool lan_query_from_peer(ByteSpan pkt) const;                      // MAC check
    void answer_lan_query(const Endpoint& src, ByteSpan pkt, Millis now);  // after the check

    // Pin to the relay and ignore the direct path (used to simulate direct loss).
    void set_force_relay(bool f) { force_relay_ = f; }

 private:
    // A direct-path candidate we probe with disco PING/PONG.
    struct DirectCand {
        Endpoint ep;
        bool lan = false;    // a peer LAN address (vs the NAT'd external path)
        Millis last_rx = 0;  // last inbound datagram from this address (0 = never)
        Millis srtt = 0;     // smoothed PONG round-trip (ms); 0 = not yet measured
        Millis learned = 0;  // last time something told us about it (CALLME, discovery, traffic)
    };

    void process(const Endpoint& src, ByteSpan raw, Millis now);
    void dispatch_inner(ByteSpan inner, Path via, const Endpoint* from, Millis now);
    void handle_wg(ByteSpan body, Path via, const Endpoint* from, Millis now);
    void handle_disco(ByteSpan body, Path via, const Endpoint* from, Millis now);

    // act on a decapsulate result (send/deliver); a direct WriteToTunnel is the
    // authenticated liveness signal for `from`.
    void pump_wg(WgResult r, Path via, const Endpoint* from, Millis now);
    void send_wg(ByteSpan wg);
    void send_payload(Path path, const Endpoint* direct_to, ByteSpan payload);
    void send_register();
    void update_tx_path(Millis now);
    void emit_udp(const Endpoint& ep, ByteSpan data);  // central egress (applies SPL_LOSS)

    DirectCand* find_cand(const Endpoint& ep);
    // Register a probe target (deduped; re-learning one keeps it from going stale).
    void add_cand(const Endpoint& ep, bool lan, Millis now);
    void prune_cands(Millis now);  // forget addresses that are dead and no longer reported
    void refresh_local_addrs();    // re-read our interfaces; a change restarts the search
    void send_lan_query();
    void restart_lan_search() {  // query promptly again (activation / direct path lost)
        lan_queries_ = 0;
        t_lan_.rearm();
    }
    void touch_cand(const Endpoint& from, Millis now);  // record inbound liveness
    void choose_direct(Millis now);  // pick the active path (lowest-RTT alive candidate)

    net::Fd udp_;
    PathConfig cfg_;
    WgTunnel wg_;

    Path tx_path_ = Path::Relay;
    std::optional<Endpoint> external_;  // our address as seen by the server
    std::vector<DirectCand> cands_;     // direct-path probe targets (external + any LAN)
    std::optional<Endpoint> chosen_;    // the active direct path (best alive candidate)
    bool active_ = false;            // gated by the owner; dormant until set_active(true)
    bool direct_confirmed_ = false;  // derived: some candidate is currently alive
    bool force_relay_ = false;
    bool relay_on_ = true;       // per-peer setting
    bool lan_broadcast_ = true;  // per-peer setting
    bool relay_ok() const { return relay_on_ && cfg_.server.valid(); }

    std::vector<Endpoint> local_eps_;  // our own interface candidates (advertised in CALLME)

    Timer t_tick_, t_register_, t_whereami_, t_callme_, t_ping_, t_lan_, t_housekeep_;
    std::vector<Endpoint> lan_hints_;
    Bytes lan_key_;                 // per-pair discovery key (from the X25519 static DH)
    bool side_ = false;             // our side bit; binds each MAC to its sender's role
    int lan_queries_ = 0;           // queries sent in the current search (fast, then slow)
    std::vector<std::array<uint8_t, 16>> lan_sent_;  // nonces of our recent queries
    std::vector<std::array<uint8_t, 16>> lan_seen_;  // nonces of queries we answered (anti-replay)
    // throughput counters (bytes), split by path
    uint64_t tx_direct_ = 0, tx_relay_ = 0, rx_direct_ = 0, rx_relay_ = 0;
    double loss_ = 0.0;  // SPL_LOSS: fraction of egress packets to drop (testing)
    uint64_t rng_ = 0;
    uint32_t whereami_token_ = 0;
    uint64_t ping_txid_ = 0;
};

}  // namespace spl::peer
