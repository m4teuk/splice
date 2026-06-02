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
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "common/time.h"
#include "net/endpoint.h"
#include "net/socket.h"
#include "peer/wg.h"
#include "proto/pairing.h"

namespace spl::peer {

enum class Path { Relay, Direct };
const char* path_name(Path p);

struct PathConfig {
    proto::Uid uid;        // this side's uid (low bit = side)
    proto::WgKey own_priv;
    proto::WgKey peer_pub;
    Endpoint server;       // resolved rendezvous/relay server address
    bool verbose = false;
    Millis disco_delay_ms = 0;  // delay hole-punching (makes the relay phase observable)
};

class PathManager {
 public:
    PathManager(net::Fd udp, PathConfig cfg);

    // Invoked for each decrypted inner IP packet, tagged with the path it arrived on.
    std::function<void(ByteSpan inner, Path via)> on_inner;
    // Invoked once per loop iteration (the app may send via send_inner here).
    std::function<void(Millis now)> on_tick;

    void run(std::atomic<bool>& stop);

    bool send_inner(ByteSpan ip_packet);  // encapsulate + send over the active path

    Path tx_path() const { return tx_path_; }
    bool direct_confirmed() const { return direct_confirmed_; }
    std::optional<Endpoint> external() const { return external_; }

    // Pin to the relay and ignore the direct path (used to simulate direct loss).
    void set_force_relay(bool f) { force_relay_ = f; }

    // Also poll an extra fd (e.g. stdin) and invoke cb when it is readable.
    void watch_fd(int fd, std::function<void()> cb) {
        extra_fd_ = fd;
        on_extra_readable_ = std::move(cb);
    }
    void unwatch_fd() { extra_fd_ = -1; }

 private:
    // A direct-path candidate we probe with disco PING/PONG.
    struct DirectCand {
        Endpoint ep;
        bool lan = false;    // a peer LAN address (preferred over the NAT'd external path)
        Millis last_rx = 0;  // last inbound datagram from this address (0 = never)
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
    void add_cand(const Endpoint& ep, bool lan);        // register a probe target (deduped)
    void touch_cand(const Endpoint& from, Millis now);  // record inbound liveness
    void choose_direct(Millis now);                     // pick the active path (LAN preferred)
    void maybe_adopt_lan();  // adopt the peer's LAN candidates when we share a NAT

    net::Fd udp_;
    PathConfig cfg_;
    WgTunnel wg_;

    Path tx_path_ = Path::Relay;
    std::optional<Endpoint> external_;  // our address as seen by the server
    std::vector<DirectCand> cands_;     // direct-path probe targets (external + any LAN)
    std::optional<Endpoint> chosen_;    // the active direct path (best alive candidate)
    bool chosen_lan_ = false;
    bool direct_confirmed_ = false;  // derived: some candidate is currently alive
    bool force_relay_ = false;

    std::vector<Endpoint> local_eps_;    // our own LAN candidates (advertised in CALLME)
    std::optional<Endpoint> peer_ext_;   // peer's external, as last advertised over CALLME
    std::vector<Endpoint> peer_locals_;  // peer's LAN candidates, as last advertised
    bool lan_adopted_ = false;           // already folded peer_locals_ into cands_

    int extra_fd_ = -1;
    std::function<void()> on_extra_readable_;
    Millis start_ = 0;
    Millis t_tick_ = 0, t_register_ = 0, t_whereami_ = 0, t_callme_ = 0, t_ping_ = 0, t_stats_ = 0;
    // verbose throughput counters (bytes), split by path
    uint64_t tx_direct_ = 0, tx_relay_ = 0, rx_direct_ = 0, rx_relay_ = 0;
    double loss_ = 0.0;  // SPL_LOSS: fraction of egress packets to drop (testing)
    uint64_t rng_ = 0;
    uint32_t whereami_token_ = 0;
    uint64_t ping_txid_ = 0;
};

}  // namespace spl::peer
