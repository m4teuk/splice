// Path manager: owns the single UDP socket and runs the WireGuard data path over
// whichever path is currently best.
//
//   start on RELAY (works as soon as both peers register with the server)
//     -> learn own external address via whereami
//     -> tell the peer (CALLME over the relay)
//     -> probe the peer's address directly (disco PING/PONG)
//     -> UPGRADE to DIRECT once a round-trip is confirmed
//     -> FALL BACK to RELAY if the direct path goes quiet
//
// All peer<->peer datagrams (relayed or direct) are [channel:1][body]:
//   channel 0x00 = WireGuard, 0x01 = disco (path control).
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>

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
    void process(const Endpoint& src, ByteSpan raw, Millis now);
    void dispatch_inner(ByteSpan inner, Path via, const Endpoint* from, Millis now);
    void handle_wg(ByteSpan body, Path via, Millis now);
    void handle_disco(ByteSpan body, const Endpoint* from, Millis now);

    void pump_wg(WgResult r, Path via);  // act on a decapsulate result (send/deliver)
    void send_wg(ByteSpan wg);
    void send_payload(Path path, const Endpoint* direct_to, ByteSpan payload);
    void send_register();
    void update_tx_path(Millis now);

    net::Fd udp_;
    PathConfig cfg_;
    WgTunnel wg_;

    Path tx_path_ = Path::Relay;
    std::optional<Endpoint> external_;     // our address as seen by the server
    std::optional<Endpoint> peer_direct_;  // peer's candidate direct address
    bool direct_confirmed_ = false;
    bool force_relay_ = false;
    Millis last_direct_recv_ = 0;

    int extra_fd_ = -1;
    std::function<void()> on_extra_readable_;
    Millis start_ = 0;
    Millis t_tick_ = 0, t_register_ = 0, t_whereami_ = 0, t_callme_ = 0, t_ping_ = 0;
    uint32_t whereami_token_ = 0;
    uint64_t ping_txid_ = 0;
};

}  // namespace spl::peer
