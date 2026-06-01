// TCP+TLS rendezvous. A leader (`spl pair`) gets a short code and waits; a
// follower (`spl pair <code>`) presents it. On match the server sends PAIRED to
// both and relays their (turn-based, leader-first) frames until one disconnects.
// The frames it relays are opaque to the server (SPAKE2 / sealed negotiation).
#pragma once

#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <optional>

#include "common/time.h"
#include "net/socket.h"
#include "net/tls.h"
#include "proto/pairing.h"
#include "server/code_alloc.h"

namespace spl::server {

struct PairingConfig {
    Millis code_ttl_ms = 60'000;        // how long a code waits for a follower
    Millis bridge_timeout_ms = 60'000;  // per-read timeout during the relay
    int max_sessions = 64;
    bool verbose = false;
};

class PairingServer {
 public:
    PairingServer(net::Fd listen, std::shared_ptr<net::TlsContext> ctx, PairingConfig cfg);
    void run(std::atomic<bool>& stop);  // blocks until stop

 private:
    struct Pending {
        std::mutex m;
        std::condition_variable cv;
        std::optional<net::TlsConn> follower;  // delivered by the follower thread
        bool taken = false;                    // guarded by PairingServer::mu_
    };

    void handle(net::Fd raw, Endpoint peer);
    void handle_leader(net::TlsConn& conn, const Endpoint& peer);
    void handle_follower(net::TlsConn& conn, const Endpoint& peer, uint64_t code);
    void bridge(net::TlsConn& leader, net::TlsConn& follower);
    void cleanup(uint64_t code);
    bool send_ctrl(net::TlsConn& c, const proto::CtrlMessage& m);

    net::Fd listen_;
    std::shared_ptr<net::TlsContext> ctx_;
    PairingConfig cfg_;

    std::mutex mu_;  // guards alloc_ and sessions_
    CodeAllocator alloc_;
    std::map<uint64_t, std::shared_ptr<Pending>> sessions_;
    std::atomic<int> active_sessions_{0};
};

}  // namespace spl::server
