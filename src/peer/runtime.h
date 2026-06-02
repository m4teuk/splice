// Shared setup for the peer data-path commands (chat / send / receive): loads a
// connection record, brings up the path manager + lwIP netstack wired together,
// installs signal handling, and runs the event loop. The command supplies only
// its connection logic (listen/connect + handlers).
#pragma once

#include <atomic>
#include <memory>
#include <string>

#include "net/endpoint.h"
#include "peer/netstack.h"
#include "peer/pathman.h"
#include "peer/store.h"
#include "proto/pairing.h"

namespace spl::peer {

struct PeerOpts {
    std::string server = "127.0.0.1";
    uint16_t port = 7777;
    bool verbose = false;
};

// Set by SIGINT/SIGTERM and by commands that are done; PeerRuntime::run() exits
// when it becomes true.
extern std::atomic<bool> g_stop;

// Default server/port for peer commands: config [peer] applied over 127.0.0.1:7777.
PeerOpts default_peer_opts();

class PeerRuntime {
 public:
    static std::unique_ptr<PeerRuntime> create(const std::string& conn_name, const PeerOpts& opts,
                                               std::string* err);
    PeerRuntime(const PeerRuntime&) = delete;

    PathManager& pm() { return pm_; }
    Netstack& ns() { return ns_; }
    const ConnRecord& record() const { return rec_; }
    const proto::Ip6& own_addr() const { return own_; }
    const proto::Ip6& peer_addr() const { return peer_; }
    bool is_leader() const { return !rec_.side; }

    void run();  // blocks until g_stop

 private:
    PeerRuntime(ConnRecord rec, net::Fd udp, Endpoint server, bool verbose);

    ConnRecord rec_;
    proto::Ip6 own_{}, peer_{};
    PathManager pm_;
    Netstack ns_;
};

}  // namespace spl::peer
