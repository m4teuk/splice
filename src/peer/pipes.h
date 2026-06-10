// Daemon-owned pipe ends. A LocalEnd is the local half of a spliced connection
// when the daemon itself runs it (PONG now; SHARE_FILE/GET_FILE later) — as
// opposed to the PIPE type, where a client process's socket is the local half.
//
// The daemon installs to_tunnel/shutdown; the end implements the data hooks.
// Ends never see the network: bytes in, bytes out, describe yourself.
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "common/bytes.h"
#include "common/time.h"

namespace spl::peer {

class LocalEnd {
 public:
    virtual ~LocalEnd() = default;

    std::function<void(ByteSpan)> to_tunnel;  // send bytes to the other end
    std::function<void()> shutdown;           // ask the daemon to close this instance

    virtual void on_tunnel_data(ByteSpan b) = 0;
    virtual void on_tunnel_closed() {}     // other end closed (instance is dying)
    virtual void tick(Millis) {}           // pump opportunity (e.g. refill send buffer)
    virtual size_t want_send() const { return 0; }  // bytes it could send if space allows
    virtual std::string describe() const = 0;  // one status line fragment
};

// ECHO: sends back everything it receives. Diagnostics.
class EchoEnd : public LocalEnd {
 public:
    void on_tunnel_data(ByteSpan b) override {
        if (to_tunnel) to_tunnel(b);
    }
    std::string describe() const override { return "echo"; }
};

// Factory for daemon-owned types ("ECHO", later "SHARE_FILE"/"GET_FILE").
// Returns null with *err set for unknown types/bad args.
std::unique_ptr<LocalEnd> make_local_end(const std::string& type,
                                         const std::vector<std::string>& args, std::string* err);

}  // namespace spl::peer
