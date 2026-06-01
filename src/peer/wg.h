// RAII wrapper over the boringtun Tunn FFI. boringtun never touches a socket:
// each call returns bytes plus an instruction (send to network / hand up to the
// tunnel / nothing). The path manager owns the socket and acts on these.
#pragma once

#include <cstdint>

#include "common/bytes.h"
#include "proto/pairing.h"  // WgKey

namespace spl::peer {

enum class WgOp { Done, WriteToNetwork, WriteToTunnel, Err };

struct WgResult {
    WgOp op = WgOp::Done;
    Bytes data;  // the bytes to send / the decrypted inner packet (empty if Done/Err)
};

class WgTunnel {
 public:
    static WgTunnel create(const proto::WgKey& own_priv, const proto::WgKey& peer_pub,
                           uint32_t index);

    WgTunnel(WgTunnel&& o) noexcept;
    WgTunnel& operator=(WgTunnel&& o) noexcept;
    WgTunnel(const WgTunnel&) = delete;
    ~WgTunnel();

    WgResult encapsulate(ByteSpan ip_packet);  // plaintext IP packet -> WG datagram
    WgResult decapsulate(ByteSpan datagram);   // WG datagram -> inner packet; empty to drain
    WgResult tick();                           // drive timers (handshakes/keepalives)

 private:
    explicit WgTunnel(void* t) : t_(t) { scratch_.resize(65536); }
    void* t_ = nullptr;
    Bytes scratch_;
};

}  // namespace spl::peer
