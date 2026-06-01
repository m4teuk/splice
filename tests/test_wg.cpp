#include <gtest/gtest.h>

#include <optional>
#include <vector>

#include "native/native.h"
#include "peer/wg.h"

using namespace spl;
using namespace spl::peer;

namespace {

// Minimal but well-formed IPv6 packet (40-byte header + payload) so boringtun
// classifies the decrypted inner as WriteToTunnelV6.
Bytes make_ipv6(uint8_t src_last, uint8_t dst_last, ByteSpan payload) {
    Bytes p(40 + payload.size(), 0);
    p[0] = 0x60;  // version 6
    p[4] = static_cast<uint8_t>(payload.size() >> 8);
    p[5] = static_cast<uint8_t>(payload.size());
    p[6] = 59;  // next header = none
    p[7] = 64;  // hop limit
    p[8] = 0xfd;
    p[23] = src_last;  // src fd00::src_last
    p[24] = 0xfd;
    p[39] = dst_last;  // dst fd00::dst_last
    std::copy(payload.begin(), payload.end(), p.begin() + 40);
    return p;
}

// Feed `dg` to `dst`, draining handshake/keepalive outputs into net_out and
// capturing any decrypted inner packet into tun_out.
void feed(WgTunnel& dst, ByteSpan dg, std::vector<Bytes>& net_out, std::optional<Bytes>& tun_out) {
    WgResult r = dst.decapsulate(dg);
    while (r.op == WgOp::WriteToNetwork) {
        net_out.push_back(r.data);
        r = dst.decapsulate({});
    }
    if (r.op == WgOp::WriteToTunnel) tun_out = r.data;
}

}  // namespace

TEST(Wg, HandshakeAndDataRoundTrip) {
    proto::WgKey priv1, pub1, priv2, pub2;
    spl_wg_keypair(priv1.data(), pub1.data());
    spl_wg_keypair(priv2.data(), pub2.data());
    WgTunnel t1 = WgTunnel::create(priv1, pub2, 1);
    WgTunnel t2 = WgTunnel::create(priv2, pub1, 2);

    Bytes payload = {'p', 'i', 'n', 'g', 1, 2, 3, 4};
    Bytes inner = make_ipv6(1, 2, as_span(payload));

    // t1 wants to send -> emits a handshake initiation.
    WgResult e1 = t1.encapsulate(as_span(inner));
    ASSERT_EQ(e1.op, WgOp::WriteToNetwork);

    // t2 handles the initiation -> handshake response.
    std::vector<Bytes> net;
    std::optional<Bytes> tun;
    feed(t2, as_span(e1.data), net, tun);
    ASSERT_FALSE(net.empty());

    // t1 handles the response (handshake complete; maybe a keepalive).
    std::vector<Bytes> net2;
    std::optional<Bytes> tun2;
    feed(t1, as_span(net[0]), net2, tun2);
    for (auto& d : net2) {
        std::vector<Bytes> n;
        std::optional<Bytes> tu;
        feed(t2, as_span(d), n, tu);
    }

    // Session up: t1 encapsulates the data packet, t2 decrypts it back.
    WgResult e2 = t1.encapsulate(as_span(inner));
    ASSERT_EQ(e2.op, WgOp::WriteToNetwork);
    std::vector<Bytes> net3;
    std::optional<Bytes> tun3;
    feed(t2, as_span(e2.data), net3, tun3);
    ASSERT_TRUE(tun3.has_value());
    EXPECT_EQ(*tun3, inner);
}
