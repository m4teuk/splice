// Path manager LAN discovery, driven with a fake clock over real loopback UDP.
// The test plays the daemon's part: it owns the "discovery port" and hands each
// query to whichever side's MAC check accepts it.
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

#include <memory>

#include "native/native.h"
#include "net/socket.h"
#include "peer/pathman.h"

using namespace spl;
using namespace spl::peer;

namespace {

struct Rig {
    net::Fd disco;
    std::unique_ptr<PathManager> a, b;
    Millis now = 1'000'000;
    int queries_from_a = 0, queries_from_b = 0;
    std::optional<Endpoint> divert_a_query_as;  // feed A's next query to B from this fake source

    Rig() {
        std::string err;
        disco = net::udp_bind("", 0, &err);
        net::set_nonblocking(disco.get(), true);
        const uint16_t dport = net::local_port(disco.get());
        const Endpoint target = *net::resolve("127.0.0.1", dport);

        proto::WgKey a_priv, a_pub, b_priv, b_pub;
        spl_wg_keypair(a_priv.data(), a_pub.data());
        spl_wg_keypair(b_priv.data(), b_pub.data());
        proto::Uid uid{};
        spl_random_bytes(uid.data(), uid.size());

        PathConfig ca;  // no server: discovery is all there is
        ca.uid = uid;
        ca.uid[proto::kUidLen - 1] &= 0xFE;
        ca.own_priv = a_priv;
        ca.peer_pub = b_pub;
        ca.lan_port = dport;
        ca.lan_targets = {target};
        PathConfig cb = ca;
        cb.uid[proto::kUidLen - 1] |= 0x01;
        cb.own_priv = b_priv;
        cb.peer_pub = a_pub;

        a = std::make_unique<PathManager>(net::udp_bind("", 0, &err), ca);
        b = std::make_unique<PathManager>(net::udp_bind("", 0, &err), cb);
        a->set_active(true);
        b->set_active(true);
    }

    void step(Millis dt) {
        now += dt;
        a->tick(now);
        b->tick(now);
        for (int round = 0; round < 3; ++round) {
            ::usleep(500);
            uint8_t buf[256];
            for (;;) {
                sockaddr_storage ss{};
                socklen_t slen = sizeof(ss);
                ssize_t n = ::recvfrom(disco.get(), buf, sizeof(buf), 0,
                                       reinterpret_cast<sockaddr*>(&ss), &slen);
                if (n < 0) break;
                const ByteSpan pkt(buf, static_cast<size_t>(n));
                const Endpoint src = endpoint_from_sockaddr(ss);
                if (b->lan_query_from_peer(pkt)) {  // sent by A
                    ++queries_from_a;
                    if (divert_a_query_as) {
                        b->answer_lan_query(*divert_a_query_as, pkt, now);
                        divert_a_query_as.reset();
                    } else {
                        b->answer_lan_query(src, pkt, now);
                    }
                } else if (a->lan_query_from_peer(pkt)) {  // sent by B
                    ++queries_from_b;
                    a->answer_lan_query(src, pkt, now);
                }
            }
            a->handle_io(now);
            b->handle_io(now);
        }
    }
    void run(Millis total, Millis dt = 250) {
        for (Millis t = 0; t < total; t += dt) step(dt);
    }
    bool direct() { return a->status(now).direct_confirmed && b->status(now).direct_confirmed; }
};

bool has_cand(PathManager& pm, Millis now, const Endpoint& ep) {
    for (const auto& c : pm.status(now).cands)
        if (c.ep == ep) return true;
    return false;
}

}  // namespace

TEST(PathManLan, FindsPeerWithNoServer) {
    Rig r;
    r.run(4000, 100);
    EXPECT_TRUE(r.direct()) << "discovery alone should yield a direct path";
    EXPECT_GT(r.queries_from_a + r.queries_from_b, 0);
}

// Take the next query `pm` broadcasts straight off its discovery port.
Bytes next_query(Rig& r, PathManager& pm) {
    uint8_t buf[256];
    for (int i = 0; i < 400; ++i) {
        r.now += 100;
        pm.tick(r.now);
        ::usleep(500);
        ssize_t n = ::recvfrom(r.disco.get(), buf, sizeof(buf), 0, nullptr, nullptr);
        if (n > 0) return Bytes(buf, buf + n);
    }
    return {};
}

TEST(PathManLan, OnlyThePairedPeerAcceptsAQuery) {
    Rig r, other;  // `other` is a different pairing: different keys
    const Bytes q = next_query(r, *r.a);
    ASSERT_TRUE(PathManager::is_lan_query(as_span(q)));
    EXPECT_TRUE(r.b->lan_query_from_peer(as_span(q))) << "the peer must recognise it";
    EXPECT_FALSE(r.a->lan_query_from_peer(as_span(q))) << "a looped-back own query is not the peer";
    EXPECT_FALSE(other.a->lan_query_from_peer(as_span(q))) << "another pairing must not match";
    EXPECT_FALSE(other.b->lan_query_from_peer(as_span(q)));

    Bytes bad = q;
    bad.back() ^= 1;  // tampered MAC
    EXPECT_FALSE(r.b->lan_query_from_peer(as_span(bad)));
    EXPECT_FALSE(PathManager::is_lan_query(ByteSpan(q.data(), q.size() - 1)));
}

TEST(PathManLan, AReplayedQueryEarnsNothing) {
    Rig r;
    const Bytes q = next_query(r, *r.a);
    ASSERT_FALSE(q.empty());
    const Endpoint real = *net::resolve("127.0.0.1", 9), forged = *net::resolve("127.0.0.1", 10);
    r.b->answer_lan_query(real, as_span(q), r.now);
    EXPECT_TRUE(has_cand(*r.b, r.now, real));
    r.b->answer_lan_query(forged, as_span(q), r.now);  // same nonce, new "source"
    EXPECT_FALSE(has_cand(*r.b, r.now, forged));
}

TEST(PathManLan, KeepsLookingWhileDirectIsUp) {
    Rig r;
    r.run(4000, 100);
    ASSERT_TRUE(r.direct());
    const int before = r.queries_from_a + r.queries_from_b;
    r.run(70'000);  // over two slow intervals, direct the whole time
    EXPECT_TRUE(r.direct());
    EXPECT_GE(r.queries_from_a + r.queries_from_b - before, 4)
        << "both sides should keep querying (slowly) with a direct path up";
}

TEST(PathManLan, ForgetsCandidatesThatStopBeingReported) {
    Rig r;
    r.run(4000, 100);
    ASSERT_TRUE(r.direct());
    // B learns a candidate for A that never answers (a verified query arriving
    // from an address A has since left).
    const Endpoint gone = *net::resolve("127.0.0.1", 9);
    r.divert_a_query_as = gone;
    r.run(35'000);
    ASSERT_FALSE(r.divert_a_query_as.has_value()) << "A never sent the query to divert";
    ASSERT_TRUE(has_cand(*r.b, r.now, gone));
    r.run(140'000);  // silent and unreported for > 2 min
    EXPECT_FALSE(has_cand(*r.b, r.now, gone)) << "stale candidate was never pruned";
    EXPECT_TRUE(r.direct()) << "…while the working path is untouched";
}
