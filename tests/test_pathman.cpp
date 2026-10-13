// Path manager LAN discovery, driven with a fake clock over real loopback UDP.
// The test plays the daemon's part: it owns the "discovery port" and hands each
// query to whichever side's MAC check accepts it.
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <memory>

#include "crypto/aead.h"
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
    std::vector<uint16_t> a_told, b_told;  // LAN ports each side was told by the other
    std::optional<Endpoint> divert_a_query_as;  // feed A's next query to B from this fake source
    PathConfig cfg_b;  // kept so B can be "restarted" (same pairing, new socket)

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
        ca.own_lan_port = 1111;  // what each says when asked "which LAN port?"
        cb.own_lan_port = 2222;

        cfg_b = cb;
        a = std::make_unique<PathManager>(net::udp_bind("", 0, &err), ca);
        a->on_peer_lan_port = [this](uint16_t p) { a_told.push_back(p); };
        a->set_active(true);
        start_b();
    }
    // (Re)start B's side: a fresh socket, as when its daemon restarts.
    void start_b() {
        std::string err;
        b = std::make_unique<PathManager>(net::udp_bind("", 0, &err), cfg_b);
        b->on_peer_lan_port = [this](uint16_t p) { b_told.push_back(p); };
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

// ---- the peer's LAN port ----

TEST(PathManPort, EachSideLearnsTheOthersPort) {
    Rig r;
    r.run(9000, 100);
    ASSERT_TRUE(r.direct());
    ASSERT_FALSE(r.a_told.empty());
    ASSERT_FALSE(r.b_told.empty());
    EXPECT_EQ(r.a_told.back(), 2222);
    EXPECT_EQ(r.b_told.back(), 1111);
}

TEST(PathManPort, FollowsAPeerThatRestartsOnANewPort) {
    Rig r;
    r.run(9000, 100);
    ASSERT_TRUE(r.direct());
    ASSERT_FALSE(r.a_told.empty());
    ASSERT_EQ(r.a_told.back(), 2222);

    // B's daemon restarts with a different LAN port. It comes back fast enough
    // that A never sees the direct path drop — only its address change.
    r.cfg_b.own_lan_port = 3333;
    r.start_b();
    r.run(15000, 100);  // far less than the 5-minute routine re-ask
    EXPECT_TRUE(r.direct());
    EXPECT_EQ(r.a_told.back(), 3333) << "A did not re-ask after the peer's address changed";
}

namespace {

// A hand-built peer: a bare UDP socket that speaks just enough of the protocol
// (answers the LAN query and pings) to become A's direct path, and derives the
// pair key itself — so it can craft valid and invalid port answers byte by byte.
// It also pins the wire format: if the encoding drifted, these would stop matching.
struct FakePeer {
    net::Fd disco, sock;
    std::unique_ptr<PathManager> a;  // the real side under test (side bit 0)
    Bytes key;
    Endpoint a_ep;
    Millis now = 1'000'000;
    std::vector<uint16_t> told;
    std::vector<Bytes> from_a;  // disco bodies A sent us, newest last (type byte first)

    FakePeer() {
        std::string err;
        disco = net::udp_bind("", 0, &err);
        sock = net::udp_bind("", 0, &err);
        net::set_nonblocking(disco.get(), true);
        net::set_nonblocking(sock.get(), true);

        proto::WgKey a_priv, a_pub, f_priv, f_pub;
        spl_wg_keypair(a_priv.data(), a_pub.data());
        spl_wg_keypair(f_priv.data(), f_pub.data());
        uint8_t dh[32];
        spl_x25519(f_priv.data(), a_pub.data(), dh);
        static const char info[] = "spl/lan-discovery/v1";
        key = crypto::hkdf_sha256(ByteSpan(dh, 32), {},
                                  ByteSpan(reinterpret_cast<const uint8_t*>(info), sizeof(info) - 1),
                                  32);

        PathConfig c;
        spl_random_bytes(c.uid.data(), c.uid.size());
        c.uid[proto::kUidLen - 1] &= 0xFE;  // A is side 0; we play side 1
        c.own_priv = a_priv;
        c.peer_pub = f_pub;
        c.lan_port = net::local_port(disco.get());
        c.lan_targets = {*net::resolve("127.0.0.1", c.lan_port)};
        c.own_lan_port = 1111;
        net::Fd afd = net::udp_bind("", 0, &err);
        a_ep = *net::resolve("127.0.0.1", net::local_port(afd.get()));
        a = std::make_unique<PathManager>(std::move(afd), c);
        a->on_peer_lan_port = [this](uint16_t p) { told.push_back(p); };
        a->set_active(true);
    }

    std::array<uint8_t, 16> mac(const char* label, bool side, ByteSpan data) const {
        Bytes m(label, label + std::strlen(label));
        m.push_back(side ? 1 : 0);
        m.insert(m.end(), data.begin(), data.end());
        const auto full = crypto::hmac_sha256(as_span(key), as_span(m));
        std::array<uint8_t, 16> out{};
        std::memcpy(out.data(), full.data(), 16);
        return out;
    }
    void send(const Bytes& disco_body, const Endpoint& to) {
        Bytes pkt{0x01};  // CH_DISCO
        pkt.insert(pkt.end(), disco_body.begin(), disco_body.end());
        sockaddr_storage ss{};
        socklen_t len = 0;
        sockaddr_from_endpoint(to, &ss, &len);
        ::sendto(sock.get(), pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&ss), len);
    }
    void deliver() {  // let A read what we sent
        ::usleep(800);
        a->handle_io(now);
    }

    void step(Millis dt) {
        now += dt;
        a->tick(now);
        ::usleep(500);
        uint8_t buf[256];
        sockaddr_storage ss{};
        socklen_t slen = sizeof(ss);
        ssize_t n;
        // A's LAN query -> a proper HERE, from our socket (so we become its candidate)
        while ((slen = sizeof(ss)),
               (n = ::recvfrom(disco.get(), buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&ss),
                               &slen)) > 0) {
            if (n != 36 || std::memcmp(buf, "SPLQ", 4) != 0) continue;
            Bytes here{0x04};
            here.insert(here.end(), buf + 4, buf + 20);
            const auto m = mac("here", true, ByteSpan(buf + 4, 16));
            here.insert(here.end(), m.begin(), m.end());
            send(here, endpoint_from_sockaddr(ss));
        }
        // what A sends our socket: answer pings, keep the rest for the test
        while ((n = ::recvfrom(sock.get(), buf, sizeof(buf), 0, nullptr, nullptr)) > 0) {
            if (n < 2 || buf[0] != 0x01) continue;  // disco only (ignore WireGuard)
            if (buf[1] == 0x02 && n == 10) {        // PING -> PONG
                Bytes pong{0x03};
                pong.insert(pong.end(), buf + 2, buf + 10);
                send(pong, a_ep);
            } else {
                from_a.emplace_back(buf + 1, buf + n);
            }
        }
        a->handle_io(now);
    }
    void run(Millis total, Millis dt = 250) {
        for (Millis t = 0; t < total; t += dt) step(dt);
    }
    // Run until A sends a message of this disco type we haven't looked at yet.
    Bytes await(uint8_t type, Millis budget) {
        const size_t start = from_a.size();
        for (Millis t = 0; t < budget; t += 250) {
            step(250);
            for (size_t i = start; i < from_a.size(); ++i)
                if (from_a[i][0] == type) return from_a[i];
        }
        return {};
    }
    Bytes port_answer(ByteSpan nonce, uint16_t port, bool side = true,
                      uint16_t signed_port = 0) const {
        if (!signed_port) signed_port = port;
        Bytes sp(nonce.begin(), nonce.end());
        sp.push_back(static_cast<uint8_t>(signed_port >> 8));
        sp.push_back(static_cast<uint8_t>(signed_port));
        Bytes b{0x06};
        b.insert(b.end(), nonce.begin(), nonce.end());
        b.push_back(static_cast<uint8_t>(port >> 8));
        b.push_back(static_cast<uint8_t>(port));
        const auto m = mac("porta", side, as_span(sp));
        b.insert(b.end(), m.begin(), m.end());
        return b;
    }
};

}  // namespace

TEST(PathManPort, OnlyAFreshAnswerFromThePeerIsAccepted) {
    FakePeer f;
    const Bytes q = f.await(0x05, 15000);  // A asks us which port we listen on
    ASSERT_EQ(q.size(), 33u) << "PORTQ = type + nonce[16] + mac[16]";
    const ByteSpan nonce(q.data() + 1, 16);
    const auto qmac = f.mac("portq", false, nonce);  // made by side 0 (A)
    ASSERT_EQ(0, std::memcmp(qmac.data(), q.data() + 17, 16)) << "A's query MAC";
    ASSERT_TRUE(f.a->status(f.now).direct_confirmed);

    // -- forgeries: none may change anything --
    Bytes bad = f.port_answer(nonce, 4444);
    bad.back() ^= 1;  // wrong MAC
    f.send(bad, f.a_ep);
    f.deliver();
    f.send(f.port_answer(nonce, 4444, /*side=*/false), f.a_ep);  // "signed" as A itself
    f.deliver();
    f.send(f.port_answer(nonce, 4444, true, /*signed_port=*/5555), f.a_ep);  // port swapped
    f.deliver();
    uint8_t other[16];
    spl_random_bytes(other, sizeof(other));
    f.send(f.port_answer(ByteSpan(other, 16), 4444), f.a_ep);  // a nonce A never sent
    f.deliver();
    Bytes zero = f.port_answer(nonce, 4444);
    zero[17] = zero[18] = 0;  // port 0
    f.send(zero, f.a_ep);
    f.deliver();
    Bytes longer = f.port_answer(nonce, 4444);
    longer.push_back(0);  // trailing junk
    f.send(longer, f.a_ep);
    f.deliver();
    EXPECT_TRUE(f.told.empty()) << "a forged answer was accepted";

    // -- the real thing (the forgeries above must not have burned the nonce) --
    const Bytes good = f.port_answer(nonce, 4444);
    f.send(good, f.a_ep);
    f.deliver();
    ASSERT_EQ(f.told.size(), 1u);
    EXPECT_EQ(f.told[0], 4444);

    // -- replaying it earns nothing: each ask is answered once --
    f.send(good, f.a_ep);
    f.deliver();
    EXPECT_EQ(f.told.size(), 1u) << "a replayed answer was accepted";

    // -- a genuine answer that arrives too late is not fresh --
    const Bytes q2 = f.await(0x05, 6 * 60000);  // the next (slow) ask
    ASSERT_EQ(q2.size(), 33u);
    const ByteSpan nonce2(q2.data() + 1, 16);
    f.run(31000);  // held back for longer than an answer may take
    f.send(f.port_answer(nonce2, 6666), f.a_ep);
    f.deliver();
    EXPECT_EQ(f.told.size(), 1u) << "a delayed answer rolled the port";
}

TEST(PathManPort, AnswersOnlyThePeersQueryAndOnlyOnce) {
    FakePeer f;
    f.run(3000);
    ASSERT_TRUE(f.a->status(f.now).direct_confirmed);
    auto ask = [&](bool side, bool break_mac) {
        uint8_t nonce[16];
        spl_random_bytes(nonce, sizeof(nonce));
        Bytes q{0x05};
        q.insert(q.end(), nonce, nonce + 16);
        auto m = f.mac("portq", side, ByteSpan(nonce, 16));
        if (break_mac) m[0] ^= 1;
        q.insert(q.end(), m.begin(), m.end());
        return q;
    };
    auto answers = [&] {
        int n = 0;
        for (const auto& b : f.from_a) n += b[0] == 0x06;
        return n;
    };

    f.send(ask(true, true), f.a_ep);   // bad MAC
    f.send(ask(false, false), f.a_ep); // made with A's own side: not from the peer
    f.run(1000);
    EXPECT_EQ(answers(), 0) << "A answered a query that wasn't the peer's";

    const Bytes q = ask(true, false);
    f.send(q, f.a_ep);
    f.run(1000);
    ASSERT_EQ(answers(), 1);
    const Bytes& ans = f.from_a.back()[0] == 0x06 ? f.from_a.back() : f.from_a[f.from_a.size() - 2];
    ASSERT_EQ(ans.size(), 35u) << "PORTA = type + nonce[16] + port[2] + mac[16]";
    EXPECT_EQ(0, std::memcmp(ans.data() + 1, q.data() + 1, 16)) << "echoes our nonce";
    EXPECT_EQ((ans[17] << 8) | ans[18], 1111) << "A's own LAN port";
    const auto want = f.mac("porta", false, ByteSpan(ans.data() + 1, 18));  // nonce | port, by A
    EXPECT_EQ(0, std::memcmp(want.data(), ans.data() + 19, 16));

    f.send(q, f.a_ep);  // the same query again
    f.run(1000);
    EXPECT_EQ(answers(), 1) << "A answered a replayed query";
}
