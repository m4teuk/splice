#include "peer/pairing.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "common/base64.h"
#include "common/bytes.h"
#include "common/log.h"
#include "crypto/aead.h"
#include "crypto/spake2.h"
#include "native/native.h"
#include "net/socket.h"
#include "net/tls.h"
#include "peer/store.h"
#include "proto/frame.h"
#include "proto/pairing.h"

namespace spl::peer {

using namespace spl::proto;

namespace {

// 12-byte AEAD nonce from a per-direction counter (4 zero bytes + big-endian u64).
Bytes nonce_from(uint64_t ctr) {
    Bytes n(12, 0);
    for (int i = 0; i < 8; ++i) n[4 + i] = static_cast<uint8_t>(ctr >> (56 - 8 * i));
    return n;
}

Ip6 random_ula() {
    Ip6 u{};
    u[0] = 0xfd;                       // ULA prefix fd00::/8
    spl_random_bytes(u.data() + 1, 7);  // random /64 (host bytes 8..15 stay 0)
    return u;
}

bool same_ula64(const Ip6& a, const Ip6& b) { return std::memcmp(a.data(), b.data(), 8) == 0; }

std::string b64(const WgKey& k) { return base64_encode(as_span(k)); }

// Runs the post-PAIRED exchange. Returns 0 on success.
int run_pairing(net::TlsConn& conn, bool is_leader, const std::string& spake_code,
                const std::string& preset_name, bool verbose) {
    auto send_peer = [&](const PeerMessage& m) {
        Bytes b = encode_peer(m);
        return net::write_frame(conn, as_span(b));
    };
    auto recv_peer = [&]() -> std::optional<PeerMessage> {
        auto f = net::read_frame(conn, kMaxFrameLen);
        if (!f) return std::nullopt;
        return decode_peer(as_span(*f));
    };
    auto protofail = [&]() {
        spl::logf("pairing failed: unexpected or garbled message from peer");
        return 1;
    };

    // 1. SPAKE2 (symmetric). Leader sends first (the bridge is turn-based).
    Bytes my_spake;
    auto spake = crypto::Spake2::start(as_span(spake_code), &my_spake);
    if (!spake) {
        spl::logf("pairing failed: SPAKE2 init");
        return 1;
    }
    Bytes leader_spake, follower_spake;
    if (is_leader) {
        if (!send_peer(Spake2Msg{my_spake})) return protofail();
        auto m = recv_peer();
        if (!m || !std::holds_alternative<Spake2Msg>(*m)) return protofail();
        leader_spake = my_spake;
        follower_spake = std::get<Spake2Msg>(*m).msg;
    } else {
        auto m = recv_peer();
        if (!m || !std::holds_alternative<Spake2Msg>(*m)) return protofail();
        leader_spake = std::get<Spake2Msg>(*m).msg;
        if (!send_peer(Spake2Msg{my_spake})) return protofail();
        follower_spake = my_spake;
    }
    auto K = spake->finish(as_span(is_leader ? follower_spake : leader_spake));
    if (!K) {
        spl::logf("pairing failed: SPAKE2 finish");
        return 1;
    }

    // 2. Derive keys, all bound to the SPAKE2 transcript (= salt).
    Bytes transcript = leader_spake;
    transcript.insert(transcript.end(), follower_spake.begin(), follower_spake.end());
    auto derive = [&](const char* info) {
        return crypto::hkdf_sha256(as_span(*K), as_span(transcript),
                                   ByteSpan(reinterpret_cast<const uint8_t*>(info), std::strlen(info)),
                                   32);
    };
    Bytes kcL = derive("spl/confirm/leader"), kcF = derive("spl/confirm/follower");
    Bytes kL2F = derive("spl/aead/l2f"), kF2L = derive("spl/aead/f2l");
    auto macL = crypto::hmac_sha256(as_span(kcL), as_span(transcript));
    auto macF = crypto::hmac_sha256(as_span(kcF), as_span(transcript));

    // 3. Key confirmation. A mismatch means a wrong code or active tampering.
    if (is_leader) {
        if (!send_peer(KeyConfirm{macL})) return protofail();
        auto m = recv_peer();
        if (!m || !std::holds_alternative<KeyConfirm>(*m)) return protofail();
        if (std::get<KeyConfirm>(*m).mac != macF) {
            spl::logf("pairing failed: key confirmation mismatch (wrong code or tampering)");
            return 1;
        }
    } else {
        auto m = recv_peer();
        if (!m || !std::holds_alternative<KeyConfirm>(*m)) return protofail();
        if (std::get<KeyConfirm>(*m).mac != macL) {
            spl::logf("pairing failed: key confirmation mismatch (wrong code or tampering)");
            return 1;
        }
        if (!send_peer(KeyConfirm{macF})) return protofail();
    }

    // 4. AEAD-protected negotiation: WG pubkeys are exchanged inside this channel,
    //    binding them to the PAKE so a malicious server cannot substitute its own.
    uint64_t n_l2f = 0, n_f2l = 0;
    auto seal_l2f = [&](ByteSpan pt) {
        return crypto::aead_seal(as_span(kL2F), as_span(nonce_from(n_l2f++)), pt, {});
    };
    auto open_l2f = [&](ByteSpan ct) {
        return crypto::aead_open(as_span(kL2F), as_span(nonce_from(n_l2f++)), ct, {});
    };
    auto seal_f2l = [&](ByteSpan pt) {
        return crypto::aead_seal(as_span(kF2L), as_span(nonce_from(n_f2l++)), pt, {});
    };
    auto open_f2l = [&](ByteSpan ct) {
        return crypto::aead_open(as_span(kF2L), as_span(nonce_from(n_f2l++)), ct, {});
    };

    ConnRecord rec;
    rec.ula_prefix = 64;
    rec.side = !is_leader;
    spl_wg_keypair(rec.own_priv.data(), rec.own_pub.data());

    std::string err;
    auto store_opt = Store::open(&err);
    std::vector<ConnRecord> existing = store_opt ? store_opt->load_all() : std::vector<ConnRecord>{};
    auto ula_collides = [&](const Ip6& b) {
        for (auto& e : existing)
            if (same_ula64(e.ula_base, b)) return true;
        return false;
    };

    bool agreed = false;
    if (is_leader) {
        Uid uid{};
        spl_random_bytes(uid.data(), kUidLen);
        uid[kUidLen - 1] &= 0xFE;  // leader side bit = 0
        Ip6 ula = random_ula();
        while (ula_collides(ula)) ula = random_ula();

        for (int attempt = 0; attempt < 10 && !agreed; ++attempt) {
            Offer off;
            off.ula_base = ula;
            off.ula_prefix = 64;
            off.uid = uid;
            off.leader_pubkey = rec.own_pub;
            Bytes pt = encode_neg(NegMessage{off});
            if (!send_peer(Sealed{seal_l2f(as_span(pt))})) return protofail();

            auto m = recv_peer();
            if (!m || !std::holds_alternative<Sealed>(*m)) return protofail();
            auto rpt = open_f2l(as_span(std::get<Sealed>(*m).ciphertext));
            if (!rpt) {
                spl::logf("pairing failed: could not decrypt peer reply");
                return 1;
            }
            auto neg = decode_neg(as_span(*rpt));
            if (!neg || !std::holds_alternative<Reply>(*neg)) return protofail();
            Reply rep = std::get<Reply>(*neg);
            if (rep.status == ReplyStatus::kAccept) {
                rec.peer_pub = rep.follower_pubkey;
                rec.uid = uid;
                rec.ula_base = ula;
                agreed = true;
            } else if (rep.status == ReplyStatus::kRejectIp) {
                Ip6 nu = random_ula();
                while (ula_collides(nu) || same_ula64(nu, rep.counter_ula_base)) nu = random_ula();
                ula = nu;
            } else {
                spl::logf("pairing declined by peer");
                return 1;
            }
        }
    } else {
        for (int attempt = 0; attempt < 10 && !agreed; ++attempt) {
            auto m = recv_peer();
            if (!m || !std::holds_alternative<Sealed>(*m)) return protofail();
            auto opt = open_l2f(as_span(std::get<Sealed>(*m).ciphertext));
            if (!opt) {
                spl::logf("pairing failed: could not decrypt peer offer");
                return 1;
            }
            auto neg = decode_neg(as_span(*opt));
            if (!neg || !std::holds_alternative<Offer>(*neg)) return protofail();
            Offer off = std::get<Offer>(*neg);

            if (ula_collides(off.ula_base)) {
                Reply r;
                r.status = ReplyStatus::kRejectIp;
                r.counter_ula_base = random_ula();
                r.counter_ula_prefix = 64;
                Bytes pt = encode_neg(NegMessage{r});
                if (!send_peer(Sealed{seal_f2l(as_span(pt))})) return protofail();
                continue;
            }
            Reply r;
            r.status = ReplyStatus::kAccept;
            r.follower_pubkey = rec.own_pub;
            Bytes pt = encode_neg(NegMessage{r});
            if (!send_peer(Sealed{seal_f2l(as_span(pt))})) return protofail();
            rec.peer_pub = off.leader_pubkey;
            rec.uid = off.uid;
            rec.uid[kUidLen - 1] |= 0x01;  // follower side bit = 1
            rec.ula_base = off.ula_base;
            agreed = true;
        }
    }
    if (!agreed) {
        spl::logf("pairing failed: could not agree on an address");
        return 1;
    }

    // 5. Trust decision (accept / decline / verify), then persist.
    std::string name = preset_name;
    if (name.empty()) {
        std::printf("\nPeer connected. Their public key:\n  %s\n", b64(rec.peer_pub).c_str());
        std::printf("[a]ccept / [d]ecline / [v]erify (paste their key)? ");
        std::fflush(stdout);
        std::string line;
        std::getline(std::cin, line);
        char choice = line.empty() ? 'a' : static_cast<char>(std::tolower(line[0]));
        if (choice == 'd') {
            std::printf("Declined.\n");
            return 1;
        }
        if (choice == 'v') {
            std::printf("Paste peer's public key (base64): ");
            std::fflush(stdout);
            std::string pasted;
            std::getline(std::cin, pasted);
            auto dec = base64_decode(pasted);
            if (!dec || dec->size() != kWgKeyLen ||
                std::memcmp(dec->data(), rec.peer_pub.data(), kWgKeyLen) != 0) {
                std::printf("Key mismatch — aborting.\n");
                return 1;
            }
        }
        std::printf("Name for this peer: ");
        std::fflush(stdout);
        std::getline(std::cin, name);
        if (name.empty()) name = "peer";
    }

    rec.name = name;
    rec.created_unix = static_cast<int64_t>(std::time(nullptr));
    if (store_opt) {
        if (!store_opt->save(rec, &err)) {
            spl::logf("pairing failed: could not save: %s", err.c_str());
            return 1;
        }
    } else {
        spl::logf("warning: %s; pairing not persisted", err.c_str());
    }

    std::printf("Paired with '%s' (you are the %s). Peer key: %s\n", name.c_str(),
                is_leader ? "leader" : "follower", b64(rec.peer_pub).c_str());
    if (verbose) std::printf("  stored in %s\n", store_opt ? store_opt->dir().c_str() : "(none)");
    return 0;
}

void usage() {
    spl::logf(
        "usage:\n"
        "  spl pair [options]            generate a code and wait for a peer (leader)\n"
        "  spl pair <code> [options]     join using a peer's code (follower)\n"
        "options:\n"
        "  --server HOST   rendezvous server (default: 127.0.0.1)\n"
        "  --port N        server port (default: 7777)\n"
        "  --name NAME     accept non-interactively and store under NAME\n"
        "  -v, --verbose");
}

}  // namespace

int pair_main(int argc, char** argv) {
    std::string code_arg, server = "127.0.0.1", name;
    uint16_t port = 7777;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* n) -> const char* {
            if (i + 1 >= argc) {
                spl::logf("spl pair: missing value for %s", n);
                return nullptr;
            }
            return argv[++i];
        };
        if (a == "--server") {
            auto v = need("--server");
            if (!v) return 2;
            server = v;
        } else if (a == "--port") {
            auto v = need("--port");
            if (!v) return 2;
            port = static_cast<uint16_t>(std::atoi(v));
        } else if (a == "--name") {
            auto v = need("--name");
            if (!v) return 2;
            name = v;
        } else if (a == "-v" || a == "--verbose") {
            verbose = true;
        } else if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else if (!a.empty() && a[0] == '-') {
            spl::logf("spl pair: unknown option '%s'", a.c_str());
            usage();
            return 2;
        } else {
            code_arg = a;  // positional: the pairing code
        }
    }

    const bool is_leader = code_arg.empty();
    std::string err;

    auto ctx = net::TlsContext::client_insecure(&err);
    if (!ctx) {
        spl::logf("spl pair: tls: %s", err.c_str());
        return 1;
    }
    net::Fd fd = net::tcp_connect(server, port, &err);
    if (!fd) {
        spl::logf("spl pair: %s", err.c_str());
        return 1;
    }
    net::set_recv_timeout(fd.get(), 70000);
    auto conn = net::TlsConn::connect(*ctx, std::move(fd), "splice", &err);
    if (!conn) {
        spl::logf("spl pair: tls connect: %s", err.c_str());
        return 1;
    }

    std::string spake_code;
    if (is_leader) {
        Bytes initb = encode(Init{1});
        if (!net::write_frame(*conn, as_span(initb))) {
            spl::logf("spl pair: send failed");
            return 1;
        }
        auto f = net::read_frame(*conn, kMaxFrameLen);
        if (!f) {
            spl::logf("spl pair: no response from server");
            return 1;
        }
        auto m = decode_ctrl(as_span(*f));
        if (!m) {
            spl::logf("spl pair: bad server response");
            return 1;
        }
        if (std::holds_alternative<Error>(*m)) {
            spl::logf("spl pair: server: %s", std::get<Error>(*m).message.c_str());
            return 1;
        }
        if (!std::holds_alternative<Code>(*m)) {
            spl::logf("spl pair: unexpected server response");
            return 1;
        }
        const uint64_t pid = std::get<Code>(*m).code;
        const uint32_t ttl = std::get<Code>(*m).ttl_seconds;

        uint8_t rb[4];
        spl_random_bytes(rb, 4);
        uint32_t d =
            ((uint32_t(rb[0]) << 24) | (rb[1] << 16) | (rb[2] << 8) | rb[3]) % 1000000u;
        char code6[7];
        std::snprintf(code6, sizeof(code6), "%06u", d);
        spake_code = code6;

        std::printf("\nPairing code:  %llu-%s\n", static_cast<unsigned long long>(pid), code6);
        std::printf("On the other device run:  spl pair %llu-%s\n",
                    static_cast<unsigned long long>(pid), code6);
        std::printf("Waiting for peer (expires in %us)...\n", ttl);
        std::fflush(stdout);

        auto f2 = net::read_frame(*conn, kMaxFrameLen);
        if (!f2) {
            spl::logf("spl pair: timed out waiting for peer");
            return 1;
        }
        auto m2 = decode_ctrl(as_span(*f2));
        if (m2 && std::holds_alternative<Error>(*m2)) {
            spl::logf("spl pair: %s", std::get<Error>(*m2).message.c_str());
            return 1;
        }
        if (!m2 || !std::holds_alternative<Paired>(*m2)) {
            spl::logf("spl pair: pairing not established");
            return 1;
        }
    } else {
        auto dash = code_arg.find('-');
        if (dash == std::string::npos) {
            spl::logf("spl pair: code must look like <id>-<digits>");
            return 2;
        }
        uint64_t pid = std::strtoull(code_arg.substr(0, dash).c_str(), nullptr, 10);
        spake_code = code_arg.substr(dash + 1);

        Bytes joinb = encode(Join{pid});
        if (!net::write_frame(*conn, as_span(joinb))) {
            spl::logf("spl pair: send failed");
            return 1;
        }
        auto f = net::read_frame(*conn, kMaxFrameLen);
        if (!f) {
            spl::logf("spl pair: no response from server");
            return 1;
        }
        auto m = decode_ctrl(as_span(*f));
        if (m && std::holds_alternative<Error>(*m)) {
            spl::logf("spl pair: server: %s", std::get<Error>(*m).message.c_str());
            return 1;
        }
        if (!m || !std::holds_alternative<Paired>(*m)) {
            spl::logf("spl pair: pairing not established");
            return 1;
        }
        std::printf("Connected to peer, verifying...\n");
        std::fflush(stdout);
    }

    return run_pairing(*conn, is_leader, spake_code, name, verbose);
}

}  // namespace spl::peer
