#include "peer/pairing.h"

#include <openssl/crypto.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <functional>
#include <sstream>
#include <cctype>
#include <csignal>
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
#include "peer/daemon.h"
#include "peer/daemon_client.h"
#include "common/time.h"
#include "net/endpoint.h"
#include "peer/pathman.h"
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

// Constant-time equality for the key-confirmation MAC. A timing side channel here
// could help a malicious server (which can re-bridge/replay) probe the code.
bool mac_eq(const Mac& a, const Mac& b) { return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0; }

// Copy text to the system clipboard via whatever helper happens to be installed.
// A missing tool just means "false" — never fatal.
bool copy_to_clipboard(const std::string& text) {
    static const char* const tools[] = {
        "wl-copy",                       // Wayland
        "xclip -selection clipboard",    // X11
        "xsel --clipboard --input",      // X11
        "pbcopy",                        // macOS
        "clip.exe",                      // WSL / Windows
    };
    auto prev = std::signal(SIGPIPE, SIG_IGN);  // a missing tool closing the pipe must not kill us
    bool ok = false;
    for (const char* tool : tools) {
        std::string cmd = std::string(tool) + " >/dev/null 2>&1";
        FILE* p = ::popen(cmd.c_str(), "w");
        if (!p) continue;
        std::fwrite(text.data(), 1, text.size(), p);
        int rc = ::pclose(p);
        if (rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0) {
            ok = true;
            break;
        }
    }
    std::signal(SIGPIPE, prev);
    return ok;
}

// The framed byte stream the peer exchange runs over: the server's TLS bridge,
// or a plain TCP connection straight to the peer (local pairing).
struct Framed {
    std::function<bool(ByteSpan)> send;
    std::function<std::optional<Bytes>()> recv;
};

// Runs the post-PAIRED exchange. Returns 0 on success. `learned` are addresses
// this pairing found the peer at (local pairing): saved as address hints so the
// two can find each other afterwards where broadcast doesn't reach.
int run_pairing(const Framed& conn, bool is_leader, const std::string& spake_code,
                const std::string& preset_name, bool verbose,
                const std::vector<std::string>& learned = {}) {
    auto send_peer = [&](const PeerMessage& m) {
        Bytes b = encode_peer(m);
        return conn.send(as_span(b));
    };
    auto recv_peer = [&]() -> std::optional<PeerMessage> {
        auto f = conn.recv();
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
        if (!mac_eq(std::get<KeyConfirm>(*m).mac, macF)) {
            spl::logf("pairing failed: key confirmation mismatch (wrong code or tampering)");
            return 1;
        }
    } else {
        auto m = recv_peer();
        if (!m || !std::holds_alternative<KeyConfirm>(*m)) return protofail();
        if (!mac_eq(std::get<KeyConfirm>(*m).mac, macL)) {
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
            off.lan_port = own_lan_port();  // where we listen for LAN discovery
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
                rec.lan_port = rep.lan_port == kLanDiscoPort ? 0 : rep.lan_port;
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
            r.lan_port = own_lan_port();
            rec.lan_port = off.lan_port == kLanDiscoPort ? 0 : off.lan_port;
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

    // 5. Trust decision (accept / decline / verify), then persist. Both keys are
    //    shown so either side can confirm them out of band before accepting.
    std::string name = preset_name;
    if (name.empty()) {
        std::printf("\nPeer connected. Compare these keys out of band if you like:\n");
        std::printf("  Your key:  %s\n", b64(rec.own_pub).c_str());
        std::printf("  Their key: %s\n", b64(rec.peer_pub).c_str());
        for (;;) {
            std::printf("[a]ccept / [d]ecline / [v]erify (paste their key) / [c]opy your key? ");
            std::fflush(stdout);
            std::string line;
            if (!std::getline(std::cin, line)) {  // EOF / non-interactive: decline, never auto-trust
                std::printf("Declined (no confirmation; use --name to accept non-interactively).\n");
                return 1;
            }
            char choice = line.empty() ? 'a' : static_cast<char>(std::tolower(line[0]));
            if (choice == 'c') {
                if (copy_to_clipboard(b64(rec.own_pub)))
                    std::printf("Copied your public key to the clipboard.\n");
                else
                    std::printf("No clipboard tool found — copy your key above manually.\n");
                continue;  // re-prompt
            }
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
                std::printf("Match confirmed.\n");
            }
            break;  // accept
        }
        std::printf("Name for this peer: ");
        std::fflush(stdout);
        std::getline(std::cin, name);
        if (name.empty()) name = "peer";
    }

    rec.name = name;
    rec.created_unix = static_cast<int64_t>(std::time(nullptr));
    for (const auto& a : learned)
        if (parse_address_hint(a, nullptr, nullptr) &&
            std::find(rec.addresses.begin(), rec.addresses.end(), a) == rec.addresses.end())
            rec.addresses.push_back(a);
    if (store_opt) {
        if (!store_opt->save(rec, &err)) {
            spl::logf("pairing failed: could not save: %s", err.c_str());
            return 1;
        }
        notify_peers_changed();  // a running daemon picks the new peer up right away
    } else {
        spl::logf("warning: %s; pairing not persisted", err.c_str());
    }

    std::printf("Paired with '%s' (you are the %s). Peer key: %s\n", name.c_str(),
                is_leader ? "leader" : "follower", b64(rec.peer_pub).c_str());
    if (verbose) std::printf("  stored in %s\n", store_opt ? store_opt->dir().c_str() : "(none)");
    for (const auto& a : rec.addresses)
        std::printf("  will also look for '%s' at %s  (spl peer show %s)\n", name.c_str(),
                    a.c_str(), name.c_str());
    return 0;
}

// ---------------------------------------------------------------------------
// Local pairing: no server. The leader listens on the LAN; the follower finds
// it by broadcast (or is told where with --at) and connects straight to it.
// The rendezvous is unauthenticated on purpose — SPAKE2 is what authenticates,
// exactly as with the (equally untrusted) server. The code is "L<id>-<digits>":
// <id> is a random rendezvous id that travels in clear, <digits> the SPAKE2
// password that never does.
//
//   query  (UDP broadcast to the discovery port): "SPLP" | id[4] | nonce[8]
//   answer (UDP, to the asker):                   "SPLR" | id[4] | nonce[8] | tcp_port[2]
//   then TCP to the leader: frame JOIN{id} -> frame PAIRED (or ERR), then the
//   usual peer exchange over the same framing.
// ---------------------------------------------------------------------------

constexpr char kPairQuery[4] = {'S', 'P', 'L', 'P'};
constexpr char kPairAnswer[4] = {'S', 'P', 'L', 'R'};
constexpr int kLocalWaitSecs = 300;

bool plain_write_frame(int fd, ByteSpan payload) {
    Bytes f = encode_frame(payload);
    for (size_t off = 0; off < f.size();) {
        ssize_t w = ::write(fd, f.data() + off, f.size() - off);
        if (w <= 0) return false;
        off += static_cast<size_t>(w);
    }
    return true;
}
bool read_exact(int fd, uint8_t* p, size_t n) {
    for (size_t off = 0; off < n;) {
        ssize_t r = ::recv(fd, p + off, n - off, 0);
        if (r <= 0) return false;  // EOF, error or timeout
        off += static_cast<size_t>(r);
    }
    return true;
}
std::optional<Bytes> plain_read_frame(int fd) {
    uint8_t hdr[4];
    if (!read_exact(fd, hdr, 4)) return std::nullopt;
    const uint32_t len =
        (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16) | (uint32_t(hdr[2]) << 8) | hdr[3];
    if (len > kMaxFrameLen) return std::nullopt;
    Bytes p(len);
    if (len && !read_exact(fd, p.data(), len)) return std::nullopt;
    return p;
}
Framed framed_plain(int fd) {
    return Framed{[fd](ByteSpan b) { return plain_write_frame(fd, b); },
                  [fd] { return plain_read_frame(fd); }};
}

uint16_t env_port(const char* name, uint16_t dflt) {
    const char* v = std::getenv(name);
    const int n = v ? std::atoi(v) : 0;
    return n > 0 && n < 65536 ? static_cast<uint16_t>(n) : dflt;
}

// "1.2.3.4:5" / "[fd00::1]:5" -> "1.2.3.4" / "fd00::1"
std::string host_of(const Endpoint& ep) {
    std::string host;
    parse_address_hint(ep.to_string(), &host, nullptr);
    return host;
}

void put_u32(Bytes& b, uint32_t v) {
    for (int i = 3; i >= 0; --i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

int pair_local_leader(const std::string& name, bool verbose) {
    std::signal(SIGPIPE, SIG_IGN);  // a peer hanging up mid-write must not kill us
    std::string err;
    const uint16_t udp_port = own_lan_port();
    net::Fd udp = net::udp_bind_shared(udp_port, &err);
    if (udp) net::set_nonblocking(udp.get(), true);

    // The well-known port lets `--at <host>` work with no port; if another
    // pairing on this machine holds it, any port will do (we print it).
    const char* forced = std::getenv("SPL_LAN_PAIR_PORT");
    net::Fd lst = net::tcp_listen("", env_port("SPL_LAN_PAIR_PORT", udp_port), 4, &err);
    if (!lst && !forced) lst = net::tcp_listen("", 0, 4, &err);
    if (!lst) {
        spl::logf("spl pair: cannot listen for a local pairing: %s", err.c_str());
        return 1;
    }
    const uint16_t tcp_port = net::local_port(lst.get());

    uint8_t rb[8];
    spl_random_bytes(rb, sizeof(rb));
    const uint32_t id = 10 + ((uint32_t(rb[0]) << 8) | rb[1]) % 90;  // 10..99
    const uint32_t d =
        ((uint32_t(rb[2]) << 24) | (rb[3] << 16) | (rb[4] << 8) | rb[5]) % 1000000u;
    char code6[7];
    std::snprintf(code6, sizeof(code6), "%06u", d);
    char code[24];
    std::snprintf(code, sizeof(code), "L%u-%s", id, code6);

    const std::string port_sfx = tcp_port == kLanPairPort ? "" : ":" + std::to_string(tcp_port);
    std::printf("\nPairing code:  %s\n", code);
    std::printf("(local pairing: works on this network, no relay involved)\n\n");
    std::printf("On the other device:\n");
    // A follower asks on the default port unless told ours.
    const std::string lan_flag =
        udp_port == kLanDiscoPort ? "" : " --lan-port " + std::to_string(udp_port);
    if (udp)
        std::printf("  %-17s spl pair %s%s\n", "same network:", code, lan_flag.c_str());
    else
        std::printf("  (discovery port %u is unavailable: use one of the --at lines)\n", udp_port);
    const auto addrs = net::local_interface_addresses();
    for (size_t i = 0; i < addrs.size(); ++i) {
        const bool v6 = addrs[i].host.find(':') != std::string::npos;
        const std::string at = (v6 && !port_sfx.empty() ? "[" + addrs[i].host + "]" : addrs[i].host) +
                               port_sfx;
        std::printf("  %-17s spl pair %s --at %s   (%s)\n", i == 0 ? "somewhere else:" : "", code,
                    at.c_str(), addrs[i].ifname.c_str());
    }
    std::printf("Waiting for peer (expires in %ds)...\n", kLocalWaitSecs);
    std::fflush(stdout);

    const Millis deadline = mono_ms() + kLocalWaitSecs * 1000;
    while (mono_ms() < deadline) {
        pollfd pf[2] = {{lst.get(), POLLIN, 0}, {udp ? udp.get() : -1, POLLIN, 0}};
        if (::poll(pf, 2, 500) <= 0) continue;

        if (pf[1].revents & POLLIN) {  // "who has rendezvous <id>?" -> our TCP port
            for (;;) {
                uint8_t buf[64];
                sockaddr_storage ss{};
                socklen_t slen = sizeof(ss);
                ssize_t n = ::recvfrom(udp.get(), buf, sizeof(buf), 0,
                                       reinterpret_cast<sockaddr*>(&ss), &slen);
                if (n < 0) break;
                if (n != 16 || std::memcmp(buf, kPairQuery, 4) != 0) continue;
                const uint32_t qid = (uint32_t(buf[4]) << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
                if (qid != id) continue;
                Bytes ans(kPairAnswer, kPairAnswer + 4);
                ans.insert(ans.end(), buf + 4, buf + 16);  // id + nonce, echoed
                ans.push_back(static_cast<uint8_t>(tcp_port >> 8));
                ans.push_back(static_cast<uint8_t>(tcp_port));
                ::sendto(udp.get(), ans.data(), ans.size(), 0, reinterpret_cast<sockaddr*>(&ss),
                         slen);
            }
        }
        if (pf[0].revents & POLLIN) {
            Endpoint from;
            net::Fd c = net::tcp_accept(lst.get(), &from);
            if (!c) continue;
            net::set_recv_timeout(c.get(), 5000);  // a silent connection can't hold us up
            auto f = plain_read_frame(c.get());
            auto m = f ? decode_ctrl(as_span(*f)) : std::nullopt;
            if (!m || !std::holds_alternative<Join>(*m) || std::get<Join>(*m).code != id) {
                Bytes e = encode(Error{6, "unknown pairing code"});
                plain_write_frame(c.get(), as_span(e));
                continue;  // not ours: keep waiting
            }
            Bytes ok = encode(Paired{});
            if (!plain_write_frame(c.get(), as_span(ok))) continue;
            std::printf("Connected to peer (%s), verifying...\n", host_of(from).c_str());
            std::fflush(stdout);
            net::set_recv_timeout(c.get(), 70000);
            return run_pairing(framed_plain(c.get()), /*is_leader=*/true, code6, name, verbose,
                               {host_of(from)});
        }
    }
    spl::logf("spl pair: pairing code expired");
    return 1;
}

int pair_local_follower(const std::string& code_arg, const std::string& at, uint16_t lan_port,
                        const std::string& name, bool verbose) {
    const auto dash = code_arg.find('-');
    if (dash == std::string::npos || dash < 2) {
        spl::logf("spl pair: a local code looks like L<id>-<digits>");
        return 2;
    }
    const uint32_t id = static_cast<uint32_t>(std::strtoul(code_arg.substr(1, dash - 1).c_str(),
                                                           nullptr, 10));
    const std::string spake_code = code_arg.substr(dash + 1);
    std::signal(SIGPIPE, SIG_IGN);

    std::string err, peer_host;
    net::Fd c;
    if (!at.empty()) {
        uint16_t port = 0;
        if (!parse_address_hint(at, &peer_host, &port)) {
            spl::logf("spl pair: --at takes a host or IP, optionally with a port");
            return 2;
        }
        c = net::tcp_connect(peer_host, port ? port : kLanPairPort, &err, 5000);
        if (!c) {
            spl::logf("spl pair: nothing is pairing at %s (%s)", at.c_str(), err.c_str());
            return 1;
        }
    } else {
        // Ask the local networks who holds this rendezvous id.
        net::Fd udp = net::udp_bind("", 0, &err);
        if (!udp) {
            spl::logf("spl pair: %s", err.c_str());
            return 1;
        }
        net::set_broadcast(udp.get());
        net::set_nonblocking(udp.get(), true);
        // The leader's discovery port: the default unless it told us (--lan-port).
        const uint16_t dport = lan_port ? lan_port : kLanDiscoPort;
        std::vector<Endpoint> fixed;  // SPL_LAN_TARGETS (tests): instead of broadcasting
        if (const char* v = std::getenv("SPL_LAN_TARGETS")) {
            std::istringstream is(v);
            std::string item;
            while (std::getline(is, item, ',')) {
                std::string h;
                uint16_t p = 0;
                if (parse_address_hint(item, &h, &p))
                    if (auto ep = net::resolve(h, p ? p : dport)) fixed.push_back(*ep);
            }
        }
        Bytes q(kPairQuery, kPairQuery + 4);
        put_u32(q, id);
        uint8_t nonce[8];
        spl_random_bytes(nonce, sizeof(nonce));
        q.insert(q.end(), nonce, nonce + 8);

        std::printf("Looking for the other device on the local network...\n");
        std::fflush(stdout);
        const Millis deadline = mono_ms() + 10000;
        while (!c && mono_ms() < deadline) {
            for (const auto& t : fixed.empty() ? net::broadcast_endpoints(dport) : fixed) {
                sockaddr_storage ss{};
                socklen_t len = 0;
                sockaddr_from_endpoint(t, &ss, &len);
                ::sendto(udp.get(), q.data(), q.size(), 0, reinterpret_cast<sockaddr*>(&ss), len);
            }
            pollfd pf{udp.get(), POLLIN, 0};
            if (::poll(&pf, 1, 400) <= 0) continue;
            for (;;) {
                uint8_t buf[64];
                sockaddr_storage ss{};
                socklen_t slen = sizeof(ss);
                ssize_t n = ::recvfrom(udp.get(), buf, sizeof(buf), 0,
                                       reinterpret_cast<sockaddr*>(&ss), &slen);
                if (n < 0) break;
                if (n != 18 || std::memcmp(buf, kPairAnswer, 4) != 0 ||
                    std::memcmp(buf + 4, q.data() + 4, 12) != 0)
                    continue;  // not an answer to *our* query
                const uint16_t tport = static_cast<uint16_t>((buf[16] << 8) | buf[17]);
                peer_host = host_of(endpoint_from_sockaddr(ss));
                c = net::tcp_connect(peer_host, tport, &err, 5000);
                if (c) break;
            }
        }
        if (!c) {
            spl::logf("spl pair: no device with that code on this network.\n"
                      "  If it's on another network (a VPN, Tailscale…), tell spl where it is:\n"
                      "    spl pair %s --at <its address>   (the other device lists them)",
                      code_arg.c_str());
            return 1;
        }
    }

    net::set_recv_timeout(c.get(), 70000);
    Bytes joinb = encode(Join{id});
    auto f = plain_write_frame(c.get(), as_span(joinb)) ? plain_read_frame(c.get()) : std::nullopt;
    auto m = f ? decode_ctrl(as_span(*f)) : std::nullopt;
    if (m && std::holds_alternative<Error>(*m)) {
        spl::logf("spl pair: %s (is the code right, and still waiting?)",
                  std::get<Error>(*m).message.c_str());
        return 1;
    }
    if (!m || !std::holds_alternative<Paired>(*m)) {
        spl::logf("spl pair: pairing not established");
        return 1;
    }
    std::printf("Connected to peer (%s), verifying...\n", peer_host.c_str());
    std::fflush(stdout);
    return run_pairing(framed_plain(c.get()), /*is_leader=*/false, spake_code, name, verbose,
                       {peer_host});
}

void usage() {
    spl::logf(
        "usage:\n"
        "  spl pair [options]            generate a code and wait for a peer (leader)\n"
        "  spl pair <code> [options]     join using a peer's code (follower)\n"
        "options:\n"
        "  --server HOST   rendezvous server (default: splice.kussowski.dev)\n"
        "  --port N        server port (default: 443)\n"
        "  --name NAME     accept non-interactively and store under NAME\n"
        "  --local         pair over the local network, without the relay (also what\n"
        "                  happens by itself when the relay can't be reached)\n"
        "  --at HOST       (joining a local code) where the other device is, when it\n"
        "                  isn't on the same network: a VPN/Tailscale address or name\n"
        "  --lan-port N    (joining a local code) the other device's LAN port, if it\n"
        "                  isn't the default (it tells you when that's needed)\n"
        "  -v, --verbose\n"
        "A code starting with L (L37-481922) is a local one.");
}

}  // namespace

int pair_main(int argc, char** argv) {
    DaemonOpts dopts = default_daemon_opts();
    std::string code_arg, server = dopts.server, name, at;
    uint16_t port = dopts.port;
    bool verbose = false, insecure = false, local = false;
    uint16_t lan_port = 0;

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
        } else if (a == "--at") {
            auto v = need("--at");
            if (!v) return 2;
            at = v;
        } else if (a == "--lan-port") {
            auto v = need("--lan-port");
            if (!v) return 2;
            lan_port = static_cast<uint16_t>(std::atoi(v));
        } else if (a == "--local") {
            local = true;
        } else if (a == "--insecure") {
            insecure = true;
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

    // A code starting with L was made by a leader pairing locally: join it there.
    if (!is_leader && (code_arg[0] == 'L' || code_arg[0] == 'l'))
        return pair_local_follower(code_arg, at, lan_port, name, verbose);
    if (!at.empty() || lan_port) {
        spl::logf("spl pair: --at / --lan-port only apply when joining a local code (L…)");
        return 2;
    }
    if (is_leader && local) return pair_local_leader(name, verbose);

    auto ctx = net::TlsContext::client(&err);
    if (!ctx) {
        spl::logf("spl pair: tls: %s", err.c_str());
        return 1;
    }
    net::Fd fd = net::tcp_connect(server, port, &err, 5000);
    if (!fd) {
        if (is_leader) {  // no relay: pairing still works on the local network
            std::fprintf(stderr, "spl pair: can't reach the relay %s (%s) — pairing locally.\n",
                         server.c_str(), err.c_str());
            return pair_local_leader(name, verbose);
        }
        spl::logf("spl pair: can't reach the relay %s (%s).\n"
                  "  That code needs it. With no relay, run `spl pair --local` on the other\n"
                  "  device: it gives a local code (starting with L).",
                  server.c_str(), err.c_str());
        return 1;
    }
    net::set_recv_timeout(fd.get(), 70000);
    auto conn = net::TlsConn::connect(*ctx, std::move(fd), server, &err);
    if (!conn) {
        spl::logf("spl pair: tls connect: %s", err.c_str());
        return 1;
    }
    if (conn->verify_result() != 0) {  // not X509_V_OK
        std::string why = net::tls_verify_error(conn->verify_result());
        if (insecure) {
            if (verbose)
                spl::logf("[tls] server cert unverified (%s); continuing (--insecure)",
                          why.c_str());
        } else {
            std::fprintf(stderr,
                         "\n!! WARNING: could not verify the TLS certificate of server '%s'.\n"
                         "   Reason: %s\n"
                         "   The connection is ENCRYPTED but NOT AUTHENTICATED -- you may be\n"
                         "   talking to an impostor relay. Your pairing code (SPAKE2) still\n"
                         "   protects the pairing itself; a fake server can only disrupt it.\n"
                         "   Continue anyway? [y/N] ",
                         server.c_str(), why.c_str());
            std::fflush(stderr);
            std::string line;
            std::getline(std::cin, line);
            if (line.empty() || (line[0] != 'y' && line[0] != 'Y')) {
                spl::logf("aborted (use --insecure to skip this check).");
                return 1;
            }
        }
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

    net::TlsConn& tc = *conn;
    const Framed framed{[&tc](ByteSpan b) { return net::write_frame(tc, b); },
                        [&tc] { return net::read_frame(tc, kMaxFrameLen); }};
    return run_pairing(framed, is_leader, spake_code, name, verbose);
}

}  // namespace spl::peer
