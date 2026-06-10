#include "peer/daemon.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <vector>

#include "common/config.h"
#include "common/log.h"
#include "common/time.h"
#include "net/poller.h"
#include "net/socket.h"
#include "peer/netstack.h"
#include "peer/pathman.h"
#include "peer/pipes.h"
#include "peer/store.h"

namespace spl::peer {

namespace {

constexpr uint16_t kPipePort = 7700;  // the one tunnel port pipes ride on
constexpr size_t kChunk = 4096;
constexpr Millis kDialRetryMs = 500;
constexpr Millis kDialDeadlineMs = 15000;
// "diagnostic" is implicit on every peer: always an ECHO, never stored, never
// unregisterable — so RESET trivially keeps it.
constexpr const char* kDiagPipe = "diagnostic";

std::atomic<bool> g_dstop{false};
void on_dsig(int) { g_dstop.store(true); }

void write_all(int fd, const void* p, size_t n) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    size_t off = 0;
    while (off < n) {
        ssize_t w = ::write(fd, b + off, n - off);
        if (w <= 0) return;
        off += static_cast<size_t>(w);
    }
}
void write_str(int fd, const std::string& s) { write_all(fd, s.data(), s.size()); }

std::vector<std::string> split_ws(const std::string& line) {
    std::vector<std::string> out;
    std::istringstream is(line);
    std::string t;
    while (is >> t) out.push_back(t);
    return out;
}

// One live spliced connection (an instance of a pipe pair).
struct Instance {
    uint64_t id = 0;
    bool inbound = false;     // spawned by our listening pipe (vs created by OPEN)
    std::string reg;          // inbound: name of the listening pipe that spawned us
    std::string want;         // outbound: remote pipe id to request
    std::string type;         // local end type name (for status)
    TcpConn* conn = nullptr;  // tunnel side (owned by the session's Netstack)
    bool open = false;        // handshake finished, splicing
    std::string lbuf;         // handshake line buffer
    std::unique_ptr<LocalEnd> local;  // daemon-owned local end…
    int cfd = -1;                     // …or a bridged client socket (PIPE)
    bool cfd_owned = false;   // OPEN-PIPE owns its fd; inbound-PIPE shares the owner's
    bool cfd_watch = false;   // currently registered with the poller
    uint64_t up = 0, down = 0;  // bytes local->peer / peer->local
    Millis next_dial = 0, dial_deadline = 0;
    bool dialing = false;
    bool wait = false;  // OPEN WAIT: UNKNOWN means "not yet" — re-dial until closed
};

// A live PIPE registration: a client process's socket waiting for connections.
// (Daemon-owned types — ECHO, files — persist in the Store instead.)
struct PipeReg {
    int owner_fd = -1;
};

struct Session {
    std::string name;
    ConnRecord rec;
    proto::Ip6 own{}, peer{};
    std::unique_ptr<PathManager> pm;
    std::unique_ptr<Netstack> ns;
    std::map<std::string, PipeReg> pipe_regs;       // live PIPE registrations
    std::map<std::string, uint64_t> finished;       // per listening-pipe completion counters
    std::map<uint64_t, std::unique_ptr<Instance>> insts;
    uint64_t next_id = 0;
    // Instances whose LocalEnd asked to shut down. Drained by tick(): a local
    // end must never be destroyed while one of its own methods is on the stack.
    std::vector<uint64_t> want_close;
};

class Daemon {
 public:
    explicit Daemon(DaemonOpts opts) : opts_(std::move(opts)) {}
    int run();

 private:
    // --- sessions / data plane ---
    Session* session_for(const std::string& peer, std::string* err);
    bool start_session(const ConnRecord& rec, std::string* err);
    void accept_inbound(Session& s, TcpConn* c);
    void on_tunnel_data(Session& s, uint64_t id, ByteSpan b);
    void on_tunnel_gone(Session& s, uint64_t id);
    void bind_end(Session& s, Instance& in);  // handshake done: start splicing
    void dial(Session& s, Instance& in, Millis now);
    void route_to_tunnel(Session& s, Instance& in, ByteSpan b);
    void close_instance(Session& s, uint64_t id, bool finished);
    void watch_cfd(Session& s, Instance& in);
    void close_reg_instances(Session& s, const std::string& name);
    void unregister_pipe(Session& s, const std::string& name);
    void tick(Millis now);

    // --- control plane ---
    void accept_ctl();
    void on_ctl_readable(int fd);
    void handle_cmd(int fd, const std::string& line);  // may adopt fd (PIPE)
    void drop_ctl(int fd, bool close_fd);
    std::string render_status(Millis now);

    DaemonOpts opts_;
    Endpoint server_{};
    std::optional<Store> store_;
    net::Poller poller_;
    int lfd_ = -1;  // unix listen socket
    std::map<std::string, Session> sessions_;
    std::map<int, std::string> ctl_;  // control conns mid-command: fd -> line buffer
};

// ---------------- sessions ----------------

bool Daemon::start_session(const ConnRecord& rec, std::string* err) {
    Session& s = sessions_[rec.name];
    s.name = rec.name;
    s.rec = rec;
    s.own = rec.ula_base;
    s.own[15] = rec.side ? 2 : 1;
    s.peer = rec.ula_base;
    s.peer[15] = rec.side ? 1 : 2;

    net::Fd udp = net::udp_bind("", 0, err);
    if (!udp) {
        sessions_.erase(rec.name);
        return false;
    }
    PathConfig cfg;
    cfg.uid = rec.uid;
    cfg.own_priv = rec.own_priv;
    cfg.peer_pub = rec.peer_pub;
    cfg.server = server_;
    s.pm = std::make_unique<PathManager>(std::move(udp), cfg);
    s.ns = std::make_unique<Netstack>();
    s.ns->configure(s.own);
    PathManager* pm = s.pm.get();
    Netstack* ns = s.ns.get();
    pm->on_inner = [ns](ByteSpan inner, Path) { ns->input(inner); };
    ns->on_output = [pm](ByteSpan ip) { pm->send_inner(ip); };
    poller_.set(pm->fd(), [pm] { pm->handle_io(mono_ms()); });
    s.ns->listen(kPipePort, [this, &s](TcpConn* c) { accept_inbound(s, c); });
    if (getenv("SPL_FORCE_RELAY")) pm->set_force_relay(true);  // test hook
    return true;
}

Session* Daemon::session_for(const std::string& peer, std::string* err) {
    auto it = sessions_.find(peer);
    if (it != sessions_.end()) return &it->second;
    // Paired after daemon start? Pick it up from the store.
    if (!store_) {
        if (err) *err = "no config store";
        return nullptr;
    }
    auto rec = store_->load(peer);
    if (!rec) {
        if (err) *err = "no peer named '" + peer + "'";
        return nullptr;
    }
    if (!start_session(*rec, err)) return nullptr;
    return &sessions_[peer];
}

void Daemon::accept_inbound(Session& s, TcpConn* c) {
    const uint64_t id = s.next_id++;
    auto in = std::make_unique<Instance>();
    in->id = id;
    in->inbound = true;
    in->conn = c;
    s.insts[id] = std::move(in);
    c->on_recv = [this, &s, id](ByteSpan b) { on_tunnel_data(s, id, b); };
    c->on_closed = [this, &s, id] { on_tunnel_gone(s, id); };
    c->on_error = [this, &s, id] { on_tunnel_gone(s, id); };
}

// Handshake done (inbound resolved a known name / outbound got OK): wire the
// local end and start splicing.
void Daemon::bind_end(Session& s, Instance& in) {
    in.open = true;
    Session* sp = &s;
    const uint64_t id = in.id;
    if (in.cfd >= 0) {
        // Only pump fds we own (OPEN-PIPE). An inbound PIPE instance shares the
        // registration owner's fd, whose one and only reader is the broadcast
        // callback installed at REGISTER — never watch it per-instance.
        if (in.cfd_owned) {
            in.conn->on_writable = [this, sp, id] {
                auto it = sp->insts.find(id);
                if (it == sp->insts.end()) return;
                Instance& in = *it->second;
                if (!in.cfd_watch && in.conn && in.conn->sndbuf() >= kChunk) watch_cfd(*sp, in);
            };
            watch_cfd(s, in);
        }
        return;
    }
    if (in.local) {
        Instance* ip = &in;
        TcpConn* conn = in.conn;
        in.local->to_tunnel = [this, sp, ip](ByteSpan b) { route_to_tunnel(*sp, *ip, b); };
        in.local->tunnel_space = [conn]() -> size_t { return conn->sndbuf(); };
        // Deferred: the end may call shutdown from inside its own methods.
        in.local->shutdown = [sp, id] { sp->want_close.push_back(id); };
        conn->on_writable = [this, sp, id] {
            auto it = sp->insts.find(id);
            if (it != sp->insts.end() && it->second->local) it->second->local->on_tunnel_writable();
        };
        in.local->start();
    }
}

void Daemon::route_to_tunnel(Session& s, Instance& in, ByteSpan b) {
    if (!in.conn || !in.open) return;
    in.up += b.size();
    in.conn->send(b);
}

void Daemon::on_tunnel_data(Session& s, uint64_t id, ByteSpan b) {
    auto it = s.insts.find(id);
    if (it == s.insts.end()) return;
    Instance& in = *it->second;

    if (!in.open) {  // still handshaking: accumulate one line
        in.lbuf.append(reinterpret_cast<const char*>(b.data()), b.size());
        const size_t nl = in.lbuf.find('\n');
        if (nl == std::string::npos) {
            if (in.lbuf.size() > 256) close_instance(s, id, false);  // garbage, not a line
            return;
        }
        std::string line = in.lbuf.substr(0, nl);
        std::string rest = in.lbuf.substr(nl + 1);
        in.lbuf.clear();

        if (in.inbound) {
            // Resolve the requested name: implicit diagnostic, then live PIPE
            // registrations, then the persistent registrations on disk.
            in.reg = line;
            if (line == kDiagPipe) {
                in.type = "ECHO";
                in.local = make_local_end("ECHO", {}, nullptr);
            } else if (auto pit = s.pipe_regs.find(line); pit != s.pipe_regs.end()) {
                in.type = "PIPE";
                in.cfd = pit->second.owner_fd;  // shared with the registration
            } else if (auto rec = store_ ? store_->load_pipe(s.name, line) : std::nullopt) {
                in.type = rec->type;
                in.local = make_local_end(rec->type, rec->args, nullptr);
            }
            if (!in.local && in.cfd < 0) {
                in.conn->send(as_span(std::string("UNKNOWN\n")));
                close_instance(s, id, false);
                return;
            }
            in.conn->send(as_span(std::string("OK\n")));
            bind_end(s, in);
        } else {
            if (line != "OK") {  // UNKNOWN or garbage
                if (in.wait && in.conn) {  // not registered yet: drop this conn, re-dial
                    in.conn->on_recv = nullptr;
                    in.conn->on_closed = nullptr;
                    in.conn->on_error = nullptr;
                    in.conn->close();
                    in.conn = nullptr;
                    in.next_dial = mono_ms() + 1000;
                    return;
                }
                close_instance(s, id, false);
                return;
            }
            bind_end(s, in);
        }
        if (!rest.empty()) on_tunnel_data(s, id, as_span(rest));
        return;
    }

    in.down += b.size();
    if (in.local) {
        in.local->on_tunnel_data(b);
    } else if (in.cfd >= 0) {
        write_all(in.cfd, b.data(), b.size());
    }
}

void Daemon::on_tunnel_gone(Session& s, uint64_t id) {
    auto it = s.insts.find(id);
    if (it == s.insts.end()) return;
    Instance& in = *it->second;
    in.conn = nullptr;  // pcb is gone; do not touch it again
    if (!in.inbound && !in.open) return;  // dial attempt failed; tick retries it
    if (in.local) in.local->on_tunnel_closed();
    close_instance(s, id, true);
}

void Daemon::dial(Session& s, Instance& in, Millis now) {
    in.dialing = true;
    in.next_dial = now + kDialRetryMs;
    Instance* ip = &in;
    Session* sp = &s;
    const uint64_t id = in.id;
    s.ns->connect(
        s.peer, kPipePort,
        [this, sp, ip, id](TcpConn* c) {
            ip->conn = c;
            ip->dialing = false;
            c->on_recv = [this, sp, id](ByteSpan b) { on_tunnel_data(*sp, id, b); };
            c->on_closed = [this, sp, id] { on_tunnel_gone(*sp, id); };
            c->on_error = [this, sp, id] { on_tunnel_gone(*sp, id); };
            c->send(as_span(ip->want + "\n"));
        },
        [ip] {  // this attempt failed; tick re-dials until the deadline
            ip->conn = nullptr;
            ip->dialing = false;
        });
}

void Daemon::watch_cfd(Session& s, Instance& in) {
    if (in.cfd < 0 || in.cfd_watch) return;
    in.cfd_watch = true;
    Session* sp = &s;
    const uint64_t id = in.id;
    poller_.set(in.cfd, [this, sp, id] {
        auto it = sp->insts.find(id);
        if (it == sp->insts.end()) return;
        Instance& in = *it->second;
        // Backpressure: when the tunnel send buffer is full, stop reading the
        // client; tick() resumes us once space frees up.
        if (in.conn && in.conn->sndbuf() < kChunk) {
            poller_.remove(in.cfd);
            in.cfd_watch = false;
            return;
        }
        uint8_t buf[kChunk];
        ssize_t n = ::read(in.cfd, buf, sizeof(buf));
        if (n <= 0) {  // client went away -> the pipe dies
            close_instance(*sp, id, true);
            return;
        }
        route_to_tunnel(*sp, in, ByteSpan(buf, static_cast<size_t>(n)));
    });
}

void Daemon::close_instance(Session& s, uint64_t id, bool finished) {
    auto it = s.insts.find(id);
    if (it == s.insts.end()) return;
    Instance& in = *it->second;
    if (in.cfd >= 0 && in.cfd_owned) {  // a shared (owner) fd is the registration's
        if (in.cfd_watch) poller_.remove(in.cfd);
        ::close(in.cfd);
    }
    if (in.conn) {
        in.conn->on_recv = nullptr;
        in.conn->on_closed = nullptr;
        in.conn->on_error = nullptr;
        in.conn->on_writable = nullptr;
        in.conn->close();
    }
    if (in.inbound && finished) ++s.finished[in.reg];
    s.insts.erase(it);
}

void Daemon::close_reg_instances(Session& s, const std::string& name) {
    std::vector<uint64_t> victims;
    for (auto& [id, in] : s.insts)
        if (in->inbound && in->reg == name) victims.push_back(id);
    for (uint64_t id : victims) close_instance(s, id, false);
}

void Daemon::unregister_pipe(Session& s, const std::string& name) {
    auto it = s.pipe_regs.find(name);
    if (it == s.pipe_regs.end()) return;
    close_reg_instances(s, name);
    poller_.remove(it->second.owner_fd);
    ::close(it->second.owner_fd);
    s.pipe_regs.erase(it);
}

void Daemon::tick(Millis now) {
    for (auto& [name, s] : sessions_) {
        s.pm->tick(now);
        s.ns->check_timeouts();

        for (size_t i = 0; i < s.want_close.size(); ++i)  // ends may queue more
            close_instance(s, s.want_close[i], true);
        s.want_close.clear();

        std::vector<uint64_t> expired;
        for (auto& [id, inp] : s.insts) {
            Instance& in = *inp;
            // Outbound dial retries (the peer's daemon may still be warming up).
            if (!in.inbound && !in.open && !in.conn && !in.dialing) {
                if (now >= in.dial_deadline)
                    expired.push_back(id);
                else if (now >= in.next_dial)
                    dial(s, in, now);
            }
            // Resume client sockets paused for backpressure (owned fds only).
            if (in.open && in.cfd >= 0 && in.cfd_owned && !in.cfd_watch && in.conn &&
                in.conn->sndbuf() >= kChunk)
                watch_cfd(s, in);
            if (in.local) in.local->tick(now);
        }
        for (uint64_t id : expired) close_instance(s, id, false);
    }
}

// ---------------- control plane ----------------

void Daemon::accept_ctl() {
    for (;;) {
        int fd = ::accept(lfd_, nullptr, nullptr);
        if (fd < 0) return;
        ctl_[fd] = "";
        poller_.set(fd, [this, fd] { on_ctl_readable(fd); });
    }
}

void Daemon::drop_ctl(int fd, bool close_fd) {
    poller_.remove(fd);
    ctl_.erase(fd);
    if (close_fd) ::close(fd);
}

void Daemon::on_ctl_readable(int fd) {
    char buf[512];
    ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n <= 0) {
        drop_ctl(fd, true);
        return;
    }
    std::string& acc = ctl_[fd];
    acc.append(buf, static_cast<size_t>(n));
    if (acc.size() > 4096) {
        drop_ctl(fd, true);
        return;
    }
    const size_t nl = acc.find('\n');
    if (nl == std::string::npos) return;
    std::string line = acc.substr(0, nl);
    handle_cmd(fd, line);
}

void Daemon::handle_cmd(int fd, const std::string& line) {
    auto t = split_ws(line);
    for (auto& tok : t) tok = ctl_decode(tok);
    auto reply_close = [&](const std::string& r) {
        write_str(fd, r);
        drop_ctl(fd, true);
    };
    if (t.empty()) return reply_close("ERR empty command\n");
    const std::string& cmd = t[0];

    if (cmd == "PING") return reply_close("OK\n");
    if (cmd == "STOP") {
        g_dstop.store(true);
        return reply_close("OK\n");
    }
    if (cmd == "STATUS") return reply_close("OK\n" + render_status(mono_ms()));

    if (cmd == "FORCE_RELAY") {  // debug/test: pin a session to the relay (1) or release (0)
        if (t.size() != 3) return reply_close("ERR usage: FORCE_RELAY <peer> <0|1>\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) return reply_close("ERR " + err + "\n");
        s->pm->set_force_relay(t[2] == "1");
        return reply_close("OK\n");
    }

    if (cmd == "RESET") {  // drop every pipe everywhere; only diagnostic remains
        for (auto& [name, s] : sessions_) {
            std::vector<uint64_t> ids;
            for (auto& [id, in] : s.insts) ids.push_back(id);
            for (uint64_t id : ids) close_instance(s, id, false);
            std::vector<std::string> regs;
            for (auto& [rname, reg] : s.pipe_regs) regs.push_back(rname);
            for (const auto& rname : regs) unregister_pipe(s, rname);
            s.finished.clear();
        }
        if (store_) store_->wipe_pipes();
        return reply_close("OK\n");
    }

    if (cmd == "REGISTER") {
        if (t.size() < 4) return reply_close("ERR usage: REGISTER <peer> <id> <TYPE> [args]\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) return reply_close("ERR " + err + "\n");
        const std::string& name = t[2];
        if (name == kDiagPipe) return reply_close("ERR '" + name + "' is reserved\n");
        const bool taken = s->pipe_regs.count(name) ||
                           (store_ && store_->load_pipe(s->name, name).has_value());
        if (taken) return reply_close("ERR pipe '" + name + "' already exists\n");

        const std::string& type = t[3];
        std::vector<std::string> args(t.begin() + 4, t.end());
        if (type == "PIPE") {
            if (!args.empty()) return reply_close("ERR PIPE takes no arguments\n");
            write_str(fd, "OK\n");
            poller_.remove(fd);
            ctl_.erase(fd);  // the connection now is the pipe's local end
            s->pipe_regs[name] = PipeReg{fd};
            Session* sp = s;
            poller_.set(fd, [this, sp, name, fd] {
                // Bytes from the owner go to every active instance of this pipe
                // (one for chat; interleaving with several is the user's choice).
                uint8_t buf[kChunk];
                ssize_t n = ::read(fd, buf, sizeof(buf));
                if (n <= 0) {  // owner process went away -> pipe and instances die
                    unregister_pipe(*sp, name);
                    return;
                }
                for (auto& [id, in] : sp->insts)
                    if (in->inbound && in->reg == name && in->open)
                        route_to_tunnel(*sp, *in, ByteSpan(buf, static_cast<size_t>(n)));
            });
            return;
        }
        std::string terr;
        if (!make_local_end(type, args, &terr)) return reply_close("ERR " + terr + "\n");
        if (!store_) return reply_close("ERR no config store\n");
        if (!store_->save_pipe(PipeRecord{s->name, name, type, args}, &terr))
            return reply_close("ERR " + terr + "\n");
        return reply_close("OK\n");
    }

    if (cmd == "UNREGISTER") {
        if (t.size() != 3) return reply_close("ERR usage: UNREGISTER <peer> <id>\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) return reply_close("ERR " + err + "\n");
        const std::string& name = t[2];
        if (name == kDiagPipe) return reply_close("ERR '" + name + "' is reserved\n");
        if (s->pipe_regs.count(name)) {
            unregister_pipe(*s, name);
            return reply_close("OK\n");
        }
        if (store_ && store_->remove_pipe(s->name, name)) {
            close_reg_instances(*s, name);
            return reply_close("OK\n");
        }
        return reply_close("ERR no pipe '" + name + "'\n");
    }

    if (cmd == "OPEN") {
        // OPEN <peer> <pipe> [WAIT] <TYPE> [args] — WAIT keeps re-dialing while
        // the peer answers UNKNOWN (the pipe isn't registered *yet*).
        size_t ti = 3;
        const bool wait = t.size() > ti && t[ti] == "WAIT";
        if (wait) ++ti;
        if (t.size() <= ti) return reply_close("ERR usage: OPEN <peer> <pipe> [WAIT] <TYPE> [args]\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) return reply_close("ERR " + err + "\n");
        auto in = std::make_unique<Instance>();
        in->id = s->next_id++;
        in->want = t[2];
        in->type = t[ti];
        in->wait = wait;
        const Millis now = mono_ms();
        in->dial_deadline = wait ? std::numeric_limits<Millis>::max() : now + kDialDeadlineMs;
        in->next_dial = now;
        if (t[ti] == "PIPE") {
            if (t.size() != ti + 1) return reply_close("ERR PIPE takes no arguments\n");
            in->cfd = fd;
            in->cfd_owned = true;
            write_str(fd, "OK " + std::to_string(in->id) + "\n");
            poller_.remove(fd);
            ctl_.erase(fd);  // fd now belongs to the instance (watched once open)
        } else {
            std::string terr;
            in->local = make_local_end(t[ti], {t.begin() + ti + 1, t.end()}, &terr);
            if (!in->local) return reply_close("ERR " + terr + "\n");
            write_str(fd, "OK " + std::to_string(in->id) + "\n");
            drop_ctl(fd, true);
        }
        const uint64_t id = in->id;
        s->insts[id] = std::move(in);
        dial(*s, *s->insts[id], now);
        return;
    }

    if (cmd == "CLOSE") {
        if (t.size() != 3) return reply_close("ERR usage: CLOSE <peer> <id>\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) return reply_close("ERR " + err + "\n");
        std::string ids = t[2];
        if (!ids.empty() && ids[0] == '#') ids = ids.substr(1);
        const uint64_t id = std::strtoull(ids.c_str(), nullptr, 10);
        if (!s->insts.count(id)) return reply_close("ERR no instance #" + ids + "\n");
        close_instance(*s, id, false);
        return reply_close("OK\n");
    }

    reply_close("ERR unknown command '" + cmd + "'\n");
}

std::string Daemon::render_status(Millis now) {
    std::ostringstream o;
    for (auto& [name, s] : sessions_) {
        PathStatus ps = s.pm->status(now);
        o << "PEER " << name << ": " << path_name(ps.active);
        if (ps.active == Path::Direct) {
            for (const auto& c : ps.cands)
                if (c.in_use) o << " via " << c.ep.to_string() << " ~" << c.rtt << "ms";
        }
        o << " | tx " << human_bytes(ps.tx_direct + ps.tx_relay) << " rx "
          << human_bytes(ps.rx_direct + ps.rx_relay) << "\n";

        // The listening pipes: implicit diagnostic, persistent ones, live PIPEs.
        std::vector<std::pair<std::string, std::string>> listening;  // name, "TYPE args"
        listening.emplace_back(kDiagPipe, "ECHO");
        if (store_) {
            for (const auto& r : store_->list_pipes(name)) {
                std::string d = r.type;
                for (const auto& a : r.args) d += " " + a;
                listening.emplace_back(r.name, d);
            }
        }
        for (const auto& [rname, reg] : s.pipe_regs) listening.emplace_back(rname, "PIPE");

        o << "  LISTENING\n";
        for (const auto& [rname, desc] : listening) {
            uint64_t active = 0;
            for (const auto& [id, in] : s.insts)
                if (in->inbound && in->reg == rname) ++active;
            const uint64_t fin = s.finished.count(rname) ? s.finished.at(rname) : 0;
            o << "    " << rname << "  " << desc << "  (" << fin << " finished, " << active
              << " active)\n";
            for (const auto& [id, in] : s.insts) {
                if (!in->inbound || in->reg != rname) continue;
                o << "      #" << id << "  up " << human_bytes(in->up) << " down "
                  << human_bytes(in->down);
                if (in->local) o << " | " << in->local->describe();
                o << "\n";
            }
        }
        bool any_out = false;
        for (const auto& [id, in] : s.insts)
            if (!in->inbound) any_out = true;
        if (any_out) {
            o << "  RUNNING\n";
            for (const auto& [id, in] : s.insts) {
                if (in->inbound) continue;
                o << "    #" << id << "  -> " << name << ":" << in->want << "  " << in->type
                  << (in->open ? "" : " (connecting)") << "  up " << human_bytes(in->up)
                  << " down " << human_bytes(in->down);
                if (in->local) o << " | " << in->local->describe();
                o << "\n";
            }
        }
    }
    return o.str();
}

// ---------------- run / entry ----------------

int Daemon::run() {
    store_ = Store::open(nullptr);
    auto srv = net::resolve(opts_.server, opts_.port);
    if (!srv) {
        spl::logf("daemon: cannot resolve %s", opts_.server.c_str());
        return 1;
    }
    server_ = *srv;

    const std::string path = daemon_socket_path();
    ::unlink(path.c_str());
    lfd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un sa{};
    sa.sun_family = AF_UNIX;
    if (path.size() >= sizeof(sa.sun_path)) {
        spl::logf("daemon: socket path too long: %s", path.c_str());
        return 1;
    }
    std::strncpy(sa.sun_path, path.c_str(), sizeof(sa.sun_path) - 1);
    if (::bind(lfd_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0 ||
        ::listen(lfd_, 16) != 0) {
        spl::logf("daemon: cannot listen on %s", path.c_str());
        return 1;
    }
    ::chmod(path.c_str(), 0600);
    net::set_nonblocking(lfd_, true);

    std::signal(SIGINT, on_dsig);
    std::signal(SIGTERM, on_dsig);
    std::signal(SIGPIPE, SIG_IGN);

    if (store_) {
        std::string err;
        for (const auto& rec : store_->load_all())
            if (!start_session(rec, &err))
                spl::logf("daemon: session %s: %s", rec.name.c_str(), err.c_str());
    }
    spl::logf("daemon: up, %zu peer session(s), socket %s", sessions_.size(), path.c_str());

    poller_.set(lfd_, [this] { accept_ctl(); });
    poller_.run(g_dstop, [this](Millis now) { tick(now); });

    ::close(lfd_);
    ::unlink(path.c_str());
    return 0;
}

}  // namespace

std::string runtime_dir() {
    std::string dir;
    if (const char* d = std::getenv("SPL_RUNTIME_DIR")) {
        dir = d;
    } else if (const char* x = std::getenv("XDG_RUNTIME_DIR")) {
        dir = std::string(x) + "/spl";
    } else {
        dir = "/tmp/spl-" + std::to_string(getuid());
    }
    ::mkdir(dir.c_str(), 0700);
    return dir;
}

std::string daemon_socket_path() { return runtime_dir() + "/daemon.sock"; }

DaemonOpts default_daemon_opts() {
    DaemonOpts o{"splice.kussowski.dev", 443};
    Config c = load_config();
    if (!c.peer.addr.empty()) o.server = c.peer.addr;
    if (c.peer.port) o.port = c.peer.port;
    return o;
}

std::string ctl_encode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (c == '%' || c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 15];
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

std::string ctl_decode(const std::string& s) {
    auto hexv = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && hexv(s[i + 1]) >= 0 && hexv(s[i + 2]) >= 0) {
            out += static_cast<char>(hexv(s[i + 1]) * 16 + hexv(s[i + 2]));
            i += 2;
        } else {
            out += s[i];
        }
    }
    return out;
}

int daemon_run(const DaemonOpts& opts) { return Daemon(opts).run(); }

}  // namespace spl::peer
