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

#include "common/base64.h"
#include "common/config.h"
#include "common/io.h"
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
// How long a peer session stays warm (registered + probing) after its last pipe
// goes away, so a follow-up command reconnects instantly. After this it goes
// dormant: no relay traffic, no probing.
constexpr Millis kWarmMs = 5 * 60 * 1000;
// A non-sticky (auto-started) daemon exits after this long with nothing
// registered and no instances running, so a casual command doesn't leave a
// daemon behind forever. `spl start` makes it sticky (never auto-stops).
constexpr Millis kIdleStopMs = 2 * 60 * 1000;

std::atomic<bool> g_dstop{false};
void on_dsig(int) { g_dstop.store(true); }

void write_str(int fd, const std::string& s) { spl::write_all(fd, s.data(), s.size()); }

std::vector<std::string> split_ws(const std::string& line) {
    std::vector<std::string> out;
    std::istringstream is(line);
    std::string t;
    while (is >> t) out.push_back(t);
    return out;
}

// Collector for an outbound __LIST__ meta-request: buffers the peer's reply
// (newline-separated pipe names) and, when the request ends, writes it to the
// waiting control-socket client and closes it. The destructor does the flush so
// it fires on success, timeout, or abort alike.
struct ListEnd : LocalEnd {
    int client_fd;
    std::string buf;
    explicit ListEnd(int fd) : client_fd(fd) {}
    ~ListEnd() override {
        if (client_fd < 0) return;
        spl::write_all(client_fd, buf.data(), buf.size());
        ::close(client_fd);
    }
    void on_tunnel_data(ByteSpan b) override {
        buf.append(reinterpret_cast<const char*>(b.data()), b.size());
    }
    std::string describe() const override { return "list"; }
};

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
    bool meta = false;  // a __LIST__ request: no OK handshake; bind on connect
    int follow_fd = -1;        // OPEN FOLLOW: control fd to stream P/D/E progress to
    std::string follow_last_;  // last progress line written (throttle)
};

// A named pipe registration the peer can connect to. Two flavours share one
// table: daemon-owned (ECHO / SHARE_FILE / GET_FILE — `persisted` on disk, the
// daemon runs each instance) and PIPE (a live client process's socket in
// `owner_fd`, gone when that process exits).
//
// LIMIT N caps the registration at N instances over its lifetime ("N-shot"):
// further connections are refused, and once N have been spawned and all have
// finished the registration is retired (deleted from disk and, for a PIPE, its
// owner socket closed). chat uses LIMIT 1 — exactly one conversation, ended
// symmetrically from either side. limit 0 = unlimited.
struct Reg {
    std::string type;             // ECHO / SHARE_FILE / GET_FILE / PIPE
    std::vector<std::string> args;
    uint32_t limit = 0;           // 0 = unlimited
    uint32_t started = 0;         // instances spawned so far (never decremented)
    uint64_t finished = 0;        // instances completed
    int owner_fd = -1;            // PIPE: the client socket; -1 for daemon-owned
    bool persisted = false;       // daemon-owned, written to the store
};

struct Session {
    std::string name;
    ConnRecord rec;
    proto::Ip6 own{}, peer{};
    std::unique_ptr<PathManager> pm;
    std::unique_ptr<Netstack> ns;
    std::map<std::string, Reg> regs;  // the one registration table (daemon-owned + PIPE)
    std::map<uint64_t, std::unique_ptr<Instance>> insts;
    uint64_t next_id = 0;
    Millis last_active = 0;      // last tick this session had a pipe listening/running
    // Instances whose LocalEnd asked to shut down. Drained by tick(): a local
    // end must never be destroyed while one of its own methods is on the stack.
    std::vector<uint64_t> want_close;
    // Registrations to retire (LIMIT reached + drained). Deferred to tick() to
    // avoid unregistering mid-callback.
    std::vector<std::string> want_retire;
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
    size_t live_instances(Session& s, const std::string& name);
    void watch_cfd(Session& s, Instance& in);
    void unregister(Session& s, const std::string& name);  // remove a reg + its instances
    void tick(Millis now);

    // --- control plane ---
    void accept_ctl();
    void on_ctl_readable(int fd);
    void handle_cmd(int fd, const std::string& line);  // may adopt fd (PIPE)
    void drop_ctl(int fd, bool close_fd);
    std::string render_status(Millis now, bool verbose);
    std::string render_status_raw();  // machine-readable, tab-separated (completion/scripting)

    DaemonOpts opts_;
    bool sticky_ = false;        // never auto-stop (set by `spl start`)
    Millis idle_stop_ms_ = kIdleStopMs;  // SPL_IDLE_STOP_MS overrides (tests)
    Millis last_busy_ = 0;       // last tick any session had a pipe registered/running
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
    // Load the peer's persisted registrations into the in-memory table; from here
    // the table is authoritative (REGISTER/UNREGISTER keep it and the disk in sync).
    if (store_)
        for (const auto& r : store_->list_pipes(rec.name))
            s.regs[r.name] = Reg{r.type, r.args, r.limit, 0, 0, -1, true};
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
            // Meta-requests: reply, then close.
            if (line == "__PING__") {  // reachability probe
                in.conn->send(as_span(std::string("PONG\n")));
                close_instance(s, id, false);
                return;
            }
            if (line == "__LIST__") {  // the names we serve this peer
                std::string names;
                for (const auto& [rname, reg] : s.regs) names += rname + "\n";
                in.conn->send(as_span(names));
                close_instance(s, id, false);
                return;
            }
            // Resolve the requested name in the one registration table.
            in.reg = line;
            auto rit = s.regs.find(line);
            if (rit == s.regs.end()) {
                spl::logf("[daemon] %s requested '%s' -> UNKNOWN", s.name.c_str(), line.c_str());
                in.conn->send(as_span(std::string("UNKNOWN\n")));
                close_instance(s, id, false);
                return;
            }
            Reg& reg = rit->second;
            if (reg.limit && reg.started >= reg.limit) {  // N-shot quota reached
                spl::logf("[daemon] %s requested '%s' -> UNKNOWN (limit %u reached)",
                          s.name.c_str(), line.c_str(), reg.limit);
                in.conn->send(as_span(std::string("UNKNOWN\n")));
                close_instance(s, id, false);
                return;
            }
            ++reg.started;
            in.type = reg.type;
            if (reg.type == "PIPE") {
                in.cfd = reg.owner_fd;  // shared with the registration
            } else {
                in.local = make_local_end(reg.type, reg.args, nullptr);
            }
            spl::logf("[daemon] %s requested '%s' -> OK (#%llu, %s)", s.name.c_str(), line.c_str(),
                      (unsigned long long)id, in.type.c_str());
            in.conn->send(as_span(std::string("OK\n")));
            bind_end(s, in);
        } else {
            if (line != "OK") {  // UNKNOWN or garbage
                if (in.wait && in.conn) {  // not registered yet: drop this conn, re-dial
                    spl::logf("[daemon] #%llu got '%s' for '%s'; not registered yet, retrying",
                              (unsigned long long)id, line.c_str(), in.want.c_str());
                    in.conn->on_recv = nullptr;
                    in.conn->on_closed = nullptr;
                    in.conn->on_error = nullptr;
                    in.conn->close();
                    in.conn = nullptr;
                    in.next_dial = mono_ms() + 1000;
                    return;
                }
                spl::logf("[daemon] #%llu got '%s' for '%s'; giving up", (unsigned long long)id,
                          line.c_str(), in.want.c_str());
                if (in.follow_fd >= 0) {  // tell the client *why* (clearer than "interrupted")
                    const std::string m = "E '" + in.want + "' isn't served by " + s.name +
                                          " (try: spl ls " + s.name + ")\n";
                    spl::write_all(in.follow_fd, m.data(), m.size());
                    ::close(in.follow_fd);
                    in.follow_fd = -1;
                }
                close_instance(s, id, false);
                return;
            }
            spl::logf("[daemon] #%llu '%s' accepted; splicing", (unsigned long long)id,
                      in.want.c_str());
            bind_end(s, in);
        }
        if (!rest.empty()) on_tunnel_data(s, id, as_span(rest));
        return;
    }

    in.down += b.size();
    if (in.local) {
        in.local->on_tunnel_data(b);
    } else if (in.cfd >= 0) {
        spl::write_all(in.cfd, b.data(), b.size());
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
    Session* sp = &s;
    const uint64_t id = in.id;
    const std::string sname = s.name;
    // Look the instance up by id in the callbacks (never capture the Instance*):
    // tick() may expire it at its deadline while a connect is still in flight, so
    // the pointer can be gone by the time lwIP resolves the connect.
    spl::logf("[daemon] #%llu dialing %s:%s (%s)", (unsigned long long)id, sname.c_str(),
              in.want.c_str(), in.wait ? "wait" : "once");
    s.ns->connect(
        s.peer, kPipePort,
        [this, sp, id, sname](TcpConn* c) {
            auto it = sp->insts.find(id);
            if (it == sp->insts.end()) {  // instance already expired/closed
                c->close();
                return;
            }
            Instance& in = *it->second;
            in.conn = c;
            in.dialing = false;
            c->on_recv = [this, sp, id](ByteSpan b) { on_tunnel_data(*sp, id, b); };
            c->on_closed = [this, sp, id] { on_tunnel_gone(*sp, id); };
            c->on_error = [this, sp, id] { on_tunnel_gone(*sp, id); };
            c->send(as_span(in.want + "\n"));
            // A meta-request gets no OK handshake: the reply bytes follow
            // immediately, so bind the collector now.
            if (in.meta) {
                in.open = true;
                bind_end(*sp, in);
            }
            spl::logf("[daemon] #%llu connected to %s, requested '%s'", (unsigned long long)id,
                      sname.c_str(), in.want.c_str());
        },
        [sp, id] {  // this attempt failed; tick re-dials until the deadline
            auto it = sp->insts.find(id);
            if (it == sp->insts.end()) return;
            it->second->conn = nullptr;
            it->second->dialing = false;
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
    if (in.follow_fd >= 0) {  // tell the following client the outcome, then close
        const std::string e = in.local ? in.local->error() : "";
        const std::string fin =
            !e.empty() ? "E " + e + "\n" : (in.local && in.local->done() ? "D\n" : "E interrupted\n");
        spl::write_all(in.follow_fd, fin.data(), fin.size());
        ::close(in.follow_fd);
    }
    const std::string reg = in.reg;
    const bool inbound = in.inbound;
    if (inbound) {
        if (auto rit = s.regs.find(reg); rit != s.regs.end() && finished) ++rit->second.finished;
    }
    spl::logf("[daemon] #%llu closed (%s, up %s down %s)", (unsigned long long)id,
              finished ? "done" : "aborted", human_bytes(in.up).c_str(),
              human_bytes(in.down).c_str());
    s.insts.erase(it);

    // An N-shot registration that has spawned its quota and now has no live
    // instances left is done: retire it (for a PIPE that closes the owner socket,
    // so a chat host exits when the conversation ends; for a daemon-owned reg it
    // deletes the file). Deferred to tick() to avoid re-entrancy.
    if (inbound) {
        auto rit = s.regs.find(reg);
        if (rit != s.regs.end() && rit->second.limit &&
            rit->second.started >= rit->second.limit && live_instances(s, reg) == 0)
            s.want_retire.push_back(reg);
    }
}

size_t Daemon::live_instances(Session& s, const std::string& name) {
    size_t n = 0;
    for (auto& [id, in] : s.insts)
        if (in->inbound && in->reg == name) ++n;
    return n;
}

// Remove a registration and tear down its live instances. PIPE: close the owner
// socket. Daemon-owned + persisted: delete it from the store.
void Daemon::unregister(Session& s, const std::string& name) {
    auto it = s.regs.find(name);
    if (it == s.regs.end()) return;
    std::vector<uint64_t> victims;
    for (auto& [id, in] : s.insts)
        if (in->inbound && in->reg == name) victims.push_back(id);
    for (uint64_t id : victims) close_instance(s, id, false);
    if (it->second.owner_fd >= 0) {
        poller_.remove(it->second.owner_fd);
        ::close(it->second.owner_fd);
    }
    if (it->second.persisted && store_) store_->remove_pipe(s.name, name);
    s.regs.erase(it);
}

void Daemon::tick(Millis now) {
    bool any_busy = false;
    for (auto& [name, s] : sessions_) {
        // Activity gate: full disco only while something is listening or running,
        // or within the warm window after the last one. Otherwise the session
        // goes dormant (no relay traffic, no probing).
        const bool busy = !s.regs.empty() || !s.insts.empty();
        any_busy |= busy;
        if (busy) s.last_active = now;
        const bool warm = busy || (s.last_active && now - s.last_active < kWarmMs);
        s.pm->set_active(warm);
        // Dormant: don't drive the path manager OR lwIP — a frozen lwIP can't even
        // leak its own IPv6 housekeeping (MLD/DAD) out through the tunnel. handle_io
        // still runs, and a local REGISTER/OPEN flips us back to warm next tick.
        if (!warm) continue;

        s.pm->tick(now);
        s.ns->check_timeouts();

        for (size_t i = 0; i < s.want_close.size(); ++i)  // ends may queue more
            close_instance(s, s.want_close[i], true);
        s.want_close.clear();

        for (const auto& reg : s.want_retire) unregister(s, reg);
        s.want_retire.clear();

        std::vector<uint64_t> expired;
        for (auto& [id, inp] : s.insts) {
            Instance& in = *inp;
            // Outbound, not yet spliced: enforce the deadline (even mid-dial — a
            // dial to a down peer can hang since WG can't handshake), else re-dial.
            if (!in.inbound && !in.open && !in.conn) {
                if (now >= in.dial_deadline)
                    expired.push_back(id);
                else if (!in.dialing && now >= in.next_dial)
                    dial(s, in, now);
            }
            // Resume client sockets paused for backpressure (owned fds only).
            if (in.open && in.cfd >= 0 && in.cfd_owned && !in.cfd_watch && in.conn &&
                in.conn->sndbuf() >= kChunk)
                watch_cfd(s, in);
            if (in.local) in.local->tick(now);
            // Stream progress to a following client when it changes.
            if (in.follow_fd >= 0 && in.local) {
                std::string line = "P " + in.local->describe() + "\n";
                if (line != in.follow_last_) {
                    in.follow_last_ = line;
                    spl::write_all(in.follow_fd, line.data(), line.size());
                }
            }
        }
        for (uint64_t id : expired) close_instance(s, id, false);
    }

    // Auto-stop: a non-sticky daemon exits once it's been idle long enough.
    if (any_busy) last_busy_ = now;
    if (!sticky_ && now - last_busy_ >= idle_stop_ms_) {
        spl::logf("[daemon] auto-stopping after %llds idle (nothing registered or running)",
                  (long long)(idle_stop_ms_ / 1000));
        g_dstop.store(true);
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
    if (cmd == "VERSION") {
#ifndef SPL_GIT_SHA
#define SPL_GIT_SHA "unknown"
#endif
        return reply_close(std::string("OK ") + SPL_GIT_SHA + "\n");
    }
    if (cmd == "STOP") {
        g_dstop.store(true);
        return reply_close("OK\n");
    }
    if (cmd == "STICKY") {  // `spl start` against an already-running daemon: keep it up
        sticky_ = true;
        return reply_close("OK\n");
    }
    if (cmd == "STATUS") {
        if (t.size() > 1 && t[1] == "RAW") return reply_close("OK\n" + render_status_raw());
        const bool verbose = t.size() > 1 && t[1] == "VERBOSE";
        return reply_close("OK\n" + render_status(mono_ms(), verbose));
    }

    if (cmd == "FORCE_RELAY") {  // debug/test: pin a session to the relay (1) or release (0)
        if (t.size() != 3) return reply_close("ERR usage: FORCE_RELAY <peer> <0|1>\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) return reply_close("ERR " + err + "\n");
        s->pm->set_force_relay(t[2] == "1");
        return reply_close("OK\n");
    }

    if (cmd == "RESET") {  // drop every registered pipe everywhere
        for (auto& [name, s] : sessions_) {
            std::vector<std::string> names;
            for (auto& [rname, reg] : s.regs) names.push_back(rname);
            for (const auto& rname : names) unregister(s, rname);  // closes instances too
        }
        return reply_close("OK\n");
    }

    if (cmd == "REGISTER") {
        // REGISTER <peer> <id> [LIMIT <n>] <TYPE> [args]
        if (t.size() < 4)
            return reply_close("ERR usage: REGISTER <peer> <id> [LIMIT <n>] <TYPE> [args]\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) return reply_close("ERR " + err + "\n");
        const std::string& name = t[2];
        if (s->regs.count(name)) return reply_close("ERR pipe '" + name + "' already exists\n");

        size_t ti = 3;
        uint32_t limit = 0;
        if (t.size() > ti && t[ti] == "LIMIT") {
            if (t.size() <= ti + 1) return reply_close("ERR LIMIT needs a count\n");
            limit = static_cast<uint32_t>(std::strtoul(t[ti + 1].c_str(), nullptr, 10));
            if (limit == 0) return reply_close("ERR LIMIT must be >= 1\n");
            ti += 2;
        }
        if (t.size() <= ti) return reply_close("ERR REGISTER needs a TYPE\n");
        const std::string& type = t[ti];
        std::vector<std::string> args(t.begin() + ti + 1, t.end());
        if (type == "PIPE") {
            if (!args.empty()) return reply_close("ERR PIPE takes no arguments\n");
            write_str(fd, "OK\n");
            poller_.remove(fd);
            ctl_.erase(fd);  // the connection now is the pipe's local end
            s->regs[name] = Reg{"PIPE", {}, limit, 0, 0, fd, false};
            Session* sp = s;
            poller_.set(fd, [this, sp, name, fd] {
                // Bytes from the owner go to every active instance of this pipe
                // (one for chat; interleaving with several is the user's choice).
                uint8_t buf[kChunk];
                ssize_t n = ::read(fd, buf, sizeof(buf));
                if (n <= 0) {  // owner process went away -> pipe and instances die
                    unregister(*sp, name);
                    return;
                }
                for (auto& [id, in] : sp->insts)
                    if (in->inbound && in->reg == name && in->open)
                        route_to_tunnel(*sp, *in, ByteSpan(buf, static_cast<size_t>(n)));
            });
            return;
        }
        // Daemon-owned: validate, persist (with its limit), add to the table.
        std::string terr;
        if (!make_local_end(type, args, &terr)) return reply_close("ERR " + terr + "\n");
        if (!store_) return reply_close("ERR no config store\n");
        if (!store_->save_pipe(PipeRecord{s->name, name, type, limit, args}, &terr))
            return reply_close("ERR " + terr + "\n");
        s->regs[name] = Reg{type, args, limit, 0, 0, -1, true};
        return reply_close("OK\n");
    }

    if (cmd == "UNREGISTER") {
        if (t.size() != 3) return reply_close("ERR usage: UNREGISTER <peer> <id>\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) return reply_close("ERR " + err + "\n");
        const std::string& name = t[2];
        if (!s->regs.count(name)) return reply_close("ERR no pipe '" + name + "'\n");
        unregister(*s, name);
        return reply_close("OK\n");
    }

    if (cmd == "OPEN") {
        // OPEN <peer> <pipe> [WAIT] [FOLLOW] <TYPE> [args]
        //   WAIT   keeps re-dialing while the peer answers UNKNOWN (not registered yet)
        //   FOLLOW streams progress (P/D/E lines) back on this control connection
        size_t ti = 3;
        bool wait = false, follow = false;
        for (; ti < t.size() && (t[ti] == "WAIT" || t[ti] == "FOLLOW"); ++ti) {
            if (t[ti] == "WAIT") wait = true;
            if (t[ti] == "FOLLOW") follow = true;
        }
        if (t.size() <= ti)
            return reply_close("ERR usage: OPEN <peer> <pipe> [WAIT] [FOLLOW] <TYPE> [args]\n");
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
            if (follow) {  // keep the control fd to stream progress + a final status
                in->follow_fd = fd;
                poller_.remove(fd);
                ctl_.erase(fd);
            } else {
                drop_ctl(fd, true);
            }
        }
        const uint64_t id = in->id;
        s->insts[id] = std::move(in);
        dial(*s, *s->insts[id], now);
        return;
    }

    // LIST / REACH: a meta round-trip to the peer (no OK handshake). The reply
    // is streamed raw to this control connection (a ListEnd), which then closes
    // it — empty if the peer is unreachable. LIST asks for the served names;
    // REACH just pings (the peer replies "PONG").
    if (cmd == "LIST" || cmd == "REACH") {
        if (t.size() != 2) return reply_close("ERR usage: " + cmd + " <peer>\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) {  // unknown peer -> empty result (close with no body)
            drop_ctl(fd, true);
            return;
        }
        auto in = std::make_unique<Instance>();
        in->id = s->next_id++;
        in->want = cmd == "LIST" ? "__LIST__" : "__PING__";
        in->type = "meta";
        in->meta = true;
        in->local = std::make_unique<ListEnd>(fd);  // owns the control fd now
        const Millis now = mono_ms();
        in->dial_deadline = now + 4000;  // give up (empty) if the peer is unreachable
        in->next_dial = now;
        poller_.remove(fd);
        ctl_.erase(fd);
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

namespace {
// Minimal IPv6 text (8 hex groups, no :: compression — enough for status).
std::string ip6_str(const proto::Ip6& a) {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%x:%x:%x:%x:%x:%x:%x:%x", (a[0] << 8) | a[1],
                  (a[2] << 8) | a[3], (a[4] << 8) | a[5], (a[6] << 8) | a[7], (a[8] << 8) | a[9],
                  (a[10] << 8) | a[11], (a[12] << 8) | a[13], (a[14] << 8) | a[15]);
    return buf;
}
}  // namespace

std::string Daemon::render_status(Millis now, bool verbose) {
    std::ostringstream o;
    if (sessions_.empty()) o << "(no peer sessions)\n";
    for (auto& [name, s] : sessions_) {
        PathStatus ps = s.pm->status(now);

        // --- header line ---
        o << "PEER " << name;
        if (verbose) o << "  (" << (s.rec.side ? "follower" : "leader") << ")";
        o << ": " << path_name(ps.active);
        if (ps.active == Path::Direct) {
            for (const auto& c : ps.cands)
                if (c.in_use) o << " via " << c.ep.to_string() << " ~" << c.rtt << "ms";
        }
        o << " | tx " << human_bytes(ps.tx_direct + ps.tx_relay) << " rx "
          << human_bytes(ps.rx_direct + ps.rx_relay) << "\n";

        // --- verbose session detail ---
        if (verbose) {
            o << "  link       " << path_name(ps.active)
              << (ps.direct_confirmed ? " (a direct path is confirmed alive)"
                                      : " (no direct path; on the relay)")
              << "\n";
            o << "  addresses  me " << ip6_str(s.own) << "  peer " << ip6_str(s.peer) << "\n";
            o << "  uid        " << base64_encode(as_span(s.rec.uid)) << "\n";
            o << "  external   "
              << (ps.external ? ps.external->to_string() : std::string("(unknown)"))
              << "   (our address as the relay sees us)\n";
            o << "  traffic    tx: direct " << human_bytes(ps.tx_direct) << " / relay "
              << human_bytes(ps.tx_relay) << "   rx: direct " << human_bytes(ps.rx_direct)
              << " / relay " << human_bytes(ps.rx_relay) << "\n";
            o << "  candidates (" << ps.cands.size() << "):\n";
            for (const auto& c : ps.cands) {
                o << "    " << (c.in_use ? "USE-> " : "      ") << c.ep.to_string() << "  ["
                  << (c.lan ? "iface" : "ext") << "]  " << (c.alive ? "ALIVE" : "dead")
                  << "  rtt " << (c.rtt ? std::to_string((long long)c.rtt) + "ms" : "?")
                  << "  last reply "
                  << (c.reply_age >= 0 ? std::to_string((long long)c.reply_age) + "ms ago"
                                       : "never")
                  << "\n";
            }
        }

        // --- the registration table (daemon-owned + live PIPEs) ---
        if (!s.regs.empty()) o << "  LISTENING\n";
        for (const auto& [rname, reg] : s.regs) {
            uint64_t active = 0;
            for (const auto& [id, in] : s.insts)
                if (in->inbound && in->reg == rname) ++active;
            std::string desc = reg.type;
            for (const auto& a : reg.args) desc += " " + a;
            o << "    " << rname << "  " << desc << "  (" << reg.finished << " finished, " << active
              << " active)";
            if (verbose && reg.limit) o << "  [limit " << reg.started << "/" << reg.limit << "]";
            o << "\n";
            for (const auto& [id, in] : s.insts) {
                if (!in->inbound || in->reg != rname) continue;
                o << "      #" << id;
                if (verbose) o << "  " << in->type << (in->open ? " open" : " handshaking");
                o << "  up " << human_bytes(in->up) << " down " << human_bytes(in->down);
                if (in->local) o << " | " << in->local->describe();
                o << "\n";
            }
        }

        // --- our outbound instances (created by OPEN) ---
        bool any_out = false;
        for (const auto& [id, in] : s.insts)
            if (!in->inbound) any_out = true;
        if (any_out) {
            o << "  RUNNING\n";
            for (const auto& [id, in] : s.insts) {
                if (in->inbound) continue;
                o << "    #" << id << "  -> " << name << ":" << in->want << "  " << in->type;
                if (in->open)
                    o << (verbose ? " open" : "");
                else
                    o << (in->wait ? " (waiting)" : " (connecting)");
                o << "  up " << human_bytes(in->up) << " down " << human_bytes(in->down);
                if (in->local) o << " | " << in->local->describe();
                o << "\n";
            }
        }
    }
    return o.str();
}

// Tab-separated, one record per line, stable for scripting/completion:
//   peer  <name>  <active|dormant>  <RELAY|DIRECT>
//   reg   <peer>  <pipe>  <TYPE>            (persisted + live PIPE registrations)
//   inst  <peer>  <id>  <in|out>  <type>    (live instances)
std::string Daemon::render_status_raw() {
    std::ostringstream o;
    for (auto& [name, s] : sessions_) {
        PathStatus ps = s.pm->status(mono_ms());
        o << "peer\t" << name << "\t" << (s.pm->active() ? "active" : "dormant") << "\t"
          << path_name(ps.active) << "\n";
        for (const auto& [rname, reg] : s.regs)
            o << "reg\t" << name << "\t" << rname << "\t" << reg.type << "\n";
        for (const auto& [id, in] : s.insts)
            o << "inst\t" << name << "\t" << id << "\t" << (in->inbound ? "in" : "out") << "\t"
              << in->type << "\n";
    }
    return o.str();
}

// ---------------- run / entry ----------------

int Daemon::run() {
    sticky_ = opts_.sticky;
    if (const char* v = std::getenv("SPL_IDLE_STOP_MS")) idle_stop_ms_ = std::atoll(v);
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
    spl::logf("daemon: up (%s), %zu peer session(s), socket %s",
              sticky_ ? "sticky" : "auto-stops when idle", sessions_.size(), path.c_str());

    last_busy_ = mono_ms();  // don't auto-stop before the first command arrives
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
