#include "peer/daemon.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <deque>
#include <ctime>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#include "common/base64.h"
#include "common/config.h"
#include "common/io.h"
#include "common/log.h"
#include "common/time.h"
#include "net/poller.h"
#include "net/private_ipc.h"
#include "net/socket.h"
#include "peer/exec.h"
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

// The relay's address, resolved off the event loop: DNS can block for many
// seconds when offline, and the daemon must come up (and keep splicing) anyway.
// A detached thread retries until it succeeds; the loop picks the result up.
struct ServerLookup {
    std::mutex m;
    std::condition_variable cv;
    std::optional<Endpoint> ep;
    bool tried = false;  // the first attempt finished (either way)
};

// Resolves address-hint hosts off the event loop (same reason as ServerLookup),
// one short-lived thread per lookup. get() returns the latest known address and
// (re)starts a lookup when due: a known host is refreshed every minute (its IP
// may change), an unknown one retried every 15s.
class HintResolver {
 public:
    std::optional<Endpoint> get(const std::string& host, uint16_t port, Millis now) {
        std::lock_guard<std::mutex> lk(st_->m);
        Entry& e = st_->hosts[host];
        if (!e.pending && now >= e.next) {
            e.pending = true;
            e.next = now + (e.ep ? 60'000 : 15'000);
            std::thread([st = st_, host] {
                auto ep = net::resolve(host, 1);
                std::lock_guard<std::mutex> lk(st->m);
                Entry& e = st->hosts[host];
                if (ep) e.ep = ep;
                e.pending = false;
            }).detach();
        }
        if (!e.ep) return std::nullopt;
        Endpoint out = *e.ep;
        out.port = port;
        return out;
    }

 private:
    struct Entry {
        std::optional<Endpoint> ep;
        bool pending = false;
        Millis next = 0;
    };
    struct State {
        std::mutex m;
        std::map<std::string, Entry> hosts;
    };
    std::shared_ptr<State> st_ = std::make_shared<State>();
};

// One live spliced connection (an instance of a pipe pair).
struct Instance {
    uint64_t id = 0;
    bool inbound = false;     // spawned by our listening pipe (vs created by OPEN)
    // Inbound: the name the peer asked for, and the serial of the registration
    // that served it (0 until the handshake resolves). Only the counters use the
    // serial; the instance is otherwise independent of its registration — it can
    // outlive it, and a new registration under the same name is a different one.
    std::string reg;
    uint64_t reg_serial = 0;
    std::string want;         // outbound: remote pipe id to request
    // The kind of the offer (pipes.h): for inbound what we announced, for
    // outbound what the peer announced ("" = an older peer that doesn't say).
    std::string kind;
    std::string expect;       // outbound: the kind our local end needs ("" = any)
    std::string type;         // local end type, snapshotted at connect (for status)
    std::vector<std::string> args;  // …and its arguments
    TcpConn* conn = nullptr;  // tunnel side (owned by the session's Netstack)
    bool open = false;        // handshake finished, splicing
    std::string lbuf;         // handshake line buffer
    std::unique_ptr<LocalEnd> local;  // daemon-owned local end…
    int cfd = -1;                     // …or a bridged client socket (PIPE)
    bool cfd_owned = false;   // OPEN-PIPE owns its fd; inbound-PIPE shares the owner's
    bool cfd_watch = false;   // currently registered with the poller
    std::vector<LocalEnd::Watch> watching;  // a LocalEnd's watches() now in the poller
    // Bytes the end will report consumed that were already acknowledged (they
    // arrived with the handshake, before its receive window was held).
    size_t preacked = 0;
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
// A registration is only an offer: the daemon consults it when the peer
// connects (and for LIST). Instances it spawns are independent of it from then
// on — unregistering (or retiring) stops new connections but leaves live ones
// running. The one shared resource is a PIPE's owner socket, which is the byte
// stream itself: it stays open until neither a registration nor a live instance
// uses it (see release_owner_fd).
//
// LIMIT N caps the registration at N instances over its lifetime ("N-shot"):
// once N have started it is retired at once (deleted from disk; live instances
// carry on). chat uses LIMIT 1 — exactly one conversation; when it ends from
// either side, the owner socket closes and both processes exit. 0 = unlimited.
struct Reg {
    uint64_t serial = 0;          // unique per session: tells same-named registrations apart
    std::string type;             // ECHO / SHARE_FILE / GET_FILE / SHELL / PIPE
    std::vector<std::string> args;
    uint32_t limit = 0;           // 0 = unlimited
    uint32_t started = 0;         // instances spawned so far (never decremented)
    uint64_t active = 0;          // spawned instances still running
    uint64_t finished = 0;        // spawned instances that have ended (any way)
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
    uint64_t next_reg_serial = 1;  // 0 means "no registration"
    // Addresses a direct path to this peer last worked at (newest first), kept
    // in the store when the peer's remember-address setting is on.
    std::vector<SeenAddress> seen;
    bool seed_seen = false;  // still to be offered to the path manager as candidates
    // The LAN port the peer itself last told us it listens on (0 = it hasn't);
    // persisted in the store, and preferred over the record's value.
    uint16_t learned_port = 0;
    uint16_t peer_lan_port() const {
        return learned_port ? learned_port : rec.lan_port ? rec.lan_port : kLanDiscoPort;
    }
    // The record as it is in effect, for display (lan_port 0 = default).
    ConnRecord effective() const {
        ConnRecord r = rec;
        r.lan_port = peer_lan_port() == kLanDiscoPort ? 0 : peer_lan_port();
        return r;
    }
    Millis last_active = 0;      // last tick this session had a pipe listening/running
    // Instances whose LocalEnd asked to shut down. Drained by tick(): a local
    // end must never be destroyed while one of its own methods is on the stack.
    std::vector<uint64_t> want_close;
    // Registrations to retire (LIMIT reached), by serial. Deferred to tick() to
    // avoid unregistering mid-callback.
    std::vector<uint64_t> want_retire;
};

// Output queued for one client socket, in arrival order across the instances
// that share it (several inbound connections on one PIPE registration).
struct ClientOut {
    struct Chunk {
        Session* s;  // null once the session is gone (nothing to account to)
        uint64_t id;
        std::string data;
        bool accounted;
    };
    std::deque<Chunk> q;
    size_t off = 0;              // written of q.front()
    bool closing = false;        // close the fd once drained
    Millis give_up_at = 0;       // …or at this time, drained or not
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
    // An OPEN that can't proceed: tell whoever waits on it why, then close it.
    void fail_open(Session& s, Instance& in, const std::string& why);
    void add_reg(Session& s, const std::string& name, Reg reg);
    void release_owner_fd(Session& s, int fd);  // close a PIPE owner socket nobody uses
    // A PIPE registration's owner socket: its bytes go to every open instance on
    // it, read only while there is one and all have room (else they wait in the
    // socket, and the owner process is held back), resumed by resume_owners().
    void watch_owner(Session* sp, const std::string& name, uint64_t serial, int fd);
    void on_owner_readable(Session* sp, const std::string& name, uint64_t serial, int fd);
    void resume_owners();
    void watch_cfd(Session& s, Instance& in);
    // Make the poller watch exactly what the instance's LocalEnd asks for now.
    void sync_watches(Session& s, Instance& in);
    // Writing to client sockets (PIPE): queued and flushed as the client reads,
    // never blocking the daemon. Tunnel bytes count as consumed (reopening the
    // sender's window) only once written, so a client that stops reading holds
    // its sender back. `accounted` = the bytes came from the tunnel.
    void client_write(Session& s, Instance& in, ByteSpan b, bool accounted);
    void flush_client(int fd);
    // `fd` is done: close it once its queue has drained (or after a timeout).
    void close_client(int fd);
    void account(Session& s, uint64_t id, size_t n);  // n tunnel bytes consumed
    // Remove a registration (live instances keep running); returns their ids.
    std::vector<uint64_t> unregister(Session& s, const std::string& name);
    void tick(Millis now);
    void adopt_server();  // pick up a (late) relay resolution and hand it to every session
    void on_lan_discovery();  // a query arrived on the shared discovery port
    void refresh_hints(Millis now);  // hand each session its resolved address hints
    void apply_peer_settings(Session& s);  // push the record's settings into the session
    void remember_paths(Millis now);       // note each session's working direct address
    std::string reload();  // reconcile sessions with the peer files; returns a summary
    void drop_session(const std::string& name);  // end a peer's session and everything on it

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
    Endpoint server_{};  // the relay; !valid() until resolved (we run without it meanwhile)
    std::shared_ptr<ServerLookup> lookup_;
    std::optional<Store> store_;
    net::Poller poller_;
    int lfd_ = -1;  // unix listen socket
    // LAN discovery: the shared UDP port we hear peers' queries on (see pathman.h).
    net::Fd lan_fd_;
    uint16_t lan_port_ = kLanDiscoPort;  // where *we* listen (own_lan_port())
    Timer t_lan_bind_;
    void set_lan_listening(bool want);   // the socket is open only while a peer is active
    std::vector<Endpoint> lan_targets_;  // SPL_LAN_TARGETS (tests): replaces broadcasting
    HintResolver hints_;
    Timer t_hints_, t_remember_;
    std::map<std::string, Session> sessions_;
    std::map<int, ClientOut> client_out_;  // client sockets with output pending
    struct PausedOwner {
        Session* s;
        std::string name;
        uint64_t serial;
    };
    std::map<int, PausedOwner> paused_owners_;  // owner sockets not being read right now
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
    cfg.lan_port = rec.lan_port;  // the peer's port (0 = default); refined just below
    cfg.own_lan_port = lan_port_;
    cfg.lan_targets = lan_targets_;
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
            add_reg(s, r.name, Reg{.type = r.type, .args = r.args, .limit = r.limit,
                                   .persisted = true});
    if (getenv("SPL_FORCE_RELAY")) pm->set_force_relay(true);  // test hook
    // The peer told us (authenticated and fresh) that it listens on another LAN
    // port: remember it and ask there from now on. Sessions are map nodes, so
    // the pointer stays valid for as long as the path manager that calls this.
    Session* sp = &s;
    pm->on_peer_lan_port = [this, sp](uint16_t port) {
        if (port == 0 || port == sp->peer_lan_port()) return;
        spl::logf("[daemon] %s now listens for LAN discovery on port %u (was %u)",
                  sp->name.c_str(), port, sp->peer_lan_port());
        sp->learned_port = port;
        if (store_) store_->save_learned_port(sp->name, port);
        sp->pm->set_lan_port(port);
        t_hints_.rearm();  // port-less hints now resolve to the new port
    };
    apply_peer_settings(s);
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
        in.conn->hold_recv(true);  // bytes count once the client has read them
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
        Instance* ip = &in;  // the end lives inside the instance: valid while it is
        in.local->to_tunnel = [this, sp, ip](ByteSpan b) { route_to_tunnel(*sp, *ip, b); };
        in.local->tunnel_space = [ip]() -> size_t { return ip->conn ? ip->conn->sndbuf() : 0; };
        // Deferred: the end may call shutdown from inside its own methods.
        in.local->shutdown = [sp, id] { sp->want_close.push_back(id); };
        in.local->peer = s.name;
        if (in.local->manual_flow()) {
            in.conn->hold_recv(true);
            in.local->consumed = [ip](size_t n) {
                const size_t pre = std::min(n, ip->preacked);  // already acknowledged
                ip->preacked -= pre;
                if (ip->conn && n > pre) ip->conn->recved(n - pre);
            };
        }
        in.conn->on_writable = [this, sp, id] {
            auto it = sp->insts.find(id);
            if (it == sp->insts.end() || !it->second->local) return;
            Instance& in = *it->second;
            in.local->on_tunnel_writable();
            sync_watches(*sp, in);  // room again: the end may want its read fds back
        };
        in.local->start();
        sync_watches(s, in);  // start() may have opened descriptors to watch
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
                for (const auto& [rname, reg] : s.regs)
                    names += rname + "\t" + offer_kind(reg.type, reg.args) + "\n";
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
            ++reg.active;
            in.reg_serial = reg.serial;
            in.type = reg.type;
            in.args = reg.args;
            // Quota now spent: stop offering it right away (live instances carry on).
            if (reg.limit && reg.started >= reg.limit) s.want_retire.push_back(reg.serial);
            if (reg.type == "PIPE") {
                in.cfd = reg.owner_fd;  // shared with the registration
            } else {
                in.local = make_local_end(reg.type, reg.args, nullptr);
            }
            spl::logf("[daemon] %s requested '%s' -> OK (#%llu, %s)", s.name.c_str(), line.c_str(),
                      (unsigned long long)id, in.type.c_str());
            in.kind = offer_kind(reg.type, reg.args);
            in.conn->send(as_span("OK " + in.kind + "\n"));
            bind_end(s, in);
        } else {
            const bool ok = line == "OK" || line.rfind("OK ", 0) == 0;
            // (the peer's words: it reaches logs, status and the user's terminal)
            if (ok) in.kind = printable(line.size() > 3 ? line.substr(3) : "");
            if (ok && !kind_matches(in.kind, in.expect)) {
                // Reached, but it's something else (an inbox, not a file share…):
                // say what it is and how to use it, rather than speak the wrong
                // protocol at it.
                const std::string use = kind_usage(in.kind, s.name, in.want);
                const std::string why = "'" + in.want + "' on " + s.name + " " +
                                        kind_label(in.kind) + (use.empty() ? "" : "; use: " + use);
                spl::logf("[daemon] #%llu '%s' is %s, need %s; closing", (unsigned long long)id,
                          in.want.c_str(), in.kind.c_str(), in.expect.c_str());
                fail_open(s, in, why);
                return;
            }
            if (!ok) {  // UNKNOWN or garbage
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
                fail_open(s, in, "'" + in.want + "' isn't offered by " + s.name +
                                     " (see: spl ls " + s.name + ")");
                return;
            }
            spl::logf("[daemon] #%llu '%s' accepted (%s); splicing", (unsigned long long)id,
                      in.want.c_str(), in.kind.empty() ? "kind unknown" : in.kind.c_str());
            // A client socket (PIPE) learns it's connected, and to what, before
            // the first byte of the stream.
            if (in.cfd >= 0) client_write(s, in, as_span("READY " + in.kind + "\n"), false);
            bind_end(s, in);
        }
        if (!rest.empty()) {
            in.preacked = rest.size();  // came with the handshake, acknowledged already
            on_tunnel_data(s, id, as_span(rest));
        }
        return;
    }

    in.down += b.size();
    if (in.local) {
        in.local->on_tunnel_data(b);
        sync_watches(s, in);
    } else if (in.cfd >= 0) {
        client_write(s, in, b, true);
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
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
        if (n <= 0) {  // client went away -> the pipe dies
            close_instance(*sp, id, true);
            return;
        }
        route_to_tunnel(*sp, in, ByteSpan(buf, static_cast<size_t>(n)));
    });
}

void Daemon::sync_watches(Session& s, Instance& in) {
    std::vector<LocalEnd::Watch> want;
    if (in.open && in.local) want = in.local->watches();
    for (const auto& w : in.watching)
        if (std::find(want.begin(), want.end(), w) == want.end()) poller_.remove(w.fd, w.write);
    Session* sp = &s;
    const uint64_t id = in.id;
    for (const auto& w : want) {
        if (std::find(in.watching.begin(), in.watching.end(), w) != in.watching.end()) continue;
        const int fd = w.fd;
        poller_.set(
            fd,
            [this, sp, id, fd] {
                auto it = sp->insts.find(id);
                if (it == sp->insts.end() || !it->second->local) return;
                Instance& in = *it->second;
                in.local->on_fd_ready(fd);
                sync_watches(*sp, in);
            },
            w.write);
    }
    in.watching = std::move(want);
}

void Daemon::close_instance(Session& s, uint64_t id, bool finished) {
    auto it = s.insts.find(id);
    if (it == s.insts.end()) return;
    Instance& in = *it->second;
    if (in.cfd >= 0 && in.cfd_owned) {  // a shared (owner) fd is the registration's
        if (in.cfd_watch) poller_.remove(in.cfd, false);
        close_client(in.cfd);  // after what's queued for it reaches the client
    }
    for (const auto& w : in.watching) poller_.remove(w.fd, w.write);  // before the end closes them
    in.watching.clear();
    if (in.conn) {
        in.conn->on_recv = nullptr;
        in.conn->on_closed = nullptr;
        in.conn->on_error = nullptr;
        in.conn->on_writable = nullptr;
        in.conn->close();
    }
    if (in.follow_fd >= 0) {  // tell the following client the outcome, then close
        const std::string e = in.local ? in.local->error() : "";
        std::string fin;
        if (!e.empty())
            fin = "E " + e + "\n";
        else if (in.local && in.local->done())
            // Flush the final state (e.g. "sent 1 file(s)") first, so the client
            // isn't left showing a stale 98% from the last tick, then signal done.
            fin = "P " + in.local->describe() + "\nD\n";
        else if (!in.open)  // never finished the handshake: the peer was unreachable
            fin = "E couldn't reach " + s.name + " (is their daemon running? check: spl ping " +
                  s.name + ")\n";
        else
            fin = "E interrupted\n";  // connected, then the path dropped mid-transfer
        spl::write_all(in.follow_fd, fin.data(), fin.size());
        ::close(in.follow_fd);
    }
    // Count it against the registration that spawned it — only if that exact
    // registration still exists (a same-named re-registration is a new one).
    if (in.reg_serial) {
        if (auto rit = s.regs.find(in.reg);
            rit != s.regs.end() && rit->second.serial == in.reg_serial) {
            --rit->second.active;
            ++rit->second.finished;
        }
    }
    const int shared_fd = (in.cfd >= 0 && !in.cfd_owned) ? in.cfd : -1;
    spl::logf("[daemon] #%llu closed (%s, up %s down %s)", (unsigned long long)id,
              finished ? "done" : "aborted", human_bytes(in.up).c_str(),
              human_bytes(in.down).c_str());
    s.insts.erase(it);
    // An inbound PIPE instance shares its registration's owner socket. If the
    // registration is already gone (unregistered/retired) and this was the last
    // instance on it, close it now — that's what ends a chat host process.
    if (shared_fd >= 0) release_owner_fd(s, shared_fd);
}

void Daemon::fail_open(Session& s, Instance& in, const std::string& why) {
    if (in.follow_fd >= 0) {  // a following CLI prints it (clearer than "interrupted")
        write_str(in.follow_fd, "E " + why + "\n");
        ::close(in.follow_fd);
        in.follow_fd = -1;
    }
    if (in.cfd >= 0 && in.cfd_owned) client_write(s, in, as_span("ERR " + why + "\n"), false);
    close_instance(s, in.id, false);
}

void Daemon::account(Session& s, uint64_t id, size_t n) {
    auto it = s.insts.find(id);
    if (it == s.insts.end()) return;  // gone: its window went with it
    Instance& in = *it->second;
    const size_t pre = std::min(n, in.preacked);  // arrived with the handshake, acked already
    in.preacked -= pre;
    if (in.conn && n > pre) in.conn->recved(n - pre);
}

void Daemon::client_write(Session& s, Instance& in, ByteSpan b, bool accounted) {
    if (in.cfd < 0 || b.empty()) return;
    ClientOut& o = client_out_[in.cfd];
    if (o.closing) {  // the client is on its way out: nobody will read this
        if (accounted) account(s, in.id, b.size());
        return;
    }
    o.q.push_back({&s, in.id, std::string(reinterpret_cast<const char*>(b.data()), b.size()),
                   accounted});
    flush_client(in.cfd);
}

void Daemon::flush_client(int fd) {
    auto it = client_out_.find(fd);
    if (it == client_out_.end()) return;
    ClientOut& o = it->second;
    bool dead = false;
    while (!o.q.empty()) {
        ClientOut::Chunk& c = o.q.front();
        const ssize_t w = ::write(fd, c.data.data() + o.off, c.data.size() - o.off);
        if (w > 0) {
            if (c.s && c.accounted) account(*c.s, c.id, static_cast<size_t>(w));
            o.off += static_cast<size_t>(w);
            if (o.off == c.data.size()) {
                o.q.pop_front();
                o.off = 0;
            }
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            poller_.set(fd, [this, fd] { flush_client(fd); }, /*writable=*/true);  // when it reads
            return;
        }
        dead = true;  // the client is gone; its read side reports that
        break;
    }
    if (dead)  // what it will never read still reopens the senders' windows
        for (size_t i = 0; i < o.q.size(); ++i) {
            const ClientOut::Chunk& c = o.q[i];
            if (c.s && c.accounted) account(*c.s, c.id, c.data.size() - (i == 0 ? o.off : 0));
        }
    poller_.remove(fd, true);
    const bool close_now = o.closing;
    client_out_.erase(it);
    if (close_now) ::close(fd);
}

void Daemon::close_client(int fd) {
    paused_owners_.erase(fd);
    auto it = client_out_.find(fd);
    if (it == client_out_.end() || it->second.q.empty()) {  // nothing pending: close now
        if (it != client_out_.end()) client_out_.erase(it);
        poller_.remove(fd);
        ::close(fd);
        return;
    }
    poller_.remove(fd, false);  // no more reading; finish writing
    it->second.closing = true;
    it->second.give_up_at = mono_ms() + 30000;
}

void Daemon::add_reg(Session& s, const std::string& name, Reg reg) {
    reg.serial = s.next_reg_serial++;
    s.regs[name] = std::move(reg);
}

void Daemon::watch_owner(Session* sp, const std::string& name, uint64_t serial, int fd) {
    paused_owners_.erase(fd);
    poller_.set(fd, [this, sp, name, serial, fd] { on_owner_readable(sp, name, serial, fd); });
}

void Daemon::on_owner_readable(Session* sp, const std::string& name, uint64_t serial, int fd) {
    // Nobody to give the bytes to, or someone without room: leave them in the
    // socket (the owner blocks) instead of dropping or piling them up here.
    bool any = false, room = true;
    for (auto& [id, in] : sp->insts)
        if (in->inbound && in->cfd == fd && in->open) {
            any = true;
            room = room && in->conn && in->conn->sndbuf() >= kChunk;
        }
    uint8_t buf[kChunk];
    ssize_t n = 0;
    if (any && room) {
        n = ::read(fd, buf, sizeof(buf));
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
    } else {
        // Still notice the owner going away: peek without consuming.
        n = ::recv(fd, buf, 1, MSG_PEEK | MSG_DONTWAIT);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
        if (n > 0) {  // data waiting, nowhere to put it: stop polling until there is
            poller_.remove(fd, false);
            paused_owners_[fd] = {sp, name, serial};
            return;
        }
    }
    if (n <= 0) {  // owner process went away -> its stream is gone
        paused_owners_.erase(fd);
        std::vector<uint64_t> users;
        for (auto& [id, in] : sp->insts)
            if (in->inbound && in->cfd == fd) users.push_back(id);
        if (auto rit = sp->regs.find(name); rit != sp->regs.end() && rit->second.serial == serial)
            unregister(*sp, name);
        // The last of these closes (and unwatches) fd via release_owner_fd.
        for (uint64_t id : users) close_instance(*sp, id, true);
        return;
    }
    // (one instance for chat; interleaving with several is the user's choice)
    for (auto& [id, in] : sp->insts)
        if (in->inbound && in->cfd == fd && in->open)
            route_to_tunnel(*sp, *in, ByteSpan(buf, static_cast<size_t>(n)));
}

void Daemon::resume_owners() {
    for (auto it = paused_owners_.begin(); it != paused_owners_.end();) {
        const int fd = it->first;
        const PausedOwner po = it->second;
        bool any = false, room = true;
        for (auto& [id, in] : po.s->insts)
            if (in->inbound && in->cfd == fd && in->open) {
                any = true;
                room = room && in->conn && in->conn->sndbuf() >= kChunk;
            }
        ++it;
        if (any && room) watch_owner(po.s, po.name, po.serial, fd);  // erases its entry
    }
}

void Daemon::release_owner_fd(Session& s, int fd) {
    for (const auto& [rname, reg] : s.regs)
        if (reg.owner_fd == fd) return;
    for (const auto& [id, in] : s.insts)
        if (in->cfd == fd) return;
    poller_.remove(fd, false);
    close_client(fd);
}

// Remove a registration: stop offering it (and delete it from the store if it
// was persisted). Its live instances keep running; their ids are returned so
// the caller can tell the user. A PIPE's owner socket stays open while any of
// them still uses it.
std::vector<uint64_t> Daemon::unregister(Session& s, const std::string& name) {
    std::vector<uint64_t> live;
    auto it = s.regs.find(name);
    if (it == s.regs.end()) return live;
    const uint64_t serial = it->second.serial;
    const int owner_fd = it->second.owner_fd;
    for (const auto& [id, in] : s.insts)
        if (in->reg_serial == serial) live.push_back(id);
    if (it->second.persisted && store_) store_->remove_pipe(s.name, name);
    s.regs.erase(it);
    if (owner_fd >= 0) release_owner_fd(s, owner_fd);
    return live;
}

// End a peer's session: its connections, its (in-memory) offers, its sockets.
// The store is not touched — whoever removed the peer already dealt with it, and
// the name may by now belong to a different peer.
void Daemon::drop_session(const std::string& name) {
    auto it = sessions_.find(name);
    if (it == sessions_.end()) return;
    Session& s = it->second;
    std::vector<uint64_t> ids;
    for (const auto& [id, in] : s.insts) ids.push_back(id);
    for (uint64_t id : ids) close_instance(s, id, false);
    for (auto& [rname, reg] : s.regs)
        if (reg.owner_fd >= 0) {
            poller_.remove(reg.owner_fd, false);
            close_client(reg.owner_fd);
        }
    s.regs.clear();
    for (auto& [fd, o] : client_out_)  // queued output outlives the session: unlink it
        for (auto& c : o.q)
            if (c.s == &s) c.s = nullptr;
    for (auto pit = paused_owners_.begin(); pit != paused_owners_.end();)
        pit = pit->second.s == &s ? paused_owners_.erase(pit) : std::next(pit);
    poller_.remove(s.pm->fd());
    sessions_.erase(it);
}

// RELOAD: make the running sessions match the peer files. A peer is identified
// by its uid, not its name, so: a uid no longer on disk is dropped (removed
// peers lose access now, not at the next restart), a uid whose file has a new
// name is renamed in place (connections and offers survive), and a new uid gets
// a session.
std::string Daemon::reload() {
    if (!store_) return "no config store";
    std::map<proto::Uid, ConnRecord> on_disk;
    for (auto& r : store_->load_all()) on_disk[r.uid] = r;

    std::vector<std::string> gone, moved;
    for (const auto& [name, s] : sessions_) {
        auto it = on_disk.find(s.rec.uid);
        if (it == on_disk.end())
            gone.push_back(name);
        else if (it->second.name != name)
            moved.push_back(name);
    }
    for (const auto& name : gone) {
        spl::logf("[daemon] reload: peer '%s' was removed; dropping its session", name.c_str());
        drop_session(name);
    }
    // Extract every renamed session before re-inserting any, so swapped names
    // work. Extraction keeps the Session object in place (callbacks hold it).
    std::vector<std::map<std::string, Session>::node_type> nodes;
    for (const auto& name : moved) nodes.push_back(sessions_.extract(name));
    for (auto& node : nodes) {
        const ConnRecord& rec = on_disk.at(node.mapped().rec.uid);
        spl::logf("[daemon] reload: peer '%s' renamed to '%s'", node.key().c_str(),
                  rec.name.c_str());
        node.key() = rec.name;
        node.mapped().name = rec.name;
        sessions_.insert(std::move(node));
    }
    size_t added = 0;
    for (const auto& [uid, rec] : on_disk) {
        bool have = false;
        for (auto& [name, s] : sessions_)
            if (s.rec.uid == uid) {
                s.rec = rec;  // pick up any edited fields
                apply_peer_settings(s);
                have = true;
            }
        if (have) continue;
        std::string err;
        if (start_session(rec, &err)) {
            spl::logf("[daemon] reload: new peer '%s'", rec.name.c_str());
            ++added;
        } else {
            spl::logf("[daemon] reload: session %s: %s", rec.name.c_str(), err.c_str());
        }
    }
    return std::to_string(sessions_.size()) + " peer(s): " + std::to_string(added) + " added, " +
           std::to_string(gone.size()) + " removed, " + std::to_string(moved.size()) + " renamed";
}

// A LAN discovery query: find the session whose peer sent it (only they can
// produce its MAC) and let that session answer from its own socket. We answer
// only for peers we're active with — nothing offered or running means nothing
// to reach, and an idle daemon stays silent.
void Daemon::on_lan_discovery() {
    uint8_t buf[256];
    for (;;) {
        sockaddr_storage ss{};
        socklen_t slen = sizeof(ss);
        ssize_t n = ::recvfrom(lan_fd_.get(), buf, sizeof(buf), 0,
                               reinterpret_cast<sockaddr*>(&ss), &slen);
        if (n < 0) return;
        const ByteSpan pkt(buf, static_cast<size_t>(n));
        if (!PathManager::is_lan_query(pkt)) continue;
        const Endpoint src = endpoint_from_sockaddr(ss);
        for (auto& [name, s] : sessions_) {
            if (!s.pm->active() || !s.pm->lan_query_from_peer(pkt)) continue;
            s.pm->answer_lan_query(src, pkt, mono_ms());
            break;
        }
    }
}

// The session follows its peer's record: the per-peer settings, and (when
// remember-address is on) the addresses that worked before.
void Daemon::apply_peer_settings(Session& s) {
    s.pm->set_relay_enabled(s.rec.use_relay);
    s.pm->set_lan_broadcast(s.rec.lan_discovery);
    s.learned_port = store_ ? store_->load_learned_port(s.name) : 0;
    s.pm->set_lan_port(s.peer_lan_port());
    s.seen.clear();
    if (s.rec.remember_address && store_) s.seen = store_->load_seen(s.name);
    s.seed_seen = !s.seen.empty();
}

// Where to send LAN queries besides the broadcasts: the user's address hints and
// the hosts of remembered addresses (the peer's daemon may have restarted on a
// new port, but it is probably still at that IP). A remembered address is also
// offered once as an exact candidate, in case the very same socket is still up.
void Daemon::refresh_hints(Millis now) {
    for (auto& [name, s] : sessions_) {
        std::vector<Endpoint> eps;
        auto add = [&](const Endpoint& ep) {
            if (std::find(eps.begin(), eps.end(), ep) == eps.end()) eps.push_back(ep);
        };
        // A host with no port is asked on the port this *peer* listens on.
        const uint16_t peer_port = s.peer_lan_port();
        for (const auto& a : s.rec.addresses) {
            std::string host;
            uint16_t port = 0;
            if (!parse_address_hint(a, &host, &port)) continue;
            if (auto ep = hints_.get(host, port ? port : peer_port, now)) add(*ep);
        }
        bool all_seeded = true;
        for (const auto& sa : s.seen) {
            std::string host;
            uint16_t port = 0;
            if (!parse_address_hint(sa.addr, &host, &port)) continue;
            if (auto ep = hints_.get(host, peer_port, now)) {
                add(*ep);
                if (s.seed_seen && port) {
                    Endpoint exact = *ep;
                    exact.port = port;
                    s.pm->add_candidate(exact, now);
                }
            } else {
                all_seeded = false;
            }
        }
        if (all_seeded) s.seed_seen = false;
        s.pm->set_lan_hints(std::move(eps));
    }
}

// Note the direct address each session is using, newest first, so the next
// start can try it straight away. Rewritten only when it changes (or hourly, to
// keep its "seen" time meaningful).
void Daemon::remember_paths(Millis now) {
    if (!store_) return;
    constexpr size_t kMaxSeen = 4;
    const int64_t t = static_cast<int64_t>(std::time(nullptr));
    for (auto& [name, s] : sessions_) {
        if (!s.rec.remember_address) continue;
        const PathStatus ps = s.pm->status(now);
        for (const auto& c : ps.cands) {
            if (!c.in_use) continue;
            const std::string addr = c.ep.to_string();
            if (!s.seen.empty() && s.seen[0].addr == addr && t - s.seen[0].when_unix < 3600) break;
            std::erase_if(s.seen, [&](const SeenAddress& x) { return x.addr == addr; });
            s.seen.insert(s.seen.begin(), SeenAddress{addr, t});
            if (s.seen.size() > kMaxSeen) s.seen.resize(kMaxSeen);
            store_->save_seen(name, s.seen);
            break;
        }
    }
}

// The discovery socket exists only while some peer session is active (something
// offered, a connection running, or the warm window after): an idle daemon holds
// no port open. A failed bind (port taken) is retried every 10s.
void Daemon::set_lan_listening(bool want) {
    if (!want) {
        if (lan_fd_) {
            poller_.remove(lan_fd_.get());
            lan_fd_ = net::Fd{};
            t_lan_bind_.rearm();  // reopen at once when a peer next becomes active
        }
        return;
    }
    if (lan_fd_ || !t_lan_bind_.due(mono_ms(), 10'000)) return;
    std::string err;
    lan_fd_ = net::udp_bind_shared(lan_port_, &err);
    if (!lan_fd_) {
        spl::logf("daemon: LAN discovery port %u unavailable (%s); peers on the local network "
                  "won't find us by broadcast (set [peer] lan_port in the config to move it)",
                  lan_port_, err.c_str());
        return;
    }
    net::set_nonblocking(lan_fd_.get(), true);
    poller_.set(lan_fd_.get(), [this] { on_lan_discovery(); });
}

void Daemon::adopt_server() {
    {
        std::lock_guard<std::mutex> lk(lookup_->m);
        if (!lookup_->ep) return;
        server_ = *lookup_->ep;
    }
    spl::logf("[daemon] relay %s resolved (%s)", opts_.server.c_str(), server_.to_string().c_str());
    for (auto& [name, s] : sessions_) s.pm->set_server(server_);
}

void Daemon::tick(Millis now) {
    reap_orphans(now);  // programs whose connection went away before they ended
    resume_owners();    // owner sockets paused for want of a connection with room
    for (auto it = client_out_.begin(); it != client_out_.end();) {  // closing, never drained
        if (it->second.closing && now >= it->second.give_up_at) {
            const int fd = it->first;
            poller_.remove(fd);
            ::close(fd);
            it = client_out_.erase(it);
        } else {
            ++it;
        }
    }
    if (!server_.valid()) adopt_server();
    if (t_hints_.due(now, 500)) refresh_hints(now);
    if (t_remember_.due(now, 2000)) remember_paths(now);
    bool any_busy = false, any_warm = false;
    for (auto& [name, s] : sessions_) {
        // Activity gate: full disco only while something is listening or running,
        // or within the warm window after the last one. Otherwise the session
        // goes dormant (no relay traffic, no probing).
        const bool busy = !s.regs.empty() || !s.insts.empty();
        any_busy |= busy;
        if (busy) s.last_active = now;
        const bool warm = busy || (s.last_active && now - s.last_active < kWarmMs);
        s.pm->set_active(warm);
        any_warm |= warm;
        // Dormant: don't drive the path manager OR lwIP — a frozen lwIP can't even
        // leak its own IPv6 housekeeping (MLD/DAD) out through the tunnel. handle_io
        // still runs, and a local REGISTER/OPEN flips us back to warm next tick.
        if (!warm) continue;

        s.pm->tick(now);
        s.ns->check_timeouts();

        for (size_t i = 0; i < s.want_close.size(); ++i)  // ends may queue more
            close_instance(s, s.want_close[i], true);
        s.want_close.clear();

        for (uint64_t serial : s.want_retire)
            for (const auto& [rname, reg] : s.regs)
                if (reg.serial == serial) {
                    unregister(s, rname);
                    break;
                }
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
            if (in.local) {
                in.local->tick(now);
                sync_watches(s, in);  // e.g. resume reads paused while the tunnel was full
            }
            // Stream progress to a following client when it changes. Until the
            // handshake lands there are no bytes moving, so show that we're still
            // connecting rather than a misleading "0%".
            if (in.follow_fd >= 0) {
                std::string line = in.open && in.local ? "P " + in.local->describe() + "\n"
                                                       : "P connecting to " + name + "...\n";
                if (line != in.follow_last_) {
                    in.follow_last_ = line;
                    spl::write_all(in.follow_fd, line.data(), line.size());
                }
            }
        }
        for (uint64_t id : expired)
            if (auto it = s.insts.find(id); it != s.insts.end())
                fail_open(s, *it->second, "couldn't reach " + name +
                                              " (is their daemon running? check: spl ping " +
                                              name + ")");
    }

    set_lan_listening(any_warm);

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
        // Only our own user may drive the daemon (the 0700 dir already ensures
        // this; the kernel's word on the peer uid is a second, independent check).
        if (net::socket_peer_uid(fd) != ::getuid()) {
            ::close(fd);
            continue;
        }
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

    if (cmd == "RELOAD") {
        const std::string summary = reload();
        t_hints_.rearm();  // edited address hints take effect on the next tick
        return reply_close("OK " + summary + "\n");
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
            std::vector<uint64_t> live;
            for (const auto& rname : names)
                for (uint64_t id : unregister(s, rname)) live.push_back(id);
            for (uint64_t id : live) close_instance(s, id, false);  // reset ends them too
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
            net::set_nonblocking(fd, true);  // never let a slow client stall the daemon
            add_reg(*s, name, Reg{.type = "PIPE", .limit = limit, .owner_fd = fd});
            const uint64_t serial = s->regs[name].serial;
            Session* sp = s;
            watch_owner(sp, name, serial, fd);
            return;
        }
        // Daemon-owned: validate, persist (with its limit), add to the table.
        std::string terr;
        if (!make_local_end(type, args, &terr)) return reply_close("ERR " + terr + "\n");
        if (!store_) return reply_close("ERR no config store\n");
        if (!store_->save_pipe(PipeRecord{s->name, name, type, limit, args}, &terr))
            return reply_close("ERR " + terr + "\n");
        add_reg(*s, name, Reg{.type = type, .args = args, .limit = limit, .persisted = true});
        return reply_close("OK\n");
    }

    if (cmd == "UNREGISTER") {
        if (t.size() != 3) return reply_close("ERR usage: UNREGISTER <peer> <id>\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) return reply_close("ERR " + err + "\n");
        const std::string& name = t[2];
        if (!s->regs.count(name)) return reply_close("ERR no pipe '" + name + "'\n");
        const std::vector<uint64_t> live = unregister(*s, name);
        if (live.empty()) return reply_close("OK\n");
        // Tell the user their live connections survive, and how to end them.
        std::string ids, hint;
        for (uint64_t id : live) {
            ids += (ids.empty() ? "#" : ", #") + std::to_string(id);
            hint += (hint.empty() ? "spl pipe close " : "; spl pipe close ") + s->name + " " +
                    std::to_string(id);
        }
        const std::string n = live.size() == 1 ? "1 connection" : std::to_string(live.size()) +
                                                                       " connections";
        return reply_close("OK note: " + n + " via '" + name + "' still active (" + ids +
                           "); " + (live.size() == 1 ? "it keeps" : "they keep") +
                           " running — " + hint + " to end " +
                           (live.size() == 1 ? "it" : "them") + "\n");
    }

    if (cmd == "OPEN") {
        // OPEN <peer> <pipe> [WAIT] [FOLLOW] <TYPE> [args]
        //   WAIT   keeps re-dialing while the peer answers UNKNOWN (not registered yet)
        //   FOLLOW streams progress (P/D/E lines) back on this control connection
        //   EXPECT <kind>  the offer must be of this kind (pipes.h); without it,
        //          what the local TYPE needs (GET_FILE needs a file sender, …)
        size_t ti = 3;
        bool wait = false, follow = false;
        std::string expect;
        for (; ti < t.size() && (t[ti] == "WAIT" || t[ti] == "FOLLOW" || t[ti] == "EXPECT"); ++ti) {
            if (t[ti] == "WAIT") wait = true;
            if (t[ti] == "FOLLOW") follow = true;
            if (t[ti] == "EXPECT") {
                if (++ti >= t.size()) break;
                expect = t[ti];
            }
        }
        if (t.size() <= ti)
            return reply_close(
                "ERR usage: OPEN <peer> <pipe> [WAIT] [FOLLOW] [EXPECT <kind>] <TYPE> [args]\n");
        std::string err;
        Session* s = session_for(t[1], &err);
        if (!s) return reply_close("ERR " + err + "\n");
        auto in = std::make_unique<Instance>();
        in->id = s->next_id++;
        in->want = t[2];
        in->type = t[ti];
        in->args.assign(t.begin() + ti + 1, t.end());
        in->wait = wait;
        in->expect = expect.empty() ? local_expects(in->type) : expect;
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
            net::set_nonblocking(fd, true);  // never let a slow client stall the daemon
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
std::string join_desc(const std::string& type, const std::vector<std::string>& args) {
    std::string d = type;
    for (const auto& a : args) d += " " + a;
    return d;
}

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
    if (!server_.valid())
        o << "RELAY " << opts_.server << ":" << opts_.port
          << " unresolved (offline?) — retrying; only direct paths work meanwhile\n";
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
        o << "  " << settings_summary(s.effective()) << " · " << ps.cands.size()
          << (ps.cands.size() == 1 ? " address known\n" : " addresses known\n");

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

        // --- what we offer (daemon-owned + live PIPEs): counters only ---
        if (!s.regs.empty()) o << "  OFFERED\n";
        for (const auto& [rname, reg] : s.regs) {
            o << "    " << rname << "  " << join_desc(reg.type, reg.args) << "  (" << reg.finished
              << " finished, " << reg.active << " active)";
            if (verbose && reg.limit) o << "  [limit " << reg.started << "/" << reg.limit << "]";
            o << "\n";
        }

        // --- live connections, each showing what it connected to *at the time*
        // (independent of the current registrations). Meta round-trips are internal.
        bool any = false;
        for (const auto& [id, in] : s.insts) {
            // Skip internal meta round-trips and inbound handshakes not yet resolved.
            if (in->meta || (in->inbound && !in->open)) continue;
            if (!any) o << "  CONNECTIONS\n";
            any = true;
            o << "    #" << id << "  ";
            if (in->inbound)
                o << "in   " << in->reg;
            else
                o << "out  " << name << ":" << in->want;
            o << "  " << join_desc(in->type, in->args);
            if (!in->open) o << (in->wait ? " (waiting)" : " (connecting)");
            o << "  up " << human_bytes(in->up) << " down " << human_bytes(in->down);
            if (in->local) o << " | " << in->local->describe();
            o << "\n";
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
    // Resolve the relay in the background (see ServerLookup). Give it a moment so
    // the normal online case starts with the relay already known; if it isn't
    // (offline, DNS down) carry on without — only direct paths work until it is.
    lookup_ = std::make_shared<ServerLookup>();
    std::thread([st = lookup_, host = opts_.server, port = opts_.port] {
        for (;;) {
            auto ep = net::resolve(host, port);
            {
                std::lock_guard<std::mutex> lk(st->m);
                st->ep = ep;
                st->tried = true;
                st->cv.notify_all();
            }
            if (ep) return;
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }).detach();
    {
        std::unique_lock<std::mutex> lk(lookup_->m);
        lookup_->cv.wait_for(lk, std::chrono::milliseconds(300),
                             [this] { return lookup_->tried; });
        if (lookup_->ep) server_ = *lookup_->ep;
    }
    if (!server_.valid())
        spl::logf("daemon: cannot resolve relay %s yet; running without it (retrying)",
                  opts_.server.c_str());

    // LAN discovery socket. Test hooks: SPL_LAN_PORT moves it (two daemons on one
    // host), SPL_LAN_TARGETS="host:port,…" replaces broadcasting with those targets.
    lan_port_ = own_lan_port();
    if (const char* v = std::getenv("SPL_LAN_TARGETS")) {
        std::istringstream is(v);
        std::string item;
        while (std::getline(is, item, ',')) {
            const size_t colon = item.rfind(':');
            if (colon == std::string::npos) continue;
            if (auto ep = net::resolve(item.substr(0, colon),
                                       static_cast<uint16_t>(std::atoi(item.c_str() + colon + 1))))
                lan_targets_.push_back(*ep);
        }
    }
    // (The socket itself is opened by tick() when a peer first becomes active.)

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

    // Every connection ends with the daemon: programs still running are hung
    // up as their instances go, then given a moment, then killed.
    sessions_.clear();
    stop_orphans(2000);

    ::close(lfd_);
    ::unlink(path.c_str());
    return 0;
}

}  // namespace

std::string runtime_dir() {
    // Resolved and checked once per process (a forked daemon inherits it).
    static const std::string dir = [] {
        std::string d;
        if (const char* e = std::getenv("SPL_RUNTIME_DIR"); e && *e) {
            d = e;
        } else if (const char* x = std::getenv("XDG_RUNTIME_DIR"); x && *x) {
            d = std::string(x) + "/spl";
        } else {
            const char* t = std::getenv("TMPDIR");  // per-user on macOS; usually unset on Linux
            std::string base = (t && *t) ? t : "/tmp";
            while (base.size() > 1 && base.back() == '/') base.pop_back();
            d = base + "/spl-" + std::to_string(getuid());
        }
        std::string err;
        if (!net::ensure_private_dir(d, &err)) {
            spl::logf("spl: %s", err.c_str());
            std::exit(1);
        }
        return d;
    }();
    return dir;
}

std::string daemon_socket_path() { return runtime_dir() + "/daemon.sock"; }

uint16_t own_lan_port() {
    if (const char* v = std::getenv("SPL_LAN_PORT")) {
        const int n = std::atoi(v);
        if (n > 0 && n < 65536) return static_cast<uint16_t>(n);
    }
    const Config c = load_config();
    return c.lan_port ? c.lan_port : kLanDiscoPort;
}

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
