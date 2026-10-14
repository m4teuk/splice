// Daemon-owned pipe ends. A LocalEnd is the local half of a spliced connection
// when the daemon itself runs it (ECHO, SHARE_FILE/GET_FILE, EXEC/SHELL) — as
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

    std::function<void(ByteSpan)> to_tunnel;   // send bytes to the other end
    std::function<size_t()> tunnel_space;      // bytes currently sendable without queueing
    std::function<void()> shutdown;            // ask the daemon to close this instance
    // With manual_flow(): report `n` bytes from on_tunnel_data as consumed. Until
    // then they count against the sender's window, so the sender slows down.
    std::function<void(size_t)> consumed;
    std::string peer;                          // the peer's name (set before start)

    virtual void start() {}                    // splicing begins (handshake done)
    virtual void on_tunnel_data(ByteSpan b) = 0;
    virtual void on_tunnel_closed() {}         // other end closed (instance is dying)
    virtual void on_tunnel_writable() {}       // send buffer freed up (pump opportunity)
    virtual void tick(Millis) {}
    virtual std::string describe() const = 0;  // one status line fragment
    virtual bool done() const { return false; }       // finished its job successfully
    virtual std::string error() const { return ""; }  // non-empty if it failed

    // True: the end calls consumed() for every byte on_tunnel_data gives it,
    // when it has really taken it (e.g. written it on to a process), so a slow
    // consumer holds the sender back rather than growing a buffer here.
    virtual bool manual_flow() const { return false; }

    // Descriptors the daemon polls on this end's behalf (a process's pipes, a
    // PTY), each for readability or writability. The daemon asks again after
    // every call into the end, so the set can change: e.g. leave a read fd out
    // while the tunnel is full (backpressure), or a write fd out while there's
    // nothing to write. When one is ready the daemon calls on_fd_ready(fd); the
    // end does the I/O itself. The end owns the fds and closes them; one it
    // closes just drops out of the set.
    struct Watch {
        int fd;
        bool write;
        bool operator==(const Watch& o) const { return fd == o.fd && write == o.write; }
    };
    virtual std::vector<Watch> watches() const { return {}; }
    virtual void on_fd_ready(int) {}
};

// ECHO: sends back everything it receives. Diagnostics.
class EchoEnd : public LocalEnd {
 public:
    void on_tunnel_data(ByteSpan b) override {
        if (to_tunnel) to_tunnel(b);
    }
    std::string describe() const override { return "echo"; }
};

// SHARE_FILE <path> / GET_FILE <target> speak a multi-entry, resumable protocol
// above the raw pipe. A path may be a single file or a directory (streamed
// recursively). Per entry the sender offers, the receiver says how much it
// already has, then the sender streams the rest:
//
//   sender -> "SPLF2 <size> <crc32hex> <relpath>\n"
//   recv   -> "RESUME <offset>\n"        (offset bytes of a matching .part it kept)
//   sender -> <size - offset> raw bytes
//   ...                                  (repeat per entry)
//   sender -> "SPLF2-END\n"
//
// The receiver writes each entry to "<dest>.part" (+ a ".part.meta" recording
// size/crc/relpath) and renames to <dest> once the crc verifies — so an
// interrupted transfer resumes, and a same-named-but-changed file restarts
// (the crc won't match). The "SPLF2" magic also lets the receiver tell a
// non-file pipe apart from a real SHARE_FILE.

// SHARE_FILE <path>: streams <path> (file or directory). Ignores nothing — it
// reads RESUME offsets from the receiver.
class ShareFileEnd : public LocalEnd {
 public:
    struct Entry {
        std::string relpath;  // path as the receiver should store it (with '/')
        std::string abspath;  // local file to read
        uint64_t size = 0;
    };
    // Enumerate <path> (file -> one entry; dir -> recursive). Null + *err if
    // unreadable / empty.
    static std::unique_ptr<ShareFileEnd> open(const std::string& path, std::string* err);
    ~ShareFileEnd() override;
    void start() override { pump(); }
    void on_tunnel_data(ByteSpan b) override;  // RESUME lines
    void on_tunnel_writable() override { pump(); }
    std::string describe() const override;
    bool done() const override { return state_ == State::Done; }
    std::string error() const override { return err_; }

 private:
    enum class State { Offer, WaitResume, Stream, End, Done };
    void pump();
    std::vector<Entry> entries_;
    size_t idx_ = 0;
    State state_ = State::Offer;
    FILE* f_ = nullptr;
    uint64_t remaining_ = 0;   // bytes left to stream in the current entry
    uint64_t total_ = 0, sent_ = 0;
    std::string rbuf_;         // accumulates the RESUME line
    std::string err_;
};

// GET_FILE <target> [OVERWRITE]: receives a SPLF2 stream into <target> (an
// existing directory -> files placed by relpath under it; otherwise a single
// file written to that path). Resumes from a kept ".part"; verifies crc.
class GetFileEnd : public LocalEnd {
 public:
    GetFileEnd(std::string target, bool overwrite)
        : target_(std::move(target)), overwrite_(overwrite) {}
    ~GetFileEnd() override;
    void on_tunnel_data(ByteSpan b) override;
    void on_tunnel_closed() override;
    std::string describe() const override;
    bool done() const override { return done_; }
    std::string error() const override { return err_; }

 private:
    void handle_header(const std::string& line);  // an OFFER or END line
    void finish_entry();
    void fail(const std::string& why);
    std::string target_;
    bool overwrite_ = false;
    enum class State { Header, Recv, Done } state_ = State::Header;
    std::string hdr_;          // accumulates the current OFFER/END line
    // current entry:
    std::string dest_, part_, meta_, relpath_;
    FILE* f_ = nullptr;
    uint64_t size_ = 0, got_ = 0;
    uint32_t want_crc_ = 0, crc_ = 0;
    uint64_t files_ = 0;       // completed files (for describe)
    bool done_ = false;
    std::string err_;
};

// --- kinds --------------------------------------------------------------
// A kind says what an offer is, from the offering side: "<protocol>/<version>"
// plus words about this end ("file/1 send", "file/1 recv", "exec/1", "exec/1 pty",
// "raw").
// The offering daemon announces it in the handshake reply ("OK <kind>"), so the
// opener knows what it reached without trusting anything said later in-band.
// An older peer announces nothing (""): treated as unknown, not as a mismatch.

// The kind an offer of `type` (with `args`) announces.
std::string offer_kind(const std::string& type, const std::vector<std::string>& args = {});
// The kind a local end of `type` needs the other side to be ("" = anything).
std::string local_expects(const std::string& type);
// Does `remote` satisfy `expect`? Same protocol, and every word of `expect`
// present in `remote`. An empty side (unknown / anything) always matches.
bool kind_matches(const std::string& remote, const std::string& expect);
// For people: what an offer of this kind does ("sends files"), and the command
// that uses it ("spl get desk report.pdf").
std::string kind_label(const std::string& kind);
std::string kind_usage(const std::string& kind, const std::string& peer, const std::string& name);

// Text a peer sent us, made safe to print: anything outside printable ASCII
// (terminal escape sequences included) becomes '?'.
std::string printable(const std::string& s);

// Factory for daemon-owned types ("ECHO", "SHARE_FILE", "GET_FILE").
// Returns null with *err set for unknown types/bad args (REGISTER also uses
// this as validation, e.g. an unreadable SHARE_FILE path fails here).
std::unique_ptr<LocalEnd> make_local_end(const std::string& type,
                                         const std::vector<std::string>& args, std::string* err);

}  // namespace spl::peer
