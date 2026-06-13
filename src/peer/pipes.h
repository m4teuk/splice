// Daemon-owned pipe ends. A LocalEnd is the local half of a spliced connection
// when the daemon itself runs it (PONG now; SHARE_FILE/GET_FILE later) — as
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

    virtual void start() {}                    // splicing begins (handshake done)
    virtual void on_tunnel_data(ByteSpan b) = 0;
    virtual void on_tunnel_closed() {}         // other end closed (instance is dying)
    virtual void on_tunnel_writable() {}       // send buffer freed up (pump opportunity)
    virtual void tick(Millis) {}
    virtual std::string describe() const = 0;  // one status line fragment
    virtual bool done() const { return false; }       // finished its job successfully
    virtual std::string error() const { return ""; }  // non-empty if it failed
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

// Factory for daemon-owned types ("ECHO", "SHARE_FILE", "GET_FILE").
// Returns null with *err set for unknown types/bad args (REGISTER also uses
// this as validation, e.g. an unreadable SHARE_FILE path fails here).
std::unique_ptr<LocalEnd> make_local_end(const std::string& type,
                                         const std::vector<std::string>& args, std::string* err);

}  // namespace spl::peer
