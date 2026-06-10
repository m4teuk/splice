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
};

// ECHO: sends back everything it receives. Diagnostics.
class EchoEnd : public LocalEnd {
 public:
    void on_tunnel_data(ByteSpan b) override {
        if (to_tunnel) to_tunnel(b);
    }
    std::string describe() const override { return "echo"; }
};

// SHARE_FILE/GET_FILE speak a one-line protocol above the raw pipe:
//   "SPLF1 <size> <name>\n" then exactly <size> raw bytes.
// The name is advisory (a suggested filename, spaces allowed); the size is what
// lets the receiver know the transfer completed — a close alone proves nothing.
std::string format_file_header(uint64_t size, const std::string& name);
// Parses a complete header line (without the newline). False if malformed.
bool parse_file_header(const std::string& line, uint64_t* size, std::string* name);
// Reduce an advisory name to a safe single path component ("received.file" if
// nothing safe remains).
std::string safe_file_name(const std::string& name);

// SHARE_FILE <path>: streams the file's content (header first). Ignores input.
class ShareFileEnd : public LocalEnd {
 public:
    static std::unique_ptr<ShareFileEnd> open(const std::string& path, std::string* err);
    ~ShareFileEnd() override;
    void start() override { pump(); }
    void on_tunnel_data(ByteSpan) override {}  // not our problem
    void on_tunnel_writable() override { pump(); }
    std::string describe() const override;

 private:
    void pump();
    FILE* f_ = nullptr;
    std::string name_;
    uint64_t size_ = 0, sent_ = 0;
    bool header_sent_ = false;
};

// GET_FILE <target> [OVERWRITE]: writes the stream to <target> (a directory
// target uses the sender's suggested name inside it). Writes to <path>.part and
// renames on completion; a broken transfer leaves nothing behind.
class GetFileEnd : public LocalEnd {
 public:
    GetFileEnd(std::string target, bool overwrite)
        : target_(std::move(target)), overwrite_(overwrite) {}
    ~GetFileEnd() override;
    void on_tunnel_data(ByteSpan b) override;
    void on_tunnel_closed() override;
    std::string describe() const override;

 private:
    void fail(const std::string& why);
    std::string target_;
    bool overwrite_ = false;
    std::string hdr_;          // header accumulator
    std::string path_, name_;  // resolved once the header arrives
    FILE* f_ = nullptr;
    uint64_t size_ = 0, got_ = 0;
    bool done_ = false;
    std::string error_;
};

// Factory for daemon-owned types ("ECHO", "SHARE_FILE", "GET_FILE").
// Returns null with *err set for unknown types/bad args (REGISTER also uses
// this as validation, e.g. an unreadable SHARE_FILE path fails here).
std::unique_ptr<LocalEnd> make_local_end(const std::string& type,
                                         const std::vector<std::string>& args, std::string* err);

}  // namespace spl::peer
