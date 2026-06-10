#include "peer/pipes.h"

#include <sys/stat.h>

#include <cstdio>
#include <cstring>

#include "common/log.h"

namespace spl::peer {

namespace {

constexpr size_t kFileChunk = 8192;

std::string basename_of(const std::string& path) {
    const size_t s = path.find_last_of('/');
    return s == std::string::npos ? path : path.substr(s + 1);
}

bool is_dir(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool exists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

std::string pct(uint64_t part, uint64_t total) {
    if (!total) return "?";
    return std::to_string(part * 100 / total) + "%";
}

}  // namespace

// ---- the SHARE_FILE/GET_FILE pair protocol ----

std::string format_file_header(uint64_t size, const std::string& name) {
    return "SPLF1 " + std::to_string(size) + " " + name + "\n";
}

bool parse_file_header(const std::string& line, uint64_t* size, std::string* name) {
    if (line.rfind("SPLF1 ", 0) != 0) return false;
    const size_t sp = line.find(' ', 6);
    if (sp == std::string::npos || sp == 6) return false;
    char* end = nullptr;
    *size = std::strtoull(line.substr(6, sp - 6).c_str(), &end, 10);
    *name = line.substr(sp + 1);
    return !name->empty();
}

std::string safe_file_name(const std::string& name) {
    std::string base = basename_of(name);
    while (!base.empty() && base[0] == '.') base.erase(0, 1);  // no dotfiles / ".."
    return base.empty() ? "received.file" : base;
}

// ---- SHARE_FILE ----

std::unique_ptr<ShareFileEnd> ShareFileEnd::open(const std::string& path, std::string* err) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        if (err) *err = "cannot read '" + path + "'";
        return nullptr;
    }
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        std::fclose(f);
        if (err) *err = "'" + path + "' is not a regular file";
        return nullptr;
    }
    auto e = std::make_unique<ShareFileEnd>();
    e->f_ = f;
    e->size_ = static_cast<uint64_t>(st.st_size);
    e->name_ = basename_of(path);
    return e;
}

ShareFileEnd::~ShareFileEnd() {
    if (f_) std::fclose(f_);
}

void ShareFileEnd::pump() {
    if (!f_ || !to_tunnel) return;
    if (!header_sent_) {
        header_sent_ = true;
        to_tunnel(as_span(format_file_header(size_, name_)));
    }
    while (sent_ < size_) {
        if (tunnel_space && tunnel_space() < kFileChunk) return;  // resumed by on_tunnel_writable
        uint8_t buf[kFileChunk];
        const size_t n = std::fread(buf, 1, sizeof(buf), f_);
        if (n == 0) break;  // truncated under us; close — the receiver's count won't add up
        sent_ += n;
        to_tunnel(ByteSpan(buf, n));
    }
    if (shutdown) shutdown();  // all queued (or unreadable): flush + FIN
}

std::string ShareFileEnd::describe() const {
    return "sending " + name_ + " " + pct(sent_, size_) + " (" + human_bytes(sent_) + "/" +
           human_bytes(size_) + ")";
}

// ---- GET_FILE ----

GetFileEnd::~GetFileEnd() {
    if (f_) std::fclose(f_);
}

void GetFileEnd::fail(const std::string& why) {
    error_ = why;
    if (f_) {
        std::fclose(f_);
        f_ = nullptr;
        ::remove((path_ + ".part").c_str());
    }
    if (shutdown) shutdown();
}

void GetFileEnd::on_tunnel_data(ByteSpan b) {
    size_t off = 0;
    if (!f_ && !done_) {  // header phase
        while (off < b.size() && hdr_.size() < 512) {
            const char c = static_cast<char>(b[off++]);
            if (c == '\n') {
                if (!parse_file_header(hdr_, &size_, &name_)) return fail("bad header");
                path_ = is_dir(target_) ? target_ + "/" + safe_file_name(name_) : target_;
                if (!overwrite_ && exists(path_)) return fail("'" + path_ + "' exists");
                f_ = std::fopen((path_ + ".part").c_str(), "wb");
                if (!f_) return fail("cannot write '" + path_ + ".part'");
                if (size_ == 0) {  // empty file: complete immediately
                    std::fclose(f_);
                    f_ = nullptr;
                    if (::rename((path_ + ".part").c_str(), path_.c_str()) != 0)
                        return fail("rename failed");
                    done_ = true;
                    if (shutdown) shutdown();
                    return;
                }
                break;
            }
            hdr_ += c;
        }
        if (!f_ && !done_) {
            if (hdr_.size() >= 512) fail("bad header");
            return;
        }
    }
    if (!f_) return;

    const size_t keep = static_cast<size_t>(std::min<uint64_t>(b.size() - off, size_ - got_));
    if (keep && std::fwrite(b.data() + off, 1, keep, f_) != keep) return fail("write failed");
    got_ += keep;
    if (got_ == size_) {
        std::fclose(f_);
        f_ = nullptr;
        if (::rename((path_ + ".part").c_str(), path_.c_str()) != 0) return fail("rename failed");
        done_ = true;
        if (shutdown) shutdown();
    }
}

void GetFileEnd::on_tunnel_closed() {
    if (done_) return;
    if (f_) {
        std::fclose(f_);
        f_ = nullptr;
        ::remove((path_ + ".part").c_str());
    }
    if (error_.empty()) error_ = "incomplete";
}

std::string GetFileEnd::describe() const {
    if (!error_.empty()) return "failed: " + error_;
    if (done_) return "received " + name_;
    if (!f_) return "waiting for header";
    return "receiving " + name_ + " " + pct(got_, size_) + " (" + human_bytes(got_) + "/" +
           human_bytes(size_) + ")";
}

// ---- factory ----

std::unique_ptr<LocalEnd> make_local_end(const std::string& type,
                                         const std::vector<std::string>& args, std::string* err) {
    if (type == "ECHO") {
        if (!args.empty()) {
            if (err) *err = "ECHO takes no arguments";
            return nullptr;
        }
        return std::make_unique<EchoEnd>();
    }
    if (type == "SHARE_FILE") {
        if (args.size() != 1) {
            if (err) *err = "usage: SHARE_FILE <path>";
            return nullptr;
        }
        return ShareFileEnd::open(args[0], err);
    }
    if (type == "GET_FILE") {
        if (args.empty() || args.size() > 2 || (args.size() == 2 && args[1] != "OVERWRITE")) {
            if (err) *err = "usage: GET_FILE <target> [OVERWRITE]";
            return nullptr;
        }
        return std::make_unique<GetFileEnd>(args[0], args.size() == 2);
    }
    if (err) *err = "unknown pipe type '" + type + "'";
    return nullptr;
}

}  // namespace spl::peer
