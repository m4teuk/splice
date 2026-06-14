#include "peer/pipes.h"

#include <dirent.h>
#include <sys/stat.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "common/log.h"
#include "peer/shell.h"

namespace spl::peer {

namespace {

constexpr size_t kChunk = 16384;
constexpr size_t kMaxHeader = 8192;

// ---- small fs / format helpers ----

std::string basename_of(const std::string& p) {
    const size_t s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}
bool is_dir(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}
bool exists(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0;
}
uint64_t file_size(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 ? static_cast<uint64_t>(st.st_size) : 0;
}
void mkdirs(const std::string& dir) {
    for (size_t i = 1; i <= dir.size(); ++i)
        if (i == dir.size() || dir[i] == '/') {
            std::string cur = dir.substr(0, i);
            if (!cur.empty() && cur != ".") ::mkdir(cur.c_str(), 0755);
        }
}
std::string pct(uint64_t part, uint64_t total) {
    return total ? std::to_string(part * 100 / total) + "%" : "?";
}

// Reduce a received relpath to a safe path under the target: drop "", ".", "..",
// absolute roots; keep the rest joined with '/'.
std::string safe_relpath(const std::string& rel) {
    std::string out, comp;
    auto flush = [&] {
        if (comp.empty() || comp == "." || comp == "..") {
            comp.clear();
            return;
        }
        if (!out.empty()) out += '/';
        out += comp;
        comp.clear();
    };
    for (char c : rel) {
        if (c == '/')
            flush();
        else
            comp += c;
    }
    flush();
    return out.empty() ? "received.file" : out;
}

// crc32 (zlib polynomial), incremental.
uint32_t crc32_update(uint32_t crc, const uint8_t* p, size_t n) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        init = true;
    }
    crc ^= 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}
uint32_t crc32_file(const std::string& path, uint64_t upto) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return 0;
    uint32_t crc = 0;
    uint8_t buf[kChunk];
    uint64_t left = upto;
    while (left > 0) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(left, sizeof(buf)));
        size_t n = std::fread(buf, 1, want, f);
        if (n == 0) break;
        crc = crc32_update(crc, buf, n);
        left -= n;
    }
    std::fclose(f);
    return crc;
}
std::string hex8(uint32_t v) {
    char b[9];
    std::snprintf(b, sizeof(b), "%08x", v);
    return b;
}

// Recursively collect files under `dir`, relpaths prefixed with `prefix`.
void walk(const std::string& dir, const std::string& prefix,
          std::vector<ShareFileEnd::Entry>& out) {
    DIR* d = ::opendir(dir.c_str());
    if (!d) return;
    std::vector<std::string> names;
    while (dirent* e = ::readdir(d)) {
        std::string n = e->d_name;
        if (n != "." && n != "..") names.push_back(n);
    }
    ::closedir(d);
    std::sort(names.begin(), names.end());
    for (const auto& n : names) {
        const std::string ap = dir + "/" + n;
        const std::string rp = prefix + "/" + n;
        struct stat st{};
        if (::stat(ap.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode))
            walk(ap, rp, out);
        else if (S_ISREG(st.st_mode))
            out.push_back({rp, ap, static_cast<uint64_t>(st.st_size)});
    }
}

}  // namespace

// ================= SHARE_FILE =================

std::unique_ptr<ShareFileEnd> ShareFileEnd::open(const std::string& path, std::string* err) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) {
        if (err) *err = "cannot read '" + path + "'";
        return nullptr;
    }
    auto e = std::make_unique<ShareFileEnd>();
    if (S_ISDIR(st.st_mode)) {
        walk(path, basename_of(path), e->entries_);
    } else if (S_ISREG(st.st_mode)) {
        e->entries_.push_back({basename_of(path), path, static_cast<uint64_t>(st.st_size)});
    } else {
        if (err) *err = "'" + path + "' is not a regular file or directory";
        return nullptr;
    }
    if (e->entries_.empty()) {
        if (err) *err = "'" + path + "' has no files to share";
        return nullptr;
    }
    for (const auto& en : e->entries_) e->total_ += en.size;
    return e;
}

ShareFileEnd::~ShareFileEnd() {
    if (f_) std::fclose(f_);
}

void ShareFileEnd::on_tunnel_data(ByteSpan b) {
    // The only thing the receiver sends us is RESUME lines.
    if (state_ != State::WaitResume) return;
    for (size_t i = 0; i < b.size(); ++i) {
        char c = static_cast<char>(b[i]);
        if (c == '\n') {
            uint64_t off = 0;
            if (rbuf_.rfind("RESUME ", 0) == 0)
                off = std::strtoull(rbuf_.c_str() + 7, nullptr, 10);
            rbuf_.clear();
            const Entry& en = entries_[idx_];
            if (off > en.size) off = 0;
            f_ = std::fopen(en.abspath.c_str(), "rb");
            if (!f_) {
                err_ = "cannot read '" + en.abspath + "'";
                if (shutdown) shutdown();
                return;
            }
            std::fseek(f_, static_cast<long>(off), SEEK_SET);
            remaining_ = en.size - off;
            sent_ += off;
            state_ = State::Stream;
            pump();
            return;
        }
        rbuf_ += c;
        if (rbuf_.size() > 64) {  // not a RESUME line; give up
            err_ = "bad RESUME from peer";
            if (shutdown) shutdown();
            return;
        }
    }
}

void ShareFileEnd::pump() {
    if (!to_tunnel || !err_.empty()) return;
    for (;;) {
        if (state_ == State::Offer) {
            if (idx_ >= entries_.size()) {
                state_ = State::End;
                continue;
            }
            const Entry& en = entries_[idx_];
            const std::string hdr = "SPLF2 " + std::to_string(en.size) + " " +
                                    hex8(crc32_file(en.abspath, en.size)) + " " + en.relpath + "\n";
            to_tunnel(as_span(hdr));
            state_ = State::WaitResume;
            return;  // wait for RESUME
        }
        if (state_ == State::Stream) {
            while (remaining_ > 0) {
                if (tunnel_space && tunnel_space() < kChunk) return;  // resumes on writable
                uint8_t buf[kChunk];
                size_t want = static_cast<size_t>(std::min<uint64_t>(remaining_, sizeof(buf)));
                size_t n = std::fread(buf, 1, want, f_);
                if (n == 0) {  // truncated under us; the receiver's crc will fail
                    err_ = "read error";
                    if (shutdown) shutdown();
                    return;
                }
                to_tunnel(ByteSpan(buf, n));
                remaining_ -= n;
                sent_ += n;
            }
            std::fclose(f_);
            f_ = nullptr;
            ++idx_;
            state_ = State::Offer;
            continue;
        }
        if (state_ == State::End) {
            to_tunnel(as_span(std::string("SPLF2-END\n")));
            state_ = State::Done;
            if (shutdown) shutdown();
            return;
        }
        return;  // WaitResume / Done
    }
}

std::string ShareFileEnd::describe() const {
    if (!err_.empty()) return "failed: " + err_;
    if (state_ == State::Done) return "sent " + std::to_string(entries_.size()) + " file(s)";
    return "sending " + pct(sent_, total_) + " (" + human_bytes(sent_) + "/" +
           human_bytes(total_) + ", file " + std::to_string(idx_ + 1) + "/" +
           std::to_string(entries_.size()) + ")";
}

// ================= GET_FILE =================

GetFileEnd::~GetFileEnd() {
    if (f_) std::fclose(f_);
}

void GetFileEnd::fail(const std::string& why) {
    err_ = why;
    if (f_) {
        std::fclose(f_);
        f_ = nullptr;
    }
    if (shutdown) shutdown();
}

void GetFileEnd::on_tunnel_data(ByteSpan b) {
    size_t off = 0;
    while (off < b.size() && !done_ && err_.empty()) {
        if (state_ == State::Header) {
            while (off < b.size()) {
                char c = static_cast<char>(b[off++]);
                if (c == '\n') {
                    const std::string line = hdr_;
                    hdr_.clear();
                    handle_header(line);
                    break;
                }
                hdr_ += c;
                if (hdr_.size() > kMaxHeader)
                    return fail("not a SHARE_FILE pipe (no header)");
            }
        } else if (state_ == State::Recv) {
            size_t keep = static_cast<size_t>(std::min<uint64_t>(b.size() - off, size_ - got_));
            if (keep) {
                if (std::fwrite(b.data() + off, 1, keep, f_) != keep) return fail("write failed");
                crc_ = crc32_update(crc_, b.data() + off, keep);
                got_ += keep;
                off += keep;
            }
            if (got_ == size_) finish_entry();
        }
    }
}

void GetFileEnd::handle_header(const std::string& line) {
    if (line == "SPLF2-END") {
        done_ = true;
        state_ = State::Done;
        if (shutdown) shutdown();
        return;
    }
    if (line.rfind("SPLF2 ", 0) != 0) return fail("not a SHARE_FILE pipe (bad header)");
    // SPLF2 <size> <crc8hex> <relpath>
    const char* p = line.c_str() + 6;
    char* end = nullptr;
    size_ = std::strtoull(p, &end, 10);
    if (end == p || *end != ' ') return fail("bad header");
    want_crc_ = static_cast<uint32_t>(std::strtoul(end + 1, &end, 16));
    if (*end != ' ') return fail("bad header");
    relpath_ = end + 1;
    if (relpath_.empty()) return fail("bad header");

    // Resolve the destination: a directory target places files by relpath; any
    // other target is a single file written to that exact path.
    const std::string dir = target_.empty() ? "." : target_;
    if (is_dir(dir)) {
        dest_ = dir + "/" + safe_relpath(relpath_);
        const size_t slash = dest_.find_last_of('/');
        if (slash != std::string::npos) mkdirs(dest_.substr(0, slash));
    } else {
        dest_ = target_;  // single-file target
    }
    if (!overwrite_ && exists(dest_)) return fail("'" + dest_ + "' exists (use -f)");

    part_ = dest_ + ".part";
    meta_ = dest_ + ".part.meta";
    crc_ = 0;
    got_ = 0;

    // Resume if we kept a matching .part (same size+crc+relpath in .part.meta).
    uint64_t off = 0;
    if (exists(part_) && exists(meta_)) {
        FILE* m = std::fopen(meta_.c_str(), "r");
        char line2[1024] = {0};
        if (m && std::fgets(line2, sizeof(line2), m)) {
            uint64_t msize = 0;
            uint32_t mcrc = 0;
            char mrel[768] = {0};
            if (std::sscanf(line2, "%llu %x %767[^\n]", (unsigned long long*)&msize, &mcrc, mrel) ==
                    3 &&
                msize == size_ && mcrc == want_crc_ && relpath_ == mrel) {
                uint64_t have = file_size(part_);
                if (have <= size_) {
                    off = have;
                    crc_ = crc32_file(part_, have);
                }
            }
        }
        if (m) std::fclose(m);
    }

    if (off > 0) {
        f_ = std::fopen(part_.c_str(), "r+b");
        if (f_) std::fseek(f_, static_cast<long>(off), SEEK_SET);
    } else {
        f_ = std::fopen(part_.c_str(), "wb");
        FILE* m = std::fopen(meta_.c_str(), "w");
        if (m) {
            std::fprintf(m, "%llu %s %s\n", (unsigned long long)size_, hex8(want_crc_).c_str(),
                         relpath_.c_str());
            std::fclose(m);
        }
    }
    if (!f_) return fail("cannot write '" + part_ + "'");
    got_ = off;

    if (to_tunnel) to_tunnel(as_span("RESUME " + std::to_string(off) + "\n"));
    state_ = State::Recv;
    if (got_ == size_) finish_entry();  // empty file (or already complete)
}

void GetFileEnd::finish_entry() {
    std::fclose(f_);
    f_ = nullptr;
    if (crc_ != want_crc_) {
        ::remove(part_.c_str());
        ::remove(meta_.c_str());
        return fail("checksum mismatch for '" + dest_ + "'");
    }
    if (::rename(part_.c_str(), dest_.c_str()) != 0) return fail("rename failed for '" + dest_ + "'");
    ::remove(meta_.c_str());
    ++files_;
    state_ = State::Header;
}

void GetFileEnd::on_tunnel_closed() {
    if (done_ || !err_.empty()) return;
    if (f_) {
        std::fclose(f_);
        f_ = nullptr;  // keep the .part + .meta so a re-run resumes
    }
    err_ = "incomplete (the connection closed early)";
}

std::string GetFileEnd::describe() const {
    if (!err_.empty()) return "failed: " + err_;
    if (done_) return "received " + std::to_string(files_) + " file(s)";
    if (state_ == State::Header) return "waiting for a file";
    return "receiving " + basename_of(relpath_) + " " + pct(got_, size_) + " (" +
           human_bytes(got_) + "/" + human_bytes(size_) + ")";
}

// ================= factory =================

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
    if (type == "SHELL") return make_shell_end(args, err);
    if (err) *err = "unknown pipe type '" + type + "'";
    return nullptr;
}

}  // namespace spl::peer
