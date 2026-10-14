// A minimal poll(2) event loop: readable- or writable-fd callbacks plus a
// per-round tick.
// Owned by whoever runs the process's loop (today the peer commands via
// PeerRuntime; the daemon later). Callbacks may add/remove fds, including
// removing themselves.
#pragma once

#include <atomic>
#include <functional>
#include <utility>
#include <vector>

#include "common/time.h"

namespace spl::net {

class Poller {
 public:
    // Add or replace `fd`'s callback for readability (or, with `writable`, for
    // writability); it's also called on hangup/error. One fd may have both.
    void set(int fd, std::function<void()> on_ready, bool writable = false);
    void remove(int fd);                 // both callbacks
    void remove(int fd, bool writable);  // just one

    // Poll until `stop` becomes true. Each round waits at most 100ms, invokes
    // the callbacks of readable fds, then on_tick(now).
    void run(std::atomic<bool>& stop, const std::function<void(Millis)>& on_tick);

 private:
    struct Entry {
        int fd;
        bool writable;
        std::function<void()> cb;
    };
    std::vector<Entry> fds_;
};

}  // namespace spl::net
