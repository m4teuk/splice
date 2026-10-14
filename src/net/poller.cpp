#include "net/poller.h"

#include <poll.h>

namespace spl::net {

void Poller::set(int fd, std::function<void()> on_ready, bool writable) {
    for (auto& e : fds_) {
        if (e.fd == fd) {
            e.cb = std::move(on_ready);
            e.writable = writable;
            return;
        }
    }
    fds_.push_back(Entry{fd, writable, std::move(on_ready)});
}

void Poller::remove(int fd) {
    for (auto it = fds_.begin(); it != fds_.end(); ++it) {
        if (it->fd == fd) {
            fds_.erase(it);
            return;
        }
    }
}

void Poller::run(std::atomic<bool>& stop, const std::function<void(Millis)>& on_tick) {
    std::vector<pollfd> pfds;
    while (!stop.load()) {
        pfds.clear();
        for (const auto& e : fds_)
            pfds.push_back(pollfd{e.fd, static_cast<short>(e.writable ? POLLOUT : POLLIN), 0});
        ::poll(pfds.data(), static_cast<nfds_t>(pfds.size()), 100);

        for (const auto& p : pfds) {
            if (!(p.revents & (POLLIN | POLLOUT | POLLHUP | POLLERR))) continue;
            // Look up fresh (a prior callback may have removed this fd) and copy
            // the function so a callback that removes itself stays alive while
            // it runs.
            for (const auto& e : fds_) {
                if (e.fd == p.fd) {
                    auto cb = e.cb;
                    cb();
                    break;
                }
            }
        }
        if (on_tick) on_tick(mono_ms());
    }
}

}  // namespace spl::net
