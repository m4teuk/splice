#include "net/poller.h"

#include <poll.h>

namespace spl::net {

void Poller::set(int fd, std::function<void()> on_ready, bool writable) {
    for (auto& e : fds_) {
        if (e.fd == fd && e.writable == writable) {
            e.cb = std::move(on_ready);
            return;
        }
    }
    fds_.push_back(Entry{fd, writable, std::move(on_ready)});
}

void Poller::remove(int fd) {
    for (auto it = fds_.begin(); it != fds_.end();)
        it = it->fd == fd ? fds_.erase(it) : it + 1;
}

void Poller::remove(int fd, bool writable) {
    for (auto it = fds_.begin(); it != fds_.end(); ++it) {
        if (it->fd == fd && it->writable == writable) {
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
            const bool writable = p.events & POLLOUT;
            // Look up fresh (a prior callback may have removed this fd) and copy
            // the function so a callback that removes itself stays alive while
            // it runs.
            for (const auto& e : fds_) {
                if (e.fd == p.fd && e.writable == writable) {
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
