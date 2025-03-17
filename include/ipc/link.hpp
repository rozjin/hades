#ifndef LINK_HPP
#define LINK_HPP

#include <cstddef>
#include <ipc/port.hpp>
#include <util/function.hpp>

namespace ipc {
    struct link {
        private:
            ipc::wire wire;
            size_t lastId = 0;

            util::ring<ipc::message> queue;
            util::spinlock lock;
        public:
            size_t request(ssize_t req, util::function<void(size_t)> exec_callback = nullptr);
            bool sync_wait(ssize_t req, size_t id, bool allow_signals = false, sched::timespec *timeout = nullptr);

            ipc::message recv(std::initializer_list<ssize_t> reqs, bool allow_signals = false, sched::timespec *timeout = nullptr);
            void reply(ssize_t req, size_t id, void *data = nullptr, size_t len = 0);

            link(): queue(512), lock() {}
    };
}

#endif