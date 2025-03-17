#ifndef PORT_HPP
#define PORT_HPP

#include <cstddef>
#include <ipc/message.hpp>
#include <ipc/wire.hpp>
#include <mm/common.hpp>
#include <sys/sched/time.hpp>
#include <util/ring.hpp>

namespace ipc {
    struct port {
        private:
            ipc::wire wire;
            size_t lastId = 0;

            util::ring<ipc::message> queue;
            util::spinlock lock;
        public:
            void send(ssize_t event, void *data = nullptr, size_t len = 0);
            ipc::message recv(bool allow_signals = false, sched::timespec *timeout = nullptr);

            port(): wire(), 
                queue(512),  lock() {}
    };
}

#endif