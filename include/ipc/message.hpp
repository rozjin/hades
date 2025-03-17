#ifndef IPC_MESSAGE_HPP
#define IPC_MESSAGE_HPP

#include <cstddef>
#include <cstdint>
#include <util/types.hpp>

namespace sched {
    class thread;
}

namespace ipc {
    struct message {
        ssize_t event;
        size_t id;
        
        sched::thread *sender;

        void *data;
        size_t len;
    };
}

#endif