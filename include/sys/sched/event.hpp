#ifndef EVENT_HPP
#define EVENT_HPP

#include <cstddef>
#include <frg/tuple.hpp>
#include <initializer_list>
#include <util/lock.hpp>
#include <frg/vector.hpp>
#include <mm/mm.hpp>
#include <sys/sched/time.hpp>
#include <util/types.hpp>

namespace sched {
    class thread;
    class process;
};

namespace ipc {
    using event_id = size_t;
    namespace _ipc {
        struct  receiver {
            ipc::event_id triggered_event;
            sched::thread *waking_thread;
            
            sched::thread *thread;
            sched::timespec timeout;

            receiver(sched::thread *thread): triggered_event(0), thread(thread) {}
        };
    };

    void send(event_id ev_id);
    void send(pid_t pid, event_id ev_id);
    void send(std::initializer_list<tid_t> tids, event_id ev_id);

    frg::tuple<event_id, sched::thread *> receive(std::initializer_list<event_id> events, bool allow_signals = false, sched::timespec *timeout = nullptr);

    struct  waitq {
        private:
            frg::vector<sched::thread *, memory::mm::heap_allocator> threads;
            sched::thread *last_waker;

            util::spinlock lock;
        public:
            waitq(): threads(), lock() {}

            sched::thread *wait();
            void arise();
    };
}

enum events {
    TIME_WAKE = (1 << 0),

    PROCESS_STATUS_CHANGE = (1 << 10),
    SIGNAL = (1 << 11),

    FD_EVENT = (1 << 14),

    FUTEX_WAKE = (1 << 13),

    KBD_PRESS = (1 << 12),
    ARP_FOUND = (1 << 15),
};

#endif