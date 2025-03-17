#ifndef EVENT_HPP
#define EVENT_HPP

#include "frg/hash_map.hpp"
#include "mm/mm.hpp"
#include <cstddef>
#include <util/lock.hpp>
#include <frg/vector.hpp>
#include <frg/tuple.hpp>
#include <sys/sched/time.hpp>

namespace sched {
    class thread;
};

namespace ipc {
    struct  wire {
        private:
            frg::vector<sched::thread *, memory::mm::heap_allocator> threads;

            ssize_t latest_event;
            sched::thread *latest_waker;
            
            util::spinlock lock;

            void wait_for_wake(sched::thread *);
        public:
            wire(): threads(), lock() {}

            wire(wire&& other): threads(std::move(other.threads)),
                latest_event(std::move(other.latest_event)), latest_waker(std::move(other.latest_waker)),
                lock() {}

            frg::tuple<ssize_t, sched::thread *> wait(ssize_t event, bool allow_signals = false, sched::timespec *timeout = nullptr);
            void arise(ssize_t event);

            void clear();
    };
}

#endif