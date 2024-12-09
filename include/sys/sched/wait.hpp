#ifndef WAIT_HPP
#define WAIT_HPP

#include <frg/tuple.hpp>
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
    struct trigger;
    struct queue;
    
    struct trigger {
        private:
            frg::vector<queue *, memory::mm::heap_allocator> queues;
            util::lock lock;
        public:
            void add(queue *waitq);
            void remove(queue *waitq);

            void arise(sched::thread *waker);
            void clear();

            trigger(): queues(), lock() {}
            ~trigger() {
                queues.clear();
            }
    };

    struct queue {
        private:
            sched::thread *last_waker;
            
            frg::vector<sched::thread *, memory::mm::heap_allocator> waiters;
            util::lock lock;

            sched::timespec time;
        public:
            friend struct trigger;

            trigger *timer_trigger;
            void set_timer(sched::timespec *time);
            sched::thread *block(sched::thread *waiter);

            queue(): last_waker(nullptr), waiters(), lock(), timer_trigger(nullptr) {}
            ~queue() {
                waiters.clear();
                last_waker = nullptr;
            }
    };
}

#endif