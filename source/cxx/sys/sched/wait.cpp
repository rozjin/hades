
#include <arch/types.hpp>
#include <cstddef>
#include <mm/mm.hpp>
#include <sys/sched/wait.hpp>
#include <sys/sched/time.hpp>
#include <sys/sched/sched.hpp>

frg::tuple<sched::thread *, bool> ipc::queue::block(sched::thread *waiter) {
    lock.irq_acquire();
    waiters.push_back(waiter);
    lock.irq_release();

    bool irqs_enabled = arch::get_irq_state();

    waiter->state = sched::thread::BLOCKED;
    while (waiter->state == sched::thread::BLOCKED && !waiter->pending_signal) arch::tick();

    if (irqs_enabled) {
        arch::irq_on();
    } else {
        arch::irq_off();
    }

    if (waiter->pending_signal) {
        arch::set_errno(EINTR);
        return {nullptr, true};
    }

    return {last_waker, false};
}

void ipc::queue::set_timer(sched::timespec *time) {
    this->time = *time;
    this->timer_trigger = frg::construct<trigger>(memory::mm::heap);
    timer_trigger->add(this);

    sched::timer *timer = frg::construct<sched::timer>(memory::mm::heap);
    timer->spec = *time;
    timer->trigger = timer_trigger;

    arch::add_timer(timer);
}

void ipc::trigger::add(queue *waitq) {
    lock.irq_acquire();
    queues.push_back(waitq);
    lock.irq_release();
}

void ipc::trigger::remove(queue *waitq) {
    lock.irq_acquire();
    for (size_t i = 0; i < queues.size(); i++) {
        auto queue = queues[i];
        if (queue == nullptr) continue;
        if (queue == waitq) {
            queues[i] = nullptr;
            lock.irq_release();

            return;
        }
    }

    lock.irq_release();
}

void ipc::trigger::arise(sched::thread *waker) {
    lock.irq_acquire();

    for (size_t i = 0; i < queues.size(); i++) {
        auto waitq = queues[i];
        if (waitq == nullptr) continue;

        waitq->lock.irq_acquire();
        waitq->last_waker = waker;
        for (size_t j = 0; j < waitq->waiters.size(); j++) {
            auto waiter = waitq->waiters[j];
            if (waiter == nullptr) continue;
            
            waiter->state = sched::thread::READY;
        }
        
        waitq->waiters.clear();
        waitq->lock.irq_release();
    }

    lock.irq_release();
}

void ipc::trigger::clear() {
    lock.irq_acquire();
    queues.clear();
    lock.irq_release();
}
