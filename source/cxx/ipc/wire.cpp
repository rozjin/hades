
#include <cstddef>
#include <frg/hash_map.hpp>
#include <arch/types.hpp>
#include <mm/mm.hpp>
#include <sys/sched/time.hpp>
#include <sys/sched/sched.hpp>
#include <ipc/wire.hpp>
#include <util/lock.hpp>

void ipc::wire::wait_for_wake(sched::thread *thread) {
    util::lock_guard guard{lock};
    threads.append(thread);
    guard.~lock_guard();

    arch::stop_thread(thread);

    arch::irq_on();
    while (thread->state == sched::thread::BLOCKED && !thread->pending_signal) arch::tick();

    util::lock_guard reguard{lock};
    threads.erase(thread);
    reguard.~lock_guard();
}

frg::tuple<ssize_t, sched::thread *> 
    ipc::wire::wait(ssize_t event, bool allow_signals, sched::timespec *timeout) {
    auto thread = arch::get_thread();
    
    if (timeout) {
        arch::add_timer({
            .spec = *timeout,
            .wire = this
        });        
    }

    bool irqs_enabled = arch::get_irq_state();
    wait_for_event:
        wait_for_wake(thread);

    if ((!allow_signals && thread->pending_signal) 
            || latest_event != event) {        
        goto wait_for_event;
    }

    if (irqs_enabled) {
        arch::irq_on();
    } else {
        arch::irq_off();
    }

    if (thread->pending_signal) {
        arch::set_errno(EINTR);
        return {-1, nullptr};
    }

    return {latest_event, latest_waker};
}

void ipc::wire::arise(ssize_t event) {
    util::lock_guard guard{lock};

    latest_waker = arch::get_thread();
    latest_event = event;

    for (auto thread: threads) {
        arch::start_thread(thread);
    }
}