
#include "frg/vector.hpp"
#include "util/types.hpp"
#include <cstddef>
#include <frg/hash_map.hpp>
#include <arch/types.hpp>
#include <mm/mm.hpp>
#include <sys/sched/time.hpp>
#include <sys/sched/sched.hpp>
#include <sys/sched/event.hpp>
#include <util/lock.hpp>

util::spinlock receiver_lock{};
frg::hash_map<ipc::event_id, frg::vector<ipc::_ipc::receiver *, memory::mm::heap_allocator>, 
    frg::hash<ipc::event_id>, memory::mm::heap_allocator> event_receivers{frg::hash<ipc::event_id>{}};

frg::tuple<ipc::event_id, sched::thread *> 
    ipc::receive(std::initializer_list<event_id> events, bool allow_signals, sched::timespec *timeout) {
    auto thread = arch::get_thread();
    auto receiver = frg::construct<_ipc::receiver>(memory::mm::heap, thread);
    if (timeout) {
        receiver->timeout = *timeout;

        auto timer = frg::construct<sched::timer>(memory::mm::heap);
        timer->spec = *timeout;
        timer->tid = thread->tid;

        arch::add_timer(timer);
    }

    util::lock_guard guard{receiver_lock};
    for (auto event: events) {
        if (!event_receivers.contains(event)) {
            event_receivers.insert(event, frg::vector<_ipc::receiver *, memory::mm::heap_allocator>{});
        }

        event_receivers[event].push(receiver);
    }
    
    if (timeout) {
        if (!event_receivers.contains(TIME_WAKE)) {
            event_receivers.insert(TIME_WAKE, frg::vector<_ipc::receiver *, memory::mm::heap_allocator>{});
        }

        event_receivers[TIME_WAKE].push(receiver);
    }
    
    guard.~lock_guard();

    bool irqs_enabled = arch::get_irq_state();

    wait_for_event:
        thread->state = sched::thread::BLOCKED;
        while (thread->state == sched::thread::BLOCKED && !thread->pending_signal) arch::tick();

    if (!allow_signals && thread->pending_signal) {
        goto wait_for_event;
    }

    util::lock_guard reguard{receiver_lock};
    for (auto event: events) {
        for (size_t i = 0; i < event_receivers[event].size(); i++) {
            if (event_receivers[event][i] != receiver) continue;

            event_receivers[event][i] = nullptr;
        }
    }
 
    reguard.~lock_guard();

    if (irqs_enabled) {
        arch::irq_on();
    } else {
        arch::irq_off();
    }

    if (thread->pending_signal) {
        arch::set_errno(EINTR);
    }

    auto event = receiver->triggered_event;
    auto waking_thread = receiver->waking_thread;

    frg::destruct(memory::mm::heap, receiver);

    return {event, waking_thread};
}

bool contains_tid(std::initializer_list<tid_t> tids, tid_t in_tid) {
    for (auto tid: tids) {
        if (tid == in_tid) return true;
    }

    return false;
}

void ipc::send(std::initializer_list<tid_t> tids, event_id ev_id) {
    util::lock_guard guard{receiver_lock};

    if (!event_receivers.contains(ev_id)) return;
    for (size_t i = 0; i < event_receivers[ev_id].size(); i++) {
        auto receiver = event_receivers[ev_id][i];

        if (receiver == nullptr) continue;
        if (!contains_tid(tids, receiver->thread->tid)) continue;
        receiver->triggered_event = ev_id;
        receiver->thread->state = sched::thread::READY;
        receiver->waking_thread = arch::get_thread();
    }

    event_receivers[ev_id].clear();
}

void ipc::send(pid_t pid, event_id ev_id) {
    util::lock_guard guard{receiver_lock};

    if (!event_receivers.contains(ev_id)) return;
    for (size_t i = 0; i < event_receivers[ev_id].size(); i++) {
        auto receiver = event_receivers[ev_id][i];

        if (receiver == nullptr) continue;
        if (receiver->thread->pid != pid) continue;
        receiver->triggered_event = ev_id;
        receiver->thread->state = sched::thread::READY;
        receiver->waking_thread = arch::get_thread();
    }

    event_receivers[ev_id].clear();
}

void ipc::send(event_id ev_id) {
    util::lock_guard guard{receiver_lock};

    if (!event_receivers.contains(ev_id)) return;
    for (size_t i = 0; i < event_receivers[ev_id].size(); i++) {
        auto receiver = event_receivers[ev_id][i];

        if (receiver == nullptr) continue;
        receiver->triggered_event = ev_id;
        receiver->thread->state = sched::thread::READY;
        receiver->waking_thread = arch::get_thread();
    }

    event_receivers[ev_id].clear();
}

sched::thread *ipc::waitq::wait() {
    auto thread = arch::get_thread();

    util::lock_guard guard{lock};

    threads.push(thread);

    guard.~lock_guard();

    thread->state = sched::thread::BLOCKED;
    while (thread->state == sched::thread::BLOCKED) arch::tick();

    return last_waker;
}

void ipc::waitq::arise() {
    util::lock_guard guard{lock};

    last_waker = arch::get_thread();
    for (auto thread: threads) {
        thread->state = sched::thread::READY;
    }

    threads.clear();
}