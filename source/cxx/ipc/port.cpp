#include <arch/types.hpp>
#include <cstddef>
#include <ipc/evtable.hpp>
#include <ipc/port.hpp>
#include <util/lock.hpp>

void ipc::port::send(ssize_t event, void *data, size_t len) {
    util::lock_guard guard{lock};

    size_t id = lastId++;
    queue.push({
        .event = event,
        .id = id,

        .sender = arch::get_thread(),

        .data = data,
        .len = len
    });

    guard.~lock_guard();
    wire.arise(evtable::NEW_MESSAGE);
}

ipc::message
    ipc::port::recv(bool allow_signals, sched::timespec *timeout) {
    auto [evt, sender] = wire.wait(evtable::NEW_MESSAGE, allow_signals, timeout);

    util::lock_guard guard{lock};

    ipc::message msg;
    queue.pop(&msg);

    return msg;
}