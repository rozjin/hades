#include <cstddef>
#include <ipc/evtable.hpp>
#include <ipc/link.hpp>

size_t ipc::link::request(ssize_t req, util::function<void(size_t)> exec_callback) {
    util::lock_guard guard{lock};

    size_t id = lastId++;
    queue.push({
        .event = req,
        .id = id,

        .sender = arch::get_thread(),

        .data = nullptr,
        .len = 0
    });

    guard.~lock_guard();
    exec_callback(id);

    wire.arise(evtable::NEW_MESSAGE);

    return id;
}

bool ipc::link::sync_wait(ssize_t req, size_t id, bool allow_signals, sched::timespec *timeout) {
    while (true) {
        util::lock_guard guard{lock};

        ipc::message msg;
        if (!queue.pop(&msg)) goto wait;

        if (msg.event == req && msg.id == id) {
            return true;
        }

        queue.push(msg);

        wait:
            guard.~lock_guard();
            auto [evt, sender] = wire.wait(evtable::NEW_MESSAGE, allow_signals, timeout);
            if (evt < 0) {
                if (allow_signals) return false;
            }
    }
}

ipc::message 
    ipc::link::recv(std::initializer_list<ssize_t> reqs, bool allow_signals, sched::timespec *timeout) {
    while(true) {
        util::lock_guard guard{lock};
        
        ipc::message msg;
        if (!queue.pop(&msg)) goto wait;
    
        if (util::within(reqs, msg.event)) {
            return msg;
        }

        wait:
            guard.~lock_guard();
            auto [evt, sender] = wire.wait(evtable::NEW_MESSAGE, allow_signals, timeout);
            if (evt < 0) {
                if (allow_signals) return {-1};
            }
    }
}

void ipc::link::reply(ssize_t req, size_t id, void *data, size_t len) {
    util::lock_guard guard{lock};

    queue.push({
        .event = req,
        .id = id,

        .sender = arch::get_thread(),

        .data = data,
        .len = len
    });

    guard.~lock_guard();
    wire.arise(evtable::NEW_MESSAGE);
}