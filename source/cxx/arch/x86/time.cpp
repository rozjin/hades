#include "ipc/evtable.hpp"
#include "mm/mm.hpp"
#include <arch/x86/smp.hpp>
#include <cstddef>
#include <sys/sched/sched.hpp>
#include <arch/x86/pit.hpp>
#include <sys/x86/apic.hpp>
#include <sys/sched/time.hpp>
#include <arch/types.hpp>

sched::timespec sched::clock_rt{};
sched::timespec sched::clock_mono{};
frg::vector<sched::timer, memory::mm::heap_allocator> sched::timers{};

void arch::add_timer(sched::timer timer) {
    sched::timers.push_back(timer);
}

void arch::tick_clock(long nanos) {
    sched::timespec interval = { .tv_sec = 0, .tv_nsec = nanos };

    sched::clock_rt = sched::clock_rt + interval;
    sched::clock_mono = sched::clock_mono + interval;

    for (auto timer = sched::timers.begin(); timer != sched::timers.end();) {
        timer->spec = timer->spec - interval;
        if (timer->spec.tv_nsec == 0 && timer->spec.tv_sec == 0) {
            timer->wire->arise(evtable::TIME_WAKE);

            frg::destruct(memory::mm::heap, timer);
            timer = sched::timers.erase(timer);
        } else {
            ++timer;
        }
    }
}
