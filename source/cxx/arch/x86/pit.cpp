#include <cstddef>
#include <util/io.hpp>
#include <mm/mm.hpp>
#include <arch/types.hpp>
#include <arch/x86/smp.hpp>
#include <arch/x86/pit.hpp>
#include <arch/x86/types.hpp>
#include <sys/x86/apic.hpp>
#include <sys/sched/time.hpp>
#include <sys/sched/sched.hpp>

void arch::init_timer() {
    pit::init();
    apic::lapic::set_timer(1);
}

void arch::add_timer(sched::timer *timer) {
    pit::timers.push_back(timer);
}

void tick_handler(arch::irq_regs *r) {
    sched::timespec interval = { .tv_sec = 0, .tv_nsec = pit::TIMER_HZ / sched::PIT_FREQ };
    sched::uptime += interval.tv_nsec;

    sched::clock_rt = sched::clock_rt + interval;
    sched::clock_mono = sched::clock_mono + interval;

    for (size_t i = 0; i < pit::timers.size(); i++) {
        auto timer = pit::timers[i];
        if (timer == nullptr) continue;

        timer->spec = timer->spec - interval;
        if (timer->spec.tv_nsec == 0 && timer->spec.tv_sec == 0) {
            for (size_t j = 0; j < timer->triggers.size(); j++) {
                auto trigger = timer->triggers[i];
                trigger->arise(x86::get_thread());
                frg::destruct(memory::mm::heap, trigger);
            }

            timer->triggers.~vector();
            pit::timers[i] = nullptr;
        }
    }
}

void pit::init() {
    x86::install_irq(1, tick_handler);

    int divisor = 1193182 / PIT_FREQ;
    if ((1193182 % PIT_FREQ) > (PIT_FREQ / 2)) {
        divisor++;
    }

    io::writeb(0x43, (0b010 << 1) | (0b11 << 4));
    io::writeb(0x40, divisor & 0xFF);
    io::writeb(0x40, divisor >> 8 & 0xFF);

    arch::route_irq(1, 1);

    sched::clock_mono = { .tv_sec = 0, .tv_nsec = 0 };
    sched::clock_rt = { .tv_sec = 0, .tv_nsec = 0 };
}