#include <cstddef>
#include <util/io.hpp>
#include <mm/mm.hpp>
#include <arch/types.hpp>
#include <arch/x86/hpet.hpp>
#include <arch/x86/smp.hpp>
#include <arch/x86/pit.hpp>
#include <arch/x86/types.hpp>
#include <sys/x86/apic.hpp>
#include <sys/sched/time.hpp>
#include <sys/sched/sched.hpp>

void pit_tick_handler(arch::irq_regs *r) {
    arch::tick_clock(sched::TIMER_HZ / pit::PIT_FREQ);
}

void pit::init() {
    if (hpet::present) {
        return;
    }

    int divisor = 1193182 / PIT_FREQ;
    if ((1193182 % PIT_FREQ) > (PIT_FREQ / 2)) {
        divisor++;
    }

    io::writeb(0x43, (0b010 << 1) | (0b11 << 4));
    io::writeb(0x40, divisor & 0xFF);
    io::writeb(0x40, divisor >> 8 & 0xFF);

    size_t vector = arch::install_irq(pit_tick_handler);
    arch::route_irq(0, vector);

    sched::clock_mono = { .tv_sec = 0, .tv_nsec = 0 };
    sched::clock_rt = { .tv_sec = 0, .tv_nsec = 0 };
}