#include <mm/common.hpp>
#include <arch/x86/hpet.hpp>
#include <arch/types.hpp>
#include <arch/x86/types.hpp>
#include <cstddef>

bool hpet::present = false;

volatile hpet::table *hpet::hpet_table;
volatile hpet::regs *hpet::hpet_regs;

void hpet::msleep(size_t ms) {
    uint32_t period = hpet_regs->capabilities >> 32;
    volatile size_t ticks = hpet_regs->counter_value + (ms * (1000000000000 / period));

    while (hpet_regs->counter_value < ticks) {
        asm volatile("pause");
    }
}

void hpet::usleep(size_t ns) {
    uint32_t period = hpet_regs->capabilities >> 32;
    volatile size_t ticks = hpet_regs->counter_value + (ns * (1000000000 / period));

    while (hpet_regs->counter_value < ticks) {
        asm volatile("pause");
    }
}

constexpr size_t FEMTOS_PER_NANO = 1000000;
constexpr size_t NANOS_PER_MILLI = 1000000;

constexpr size_t HPET_NANOS = NANOS_PER_MILLI * FEMTOS_PER_NANO;
size_t timer_idx = 0;
size_t num_timers;

void hpet_tick_handler(arch::irq_regs *r) {
    arch::tick_clock(NANOS_PER_MILLI);
}

void hpet::init() {
    hpet_table = (hpet::table *) acpi::table("HPET", 0);
    if (hpet_table == nullptr) {
        return;
    }

    hpet_regs = (hpet::regs *) (hpet_table->gas.address + memory::x86::virtualBase);

    hpet_regs->general_config &= ~(1 << 0);
    hpet_regs->general_config &= ~(1 << 1);
    hpet_regs->counter_value = 0;

    present = true;

    num_timers = ((hpet_regs->capabilities >> 8) & 0x1F) + 1;

    for (size_t i = 0; i < num_timers; i++) {
        if ((hpet_regs->compars[i].config_capabilities >> 4) & 1) {
            timer_idx = i;
            break;
        }
    }

    uint32_t allowed_routes = hpet_regs->compars[timer_idx].config_capabilities >> 32;
    size_t used_route = 0;
    while ((allowed_routes & 1) == 0 || used_route <= 2) {
        used_route++;
        allowed_routes >>= 1;
    }

    size_t vector = arch::alloc_vector();
    arch::install_vector(vector, hpet_tick_handler);
    arch::route_irq(used_route, vector);

    uint32_t period = hpet_regs->capabilities >> 32;
    uint32_t ticks = HPET_NANOS / period;

    hpet_regs->compars[timer_idx].config_capabilities &= ~(0xF << 9);
    hpet_regs->compars[timer_idx].config_capabilities |= (used_route << 9) | (1 << 3) | (1 << 6) | (1 << 2);

    hpet_regs->compars[timer_idx].comparator_value = hpet_regs->counter_value + ticks;
    hpet_regs->compars[timer_idx].comparator_value = ticks;

    hpet_regs->general_config |= (1 << 0);
}