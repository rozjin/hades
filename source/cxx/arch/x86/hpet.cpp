#include <mm/common.hpp>
#include <arch/x86/hpet.hpp>
#include <cstddef>

volatile hpet::table *hpet_table;
volatile hpet::regs *hpet_regs;

void hpet::msleep(size_t ms) {
    uint32_t period = hpet_regs->capabilities >> 32;
    volatile size_t ticks = hpet_regs->counter_value + (ms * (1000000000000 / period));

    while (hpet_regs->counter_value < ticks) {
        asm volatile("pause");
    }
}

void hpet::usleep(size_t ms) {
    uint32_t period = hpet_regs->capabilities >> 32;
    volatile size_t ticks = hpet_regs->counter_value + (ms * (1000000000 / period));

    while (hpet_regs->counter_value < ticks) {
        asm volatile("pause");
    }
}

void hpet::init() {
    hpet_table = (hpet::table *) acpi::table("HPET", 0);
    hpet_regs = (hpet::regs *) (hpet_table->address + memory::x86::virtualBase);

    hpet_regs->counter_value = 0;
    hpet_regs->general_config = 1;
}