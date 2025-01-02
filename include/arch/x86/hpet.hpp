#ifndef HPET_HPP
#define HPET_HPP

#include <cstddef>
#include <sys/acpi.hpp>

namespace hpet {
    struct [[gnu::packed]] table {
        acpi::sdt _sdt;
        uint8_t hardware_rev_id;
        uint8_t info;
        uint16_t pci_id;
        acpi::gas gas;
        uint8_t id;
        uint16_t minim_ticks;
        uint8_t page_protection;
    };

    struct [[gnu::packed]] comparator_regs {
        volatile uint64_t config_capabilities;
        volatile uint64_t comparator_value;
        volatile uint64_t fsb_irq;
        volatile uint64_t rsv;
    };

    struct [[gnu::packed]] regs {
        volatile uint64_t capabilities;
        volatile uint64_t rsv0;
        volatile uint64_t general_config;
        volatile uint64_t rsv1;
        volatile uint64_t int_status;
        volatile uint64_t rsv2;
        volatile uint64_t rsv3[24];
        volatile uint64_t counter_value;
        volatile uint64_t rsv4;
        comparator_regs compars[32];
    };

    extern bool present;
    extern volatile hpet::table *hpet_table;
    extern volatile hpet::regs *hpet_regs;

    void msleep(size_t ms);
    void usleep(size_t us);
    void init();
}

#endif
