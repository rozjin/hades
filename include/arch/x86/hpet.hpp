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
        uint8_t address_space_id;
        uint8_t register_width;
        uint8_t register_offset;
        uint8_t reserved;
        uint64_t address;
        uint8_t hpet_num;
        uint16_t minim_ticks;
        uint8_t page_protection;
    };

    struct [[gnu::packed]] regs {
        uint64_t capabilities;
        uint64_t rsv0;
        uint64_t general_config;
        uint64_t rsv1;
        uint64_t int_status;
        uint64_t rsv2;
        uint64_t rsv3[24];
        volatile uint64_t counter_value;
        uint64_t rsv4;
    };

    void msleep(size_t ms);
    void usleep(size_t us);
    void init();
}

#endif
