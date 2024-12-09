#ifndef APIC_HPP
#define APIC_HPP

#include <cstddef>
#include <cstdint>
#include <mm/common.hpp>
#include <sys/acpi.hpp>

namespace apic {
    constexpr size_t IOAPIC_REG_ID = 0x00;
    constexpr size_t IOAPIC_ID = 0xF000000;

    constexpr size_t IOAPIC_REG_VERREDIR = 0x01;
    constexpr size_t IOAPIC_VERSION = 0x7F;
    constexpr size_t IOAPIC_MAX_REDIRS = 0xFF0000;

    constexpr size_t IOAPIC_REG_PRIORITY = 0x02;
    constexpr size_t IOAPIC_ARBIT_PRIORITY = 0xF000000;

    constexpr size_t IOAPIC_REDIR_START = 0x10;
    constexpr size_t IOAPIC_REDIR_END = 0x3F;

    constexpr size_t IOAPIC_REDIR_ENTR_VECTOR = 0xFF;
    constexpr size_t IOAPIC_REDIR_DELV_TYPE = 0x700;
    constexpr size_t IOAPIC_REDIR_DEST_MODE = (1 << 11);
    constexpr size_t IOAPIC_REDIR_POLARITY = (1 << 13);
    constexpr size_t IOAPIC_REDIR_LTI_RECV = (1 << 14);
    constexpr size_t IOAPIC_REDIR_TRIGGER_MODE = (1 << 15);
    constexpr size_t IOAPIC_REDIR_MASK = (1 << 16);
    constexpr size_t IOAPIC_REDIR_DEST = 0xFF80000000000000;

    constexpr size_t LAPIC_REG_ID = 0x20;
    constexpr size_t LAPIC_REG_VERSION = 0x30;
    constexpr size_t LAPIC_REG_TPR = 0x80;
    constexpr size_t LAPIC_REG_APR = 0x90;
    constexpr size_t LAPIC_REG_PPR = 0xA0;
    constexpr size_t LAPIC_REG_EOI = 0xB0;
    constexpr size_t LAPIC_REG_RRD = 0xC0;
    constexpr size_t LAPIC_REG_LDR = 0xD0;
    constexpr size_t LAPIC_REG_DFR = 0xE0;
    constexpr size_t LAPIC_REG_SIVR = 0xF0;
    constexpr size_t LAPIC_REG_INSERVICE_START = 0x100;
    constexpr size_t LAPIC_REG_INSERVICE_END = 0x170;
    constexpr size_t LAPIC_REG_TMR_START = 0x180;
    constexpr size_t LAPIC_REG_TMR_END = 0x1F0;
    constexpr size_t LAPIC_REG_IRR_START = 0x200;
    constexpr size_t LAPIC_REG_IRR_END = 0x270;
    constexpr size_t LAPIC_REG_ESR = 0x280;
    constexpr size_t LAPIC_REG_CORRECTED_MCEI = 0x2F0;
    constexpr size_t LAPIC_REG_ICR_LOW = 0x300;
    constexpr size_t LAPIC_REG_ICR_HIGH = 0x310;
    constexpr size_t LAPIC_REG_LVT_TIMR = 0x320;
    constexpr size_t LAPIC_REG_LVT_TSR = 0x330;
    constexpr size_t LAPIC_REG_LVT_PMCR = 0x340;
    constexpr size_t LAPIC_REG_LVT_LINT0 = 0x350;
    constexpr size_t LAPIC_REG_LVT_LINT1 = 0x360;
    constexpr size_t LAPIC_REG_LVT_ERR = 0x370;
    constexpr size_t LAPIC_REG_INTERNAL_CNTR = 0x380;
    constexpr size_t LAPIC_REG_CURR_CNTR = 0x390;
    constexpr size_t LAPIC_REG_DCR = 0x3E0;

    constexpr size_t LAPIC_LVT_INTR_PEND = (1 << 12);
    constexpr size_t LAPIC_LVT_POLARITY = (1 << 13);
    constexpr size_t LAPIC_LVT_RIRR = (1 << 14);
    constexpr size_t LAPIC_LVT_TM = (1 << 15);
    constexpr size_t LAPIC_LVT_MASK = (1 << 16);

    constexpr size_t LAPIC_BASE_MSR = 0x1B;
    constexpr size_t LAPIC_BASE_MSR_ENABLE = 0x800;

    constexpr size_t ICR_DEST_SIPI = (0x6 << 8);
    constexpr size_t ICR_DEST_INIT = (0x5 << 8);
    constexpr size_t ICR_DEASSERT = (1 << 15);

    namespace ioapic {
        uint32_t read(size_t ioapic, uint32_t reg);
        void write(size_t ioapic, uint32_t reg, uint32_t data);

        uint64_t read_route(size_t ioapic, uint32_t entry);
        void write_route(size_t ioapic, uint32_t entry, uint64_t data);
        size_t max_redirs(size_t ioapic);
        
        uint8_t route(uint8_t apic, uint8_t irq, uint8_t vector, uint8_t masked);

        void setup();
    };

    namespace lapic {
        void write(uint32_t reg, uint32_t data);
        uint32_t read(uint32_t reg);
        void setup();
        void set_timer(uint32_t ms);
        void *get_base();

        uint64_t id();
        void eoi();
        void ipi(uint32_t ap, uint32_t flags);
    };

    void remap();
    void init();
};

#endif