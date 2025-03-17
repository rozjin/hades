#include <mm/common.hpp>
#include <cstddef>
#include <cstdint>
#include <arch/x86/hpet.hpp>
#include <arch/x86/types.hpp>
#include <sys/acpi.hpp>
#include <sys/x86/apic.hpp>
#include <util/io.hpp>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>
#include <util/misc.hpp>

namespace apic {
    namespace ioapic {
        uint32_t read(size_t ioapic, uint32_t reg) {
            if (ioapic > acpi::madt::ioapics.size()) {
                panic("[IOAPIC] Invalid IOAPIC access of %u", ioapic);
            }

            volatile uint32_t *base = (volatile uint32_t *) (acpi::madt::ioapics[ioapic]->address + memory::x86::virtualBase);
            *base = reg;
            return *(base + 4);
        }

        void write(size_t ioapic, uint32_t reg, uint32_t data) {
            if (ioapic > acpi::madt::ioapics.size()) {
                panic("[IOAPIC] Invalid IOAPIC access of %u", ioapic);
            }

            volatile uint32_t *base = (volatile uint32_t *) (acpi::madt::ioapics[ioapic]->address + memory::x86::virtualBase);
            *base = reg;
            *(base + 4) = data;
        }

        void write_route(size_t ioapic, uint32_t entry, uint64_t data) {
            write(ioapic, entry + 0x10, data & 0xFFFFFFFF);
            write(ioapic, entry + 0x10 + 1, (data >> 32) & 0xFFFFFFFF);            
        }

        uint64_t read_route(size_t ioapic, uint32_t entry) {
            uint64_t data = read(ioapic, entry + 0x10) | (((uint64_t) read(ioapic, entry + 0x10 + 1)) << 32);
            return data;
        }

        size_t max_redirs(size_t ioapic) {
            return (ioapic::read(ioapic, 1) >> 16) & 0xFF;
        }

        uint8_t route(uint8_t apic, uint8_t irq, uint8_t vector, uint8_t masked) {
            uint64_t flags = 0;
            for (size_t i = 0; i < acpi::madt::isos.size(); i++) {
                acpi::madt::iso *iso = acpi::madt::isos[i];
                if (iso->irq != irq) {
                    continue;
                }

                if (iso->flags & (1 << 1)) {
                    flags |= IOAPIC_REDIR_POLARITY;
                } else if (iso->flags & (1 << 3)) {
                    flags |= IOAPIC_REDIR_TRIGGER_MODE;
                }

                irq = iso->gsi;
                break;
            }
            
            if (masked) {
                flags |= IOAPIC_REDIR_MASK;
            }

            uint64_t entry = vector | flags | (((uint64_t) apic) << 56);
            for (size_t i = 0; i < acpi::madt::ioapics.size(); i++) {
                auto ioapic = acpi::madt::ioapics[i];
                if (irq <= max_redirs(i) && irq >= ioapic->gsi_base) {
                    write_route(i, (irq - ioapic->gsi_base) * 2, entry);
                    return irq;
                }
            }
            
            return irq;
        }

        void setup() {
            uint8_t base_vector = 32;
            uint64_t irq_bits = 0;
            for (size_t i = 0; i < 16; i++) {
                if (!util::bit_test((uint8_t *) &irq_bits, i)) {
                    uint8_t irq = route(0, i, i + base_vector, true);
                    util::bit_set((uint8_t *) &irq_bits, irq);
                }
            }
        };
    };

    void remap() {
        io::writeb(0x20, 0x11);
        io::writeb(0xA0, 0x11);

        io::writeb(0x21, 0x20);
        io::writeb(0xA1, 0x28);

        io::writeb(0x21, 0x4);
        io::writeb(0xA1, 0x2);

        io::writeb(0x21, 0x1);
        io::writeb(0xA1, 0x1);

        io::writeb(0xA1, 0xFF);
        io::writeb(0x21, 0xFF);
    };

    namespace lapic {
        uint32_t read(uint32_t reg) {
            size_t base = (size_t) get_base() + memory::x86::virtualBase;
            return *(volatile uint32_t *) (base + reg);
        }

        void write(uint32_t reg, uint32_t data) {
            size_t base = (size_t) get_base() + memory::x86::virtualBase;
            *((volatile uint32_t *) (base + reg)) = data;
        }

        void *get_base() {
            return (void *) (x86::rdmsr<uint64_t>(LAPIC_BASE_MSR) & 0xfffff000);
        };

        void set_base(void *base) {
            uint32_t rdx = (uint64_t) base >> 32;
            uint32_t rax = ((uint64_t) base & ~0xFFF) | LAPIC_BASE_MSR_ENABLE;

            x86::wrmsr(LAPIC_BASE_MSR, ((uint64_t) rdx) >> 32 | rax);
        }

        void setup() {
            if (!(x86::rdmsr<size_t>(LAPIC_BASE_MSR) & LAPIC_BASE_MSR_ENABLE)) {
                lapic::set_base(lapic::get_base());
            }
            lapic::write(LAPIC_REG_TPR, 0);
            lapic::write(LAPIC_REG_SIVR, apic::lapic::read(LAPIC_REG_SIVR) | 0x1FF);
        }

        void set_timer(uint32_t ms) {
            lapic::write(LAPIC_REG_DCR, 0x3);
            lapic::write(LAPIC_REG_INTERNAL_CNTR, ~0);

            hpet::msleep(20);

            uint32_t ticks = ~0 - lapic::read(LAPIC_REG_CURR_CNTR);

            lapic::write(LAPIC_REG_LVT_TIMR, 0x20 | (1 << 17));
            lapic::write(LAPIC_REG_DCR, 0x3);
            lapic::write(LAPIC_REG_INTERNAL_CNTR, ticks);
        }

        uint64_t id() {
            return (lapic::read(LAPIC_REG_ID) >> 24);
        }

        void eoi() {
            lapic::write(LAPIC_REG_EOI, 0);
        }

        void ipi(uint32_t ap, uint32_t flags) {
            lapic::write(LAPIC_REG_ICR_HIGH, ap << 24);
            lapic::write(LAPIC_REG_ICR_LOW, flags);
        }
    };

    void init() {
        remap();
        ioapic::setup();
        lapic::setup();

        asm volatile("mov %0, %%cr8" :: "r"(0ULL));
    }
};
