#include <cstddef>
#include <cstdint>
#include <sys/acpi.hpp>
#include <sys/x86/apic.hpp>
#include <util/io.hpp>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>

namespace apic {
    namespace ioapic {
        uint32_t read(size_t ioapic, uint32_t reg) {
            if (ioapic > acpi::madt::ioapics.size()) {
                panic("[IOAPIC] Invalid IOAPIC access of ", ioapic);
            }

            volatile uint32_t *base = (volatile uint32_t *) (acpi::madt::ioapics[ioapic]->address + memory::common::virtualBase);
            *base = reg;
            return *(base + 4);
        }

        void write(size_t ioapic, uint32_t reg, uint32_t data) {
            if (ioapic > acpi::madt::ioapics.size()) {
                panic("[IOAPIC] Invalid IOAPIC access of ", ioapic);
            }

            volatile uint32_t *base = (volatile uint32_t *) (acpi::madt::ioapics[ioapic]->address + memory::common::virtualBase);
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

                if (iso->flags & 2) {
                    flags |= IOAPIC_REDIR_POLARITY;
                }

                if (iso->flags & 8) {
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
            for (size_t i = 0; i < 16; i++) {
                route(0, i, i + base_vector, true);
            }
        };
    };

    void remap() {
        uint8_t master_mask = io::ports::read<uint8_t>(0x21);
        uint8_t slave_mask  = io::ports::read<uint8_t>(0xA1);

        if (master_mask == 0xFF && slave_mask == 0xFF) {
            return;
        }

        io::ports::write<uint8_t>(0x20, 0x11);
        io::ports::io_wait();
        io::ports::write<uint8_t>(0xA0, 0x11);
        io::ports::io_wait();

        io::ports::write<uint8_t>(0x21, 0x20);
        io::ports::io_wait();
        io::ports::write<uint8_t>(0xA1, 0x40);
        io::ports::io_wait();

        io::ports::write<uint8_t>(0x21, 4);
        io::ports::io_wait();
        io::ports::write<uint8_t>(0xA1, 2);
        io::ports::io_wait();

        io::ports::write<uint8_t>(0x21, 1);
        io::ports::io_wait();
        io::ports::write<uint8_t>(0xA1, 1);
        io::ports::io_wait();

        io::ports::write<uint8_t>(0x21, master_mask);
        io::ports::io_wait();
        io::ports::write<uint8_t>(0xA1, slave_mask);
        io::ports::io_wait();
        io::ports::write<uint8_t>(0xA1, 0xFF);
        io::ports::write<uint8_t>(0x21, 0xFF);
    };

    namespace lapic {
        uint32_t read(uint32_t reg) {
            size_t base = (size_t) get_base() + memory::common::virtualBase;
            return *(volatile uint32_t *) (base + reg);
        }

        void write(uint32_t reg, uint32_t data) {
            size_t base = (size_t) get_base() + memory::common::virtualBase;
            *((volatile uint32_t *) (base + reg)) = data;
        }

        void *get_base() {
            return (void *) (io::rdmsr<uint64_t>(0x1B) & 0xfffff000);
        };

        void set_base(void *base) {
            uint32_t rdx = (uint64_t) base >> 32;
            uint32_t rax = ((uint64_t) base & ~0xFFF) | LAPIC_BASE_MSR_ENABLE;

            io::wrmsr(LAPIC_BASE_MSR, ((uint64_t) rdx) >> 32 | rax);
        }

        void setup() {
            if (!(io::rdmsr<size_t>(LAPIC_BASE_MSR) & LAPIC_BASE_MSR_ENABLE)) {
                lapic::set_base(lapic::get_base());
            }
            lapic::write(LAPIC_REG_SIVR, apic::lapic::read(LAPIC_REG_SIVR) | LAPIC_BASE_MSR_BSP);
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
        lapic::setup();
        ioapic::setup();
    }
};
