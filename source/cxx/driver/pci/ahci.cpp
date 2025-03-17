#include "mm/common.hpp"
#include "util/types.hpp"
#include <cstddef>
#include <driver/bus/pci.hpp>
#include <driver/dtable.hpp>
#include <fs/dev.hpp>
#include <mm/mm.hpp>
#include <driver/ahci.hpp>
#include <driver/pci/ahci.hpp>
#include <util/log/panic.hpp>

static log::subsystem logger = log::make_subsystem("AHCIBUS");

uint8_t port_type(volatile ahci::port *port) {
    uint32_t sata_status = port->sata_status;
    uint8_t detection = sata_status & 0x0F;
    if (detection != 3) {
        return ahci::DEV_NULL;
    }

    switch (port->sig) {
        case ahci::SIG_ATAPI:
            return ahci::DEV_ATAPI;
        case ahci::SEG_SEMB:
            return ahci::DEV_SEMB;
        case ahci::SIG_PM:
            return ahci::DEV_PM;
        default:
            return ahci::DEV_ATA;
    }

    return ahci::DEV_NULL;
};

uint8_t port_present(volatile ahci::abar *bar, uint8_t port) {
    uint32_t port_implemented = bar->port_implemented;

    if (port_implemented & (1 << port)) {
        return port_type(&bar->ports[port]);
    }

    return ahci::DEV_NULL;
}

void get_ownership(volatile ahci::abar *bar) {
    if (!(bar->cap2 & (1 << 0))) {
        kmsg(logger, "BIOS Handoff not supported");
        return;
    }

    bar->bohc |= (1 << 1);
    while ((bar->bohc & (1 << 0)) == 0) asm volatile("pause");

    for (int i = 0; i < 0x800000; i++) asm volatile("pause");

    if (bar->bohc & (1 << 4)) {
        for (int i = 0; i < 0x800000; i++) asm volatile("pause");
    }

    uint32_t bohc = bar->bohc;
    if (bohc & (1 << 4) || bohc & (1 << 0) || (bohc & (1 << 1)) == 0) {
        panic("[AHCI]: Unable to get BIOS handoff");
    }

    kmsg(logger, "BIOS handoff successful");
}

vfs::devfs::device 
    *pci::ahcibus::matcher::match(vfs::devfs::busdev *bus, void *aux) {
    return frg::construct<ahcibus>(memory::mm::heap, bus, (pci::device *) aux);
}

void pci::ahcibus::matcher::attach(vfs::devfs::busdev *bus, vfs:: devfs::device *dev, void *aux) {
    return;
}

void pci::ahcibus::attach(ssize_t major, void *aux) {
    switch(major) {
        case dtable::majors::AHCI: {
            auto device = frg::construct<::ahci::device>(memory::mm::heap, this, dtable::majors::AHCI, -1, aux);

            devices.push_back(device);
            bus_devices.push_back(device);

            device->setup();
            vfs::devfs::append_device(device, dtable::majors::AHCI);
            
            break;
        }
    }
}

void pci::ahcibus::enumerate() {
    device->enable_mmio();
    device->enable_busmastering();

    pci::bar pci_bar;
    device->read_bar(5, pci_bar);
    if (!pci_bar.valid || !pci_bar.is_mmio || !pci_bar.base) {
        kmsg(logger, "AHCI ABAR Invalid!");
        return;
    }

    volatile ::ahci::abar *ahci_bar = memory::add_virt((::ahci::abar *) pci_bar.base);
    kmsg(logger, "ABAR Base: %x", ahci_bar);

    ahci_bar->ghc |= (1 << 31);
    get_ownership(ahci_bar);

    for (size_t i = 0; i < ::ahci::MAX_SLOTS; i++) {
        switch (port_present(ahci_bar, i)) {
            case ::ahci::DEV_PM:
            case ::ahci::DEV_SEMB:
            case ::ahci::DEV_ATAPI:
                kmsg(logger, "Found Unsupported AHCI device with port id  %d", i);
                break;
            case ::ahci::DEV_ATA: {
                kmsg(logger, "Found SATA device with port id %d", i);

                ::ahci::setup_args args{
                    // bus_addr_t addr, bus_size_t size, bool linear
                    .bar = frg::construct<pci_space>(memory::mm::heap, pci_bar.base, pci_bar.size, pci_bar.is_mmio),
                    .port = frg::construct<pci_space>(memory::mm::heap, (bus_addr_t) memory::remove_virt(&ahci_bar->ports[i]), sizeof(::ahci::port), true),
                };

                attach(dtable::majors::AHCI, &args);
                break;
            }
            default:
                break;
        }
    }
}

shared_ptr<vfs::devfs::bus_dma> pci::ahcibus::get_dma(size_t size) {
    return this->bus->get_dma(size);
}