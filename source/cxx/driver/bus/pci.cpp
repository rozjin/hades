#include "driver/dtable.hpp"
#include "frg/unique.hpp"
#include "fs/dev.hpp"
#include "mm/common.hpp"
#include "mm/mm.hpp"
#include "mm/pmm.hpp"
#include "smarter/smarter.hpp"
#include "util/types.hpp"
#include <cstddef>
#include <cstdint>
#include <driver/bus/pci.hpp>
#include <util/io.hpp>
#include <util/log/log.hpp>

static log::subsystem logger = log::make_subsystem("PCI");
namespace pci {
    uint8_t device::get_bus() {
        return bus;
    }
    
    uint8_t device::get_slot() {
        return slot;
    }
    
    uint8_t device::get_clazz() {
        return clazz;
    }
    
    uint8_t device::get_subclass() {
        return subclass;
    }
    
    uint8_t device::get_prog_if() {
        return prog_if;
    }
    
    uint8_t device::get_func() {
        return func;
    }
    
    uint16_t device::get_device() {
        return devize;
    }
    
    uint16_t device::get_vendor() {
        return vendor_id;
    }
    
    static inline uint8_t get_secondary_bus(uint8_t bus, uint8_t slot, uint8_t func) {
        return (uint8_t) (read_dword(bus, slot, func, 0x18) >> 8);
    }
    
    static inline uint16_t get_vendor(uint8_t bus, uint8_t slot, uint8_t func) {
        return (uint16_t) read_dword(bus, slot, func, 0);
    }
    
    static inline uint16_t get_device(uint8_t bus, uint8_t slot, uint8_t func) {
        return (uint16_t) (read_dword(bus, slot, func, 0) >> 16);
    }
    
    static inline uint8_t get_class(uint8_t bus, uint8_t slot, uint8_t func) {
        return (uint8_t) (read_dword(bus, slot, func, 0x8) >> 24);
    }
    
    static inline uint8_t get_subclass(uint8_t bus, uint8_t slot, uint8_t func) {
        return (uint8_t) (read_dword(bus, slot, func, 0x8) >> 16);
    }
    
    static inline uint8_t get_prog_if(uint8_t bus, uint8_t slot, uint8_t func) {
        return (uint8_t) (read_dword(bus, slot, func, 0x8) >> 8);
    }
    
    static inline uint16_t get_status(uint8_t bus, uint8_t slot, uint8_t func) {
        return (uint16_t) (read_dword(bus, slot, func, 0x4) >> 16);
    }
    
    static inline uint8_t get_capability(uint8_t bus, uint8_t slot, uint8_t func, uint8_t capability) {
        uint16_t reg_status = get_status(bus, slot, func);
        if (!(reg_status & (1 << 4))) {
            return 0;
        }
    
        uint8_t reg_cap = read_byte(bus, slot, func, 0x34);
        uint16_t cap_word = read_word(bus, slot, func, reg_cap);
    
        uint8_t cap_id = (uint8_t) cap_word;
        uint8_t cap_next = (uint8_t) cap_word >> 8;
    
        cap_next &= 0xFC;
        while (cap_next) {
            if (cap_id == capability) {
                return cap_next;
            }
    
            cap_word = read_dword(bus, slot, func, cap_next);
    
            cap_id = (uint8_t) cap_word;
            cap_next = (uint8_t) cap_word >> 8;
    
            cap_next &= 0xFC;
        }
    
        return 0;
    }
    
    static inline uint8_t is_bridge(uint8_t bus, uint8_t slot, uint8_t func) {
        if (get_class(bus, slot, func) != 0x6) return 0;
        if (get_subclass(bus, slot, func) != 0x4) return 0;
    
        return 1;
    }
    
    static inline uint8_t is_multifunction(uint8_t bus, uint8_t slot) {
        uint8_t header_type = (uint8_t) (read_dword(bus, slot, 0, 0xC) >> 16);
        return header_type & (1 << 7);
    }
    
    static inline uint8_t is_function(uint8_t bus, uint8_t slot, uint8_t func) {
        return (get_vendor(bus, slot, func) != 0xFFFF);
    }
    
    int device::read_bar(size_t index, bar& bar_out) {
        if (index > 5) {
            return 0;
        }
    
        uint32_t reg_idx = 0x10 + (index * 4);
        uint32_t bar = readd(reg_idx);

        if (!bar) {
            return 0;
        }
    
        uint64_t base;
        uint32_t size;
    
        uint8_t is_mmio = !(bar & 1);
        uint8_t is_prefetchable = is_mmio && bar & (1 << 3);
        uint8_t is_long = ((bar >> 1) & 0x3) == 0x2;

        writed(reg_idx, ~0);
        size = readd(reg_idx);
        writed(reg_idx, bar);

        if (!is_mmio) {
            size &= ~0x3;
            size = (~size) + 1;

            base = bar & ~0x3;

            bar_out.base = base;
            bar_out.size = size;
            bar_out.is_mmio = is_mmio;
            bar_out.is_prefetchable = is_prefetchable;
            bar_out.valid = true;
        } else {
            uint64_t bar_hi, size_hi = 0;
            if (is_long) {
                bar_hi = readd(reg_idx + 4);
        
                writed(reg_idx + 4, ~0);
                size_hi = readd(reg_idx + 4);
                writed(reg_idx + 4, bar_hi);
            }

            size &= ~0xF;
            size = (~size) + 1;

            base = bar & ~0xF;

            bar_out.base = is_long ? (bar_hi << 32) | base : base;
            bar_out.size = is_long ? (size_hi << 32) | size : size;
            bar_out.is_mmio = is_mmio;
            bar_out.is_prefetchable = is_prefetchable;
            bar_out.valid = true;
        }

        return 1;
    }
    
    int device::register_msi(uint8_t vector, uint8_t lapic_id) {
        uint8_t off = 0;
    
        uint32_t config_4  = readd(PCI_HAS_CAPS);
        uint8_t  config_34 = readb(PCI_CAPS);
        if ((config_4 >> 16) & (1 << 4)) {
            uint8_t cap_off = config_34;
    
            while (cap_off) {
                uint8_t cap_id   = readb(cap_off);
                uint8_t cap_next = readb(cap_off + 1);
    
                switch (cap_id) {
                    case 0x05: {
                        kmsg(logger, "Device has MSI support");
                        off = cap_off;
                        break;
                    }
                }
                cap_off = cap_next;
            }
        }
    
        if (off == 0) {
            kmsg(logger, "Device does not support MSI");
            return 0;
        }
    
        uint16_t msi_opts = readw(off + MSI_OPT);
        if (msi_opts & MSI_64BIT_SUPPORTED) {
            msi_data data    = {.raw = 0};
            msi_address addr = {.raw = 0};
            addr.raw = readw(off + MSI_ADDR_LOW);
            data.raw = readw(off + MSI_DATA_64);
    
            data.vector = vector;
            data.delv_mode = 0;
            addr.base_addr = 0xFEE;
            addr.dest_id = lapic_id;
            writed(off + MSI_ADDR_LOW, addr.raw);
            writed(off + MSI_DATA_64, data.raw);
        } else {
            msi_data data    = {.raw = 0};
            msi_address addr = {.raw = 0};
            addr.raw = readw(off + MSI_ADDR_LOW);
            data.raw = readw(off + MSI_DATA_32);
            
            data.vector = vector;
            data.delv_mode = 0;
            addr.base_addr = 0xFEE;
            addr.dest_id = lapic_id;
            writed(off + MSI_ADDR_LOW, addr.raw);
            writed(off + MSI_DATA_32, data.raw);
        }
    
        msi_opts |= (1 << 16);
        writew(off + MSI_OPT, msi_opts);
    
        return 1;
    }
    
    uint8_t device::readb(uint32_t offset) {
        return read_byte(bus, slot, func, offset);
    }
    
    void device::writeb(uint32_t offset, uint8_t value) {
        write_byte(bus, slot, func, offset, value);
    }
    
    uint16_t device::readw(uint32_t offset) {
        return read_word(bus, slot, func, offset);
    }
    
    void device::writew(uint32_t offset, uint16_t value) {
        write_word(bus, slot, func, offset, value);
    }
    
    uint32_t device::readd(uint32_t offset) {
        return read_dword(bus, slot, func, offset);
    }
    
    void device::writed(uint32_t offset, uint32_t value) {
        write_dword(bus, slot, func, offset, value);
    }
    
    void device::enable_busmastering() {
        if (!(readd(0x4) & (1 << 2))) {
            writed(0x4, readd(0x4) | (1 << 2));
        }
    }
    
    void device::enable_mmio() {
        if (!(readd(0x4) & (1 << 1))) {
            writed(0x4, readd(0x4) | (1 << 1));
        }
    }
    
    uint8_t device::read_pin() {
        return readw(0x3C) >> 8;
    }
    
    const char *to_string(uint8_t clazz, uint8_t subclass, uint8_t prog_if) {
        switch (clazz) {
            case 0:
                return "Undefined";
            case 1:
                switch (subclass) {
                    case 0:
                        return "SCSI Bus Controller";
                    case 1:
                        return "IDE Controller";
                    case 2:
                        return "Floppy Disk Controller";
                    case 3:
                        return "IPI Bus Controller";
                    case 4:
                        return "RAID Controller";
                    case 5:
                        return "ATA Controller";
                    case 6:
                        switch (prog_if) {
                            case 0:
                                return "Vendor Specific SATA Controller";
                            case 1:
                                return "AHCI SATA Controller";
                            case 2:
                                return "Serial Storage Bus SATA Controller";
                        }
                        break;
                    case 7:
                        return "Serial Attached SCSI Controller";
                    case 8:
                        switch (prog_if) {
                            case 1:
                                return "NVMHCI Controller";
                            case 2:
                                return "NVMe Controller";
                        }
                        break;
                    return "Mass Storage Controller";
                }
            case 2:
                switch (subclass) {
                    case 0:
                        return "Ethernet Controller";
                    case 1:
                        return "Token Ring Controller";
                    case 2:
                        return "FDDI Controller";
                    case 3:
                        return "ATM Controller";
                    case 4:
                        return "ISDN Controller";
                    case 5:
                        return "WorldFip Controller";
                    case 6:
                        return "PICMG 2.14 Controller";
                    case 7:
                        return "InfiniBand Controller";
                    case 8:
                        return "Fabric Controller";
                }
                return "Network Controller";
            case 3:
                switch (subclass) {
                    case 0:
                        return "VGA Compatible Controller";
                    case 1:
                        return "XGA Controller";
                    case 2:
                        return "3D Controller";
                }
                return "Display Controller";
            case 4:
                return "Multimedia Controller";
            case 5:
                return "Memory Controller";
            case 6:
                switch (subclass) {
                    case 0:
                        return "Host Bridge";
                    case 1:
                        return "ISA Bridge";
                    case 2:
                        return "EISA Bridge";
                    case 3:
                        return "MCA Bridge";
                    case 4:
                        return "PCI-to-PCI Bridge";
                    case 5:
                        return "PCMCIA Bridge";
                    case 6:
                        return "NuBus Bridge";
                    case 7:
                        return "CardBus Bridge";
                    case 8:
                        return "RACEway Bridge";
                    case 9:
                        return "Semi-Transparent PCI-to-PCI Bridge";
                    case 10:
                        return "InfiniBand-to-PCI Host Bridge";
                }
                return "Bridge Device";
            case 8:
                switch (subclass) {
                    case 0:
                        switch (prog_if) {
                            case 0:
                                return "8259-Compatible PIC";
                            case 1:
                                return "ISA-Compatible PIC";
                            case 2:
                                return "EISA-Compatible PIC";
                            case 16:
                                return "I/O APIC IRQ Controller";
                            case 32:
                                return "I/O xAPIC IRQ Controller";
                        }
                        break;
                    case 1:
                        switch (prog_if) {
                            case 0:
                                return "8239-Compatible DMA Controller";
                            case 1:
                                return "ISA-Compatible DMA Controller";
                            case 2:
                                return "EISA-Compatible DMA Controller";
                        }
                        break;
                    case 2:
                        switch (prog_if) {
                            case 0:
                                return "8254-Compatible PIT";
                            case 1:
                                return "ISA-Compatible PIT";
                            case 2:
                                return "EISA-Compatible PIT";
                            case 3:
                                return "HPET";
                        }
                        break;
                    case 3:
                        return "Real Time Clock";
                    case 4:
                        return "PCI Hot-Plug Controller";
                    case 5:
                        return "SDHCI";
                    case 6:
                        return "IOMMU";
                }
                return "Base System Peripheral";
            case 12:
                switch (subclass) {
                    case 0:
                        switch (prog_if) {
                            case 0:
                                return "Generic FireWire (IEEE 1394) Controller";
                            case 1:
                                return "OHCI FireWire (IEEE 1394) Controller";
                        }
                        break;
                    case 1:
                        return "ACCESS Bus Controller";
                    case 2:
                        return "SSA Controller";
                    case 3:
                        switch (prog_if) {
                            case 0:
                                return "UHCI USB1 Controller";
                            case 16:
                                return "OHCI USB1 Controller";
                            case 32:
                                return "EHCI USB2 Controller";
                            case 48:
                                return "XHCI USB3 Controller";
                            case 254:
                                return "USB Device";
                        }
                        break;
                    case 4:
                        return "Fibre Channel Controller";
                    case 5:
                        return "SMBus Controller";
                    case 6:
                        return "InfiniBand Controller";
                    case 7:
                        return "IPMI Interface Controller";
                }
                return "Serial Bus Controller";
            default:
                return "Unknown";
        }
    }
    
    static inline device create_device(uint8_t bus, uint8_t slot, uint8_t func) {
        return device(
            bus,
            slot,
            func,
            get_class(bus, slot, func),
            get_subclass(bus, slot, func),
            get_prog_if(bus, slot, func),
            get_device(bus, slot, func),
            get_vendor(bus, slot, func),
            is_multifunction(bus, slot)
        );
    }
}

pci::device *pcibus::get_device(uint8_t cl, uint8_t subcl, uint8_t prog_if) {
    auto len = devices.size();
    for (size_t i = 0; i < len; i++) {
        auto current_class    = devices[i].get_clazz();
        auto current_subclass = devices[i].get_subclass();
        auto current_prog_if  = devices[i].get_prog_if();

        if (current_class == cl && current_subclass == subcl &&
            current_prog_if == prog_if) {
            return &devices[i];
        }
    }

    return nullptr;
}

pci::device *pcibus::get_device(uint16_t vendor, uint16_t device) {
    auto len = devices.size();
    for (size_t i = 0; i < len; i++) {
        auto current_vendor    = devices[i].get_vendor();
        auto current_device = devices[i].get_device();

        if (current_vendor == vendor && current_device == device) {
            return &devices[i];
        }
    }

    return nullptr;
}

void pcibus::attach(ssize_t major, void *aux) {
    switch(major) {
        case dtable::majors::PCI: {
            auto info = (pci::attach_args *) aux;

            pcibus *secondary_bus = frg::construct<pcibus>(memory::mm::heap, this,
                pci::get_secondary_bus(info->bus, info->slot, info->func));

            bus_devices.push_back(secondary_bus);
            secondary_bus->minor = bus_devices.size() - 1;
            secondary_bus->enumerate();

            break;
        }

        default: {
            auto info = (pci::attach_args *) aux;

            // {vend:#x}, {dev:#x}, {cls:#x}, {subcls:#x}, {progif:#x}, {"MATCH_END"}

            int match_data[5] = {
                pci::get_vendor(info->bus, info->slot, info->func),
                pci::get_device(info->bus, info->slot, info->func),

                pci::get_class(info->bus, info->slot, info->func),
                pci::get_subclass(info->bus, info->slot, info->func),
                pci::get_prog_if(info->bus, info->slot, info->func)
            };

            auto matcher = dtable::lookup_by_data(match_data, 5);
            if (matcher) {
                auto pci_device = pci::create_device(info->bus, info->slot, info->func);
                devices.push_back(pci_device);

                auto device = matcher->match(this, &pci_device);
                if (device) {
                    matcher->attach(this, device, &pci_device);

                    bus_devices.push_back(device);
                    vfs::devfs::append_device(device, device->major);
                }
            }

            break;
        }
    }
}

void pcibus::enumerate() {
    for (size_t slot = 0; slot < pci::MAX_DEVICE; slot++) {
        if (pci::is_function(bus, slot, 0)) {
            pci::attach_args info{
                .bus = (uint8_t) bus,
                .slot = (uint8_t) slot,
                .func = 0
            };

            if (pci::is_bridge(bus, slot, 0)) {
                attach(dtable::majors::PCI, &info);
            } else {
                attach(-1, &info);
            }

            if (pci::is_multifunction(bus, slot)) {                
                for (size_t func = 1; func < pci::MAX_FUNCTION; func++) {
                    if (pci::is_function(bus, slot, func)) {
                        pci::attach_args info{
                            .bus = (uint8_t) bus,
                            .slot = (uint8_t) slot,
                            .func = (uint8_t) func
                        };

                        if (pci::is_bridge(bus, slot, func)) {        
                            attach(dtable::majors::PCI, &info);                  
                        } else {
                            attach(-1, &info);
                        }
                    }
                }
            }
        } else {
            continue;
        }
    }
}

shared_ptr<vfs::devfs::bus_dma> pcibus::get_dma(size_t size) {
    return smarter::allocate_shared<pci_dma>(memory::mm::heap,
        size);
}

bus_size_t pci_dma::vaddr() {
    return addr;
}

bus_size_t pci_dma::paddr() {
    return memory::remove_virt(addr);
}

bus_addr_t pci_dma::map(void *vaddr) {
    return (bus_addr_t) memory::remove_virt(vaddr);
}

void pci_dma::unmap(bus_addr_t vaddr) {
    return;
}

/**
 * 
 *     while (current) {
        if (current->addr <= addr && ((char *) current->addr + current->len) >= addr) {
            return current;
        }

        if (current->addr > addr) {
            current = this->mappings.get_left(current);
        } else {
            current = this->mappings.get_right(current);
        }
 */

bus_handle_t pci_space::map(bus_addr_t offset, bus_size_t size) {
    if (this->addr + offset + size > (this->addr + this->size)) return -1;
    return offset + this->addr;
 }

void pci_space::unmap(bus_handle_t handle) {
    return;
}

void *pci_space::vaddr(bus_handle_t handle) {
    if (linear) return (void *) memory::add_virt(handle);
    return nullptr;
}

uint8_t pci_space::readb(bus_handle_t handle, bus_size_t offset) {
    if (offset > size || handle < addr || handle + offset > addr + size) return (uint8_t) -1;

    if (linear) return *(uint8_t *) (memory::add_virt(handle + offset));
    return io::readb(addr + offset);
}

uint16_t pci_space::readw(bus_handle_t handle, bus_size_t offset) {
    if (offset > size || handle < addr || handle + offset > addr + size) return (uint16_t) -1;

    if (linear) return *(uint16_t *) (memory::add_virt(handle + offset));
    return io::readw(addr + offset);
}

uint32_t pci_space::readd(bus_handle_t handle, bus_size_t offset) {
    if (offset > size || handle < addr || handle + offset > addr + size) return (uint32_t) -1;

    if (linear) return *(uint32_t *) (memory::add_virt(handle + offset));
    return io::readd(addr + offset);
}

uint64_t pci_space::readq(bus_handle_t handle, bus_size_t offset) {
    if (offset > size || handle < addr || handle + offset > addr + size) return (uint64_t) -1;

    if (linear) return *(uint64_t *) (memory::add_virt(handle + offset));
    return (uint64_t) -1;
}

void pci_space::writeb(bus_handle_t handle, bus_size_t offset, uint8_t val) {
    if (offset > size || handle < addr || handle + offset > addr + size) return;

    if (linear) *(uint8_t*) (memory::add_virt(handle + offset)) = val;
    else io::writeb(handle + offset, val);
}

void pci_space::writew(bus_handle_t handle, bus_size_t offset, uint16_t val) {
    if (offset > size || handle < addr || handle + offset > addr + size) return;

    if (linear) *(uint16_t*) (memory::add_virt(handle + offset)) = val;
    else io::writew(handle + offset, val);
}

void pci_space::writed(bus_handle_t handle, bus_size_t offset, uint32_t val) {
    if (offset > size || handle < addr || handle + offset > addr + size) return;

    if (linear) *(uint32_t*) (memory::add_virt(handle + offset)) = val;
    else io::writed(handle + offset, val);
}

void pci_space::writeq(bus_handle_t handle, bus_size_t offset, uint64_t val) {
    if (offset > size || handle < addr || handle + offset > addr + size) return;

    if (linear) *(uint64_t*) (memory::add_virt(handle + offset)) = val;
    else return;
}

void pci_space::read_regionb(bus_handle_t handle, bus_size_t offset, uint8_t *data, size_t count) {
    if (handle + offset + (sizeof(uint8_t) * size) > addr + size || handle < addr) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint8_t) * i);

        if (linear) data[i] = *(uint8_t *) (memory::add_virt(curr_offset));
        else data[i] = io::readb(curr_offset);
    }
}

void pci_space::read_regionw(bus_handle_t handle, bus_size_t offset, uint16_t *data, size_t count) {
    if (handle + offset + (sizeof(uint16_t) * size) > addr + size || handle < addr) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint16_t) * i);

        if (linear) data[i] = *(uint16_t *) (memory::add_virt(curr_offset));
        else data[i] = io::readw(curr_offset);
    }
}

void pci_space::read_regiond(bus_handle_t handle, bus_size_t offset, uint32_t *data, size_t count) {
    if (handle + offset + (sizeof(uint32_t) * size) > addr + size || handle < addr) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint32_t) * i);

        if (linear) data[i] = *(uint32_t *) (memory::add_virt(curr_offset));
        else data[i] = io::readd(curr_offset);
    }
}

void pci_space::read_regionq(bus_handle_t handle, bus_size_t offset, uint64_t *data, size_t count) {
    if (handle + offset + (sizeof(uint64_t) * size) > addr + size || handle < addr
        || !linear) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint64_t) * i);
        data[i] = *(uint64_t *) (memory::add_virt(curr_offset));
    }
}

void pci_space::write_regionb(bus_handle_t handle, bus_size_t offset, uint8_t *data, size_t count) {
    if (handle + offset + (sizeof(uint8_t) * size) > addr + size || handle < addr) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint8_t) * i);

        if (linear) *(uint8_t *) (memory::add_virt(curr_offset)) = data[i];
        else io::writeb(curr_offset, data[i]);
    }
}

void pci_space::write_regionw(bus_handle_t handle, bus_size_t offset, uint16_t *data, size_t count) {
    if (handle + offset + (sizeof(uint16_t) * size) > addr + size || handle < addr) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint16_t) * i);

        if (linear) *(uint16_t *) (memory::add_virt(curr_offset)) = data[i];
        else io::writew(curr_offset, data[i]);
    }
}

void pci_space::write_regiond(bus_handle_t handle, bus_size_t offset, uint32_t *data, size_t count) {
    if (handle + offset + (sizeof(uint32_t) * size) > addr + size || handle < addr) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint32_t) * i);

        if (linear) *(uint32_t *) (memory::add_virt(curr_offset)) = data[i];
        else io::writed(curr_offset, data[i]);
    }
}

void pci_space::write_regionq(bus_handle_t handle, bus_size_t offset, uint64_t *data, size_t count) {
    if (handle + offset + (sizeof(uint64_t) * size) > addr + size || handle < addr
        || !linear) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint64_t) * i);
        *(uint64_t *) (memory::add_virt(curr_offset)) = data[i];
    }
}

void pci_space::set_regionb(bus_handle_t handle, bus_size_t offset, uint8_t val, size_t count) {
    if (handle + offset + (sizeof(uint8_t) * size) > addr + size || handle < addr) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint8_t) * i);

        if (linear) *(uint8_t *) (memory::add_virt(curr_offset)) = val;
        else io::writeb(curr_offset, val);
    }
}

void pci_space::set_regionw(bus_handle_t handle, bus_size_t offset, uint16_t val, size_t count) {
    if (handle + offset + (sizeof(uint16_t) * size) > addr + size || handle < addr) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint16_t) * i);

        if (linear) *(uint16_t *) (memory::add_virt(curr_offset)) = val;
        else io::writew(curr_offset, val);
    }
}

void pci_space::set_regiond(bus_handle_t handle, bus_size_t offset, uint32_t val, size_t count) {
    if (handle + offset + (sizeof(uint32_t) * size) > addr + size || handle < addr) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint32_t) * i);

        if (linear) *(uint32_t *) (memory::add_virt(curr_offset)) = val;
        else io::writed(curr_offset, val);
    }
}

void pci_space::set_regionq(bus_handle_t handle, bus_size_t offset, uint64_t val, size_t count) {
    if (handle + offset + (sizeof(uint64_t) * size) > addr + size || handle < addr
        || !linear) return;

    for (size_t i = 0; i < count; i++) {
        auto curr_offset = handle + offset + (sizeof(uint64_t) * i);
        *(uint64_t *) (memory::add_virt(curr_offset)) = val;
    }
}

void pci_space::read_multib(bus_handle_t handle, bus_size_t offset, uint8_t *data, size_t count) {
    if (handle + offset > addr + size || handle < addr) return;
    
    for (size_t i = 0; i < count; i++) {
        if (linear) data[i] = *(uint8_t *) (memory::add_virt(handle + offset));
        else data[i] = io::readb(addr + offset);
    }
}

void pci_space::read_multiw(bus_handle_t handle, bus_size_t offset, uint16_t *data, size_t count) {
    if (handle + offset > addr + size || handle < addr) return;
    
    for (size_t i = 0; i < count; i++) {
        if (linear) data[i] = *(uint16_t *) (memory::add_virt(handle + offset));
        else data[i] = io::readw(addr + offset);
    }
}

void pci_space::read_multid(bus_handle_t handle, bus_size_t offset, uint32_t *data, size_t count) {
    if (handle + offset > addr + size || handle < addr) return;
    
    for (size_t i = 0; i < count; i++) {
        if (linear) data[i] = *(uint32_t *) (memory::add_virt(handle + offset));
        else data[i] = io::readd(addr + offset);
    }
}

void pci_space::read_multiq(bus_handle_t handle, bus_size_t offset, uint64_t *data, size_t count) {
    if (handle + offset > addr + size || handle < addr
        || !linear) return;
    
    for (size_t i = 0; i < count; i++) {
        data[i] = *(uint64_t *) (memory::add_virt(handle + offset));
    }
}

void pci_space::write_multib(bus_handle_t handle, bus_size_t offset, uint8_t *data, size_t count) {
    if (handle + offset > addr + size || handle < addr) return;
    
    for (size_t i = 0; i < count; i++) {
        if (linear) *(uint8_t *) (memory::add_virt(handle + offset)) = data[i];
        io::writeb(addr + offset, data[i]);
    }
}

void pci_space::write_multiw(bus_handle_t handle, bus_size_t offset, uint16_t *data, size_t count) {
    if (handle + offset > addr + size || handle < addr) return;
    
    for (size_t i = 0; i < count; i++) {
        if (linear) *(uint16_t *) (memory::add_virt(handle + offset)) = data[i];
        io::writew(addr + offset, data[i]);
    }
}

void pci_space::write_multid(bus_handle_t handle, bus_size_t offset, uint32_t *data, size_t count) {
    if (handle + offset > addr + size || handle < addr) return;
    
    for (size_t i = 0; i < count; i++) {
        if (linear) *(uint32_t *) (memory::add_virt(handle + offset)) = data[i];
        io::writed(addr + offset, data[i]);
    }
}

void pci_space::write_multiq(bus_handle_t handle, bus_size_t offset, uint64_t *data, size_t count) {
    if (handle + offset > addr + size || handle < addr
        || !linear) return;
    
    for (size_t i = 0; i < count; i++) {
        *(uint64_t *) (memory::add_virt(handle + offset)) = data[i];
    }
}

