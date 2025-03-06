#include "util/lock.hpp"
#include <arch/types.hpp>
#include <sys/sched/sched.hpp>
#include <sys/sched/event.hpp>
#include <util/misc.hpp>
#include <cstddef>
#include <cstdint>
#include <driver/ahci.hpp>
#include <driver/part.hpp>
#include <fs/dev.hpp>
#include <fs/vfs.hpp>
#include <frg/allocation.hpp>
#include <mm/common.hpp>
#include <mm/mm.hpp>
#include <mm/pmm.hpp>
#include <driver/bus/pci.hpp>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>
#include <util/string.hpp>


static log::subsystem logger = log::make_subsystem("AHCI");
void ahci::device::await_ready() {
    while (port->tfd & (1 << 3) || port->tfd & (1 << 7)) {
        asm volatile("pause");
    }
}

void ahci::device::issue_command(size_t slot) {
    port->cmd_issue |= (1 << slot);
}

ssize_t ahci::device::find_cmdslot() {
    for (size_t i = 0; i < ahci::MAX_SLOTS; i++) {
        if (!(port->cmd_issue & (1 << i))) {
            return i;
        }
    }

    return -1;
}

ahci::command_slot ahci::device::get_command(uint64_t fis_size) {
    auto slot_dma = bus->get_dma(fis_size);
    ahci::command_slot slot = {-1, nullptr, slot_dma};

    auto slot_idx = find_cmdslot();
    if (slot_idx == -1) {
        return slot;
    }

    ahci::command_entry *entry = (ahci::command_entry *) slot_dma->vaddr();

    slot.idx = slot_idx;
    slot.entry = entry;

    ahci::command_header *headers = (ahci::command_header *) data_dma->vaddr();

    headers[slot_idx].command_entry = (uint32_t) slot_dma->paddr();
    uint8_t is_long = (uint8_t) ((bar->cap & (1 << 31)) >> 31);

    if (is_long) {
        headers[slot_idx].command_entry_hi = (uint32_t) (slot_dma->paddr() >> 32);
    } else {
        headers[slot_idx].command_entry_hi = 0;
    }

    return slot;
}

ahci::command_header *ahci::device::get_header(uint8_t slot) {
    ahci::command_header *headers = (ahci::command_header *) data_dma->vaddr();

    return headers + slot;
}

void ahci::device::comreset() {
    port->sata_ctl = (port->sata_ctl & ~(0b1111)) | 0x1;
    for (int i = 0; i < 100000; i++) asm volatile ("pause");
    port->sata_ctl = port->sata_ctl & (0b1111);
}

int ahci::device::wait_command(size_t slot) {
    while (port->cmd_issue & (1 << slot)) {
        asm volatile("pause");
    }

    if (port->tfd & (1 << 0)) {
        return 1;
    }

    return 0;
}

void ahci::device::reset_engine() {
    port->cas &= ahci::HBA_PxCMD_ST;
    while (port->cas & ahci::HBA_PxCMD_CR) asm volatile("pause");

    if (port->tfd & (1 << 7) || port->tfd & (1 << 3)) {
        comreset();
    }

    port->cas |= (1 << 0);
    while (!(port->cas & ahci::HBA_PxCMD_CR)) asm volatile("pause");
}

void ahci::device::stop_command() {
    port->cas &= ~ahci::HBA_PxCMD_ST;
    port->cas &= ~ahci::HBA_PxCMD_FRE;

    while ((port->cas & ahci::HBA_PxCMD_CR) || (port->cas & ahci::HBA_PxCMD_FR));
}

void ahci::device::start_command() {
    while (port->cas & ahci::HBA_PxCMD_CR);

    port->cas |= ahci::HBA_PxCMD_ST;
    port->cas |= ahci::HBA_PxCMD_FRE;
}

void ahci::device::fill_prdt(void *mem, ahci::prdt_entry *prdt) {
    prdt->base = (uint64_t) data_dma->map(mem) & 0xFFFFFFFF;

    uint8_t is_long = (uint8_t) ((bar->cap & (1 << 31)) >> 31);
    if (is_long) {
        prdt->base_hi = (uint32_t) (data_dma->map(mem) >> 32);
    } else {
        prdt->base_hi = 0;
    }
}

void ahci::device::setup() {
    stop_command();
    uint64_t command_base = (uint64_t) data_dma->paddr();
    uint64_t fis_base = command_base + (32 * 32);

    if (bar->cap & (1 << 31)) {
        port->commands_addr = command_base & 0xFFFFFFFF;
        port->commands_addr_upper = (command_base >> 32) & 0xFFFFFFFF;

        port->fis_addr = fis_base & 0xFFFFFFFF;
        port->fis_upper = (fis_base >> 32) & 0xFFFFFFFF;
    } else {
        port->commands_addr = command_base & 0xFFFFFFFF;
        port->commands_addr_upper = 0;

        port->fis_addr = fis_base & 0xFFFFFFFF;
        port->fis_upper = 0;
    }

    start_command();
    if (port->sig == SIG_ATA) {
        kmsg(logger, "Found ATA Device");
        identify_sata();
    }
}

void ahci::device::identify_sata() {
    ahci::command_slot slot = get_command(get_fis_size(1));
    ahci::command_header *header = get_header(slot.idx);

    if (slot.idx == -1) {
        kmsg(logger, "Could not find ATA slot");
        return;
    }

    header->prdt_cnt = 1;
    header->write = 0;
    header->cmd_fis_len = 5;

    fis::reg_h2d *fis_area = (fis::reg_h2d *) slot.entry->cfis;
    fis_area->fis_type = FIS_REG_H2D;
    fis_area->cmd_ctl = 1;
    fis_area->command = ATA_COMMAND_IDENTIFY;
    fis_area->dev = 0xA0;
    fis_area->control = ATA_DEVICE_DRQ;

    auto ident_dma = bus->get_dma(memory::page_size);
    uint8_t *id_mem = (uint8_t *) ident_dma->vaddr();

    ahci::prdt_entry *prdt = (ahci::prdt_entry *) &(slot.entry->prdts[0]);
    fill_prdt(id_mem, prdt);
    prdt->bytes = get_prdt_bytes(512);

    await_ready();
    issue_command(slot.idx);
    int err = wait_command(slot.idx);

    // TODO: device initialization error, somehow
    if (err) {
        uint8_t error = (uint8_t) (port->tfd >> 8);
        kmsg(logger, "Identify Error: ", error);

        reset_engine();
        return;
    }

    if (port->tfd & (1 << 0)) {
        uint8_t error = (uint8_t) (port->tfd >> 8);
        kmsg(logger, "Identify Error: ", error);

        reset_engine();
        return;
    }

    uint16_t valid = *(uint16_t *) (&id_mem[212]);
    if (!(valid & (1<<15)) && (valid & (1<<14)) && (valid & (1<<12))) {
        sector_size = *(uint32_t *) (&id_mem[234]);
    } else {
        sector_size = 512;
    }

    sectors = *(uint64_t *) (&id_mem[200]);
    if (!sectors) {
        sectors = (uint64_t) (*(uint32_t *) (&id_mem[120]));
    }

    lba48 = (id_mem[167] & (1 << 2)) && (id_mem[173] & (1 << 2));

    block_size = sector_size;
    blocks = sectors;

    kmsg(logger, "Identify succeeded");
}

ahci::command_slot ahci::device::issue_read_write(void *buf, uint16_t count, size_t offset, bool rw) {
    uint64_t prdt_count = ((count * sector_size) + 0x400000 - 1) / 0x400000;
    ahci::command_slot slot = get_command(get_fis_size(prdt_count + 1));
    ahci::command_header *header = get_header(slot.idx);

    if (slot.idx == -1) {
        kmsg(logger, "No free command slots.");
        return slot;
    }

    header->prdt_cnt = prdt_count;
    header->write = rw;
    header->cmd_fis_len = 5;

    fis::reg_h2d *fis_area = (fis::reg_h2d *) slot.entry->cfis;
    fis_area->fis_type = FIS_REG_H2D;
    fis_area->cmd_ctl = 1;
    fis_area->command = rw ? (lba48 ? ATA_COMMAND_DMA_EXT_WRITE : ATA_COMMAND_DMA_WRITE) :
                        (lba48 ? ATA_COMMAND_DMA_EXT_READ : ATA_COMMAND_DMA_READ);
    fis_area->dev = 0xA0 | (1 << 6);
    fis_area->control = ATA_DEVICE_DRQ;

    fis_area->lba0 = (offset >> 0) & 0xFF;
    fis_area->lba1 = (offset >> 8) & 0xFF;
    fis_area->lba2 = (offset >> 16) & 0xFF;

    if (lba48) {
        fis_area->lba3 = (offset >> 24) & 0xFF;
        fis_area->lba4 = (offset >> 32) & 0xFF;
        fis_area->lba5 = (offset >> 40) & 0xFF;
    }

    if (count != 0xFFFF) {
        fis_area->countl = (count >> 0) & 0xFF;
        fis_area->counth = (count >> 8) & 0xFF;
    } else {
        fis_area->countl = 0;
        fis_area->counth = 0;
    }

    char *data = (char *) buf;
    uint64_t rest = count * sector_size;
    for (uint64_t i = 0; i < prdt_count; i++){
        ahci::prdt_entry *prdt = (ahci::prdt_entry *) &(slot.entry->prdts[i]);
        fill_prdt(data + (i * 0x400000), prdt);

        if (rest >= 0x400000) {
            prdt->bytes = get_prdt_bytes(0x400000);
            rest -= 0x400000;
        } else {
            prdt->bytes = get_prdt_bytes(rest);
            rest = 0;
        }
    }

    return slot;
}

ssize_t ahci::device::do_sector_io(void *buf, uint16_t count, size_t offset, bool rw) {
    auto slot = issue_read_write(buf, count, offset, false);
    await_ready();

    issue_command(slot.idx);
    wait_command(slot.idx);

    if (port->tfd & (1 << 0)) {
        uint8_t error = (uint8_t) (port->tfd >> 8);
        kmsg(logger, "Transfer Error: ", error);

        reset_engine();
        return -1;
    }

    return 0;
}

ssize_t ahci::device::read(void *buf, size_t count, size_t offset) {
    // offset is a multiple of sector_size
    // count is a multiple of sector_size

    uint64_t sector_start = offset / sector_size;
    uint64_t sector_count = count / sector_size;

    if (sector_count > 0xFFFF) {
        return -EIO;
    } else if (sector_count == 0) {
        return -EIO;
    }

    util::lock_guard guard{lock};

    auto err = do_sector_io(buf, sector_count, sector_start, false);
    if (err) {
        return -EIO;
    }

    return count;
}

ssize_t ahci::device::write(void *buf, size_t count, size_t offset) {
    // offset is a multiple of sector_size
    // count is a multiple of sector_size

    uint64_t sector_start = offset / sector_size;
    uint64_t sector_count = count / sector_size;

    if (sector_count > 0xFFFF) {
        return -EIO;
    } else if (sector_count == 0) {
        return -EIO;
    }

    util::lock_guard guard{lock};

    auto err = do_sector_io(buf, sector_count, sector_start, true);
    if (err) {
        return -EIO;        
    }

    return count;
}