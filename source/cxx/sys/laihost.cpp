#include <arch/x86/types.hpp>
#include <arch/x86/hpet.hpp>
#include <sys/acpi.hpp>
#include <sys/pci.hpp>
#include <cstddef>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>
#include <util/string.hpp>
#include <mm/mm.hpp>
#include <mm/common.hpp>
#include <lai/host.h>

static log::subsystem logger = log::make_subsystem("LAI");
extern "C" {
    void laihost_log(int level, const char *msg) {
        kmsg(logger, msg);
    }

    __attribute__((noreturn))
    void laihost_panic(const char *msg) {
        panic(msg);
    }

    void *laihost_malloc(size_t size) {
        return kmalloc(size);
    }

    void *laihost_realloc(void *old, size_t newsize, size_t oldsize) {
        if (old == nullptr) return kmalloc(newsize);

        void *ptr = kmalloc(newsize);
        size_t len = newsize > oldsize ? oldsize : newsize;

        memcpy(ptr, old, len);
        kfree(old);

        return ptr;
    }

    void laihost_free(void *ptr, size_t size) {
        kfree(ptr);
    }

    void *laihost_map(size_t address, size_t count) {
        return (void *) (address > memory::x86::virtualBase ? address : address + memory::x86::virtualBase);
    }

    void laihost_unmap(void *ptr, size_t count) {
        return;
    }

    void *laihost_scan(const char *sig, size_t index) {
        return acpi::table(sig, index);
    }

    void laihost_outb(uint16_t port, uint8_t val) {
        io::writeb(port, val);
    }

    void laihost_outw(uint16_t port, uint16_t val) {
        io::writew(port, val);
    }

    void laihost_outd(uint16_t port, uint32_t val) {
        io::writed(port, val);
    }

    uint8_t laihost_inb(uint16_t port) {
        return io::readb(port);
    }

    uint16_t laihost_inw(uint16_t port) {
        return io::readw(port);
    }

    uint32_t laihost_ind(uint16_t port) {
        return io::readd(port);
    }

    void laihost_pci_writeb(uint16_t seg, uint8_t bus, uint8_t slot, uint8_t fun, uint16_t offset, uint8_t val) {
        pci::write_byte(bus, slot, fun, offset, val);
    }

    void laihost_pci_writew(uint16_t seg, uint8_t bus, uint8_t slot, uint8_t fun, uint16_t offset, uint16_t val) {
        pci::write_word(bus, slot, fun, offset, val);
    }

    void laihost_pci_writed(uint16_t seg, uint8_t bus, uint8_t slot, uint8_t fun, uint16_t offset, uint32_t val) {
        pci::write_dword(bus, slot, fun, offset, val);
    }

    uint8_t laihost_pci_readb(uint16_t seg, uint8_t bus, uint8_t slot, uint8_t fun, uint16_t offset) {
        return pci::read_byte(bus, slot, fun, offset);
    }

    uint16_t laihost_pci_readw(uint16_t seg, uint8_t bus, uint8_t slot, uint8_t fun, uint16_t offset) {
        return pci::read_word(bus, slot, fun, offset);
    }

    uint32_t laihost_pci_readd(uint16_t seg, uint8_t bus, uint8_t slot, uint8_t fun, uint16_t offset) {
        return pci::read_dword(bus, slot, fun, offset);
    }

    void laihost_sleep(uint64_t ms) {
        hpet::msleep(ms);
    }

    uint64_t laihost_timer() {
        return x86::tsc();
    }
}