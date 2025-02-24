#ifndef PCI_HPP
#define PCI_HPP

#include "fs/dev.hpp"
#include "mm/pmm.hpp"
#include "util/types.hpp"
#include <cstddef>
#include <cstdint>
#include <frg/vector.hpp>
#include <mm/mm.hpp>

namespace pci {
    static constexpr auto PCI_HAS_CAPS = 0x4;
    static constexpr auto PCI_CAPS     = 0x34;
    static constexpr auto MSI_OPT      = 0x2;
    static constexpr auto MSI_ADDR_LOW = 0x4;
    static constexpr auto MSI_DATA_32  = 0x8;
    static constexpr auto MSI_DATA_64  = 0xC;
    static constexpr auto MSI_64BIT_SUPPORTED = (1 << 7);

    static constexpr size_t MAX_FUNCTION = 8;
    static constexpr size_t MAX_DEVICE   = 32;
    static constexpr size_t MAX_BUS      = 256;

    struct bar {
        size_t base;
        size_t size;
        bool is_mmio;
        bool is_prefetchable;
        bool valid;
    };

    class device {
        private:
            uint8_t
                bus,
                slot,
                clazz,
                subclass,
                prog_if,
                func;

            uint16_t
                devize,
                vendor_id;
            bool is_multifunc;

        public:
            device(uint8_t bus, uint8_t slot, uint8_t func, uint8_t clazz, uint8_t subclass,
                                uint8_t prog_if,
                                uint16_t device, uint16_t vendor_id,
                                bool is_multifunc) {
                this->bus      = bus;
                this->slot     = slot;
                this->func     = func;
                this->clazz    = clazz;
                this->subclass = subclass;
                this->prog_if  = prog_if;

                this->devize = device;
                this->vendor_id = vendor_id;
                this->is_multifunc = is_multifunc;
            }

            uint8_t get_bus(),
                    get_slot(),
                    get_clazz(),
                    get_subclass(),
                    get_prog_if(),
                    get_func();
                    
            uint16_t
                    get_vendor(),
                    get_device();

            uint8_t  readb(uint32_t offset);
            void     writeb(uint32_t offset, uint8_t value);
            uint16_t readw(uint32_t offset);
            void     writew(uint32_t offset, uint16_t value);
            uint32_t readd(uint32_t offset);
            void     writed(uint32_t offset, uint32_t value);
            int      read_bar(size_t index, bar& bar_out);
            int      register_msi(uint8_t vector, uint8_t lapic_id);

            void     enable_busmastering();
            void     enable_mmio();
            uint8_t  read_pin();
    };

    union [[gnu::packed]] msi_address {
        struct {
            uint32_t resv0 : 2;
            uint32_t dest_mode : 1;
            uint32_t redir_hint : 1;
            uint32_t resv1 : 8;
            uint32_t dest_id : 8;
            uint32_t base_addr : 12;
        };
        uint32_t raw;
    };

    union [[gnu::packed]] msi_data {
        struct {
            uint32_t vector : 8;
            uint32_t delv_mode : 3;
            uint32_t resv0 : 3;
            uint32_t level : 1;
            uint32_t trig_mode : 1;
            uint32_t resv1 : 16;
        };
        uint32_t raw;
    };
    
    uint32_t read_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg);
    void write_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg, uint32_t data);

    uint16_t read_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg);
    void write_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg, uint16_t data);

    uint16_t read_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg);
    void write_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg, uint8_t data);
    const char *to_string(uint8_t clazz, uint8_t subclass, uint8_t prog_if);

    struct attach_args {
        uint8_t bus = 0;
        uint8_t slot = 0;
        uint8_t func = 0;
    };
};

struct pci_dma: vfs::devfs::bus_dma {
    pci_dma(bus_size_t len): bus_dma(len) { addr = (bus_addr_t) pmm::phys(util::ceil(len, memory::page_size)); }
    ~pci_dma() { if (addr) { pmm::free((void *) addr); } }

    bus_addr_t vaddr() override;
    bus_addr_t paddr() override;

    bus_addr_t map(void *vaddr) override;
    void unmap(bus_addr_t paddr) override;
};

struct pci_space: vfs::devfs::bus_space {
    pci_space(bus_addr_t addr, bus_size_t size, bool linear)
    : vfs::devfs::bus_space(addr, size, linear) {}

    bus_handle_t map(bus_addr_t offset, bus_size_t size) override;
    void unmap(bus_handle_t handle) override;
    void *vaddr(bus_handle_t handle) override;

    uint8_t readb(bus_handle_t handle, bus_size_t offset) override;
    uint16_t readw(bus_handle_t handle, bus_size_t offset) override;
    uint32_t readd(bus_handle_t handle, bus_size_t offset) override;
    uint64_t readq(bus_handle_t handle, bus_size_t offset) override;

    void writeb(bus_handle_t handle, bus_size_t offset, uint8_t val) override;
    void writew(bus_handle_t handle, bus_size_t offset, uint16_t val) override;
    void writed(bus_handle_t handle, bus_size_t offset, uint32_t val) override;
    void writeq(bus_handle_t handle, bus_size_t offset, uint64_t val) override;
    
    void read_regionb(bus_handle_t handle, bus_size_t offset, uint8_t *data, size_t count) override;
    void read_regionw(bus_handle_t handle, bus_size_t offset, uint16_t *data, size_t count) override;
    void read_regiond(bus_handle_t handle, bus_size_t offset, uint32_t *data, size_t count) override;
    void read_regionq(bus_handle_t handle, bus_size_t offset, uint64_t *data, size_t count) override;

    void write_regionb(bus_handle_t handle, bus_size_t offset, uint8_t *data, size_t count) override;
    void write_regionw(bus_handle_t handle, bus_size_t offset, uint16_t *data, size_t count) override;
    void write_regiond(bus_handle_t handle, bus_size_t offset, uint32_t *data, size_t count) override;
    void write_regionq(bus_handle_t handle, bus_size_t offset, uint64_t *data, size_t count) override;

    void set_regionb(bus_handle_t handle, bus_size_t offset, uint8_t val, size_t count) override;
    void set_regionw(bus_handle_t handle, bus_size_t offset, uint16_t val, size_t count) override;
    void set_regiond(bus_handle_t handle, bus_size_t offset, uint32_t val, size_t count) override;
    void set_regionq(bus_handle_t handle, bus_size_t offset, uint64_t val, size_t count) override;

    void read_multib(bus_handle_t handle, bus_size_t offset, uint8_t *data, size_t count) override;
    void read_multiw(bus_handle_t handle, bus_size_t offset, uint16_t *data, size_t count) override;
    void read_multid(bus_handle_t handle, bus_size_t offset, uint32_t *data, size_t count) override;
    void read_multiq(bus_handle_t handle, bus_size_t offset, uint64_t *data, size_t count) override;

    void write_multib(bus_handle_t handle, bus_size_t offset, uint8_t *data, size_t count) override;
    void write_multiw(bus_handle_t handle, bus_size_t offset, uint16_t *data, size_t count) override;
    void write_multid(bus_handle_t handle, bus_size_t offset, uint32_t *data, size_t count) override;
    void write_multiq(bus_handle_t handle, bus_size_t offset, uint64_t *data, size_t count) override;
};

constexpr size_t PCI_MAJOR = 0xF;
struct pcibus: vfs::devfs::busdev {
    private:
        uint8_t bus;

        frg::vector<pci::device, memory::mm::heap_allocator> devices;

        pci::device *get_device(uint8_t clazz, uint8_t subclazz, uint8_t prog_if);
        pci::device *get_device(uint16_t vendor, uint16_t device);
    public:
        void enumerate() override;
        void attach(ssize_t major, void *aux) override;

        unique_ptr<vfs::devfs::bus_dma> get_dma(size_t size) override;

        pcibus(vfs::devfs::busdev *bus,
            uint8_t pci_bus = 0): vfs::devfs::busdev(bus, PCI_MAJOR, -1, nullptr), bus(pci_bus), devices() {};
};


#endif