#ifndef AHCI_PCI
#define AHCI_PCI

#include "driver/majtable.hpp"
#include <driver/ahci.hpp>
#include <driver/bus/pci.hpp>
#include <fs/dev.hpp>

namespace pci {
    class ahcibus: public vfs::devfs::busdev {
        private:
            pci::device *device;
    
            frg::vector<::ahci::device *, memory::mm::heap_allocator> devices;
        public:
            struct matcher: vfs::devfs::matcher {
                vfs::devfs::device *match(vfs::devfs::busdev *bus, void *aux) override;
                void attach(vfs::devfs::busdev *bus, vfs::devfs::device *dev, void *aux) override;        

                matcher(): vfs::devfs::matcher(false, false,
                    nullptr, nullptr, false, 0) {}
            };

            void enumerate() override;
            void attach(ssize_t major, void *aux) override;

            shared_ptr<vfs::devfs::bus_dma> get_dma(size_t size) override;

            ahcibus(vfs::devfs::busdev *bus,
                pci::device *device): vfs::devfs::busdev(bus, dtable::majors::AHCIBUS, -1, nullptr), device(device), devices() {};
    };    
}

#endif