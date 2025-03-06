#ifndef NET_PCI
#define NET_PCI

#include <driver/bus/pci.hpp>
#include <fs/dev.hpp>

namespace pci {
    namespace net {
        constexpr size_t intel_id = 0x8086;
        constexpr size_t emu_id = 0x100E;
        constexpr size_t i217_id = 0x153A;
        constexpr size_t lm_id = 0x10EA;

        struct matcher: vfs::devfs::matcher {
            vfs::devfs::device *match(vfs::devfs::busdev *bus, void *aux) override;
            void attach(vfs::devfs::busdev *bus, vfs::devfs::device *dev, void *aux) override;

            matcher(): vfs::devfs::matcher(false, false,
                nullptr, nullptr, false, 0) {}
        };
    }    
}

#endif