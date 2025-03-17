#ifndef KB_HPP
#define KB_HPP

#include "ipc/wire.hpp"
#include <arch/x86/types.hpp>
#include <fs/dev.hpp>
#include <cstdint>

namespace kb {
    constexpr uint8_t KBD_PS2_DATA = 0x60;
    constexpr uint8_t KBD_PS2_STATUS = 0x64;
    constexpr uint8_t KBD_PS2_COMMAND = 0x64;

    void init();
    void irq_handler(arch::irq_regs *r);

    extern ipc::wire wire;

    struct matcher: vfs::devfs::matcher {
        matcher(): vfs::devfs::matcher(false, false,
            nullptr, nullptr, false, 0) {}
    };
};

#endif