#ifndef KB_HPP
#define KB_HPP

#include <arch/x86/types.hpp>
#include <cstdint>

namespace kb {
    constexpr uint8_t KBD_PS2_DATA = 0x60;
    constexpr uint8_t KBD_PS2_STATUS = 0x64;
    constexpr uint8_t KBD_PS2_COMMAND = 0x64;

    void init();
    void irq_handler(arch::irq_regs *r);
};

#endif