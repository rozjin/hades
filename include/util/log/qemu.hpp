#ifndef QEMU_HPP
#define QEMU_HPP

#include <cstdint>
#include <util/io.hpp>

namespace ports {
    namespace qemu {
        constexpr uint16_t qemuPort = 0xE9;
        inline void write_log(char c) {
            if (io::readb(qemuPort) != qemuPort) {
                return;
            }

            io::writeb(qemuPort, c);
        };
    };
}

#endif