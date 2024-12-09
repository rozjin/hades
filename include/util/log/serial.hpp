#ifndef SERIAL_HPP
#define SERIAL_HPP

#include <cstdint>
#include <util/io.hpp>

namespace ports {
    namespace serial {
        constexpr uint16_t serialPort = 0x3F8;
        static inline bool serialInitialized = false;
        namespace {
            static inline void init() {
                io::writeb(serialPort + 1, 0x00);    // Disable all interrupts
                io::writeb(serialPort + 3, 0x80);    // Enable DLAB (set baud rate divisor)
                io::writeb(serialPort + 0, 0x03);    // Set divisor to 3 (lo byte) 38400 baud
                io::writeb(serialPort + 1, 0x00);    // (hi byte)
                io::writeb(serialPort + 3, 0x03);    // 8 bits, no parity, one stop bit
                io::writeb(serialPort + 2, 0xC7);    // Enable FIFO, clear them, with 14-byte threshold
                io::writeb(serialPort + 4, 0x0B);    // IRQs enabled, RTS/DSR set
                serialInitialized = true;
            }
        };

        inline void write_log(char c) {
            if (!serialInitialized) {
                init();            
            }

            while (!(io::readb(serialPort + 5) & 0x20)) {
                asm volatile("pause");
            }

            io::writeb(serialPort, c);
        };
    };
}

#endif