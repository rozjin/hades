#ifndef PORTS_HPP
#define PORTS_HPP

#include <cstdint>

namespace io {
    void writeb(uint16_t port, uint8_t val);
    void writew(uint16_t port, uint16_t val);
    void writed(uint16_t port, uint32_t val);

    uint8_t  readb(uint16_t port);
    uint16_t readw(uint16_t port);
    uint32_t readd(uint16_t port);

    void wait();

    namespace mmio {
        template<typename S>
        void write(uint64_t addr, S val) {
            (*((volatile S*) addr)) = val;
        }

        template<typename S>
        S read(uint64_t addr) {
            return *((volatile S*) (addr));
        }
    };
};

#endif