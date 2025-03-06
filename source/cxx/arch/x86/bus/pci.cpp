#include <driver/bus/pci.hpp>

static constexpr auto CONFIG_PORT = 0xCF8;
static constexpr auto DATA_PORT   = 0xCFC;

namespace pci {
    static inline uint32_t get_address(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg) {
        uint32_t lbus  = (uint32_t) bus;
        uint32_t lslot = (uint32_t) slot;
        uint32_t lfunc = (uint32_t) func;
     
        uint32_t address = (uint32_t) ((lbus << 16) | (lslot << 11) |
                  (lfunc << 8) | (reg & 0xFC) | (1ULL << 31));
        return address;
    }
    
    uint32_t read_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg) {
        io::writed(CONFIG_PORT, get_address(bus, slot, func, reg));
        return io::readd(DATA_PORT + (reg & 3));
    }
    
    void write_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg, uint32_t data) {
        io::writed(CONFIG_PORT, get_address(bus, slot, func, reg));
        io::writed(DATA_PORT + (reg & 3), data);
    }
    
    uint16_t read_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg) {
        io::writed(CONFIG_PORT, get_address(bus, slot, func, reg));
        return io::readw(DATA_PORT + (reg & 3));
    }
    
    void write_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg, uint16_t data) {
        io::writed(CONFIG_PORT, get_address(bus, slot, func, reg));
        io::writew(DATA_PORT + (reg & 3), data);
    }
    
    uint16_t read_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg) {
        io::writed(CONFIG_PORT, get_address(bus, slot, func, reg));
        return io::readb(DATA_PORT + (reg & 3));
    }
    
    void write_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t reg, uint8_t data) {
        io::writed(CONFIG_PORT, get_address(bus, slot, func, reg));
        io::writeb(DATA_PORT + (reg & 3), data);
    }    
};