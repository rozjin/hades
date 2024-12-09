#ifndef COMMON_MM_HPP
#define COMMON_MM_HPP

#include <cstddef>
#include <cstdint>

namespace memory {
    namespace x86 {
        constexpr size_t virtualBase = 0xFFFF800000000000;
        constexpr size_t kernelBase = 0xFFFFFFFF80000000;
    }

    constexpr size_t page_size = 0x1000;
    constexpr size_t page_large = 0x200000;

    inline size_t page_round(size_t size) {
        if ((size % page_size) != 0) {
            return ((size / page_size) * page_size) + page_size;
        }
        
        return ((size / page_size) * page_size);
    }

    template<typename T>
    inline T *page_round(T *address) {
        return (T *) page_round((size_t) address);
    }

    inline size_t page_count(size_t size) {
        return page_round(size) / page_size;
    }

    template<typename T>
    T *add_virt(T *ptr) {
        uint64_t addr = (uint64_t) ptr;
        if (addr > x86::virtualBase) {
            return ptr;
        }

        return (T *) (addr + x86::virtualBase);
    }

    inline uint64_t add_virt(uint64_t ptr) {
        uint64_t addr = (uint64_t) ptr;
        if (addr > x86::virtualBase) {
            return ptr;
        }

        return addr + x86::virtualBase;
    }

    template<typename T>
    T *remove_virt(T *ptr) {
        uint64_t addr = (uint64_t) ptr;
        if (addr >= x86::kernelBase) {
            return (T *) (addr - x86::kernelBase);
        }

        if (addr >= x86::virtualBase) {
            return (T *) (addr - x86::virtualBase);
        }

        return (T *) addr;
    }

    inline uint64_t remove_virt(uint64_t ptr) {
        uint64_t addr = (uint64_t) ptr;
        if (addr >= x86::kernelBase) {
            return (addr - x86::kernelBase);
        }

        if (addr >= x86::virtualBase) {
            return (addr - x86::virtualBase);
        }

        return addr;
    }    
}

#endif