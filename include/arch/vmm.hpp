#ifndef ARCH_VMM_HPP
#define ARCH_VMM_HPP

#include <arch/x86/types.hpp>

namespace vmm {
    enum class map_flags: uint64_t {
        PRESENT = 1,
        WRITE = 2,
        USER = 4,

        FIXED = 8,
        COW = 16,
        SHARED = 32,
        FILE = 64,

        EXEC = 128,

        FILL_NOW = 256
    };

    inline constexpr map_flags
    operator&(map_flags x, map_flags y) {
        return static_cast<map_flags>
        (static_cast<uint64_t>(x) & static_cast<uint64_t>(y));
    }

    inline constexpr map_flags
    operator|(map_flags x, map_flags y) {
        return static_cast<map_flags>
        (static_cast<uint64_t>(x) | static_cast<uint64_t>(y));
    }

    inline constexpr map_flags
    operator^(map_flags x, map_flags y) {
        return static_cast<map_flags>
        (static_cast<uint64_t>(x) ^ static_cast<uint64_t>(y));
    }

    inline constexpr map_flags
    operator~(map_flags x) {
        return static_cast<map_flags>(~static_cast<uint64_t>(x));
    }

    inline map_flags &
    operator&=(map_flags & x, map_flags y) {
        x = x & y;
        return x;
    }

    inline map_flags &
    operator|=(map_flags & x, map_flags y) {
        x = x | y;
        return x;
    }

    inline map_flags &
    operator^=(map_flags & x, map_flags y) {
        x = x ^ y;
        return x;
    }    

    constexpr size_t limit_4g = 4294967296;

    vmm_ctx_map new_pagemap();
    void copy_boot_map(vmm_ctx_map map);

    void load_pagemap(vmm_ctx_map map);

    void *map_single_4k(void *phys, void *virt, page_flags flags, vmm_ctx_map map);
    void *map_single_2m(void *phys, void *virt, page_flags flags, vmm_ctx_map map);

    void *resolve_single_4k(void *virt, vmm_ctx_map map);
    void *resolve_single_2m(void *virt, vmm_ctx_map map);

    void *unmap_single_4k(void *virt, vmm_ctx_map map);
    void *unmap_single_2m(void *virt, vmm_ctx_map map);

    void *perms_single_4k(void *virt, page_flags flags, vmm_ctx_map map);
    void *perms_single_2m(void *virt, page_flags flags, vmm_ctx_map map);

    void *remap_single_4k(void *phys, void *virt, page_flags flags, vmm_ctx_map map);
    void *remap_single_2m(void *phys, void *virt, page_flags flags, vmm_ctx_map map);
    
    void shootdown(uint64_t addr);
    void shootdown(void *addr);

    page_flags to_arch(map_flags flags);
    map_flags from_arch(page_flags flags);
}

#endif