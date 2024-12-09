#include "arch/x86/smp.hpp"
#include "mm/common.hpp"
#include "mm/pmm.hpp"
#include <cstdint>
#include <mm/vmm.hpp>
#include <arch/x86/types.hpp>
#include <arch/vmm.hpp>

namespace vmm {
    vmm_ctx_map new_pagemap() {
        vmm_ctx_map map = (uint64_t *) memory::pmm::alloc(1);
        return map;
    }

    void load_pagemap(vmm_ctx_map map) {
        x86::swap_cr3(memory::remove_virt(map));
    }

    void copy_boot_map(vmm_ctx_map map) {
        for (size_t i = (x86::entries_per_table / 2); i < x86::entries_per_table; i++) {
            map[i] = boot->get_page_map()[i];
        }
    }

    void *resolve_single_4k(void *virt, vmm_ctx_map map) {
        uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
        uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
        uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;
        uint64_t p1idx = ((uint64_t) virt >> 12) & 0x1FF;

        uint64_t *p4 = map;
        uint64_t* p3 = nullptr;
        uint64_t* p2 = nullptr;
        uint64_t* p1 = nullptr;
        uint64_t *phys = nullptr;

        if (p4[p4idx] & (uint64_t) page_flags::PRESENT) {
            p3 = (uint64_t *) memory::add_virt(p4[p4idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p3[p3idx] & (uint64_t) page_flags::PRESENT) {
            p2 = (uint64_t *) memory::add_virt(p3[p3idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p2[p2idx] & (uint64_t) page_flags::PRESENT) {
            p1 = (uint64_t *) memory::add_virt(p2[p2idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p1[p1idx] & (uint64_t) page_flags::PRESENT) {
            phys = (uint64_t *) (p1[p1idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        return phys;
    }

    void *resolve_single_2m(void *virt, vmm_ctx_map map) {
        uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
        uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
        uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;

        uint64_t *p4 = map;
        uint64_t* p3 = nullptr;
        uint64_t* p2 = nullptr;
        uint64_t *phys = nullptr;

        if (p4[p4idx] & (uint64_t) page_flags::PRESENT) {
            p3 = (uint64_t *) memory::add_virt(p4[p4idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p3[p3idx] & (uint64_t) page_flags::PRESENT) {
            p2 = (uint64_t *) memory::add_virt(p3[p3idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p2[p2idx] & (uint64_t) page_flags::PRESENT) {
            phys = (uint64_t *) (p2[p2idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        return phys;
    }

    void *map_single_4k(void *phys, void *virt, page_flags flags, vmm_ctx_map map) {
        uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
        uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
        uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;
        uint64_t p1idx = ((uint64_t) virt >> 12) & 0x1FF;

        uint64_t *p4 = map;
        uint64_t* p3 = nullptr;
        uint64_t* p2 = nullptr;
        uint64_t* p1 = nullptr;

        if (p4[p4idx] & (uint64_t) page_flags::PRESENT) {
            p3 = (uint64_t *) memory::add_virt(p4[p4idx] & x86::addr_mask);
        } else {
            p3 = (uint64_t *) memory::pmm::phys(1);
            p4[p4idx] = (uint64_t) p3 | (uint64_t) page_flags::PRESENT | (uint64_t) page_flags::USER | (uint64_t) page_flags::WRITE;
            p3 = (uint64_t *) memory::add_virt(p3);
        }

        if (p3[p3idx] & (uint64_t) page_flags::PRESENT) {
            p2 = (uint64_t *) memory::add_virt(p3[p3idx] & x86::addr_mask);
        } else {
            p2 = (uint64_t *) memory::pmm::phys(1);
            p3[p3idx] = (uint64_t) p2 | (uint64_t) page_flags::PRESENT | (uint64_t) page_flags::USER | (uint64_t) page_flags::WRITE;
            p2 = (uint64_t *) memory::add_virt(p2);
        }

        if (p2[p2idx] & (uint64_t) page_flags::PRESENT) {
            p1 = (uint64_t *) memory::add_virt(p2[p2idx] & x86::addr_mask);
        } else {
            p1 = (uint64_t *) memory::pmm::phys(1);
            p2[p2idx] = (uint64_t) p1 | (uint64_t) page_flags::PRESENT | (uint64_t) page_flags::USER | (uint64_t) page_flags::WRITE;
            p1 = (uint64_t *) memory::add_virt(p1);
        }

        p1[p1idx] = ((uint64_t) phys) | (uint64_t) flags;

        return virt;
    }

    void *map_single_2m(void *phys, void *virt, page_flags flags, vmm_ctx_map map) {
        uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
        uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
        uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;

        uint64_t *p4 = map;
        uint64_t* p3 = nullptr;
        uint64_t* p2 = nullptr;

        if (p4[p4idx] & (uint64_t) page_flags::PRESENT) {
            p3 = (uint64_t *) memory::add_virt(p4[p4idx] & x86::addr_mask);
        } else {
            p3 = (uint64_t *) memory::pmm::phys(1);
            p4[p4idx] = (uint64_t) p3 | (uint64_t) page_flags::PRESENT | (uint64_t) page_flags::USER | (uint64_t) page_flags::WRITE;
            p3 = (uint64_t *) memory::add_virt(p3);
        }

        if (p3[p3idx] & (uint64_t) page_flags::PRESENT) {
            p2 = (uint64_t *) memory::add_virt(p3[p3idx] & x86::addr_mask);
        } else {
            p2 = (uint64_t *) memory::pmm::phys(1);
            p3[p3idx] = (uint64_t) p2 | (uint64_t) page_flags::PRESENT | (uint64_t) page_flags::USER | (uint64_t) page_flags::WRITE;
            p2 = (uint64_t *) memory::add_virt(p2);
        }

        p2[p2idx] = ((uint64_t) phys) | (uint64_t) flags | (uint64_t) page_flags::LARGE;

        return virt;
    }

    void *unmap_single_4k(void *virt, vmm_ctx_map map) {
        uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
        uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
        uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;
        uint64_t p1idx = ((uint64_t) virt >> 12) & 0x1FF;

        uint64_t *p4 = map;
        uint64_t* p3 = nullptr;
        uint64_t* p2 = nullptr;
        uint64_t* p1 = nullptr;

        if (p4[p4idx] & (uint64_t) page_flags::PRESENT) {
            p3 = (uint64_t *) memory::add_virt(p4[p4idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p3[p3idx] & (uint64_t) page_flags::PRESENT) {
            p2 = (uint64_t *) memory::add_virt(p3[p3idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p2[p2idx] & (uint64_t) page_flags::PRESENT) {
            p1 = (uint64_t *) memory::add_virt(p2[p2idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        p1[p1idx] = 0;

        return virt;
    }

    void *unmap_single_2m(void *virt, vmm_ctx_map map) {
        uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
        uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
        uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;

        uint64_t *p4 = map;
        uint64_t* p3 = nullptr;
        uint64_t* p2 = nullptr;

        if (p4[p4idx] & (uint64_t) page_flags::PRESENT) {
            p3 = (uint64_t *) memory::add_virt(p4[p4idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p3[p3idx] & (uint64_t) page_flags::PRESENT) {
            p2 = (uint64_t *) memory::add_virt(p3[p3idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        p2[p2idx] = 0;

        return virt;
    }

    void *perms_single_4k(void *virt, page_flags flags, vmm_ctx_map map) {
        uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
        uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
        uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;
        uint64_t p1idx = ((uint64_t) virt >> 12) & 0x1FF;

        uint64_t *p4 = map;
        uint64_t* p3 = nullptr;
        uint64_t* p2 = nullptr;
        uint64_t* p1 = nullptr;

        if (p4[p4idx] & (uint64_t) page_flags::PRESENT) {
            p3 = (uint64_t *) memory::add_virt(p4[p4idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p3[p3idx] & (uint64_t) page_flags::PRESENT) {
            p2 = (uint64_t *) memory::add_virt(p3[p3idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p2[p2idx] & (uint64_t) page_flags::PRESENT) {
            p1 = (uint64_t *) memory::add_virt(p2[p2idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        uint64_t phys = (uint64_t) p1[p1idx] & x86::addr_mask;
        p1[p1idx] = phys | (uint64_t) flags;

        return virt;
    }

    void *perms_single_2m(void *virt, page_flags flags, vmm_ctx_map map) {
        uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
        uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
        uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;

        uint64_t *p4 = map;
        uint64_t* p3 = nullptr;
        uint64_t* p2 = nullptr;


        if (p4[p4idx] & (uint64_t) page_flags::PRESENT) {
            p3 = (uint64_t *) memory::add_virt(p4[p4idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p3[p3idx] & (uint64_t) page_flags::PRESENT) {
            p2 = (uint64_t *) memory::add_virt(p3[p3idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        uint64_t phys = (uint64_t) p2[p2idx] & x86::addr_mask;
        p2[p2idx] = phys | (uint64_t)  flags | (uint64_t) page_flags::LARGE;

        return virt;
    }

    void *remap_single_4k(void *virt, void *phys, page_flags flags, vmm_ctx_map map) {
        uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
        uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
        uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;
        uint64_t p1idx = ((uint64_t) virt >> 12) & 0x1FF;

        uint64_t *p4 = map;
        uint64_t* p3 = nullptr;
        uint64_t* p2 = nullptr;
        uint64_t* p1 = nullptr;

        if (p4[p4idx] & (uint64_t) page_flags::PRESENT) {
            p3 = (uint64_t *) memory::add_virt(p4[p4idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p3[p3idx] & (uint64_t) page_flags::PRESENT) {
            p2 = (uint64_t *) memory::add_virt(p3[p3idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p2[p2idx] & (uint64_t) page_flags::PRESENT) {
            p1 = (uint64_t *) memory::add_virt(p2[p2idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        p1[p1idx] = ((uint64_t) phys) | (uint64_t) flags;

        return virt;
    }

    void *remap_single_2m(void *virt, void *phys, page_flags flags, vmm_ctx_map map) {
        uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
        uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
        uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;

        uint64_t *p4 = map;
        uint64_t* p3 = nullptr;
        uint64_t* p2 = nullptr;


        if (p4[p4idx] & (uint64_t) page_flags::PRESENT) {
            p3 = (uint64_t *) memory::add_virt(p4[p4idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        if (p3[p3idx] & (uint64_t) page_flags::PRESENT) {
            p2 = (uint64_t *) memory::add_virt(p3[p3idx] & x86::addr_mask);
        } else {
            return nullptr;
        }

        p2[p2idx] = ((uint64_t) phys) | (uint64_t) flags | (uint64_t) page_flags::LARGE;

        return virt;
    }


    vmm::page_flags to_arch(map_flags flags) {
        page_flags out_flags {};

        if ((uint64_t) (flags & map_flags::PRESENT))
            out_flags |= page_flags::PRESENT;

        if ((uint64_t) (flags & map_flags::WRITE))
            out_flags |= page_flags::WRITE;

        if ((uint64_t) (flags & map_flags::USER))
            out_flags |= page_flags::USER;

        if ((uint64_t) (flags & map_flags::COW))
            out_flags |= page_flags::COW;

        if ((uint64_t) (flags & map_flags::FIXED))
            out_flags |= page_flags::FIXED;

        if ((uint64_t) (flags & map_flags::SHARED))
            out_flags |= page_flags::SHARED;

        if ((uint64_t) (flags & map_flags::FILE))
            out_flags |= page_flags::FILE;

        if ((uint64_t) (flags & map_flags::EXEC))
            out_flags |= page_flags::EXEC;

        return out_flags;
    }

    void shootdown(uint64_t addr) {
        x86::invlpg(addr);
    }

    void shootdown(void *addr) {
        x86::invlpg((uint64_t) addr);
    }
}

namespace x86 {
    bool handle_pf(arch::irq_regs *r) {
        auto task = x86::get_thread();
        auto ctx = task->mem_ctx;

        uint64_t faulting_addr;
        asm volatile("mov %%cr2, %0": "=a"(faulting_addr));

        uint64_t faulting_page = faulting_addr & (~0xFFF);

        auto mapping = ctx->get_mapping((void *) faulting_page);
        if (mapping == nullptr) {
            // fake news
            return false;
        }

        if (!((uint64_t) (mapping->perms & vmm::page_flags::PRESENT))) {
            void *phys = memory::pmm::phys(1);
            vmm::remap_single_4k((void *) faulting_page, phys, mapping->perms | vmm::page_flags::PRESENT, ctx->page_map);

            invlpg(faulting_page);

            if ((uint64_t) (mapping->perms & vmm::page_flags::FILE)) {
                // TODO: map_filep
            }

            return true;
        }

        if ((uint64_t) (mapping->perms & vmm::page_flags::COW)) {
            void *phys = memory::pmm::phys(1);
            void *prev = vmm::resolve_single_4k((void *) faulting_page, ctx->page_map);
            memcpy(memory::add_virt(phys), memory::add_virt(prev), memory::page_size);

            vmm::unref_page(prev);
            vmm::remap_single_4k((void *) faulting_page, phys, mapping->perms | vmm::page_flags::WRITE, ctx->page_map);

            invlpg(faulting_page);

            return true;
        }

        return false;
    }
}