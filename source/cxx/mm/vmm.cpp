#include <arch/vmm.hpp>
#include <arch/x86/types.hpp>
#include <cstddef>
#include <cstdint>
#include <frg/allocation.hpp>
#include <mm/common.hpp>
#include <mm/mm.hpp>
#include <mm/pmm.hpp>
#include <mm/vmm.hpp>
#include <util/log/log.hpp>
#include <util/io.hpp>

int64_t *refs = nullptr;
uint64_t refs_len = 0;
vmm::vmm_ctx *vmm::boot = nullptr;
util::lock vmm_lock{};

void vmm::ref_page(uint64_t addr) {
    uint64_t idx = addr / memory::page_size;
    if (refs[idx] == -1) {
        refs[idx] = 1;
    }

    refs[idx]++;
}

void vmm::ref_page(void *addr) {
    vmm::ref_page((uint64_t) addr);
}

void vmm::unref_page(uint64_t addr) {
    uint64_t idx = addr / memory::page_size;
    if (refs[idx] <= -1) {
        return;
    }

    if (--refs[idx] <= 0) {
        refs[idx] = -1;
        memory::pmm::free(memory::add_virt((void *) addr));
    }
}

void vmm::unref_page(void *addr) {
    unref_page((uint64_t) addr);
}

static log::subsystem logger = log::make_subsystem("VM");
// API Functions
void vmm::init() {
    refs_len = memory::pmm::nr_pages * sizeof(int64_t);
    refs = (int64_t *) kmalloc(refs_len);
    for (size_t i = 0; i < memory::pmm::nr_pages; i++) {
        refs[i] = -1;
    }

    boot = frg::construct<vmm_ctx>(memory::mm::heap);
    boot->page_map = new_pagemap();
    boot->create_hole((void *) 0x100000, 0x7ffffff00000);

    for (size_t i = 0; i < 8; i++) {
        void *phys = (void *) (i * memory::page_large);
        void *addr = (void *) (memory::x86::kernelBase + (i * memory::page_large));
        map_single_2m(phys, addr, page_flags::PRESENT, boot->page_map);
    }

    if (memory::pmm::nr_pages * memory::page_size < limit_4g) {
        for (size_t i = 0; i < limit_4g / memory::page_large; i++) {
            void *phys = (void *) (i * memory::page_large);
            void *addr = (void *) (memory::x86::virtualBase + (i * memory::page_large));
            map_single_2m(phys, addr, page_flags::PRESENT | page_flags::WRITE, boot->page_map);
        }
    } else {
        for (size_t i = 0; i < ((memory::pmm::nr_pages) * memory::page_size) / memory::page_large; i++) {
            void *phys = (void *) (i * memory::page_large);
            void *addr = (void *) (memory::x86::virtualBase + (i * memory::page_large));
            map_single_2m(phys, addr, page_flags::PRESENT | page_flags::WRITE, boot->page_map);
        }
    }

    boot->swap_in();
    kmsg(logger, "Initialized");
}

vmm::vmm_ctx *vmm::create() {
    auto new_ctx = frg::construct<vmm_ctx>(memory::mm::heap);

    new_ctx->page_map = new_pagemap();
    new_ctx->create_hole((void *) 0x100000, 0x7ffffff00000);   
    copy_boot_map(new_ctx->page_map);

    return new_ctx;
}

void vmm::destroy(vmm_ctx *ctx) {
    boot->swap_in();

    ctx->~vmm_ctx();
    frg::destruct(memory::mm::heap, ctx);
}