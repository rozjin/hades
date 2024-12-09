#include "mm/common.hpp"
#include <arch/vmm.hpp>
#include <arch/x86/types.hpp>
#include <cstddef>
#include <cstdint>
#include <frg/allocation.hpp>
#include <mm/mm.hpp>
#include <mm/pmm.hpp>
#include <mm/vmm.hpp>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>

vmm::vmm_ctx::vmm_ctx(): holes(), page_map(nullptr), lock() {}

// TODO: update destroy for shared pages
// TODO: free up the map
vmm::vmm_ctx::~vmm_ctx() {
    auto mapping = mappings.first();
    while (mapping) {
        auto next = mappings.successor(mapping);
        delete_mapping(mapping);
        frg::destruct(memory::mm::heap, mapping);
        mapping = next;
    }
}

bool vmm::vmm_ctx::hole_aggregator::aggregate(hole *node) {
    size_t size = node->len;

    if (hole_tree::get_left(node) && hole_tree::get_left(node)->largest_hole > size) {
        size = hole_tree::get_left(node)->largest_hole;
    }

    if (hole_tree::get_right(node) && hole_tree::get_right(node)->largest_hole > size) {
        size = hole_tree::get_right(node)->largest_hole;
    }

    if (node->largest_hole == size) {
        return false;
    }

    node->largest_hole = size;
    return true;
};

bool vmm::vmm_ctx::hole_aggregator::check_invariant(hole_tree &tree, hole *node) {
    size_t size = node->len;

    hole *pred = tree.predecessor(node);
    hole *sucs = tree.successor(node);

    if (hole_tree::get_left(node) && hole_tree::get_left(node)->largest_hole > size) {
        size = hole_tree::get_left(node)->largest_hole;
    }

    if (hole_tree::get_right(node) && hole_tree::get_right(node)->largest_hole > size) {
        size = hole_tree::get_left(node)->largest_hole;
    }

    if (node->largest_hole != size) {
        panic("[VMM] Hole state violated with address %lx, pagemap %lx", node->addr, node->map);
        return false;
    }

    if (pred && node->addr < (char *) pred->addr + pred->len) {
        panic("[VMM] Hole state violated with address %lx, pagemap %lx", node->addr, node->map);
        return false;
    }

    if (sucs && sucs->addr < (char *) node->addr + node->len) {
        panic("[VMM] Hole state violated with address %lx, pagemap %lx", node->addr, node->map);
        return false;
    }

    return true;
}

static log::subsystem logger = log::make_subsystem("VM");
void *vmm::vmm_ctx::create_hole(void *addr, uint64_t len) {
    hole *current = this->holes.get_root();
    if (!current) {
        this->holes.insert(frg::construct<hole>(memory::mm::heap, addr, len, (void *) this));
        return addr;
    }

    if (!addr) {
        while (true) {
            if (this->holes.get_left(current) && this->holes.get_left(current)->largest_hole >= len) {
                current = this->holes.get_left(current);
                continue;
            }

            if (current->len >= len) {
                auto addr = current->addr;
                this->split_hole(current, 0, len);
                return addr;
            }

            current = this->holes.get_right(current);
        }
    } else {
        while (true) {
            if (!current) {
                kmsg(logger, "Out of virtual memory");
                return nullptr;
            }

            if (addr < current->addr) {
                current = this->holes.get_left(current);
            } else if (addr >= (char *) current->addr + current->len) {
                current = this->holes.get_right(current);
            } else {
                break;
            }
        }

        if ((char *) addr - (char *) current->addr + len > current->len) {
            kmsg(logger, "Out of virtual memory");
            return nullptr;
        }

        this->split_hole(current, (uint64_t) addr - (uint64_t) current->addr, len);
        return addr;
    }

    return nullptr;
}

uint8_t vmm::vmm_ctx::delete_hole(void *addr, uint64_t len) {
    hole *current = this->holes.get_root();

    hole *pre = nullptr;
    hole *succ = nullptr;

    while (true) {
        if (addr < current->addr) {
            if (this->holes.get_left(current)) {
                current = this->holes.get_left(current);
            } else {
                pre = this->holes.predecessor(current);
                succ = current;
                break;
            }
        } else {
            if (this->holes.get_right(current)) {
                current = this->holes.get_right(current);
            } else {
                pre = current;
                succ = this->holes.successor(current);
                break;
            }
        }
    }

    if (pre && (char *) pre->addr + pre->len == addr && succ && (char *) addr + len == succ->addr) {
        hole *cur = frg::construct<hole>(memory::mm::heap, pre->addr, pre->len + len + succ->len, (void *) this);

        this->holes.remove(pre);
        this->holes.remove(succ);
        this->holes.insert(cur);

        frg::destruct(memory::mm::heap, pre);
        frg::destruct(memory::mm::heap, succ);
    } else if (pre && (char *) pre->addr + pre->len == addr) {
        hole *cur = frg::construct<hole>(memory::mm::heap, pre->addr, pre->len + len, (void *) this);

        this->holes.remove(pre);
        this->holes.insert(cur);

        frg::destruct(memory::mm::heap, pre);
    } else if (succ && (char *) addr + len == succ->addr) {
        hole *cur = frg::construct<hole>(memory::mm::heap, addr, succ->len + len, (void *) this);

        this->holes.remove(succ);
        this->holes.insert(cur);

        frg::destruct(memory::mm::heap, succ);
    } else {
        hole *cur = frg::construct<hole>(memory::mm::heap, addr, len, (void *) this);

        this->holes.insert(cur);
    }
    return 0;
}

void vmm::vmm_ctx::split_hole(hole *node, uint64_t offset, size_t len) {
    this->holes.remove(node);

    if (offset) {
        hole *pred = frg::construct<hole>(memory::mm::heap, node->addr, offset, (void *) this);
        this->holes.insert(pred);
    }

    if ((offset + len) < node->len) {
        hole *sucs = frg::construct<hole>(memory::mm::heap, (char *) node->addr + offset + len, node->len - (offset + len), (void *) this);
        this->holes.insert(sucs);
    }

    frg::destruct(memory::mm::heap, node);
}

void *vmm::vmm_ctx::create_mapping(void *addr, uint64_t len, page_flags flags, bool fill_now) {
    void *dst = this->create_hole(addr, len);

    for (size_t i = 0; i < memory::page_count(len); i++) {
        void *phys = fill_now ? memory::pmm::phys(1) : nullptr;
        if (fill_now) {
            ref_page(phys);
        }
        map_single_4k(phys, (char *) dst + (memory::page_size * i), flags, page_map);
    }

    mapping *node = frg::construct<mapping>(memory::mm::heap, dst, len, page_map);
    if (fill_now) node->free_pages = true;
    node->perms = flags;

    this->mappings.insert(node);
    return dst;
}

void vmm::vmm_ctx::copy_mappings(vmm::vmm_ctx *other) {
    mapping *current = other->mappings.first();
    while (current) {
        mapping *node = frg::construct<mapping>(memory::mm::heap, current->addr, current->len, page_map);

        this->create_hole(current->addr, current->len);
        node->perms = current->perms;
        this->mappings.insert(node);

        for (void *inner = current->addr; inner <= ((char *) current->addr + current->len); inner = (char *) inner + memory::page_size) {
            void *phys = resolve_single_4k(inner, page_map);
            map_single_4k(phys, inner, current->perms, page_map);
        }

        current = other->mappings.successor(current);
    }
}

vmm::vmm_ctx::mapping *vmm::vmm_ctx::get_mapping(void *addr) {
    mapping *current = this->mappings.get_root();
    while (current) {
        if (current->addr <= addr && ((char *) current->addr + current->len) >= addr) {
            return current;
        }

        if (current->addr > addr) {
            current = this->mappings.get_left(current);
        } else {
            current = this->mappings.get_right(current);
        }
    }

    return nullptr;
}

void vmm::vmm_ctx::unmap_pages(void *addr, size_t len, bool free_pages) {
    for (void *inner = addr; inner <= ((char *) addr + len); inner = (char *) inner + memory::page_size) {
        if (free_pages) {
            void *phys = resolve_single_4k(inner, page_map);
            unref_page(phys);
        }

        unmap_single_4k(inner, page_map);
        shootdown(inner);
    }
}

void *vmm::vmm_ctx::delete_mappings(void *addr, uint64_t len) {
    auto [start, end] = split_mappings(addr, len);
    if (!start) {
        return nullptr;
    }

    delete_mappings(addr, len, start, end);
    return addr;
}

frg::tuple<vmm::vmm_ctx::mapping *, vmm::vmm_ctx::mapping *>vmm::vmm_ctx::split_mappings(void *addr, uint64_t len) {
    auto highest = mappings.get_root();
    while (highest) {
        if (auto next = mappings.get_left(highest)) {
            highest = next;
        } else {
            break;
        }
    }

    mapping *start = nullptr;
    mapping *end = nullptr;
    for (auto cur = highest; cur;) {
        if (((char *) cur->addr + cur->len) <= addr) {
            cur = mappings.successor(cur);
            start = cur;
            continue;
        }

        if (cur->addr >= ((char *) addr + len)) {
            if (start) {
                end = cur;
            }
            break;
        }

        if (!start) {
            start = cur;
        }

        auto cur_addr = addr;
        if (cur_addr <= cur->addr) {
            cur_addr = (char *) addr + len;
        }

        if (cur_addr > cur->addr && cur_addr < ((char *) cur->addr + cur->len)) {
            auto left = frg::construct<mapping>(memory::mm::heap, cur->addr, ((char *) cur_addr - (char *) cur->addr), page_map);

            left->free_pages = cur->free_pages;
            left->perms = cur->perms;

            uint64_t offset = ((char *) cur_addr - (char *) cur->addr);
            auto right = frg::construct<mapping>(memory::mm::heap, (char *) cur->addr + offset, cur->len - offset, page_map);

            right->free_pages = cur->free_pages;
            right->perms = cur->perms;

            mappings.remove(cur);
            mappings.insert(left);
            mappings.insert(right);

            frg::destruct(memory::mm::heap, cur);

            if (start == cur) {
                if (addr < cur_addr) {
                    start = left;
                } else {
                    start = right;
                }
            }

            cur = right;
        } else {
            cur = mappings.successor(cur);
        }
    }

    return {start, end};
}

void vmm::vmm_ctx::delete_mappings(void *addr, uint64_t len, mapping *start, mapping *end) {
    for (auto current = start; current != end;) {
        auto mapping = current;
        current = mappings.successor(current);

        if (mapping->addr >= addr && ((char *) mapping->addr + mapping->len) <= ((char *) addr + len)) {
            delete_hole(mapping->addr, mapping->len);
            unmap_pages(mapping->addr, mapping->len, mapping->free_pages);
            mappings.remove(mapping);
            frg::destruct(memory::mm::heap, mapping);
        }
    }
}

void vmm::vmm_ctx::delete_mapping(vmm::vmm_ctx::mapping *node) {
    this->delete_hole(node->addr, node->len);
    unmap_pages(node->addr, node->len, node->free_pages);
    this->mappings.remove(node);
}

void *vmm::vmm_ctx::map(void *virt, uint64_t len, map_flags flags) {
    if (virt && (uint64_t) (flags & map_flags::FIXED)) {
        delete_mappings(virt, len);
    }

    return create_mapping(virt, len, to_arch(flags), ((uint64_t) (flags & map_flags::FILL_NOW)));
}

void *vmm::vmm_ctx::stack(void *virt, uint64_t len, map_flags flags) {
    return (void *) (((uint64_t) map(virt, len, flags)) + len);
}

void *vmm::vmm_ctx::resolve(void *virt) {
    return resolve_single_4k(virt, page_map);
}

void *vmm::vmm_ctx::unmap(void *virt, uint64_t len, bool stack) {
    if (!stack) {
        return delete_mappings(virt, len);
    }

    return delete_mappings((void *) ((uint64_t) virt - len), len);
}

vmm::vmm_ctx *vmm::vmm_ctx::fork() {
    auto new_ctx = frg::construct<vmm_ctx>(memory::mm::heap);

    new_ctx->page_map = new_pagemap();
    new_ctx->create_hole((void *) 0x100000, 0x7ffffff00000);   
    copy_boot_map(new_ctx->page_map);
    
    new_ctx->copy_mappings(this);

    vmm_ctx::mapping *current = new_ctx->mappings.first();

    while (current) {
        if ((uint64_t) (current->perms & page_flags::SHARED))
            continue;
        
        if ((uint64_t) (current->perms & page_flags::FILE))
            continue;

        if ((uint64_t) (current->perms & page_flags::COW)) {
            current->perms &= page_flags::WRITE;

            for (void *addr = current->addr; addr <= (void *) ((char *) current->addr + current->len); addr = ((char *) addr + memory::page_size)) {
                void *phys = resolve_single_4k(addr, page_map);

                perms_single_4k(addr, current->perms, new_ctx->page_map);
                ref_page(phys);
                shootdown(addr);
            }
        } else {

        }

        current = new_ctx->mappings.successor(current);
    }

    return new_ctx;
}

vmm::vmm_ctx_map vmm::vmm_ctx::get_page_map() {
    return page_map;
}

void vmm::vmm_ctx::swap_in() {
    load_pagemap(page_map);
}