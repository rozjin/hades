#include "mm/common.hpp"
#include <arch/vmm.hpp>
#include <arch/x86/types.hpp>
#include <cstddef>
#include <cstdint>
#include <util/string.hpp>
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
void vmm::vmm_ctx::setup_hole() {
    this->holes.insert(frg::construct<hole>(memory::mm::heap,(void *) 0x1000, (1ULL << get_user_bits()) - 0x1000, (void *) this));
}

void *vmm::vmm_ctx::create_hole(void *addr, uint64_t len) {
    hole *current = this->holes.get_root();
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

union vmm::vmm_ctx::mapping::mapping_perms vmm::vmm_ctx::flags_to_perms(vmm::map_flags flags) {
    mapping::mapping_perms res {.number = 0};

    if ((uint64_t) (flags & map_flags::READ))
        res.read = 1;

    if ((uint64_t) (flags & map_flags::WRITE))
        res.write = 1;

    if ((uint64_t) (flags & map_flags::USER))
        res.user = 1; 

    if ((uint64_t) (flags & map_flags::SHARED))
        res.shared = 1;

    if ((uint64_t) (flags & map_flags::PRIVATE))
        res.priv = 1;

    if ((uint64_t) (flags & map_flags::EXEC))
        res.exec = 1;

    return res;
}

void *vmm::vmm_ctx::create_mapping(void *addr, uint64_t len, map_flags flags, bool fill_now) {
    void *dst = this->create_hole(addr, len);

    page_flags mapped_flags = to_arch(flags);
    if ((uint64_t) (flags & map_flags::DEMAND)) {
        mapped_flags &= ~(page_flags::PRESENT);
    }

    for (size_t i = 0; i < memory::page_count(len); i++) {
        void *phys = fill_now ? memory::pmm::phys(1) : nullptr;
       /* if (fill_now) {
            vmm::ref[phys] = 1;
        } */

        map_single_4k((char *) dst + (memory::page_size * i), phys, mapped_flags, page_map);
    }

    mapping *node = frg::construct<mapping>(memory::mm::heap, dst, len, page_map);
    if (fill_now) node->free_pages = true;
    node->perms = flags_to_perms(flags);

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
            void *phys = resolve_single_4k(inner, other->page_map);
            page_flags perms = resolve_perms_4k(inner, other->page_map);

            map_single_4k(inner, phys, perms, page_map);
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

       /*     if (phys) {
                vmm::ref[phys]--;
                if (vmm::ref[phys] == 0) {
                    memory::pmm::free(memory::add_virt(phys));
                }
            } */
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
    auto left = mappings.get_root();
    while (left) {
        if (auto next = mappings.get_left(left)) {
            left = next;
        } else {
            break;
        }
    }

    mapping *start = nullptr;
    mapping *end = nullptr;
    for (auto it = left; it;) {
        if (((char *) it->addr + it->len) <= addr) {
            it = mappings.successor(it);
            start = it;
            continue;
        }

        if (it->addr >= ((char *) addr + len)) {
            if (start) {
                end = it;
            }

            break;
        }

        if (!start) {
            start = it;
        }

        auto at = addr;
        if (at <= it->addr) {
            at = (char *) addr + len;
        }

        if (at > it->addr && at < ((char *) it->addr + it->len)) {
            uint64_t leftSize = ((char *) at - (char *) it->addr);
            auto left = frg::construct<mapping>(memory::mm::heap, it->addr, leftSize, page_map);

            left->free_pages = it->free_pages;
            left->perms = it->perms;

            auto right = frg::construct<mapping>(memory::mm::heap, at, it->len - leftSize, page_map);

            right->free_pages = it->free_pages;
            right->perms = it->perms;

            mappings.remove(it);
            mappings.insert(left);
            mappings.insert(right);

            frg::destruct(memory::mm::heap, it);

            if (start == it) {
                if (addr < at) {
                    start = left;
                } else {
                    start = right;
                }
            }

            it = right;
        } else {
            it = mappings.successor(it);
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

void *vmm::vmm_ctx::map(void *virt, uint64_t len, map_flags flags, bool fixed) {
    if (virt && fixed) {
        delete_mappings(virt, len);
    }

    return create_mapping(virt, len, flags, ((uint64_t) (flags & map_flags::FILL_NOW)));
}

void *vmm::vmm_ctx::stack(void *virt, uint64_t len, map_flags flags) {
    return (void *) (((uint64_t) map(virt, len, flags)) + len);
}

void *vmm::vmm_ctx::unmap(void *virt, uint64_t len, bool stack) {
    if (!stack) {
        return delete_mappings(virt, len);
    }

    return delete_mappings((void *) ((uint64_t) virt - len), len);
}

void *vmm::vmm_ctx::resolve(void *virt) {
    return resolve_single_4k(virt, page_map);
}

void vmm::vmm_ctx::modify(void *virt, uint64_t len, map_flags flags) {
    auto mapping = get_mapping(virt);

    if (mapping == nullptr) {
        kmsg(logger, log::level::WARN, "Mapping not found for %lx", virt);
    }

}

vmm::vmm_ctx *vmm::vmm_ctx::fork() {
    lock.irq_acquire();

    auto new_ctx = frg::construct<vmm_ctx>(memory::mm::heap);

    new_ctx->page_map = new_pagemap();
    new_ctx->setup_hole();
    copy_boot_map(new_ctx->page_map);
    
    new_ctx->copy_mappings(this);

    vmm_ctx::mapping *current = new_ctx->mappings.first();
    while (current) {
        if (current->perms.shared)
            goto skip;
        
        for (void *addr = current->addr; addr <= (void *) ((char *) current->addr + current->len); addr = ((char *) addr + memory::page_size)) {
            void *prev_phys = resolve_single_4k(addr, new_ctx->page_map);
            page_flags perms = resolve_perms_4k(addr, new_ctx->page_map);

            if (current->perms.write) {
                void *phys = memory::pmm::phys(1);
                memcpy(memory::add_virt(phys), memory::add_virt(prev_phys), memory::page_size);

                remap_single_4k(addr, phys, perms, new_ctx->page_map);
            } else {
                perms &= ~(page_flags::WRITE);
                perms |= page_flags::COW;

                perms_single_4k(addr, perms, new_ctx->page_map);
                perms_single_4k(addr, perms, page_map);
            }

         //   vmm::ref[phys]++;
            shootdown(addr);
        }

        skip:
        current = new_ctx->mappings.successor(current);
    }

    lock.irq_release();
    return new_ctx;
}

vmm::vmm_ctx_map vmm::vmm_ctx::get_page_map() {
    return page_map;
}

void vmm::vmm_ctx::swap_in() {
    load_pagemap(page_map);
}