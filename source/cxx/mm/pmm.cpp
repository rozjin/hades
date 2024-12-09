#include "frg/tuple.hpp"
#include <cstddef>
#include <cstdint>
#include <mm/common.hpp>
#include <mm/pmm.hpp>
#include <util/log/log.hpp>
#include <util/stivale.hpp>
#include <util/string.hpp>
#include <util/log/panic.hpp>

static log::subsystem logger = log::make_subsystem("PM");
memory::pmm::block *next_block(memory::pmm::block *block) {
    return (memory::pmm::block *)(((char *) block) + block->sz);
}

memory::pmm::block *split_block(memory::pmm::block *block, size_t size) {
    if (block != nullptr && size != 0) {
        while (size < block->sz) {
            size_t sz = block->sz >> 1;
            block->sz = sz;
            block = next_block(block);
            block->sz = sz;
            block->is_free = true;
        }

        if (size <= block->sz) {
            return block;
        }
    }

    return nullptr;
}

memory::pmm::block *find_best(memory::pmm::block *head, memory::pmm::block *tail, size_t size) {
    memory::pmm::block *best = nullptr;
    memory::pmm::block *block = head;
    memory::pmm::block *buddy = next_block(block);

    if (buddy == tail && block->is_free) {
        return split_block(block, size);
    }

    while (block < tail && buddy < tail) {
        if (block->is_free && buddy->is_free && block->sz == buddy->sz) {
            block->sz <<= 1;

            if (size <= block->sz && (best == nullptr || block->sz <= best->sz)) {
                best = block;
            }

            block = next_block(buddy);
            if (block < tail) {
                buddy = next_block(block);
            }

            continue;
        }

        if (block->is_free && size <= block->sz && 
            (best == nullptr || block->sz <= best->sz)) {
            best = block;
        }

        if (buddy->is_free && size <= buddy->sz &&
            (best == nullptr || buddy->sz < best->sz)) {
            best = buddy;
        }

        if (block->sz <= buddy->sz) {
            block = next_block(buddy);
            if (block < tail) {
                buddy = next_block(block);
            }
        } else {
            block = buddy;
            buddy = next_block(buddy);
        }
    }

    if (best != nullptr) {
        return split_block(best, size);
    }

    // OOM
    return nullptr;
}


size_t align_forward(size_t num, size_t align) {
    auto p = num;
    auto modulo = p & ( align - 1 );
    if (modulo != 0) {
        p += align - modulo;
    }

    return p;
}

size_t align_size(memory::pmm::region *region, size_t size) {
    size_t actual_size = region->alignment;
    
    size += sizeof(memory::pmm::block);
    size = align_forward(size, region->alignment);

    while (size > actual_size) {
        actual_size <<= 1;
    }

    return actual_size;
}

void coalesce_blocks(memory::pmm::block *head, memory::pmm::block *tail) {
    for (;;) {
        memory::pmm::block *block = head;
        memory::pmm::block *buddy = next_block(block);

        bool no_coalesce = true;
        while (block < tail && buddy < tail) {
            if (block->is_free && buddy->is_free && block->sz == buddy->sz) {
                block->sz <<= 1;
                block = next_block(block);
                if (block < tail) {
                    buddy = next_block(block);
                    no_coalesce = false;
                } 
            } else if (block->sz < buddy->sz) { 
                block = buddy;
                buddy = next_block(buddy);
            } else {
                block = next_block(buddy);
                if (block < tail) {
                    buddy = next_block(block);
                }
            }
        }

        if (no_coalesce) {
            return;
        }
    }
}

void *alloc_block(memory::pmm::region *region, size_t size) {
    if (size != 0) {
        size_t actual_size = align_size(region, size);

        memory::pmm::block *found = find_best(region->head, region->tail, actual_size);
        if (found == nullptr) {
            coalesce_blocks(region->head, region->tail);
            found = find_best(region->head, region->tail, actual_size);
        }

        if (found != nullptr) {
            found->is_free = false;
            return (void *) ((char *) found + region->alignment);
        }

        // OOM
        region->has_blocks = false;
    }

    return nullptr;
}

void free_block(memory::pmm::region *region, void *data) {
    if (data != nullptr) {
        memory::pmm::block *block = (memory::pmm::block *)((char *) data + region->alignment);
        block->is_free = true;

        coalesce_blocks(region->head, region->tail);
    }
}

size_t nearest_pow2(size_t size, size_t alignment) {
    for (size_t i = (size - alignment); i >= 1; i = i - alignment) {
        if ((i & (i - 1)) == 0) {
            return i;
        }
    }

    return 0;
}

frg::tuple<memory::pmm::region *, size_t> init_region(void *start, size_t size, size_t alignment) {
    if (alignment < sizeof(memory::pmm::block)) {
        alignment = sizeof(memory::pmm::block);
    }

    size_t region_size = nearest_pow2(size, alignment);
    if (region_size == 0) {
        return {nullptr, 0};
    }

    start = memory::add_virt(start);
    void *data = ((char *) start) + alignment;

    memory::pmm::region *region = (memory::pmm::region *) start;
    region->has_blocks = true;
    region->head = (memory::pmm::block *) data;
    region->alignment = alignment;
    region->head->sz = region_size;
    region->head->is_free = true;
    region->tail = next_block(region->head);

    return {region, size - region_size};
}

void append_region(memory::pmm::region *region, memory::pmm::region **curr) {
    if (memory::pmm::head == nullptr) {
        memory::pmm::head = region;
        *curr = region;
        region->next = nullptr;
    } else {
        (*curr)->next = region;
        *curr = region;
    }
}

void memory::pmm::init(stivale::boot::tags::region_map *info) {
    nr_pages = info->page_count();

    memory::pmm::region *curr = nullptr;
    for (size_t i = 0; i < info->entries; i++) {
        auto region = info->regionmap[i];
        if (region.base < 0x100000)
            continue;
        if (region.type == stivale::boot::info::type::USABLE) {
            nr_usable++;

            auto [buddy_region, rest] = init_region((void *) region.base, region.length, page_size);
            while (buddy_region != nullptr && rest > 0) {
                append_region(buddy_region, &curr);
                auto res = init_region((void *) (region.base + buddy_region->head->sz), rest, page_size);
                
                buddy_region = res.get<0>();
                rest = res.get<1>();
            }
        }
    }

    kmsg(logger, "[PMM] Free memory: %lu bytes", nr_usable * page_size);
}

void *memory::pmm::alloc(size_t req_pages) {
    pmm_lock.acquire();

    find_region:
        pmm::region *region = pmm::head;
        while (region && region->next != nullptr && region->head->sz < (req_pages + 1) * page_size && region->has_blocks) {
            region = region->next;
        }

    auto ret = alloc_block(region, (req_pages + 1) * page_size);
    if (ret == nullptr) {
        goto find_region;
    }

    if (ret == nullptr) {
        panic("[PMM] Out of Memory!");
        pmm_lock.release();
    }

    auto alloc = (pmm::allocation *) ret;
    memset(alloc, 0, (req_pages + 1) * page_size);
    alloc->reg = region;

    pmm_lock.release();

    return ((char *) alloc) + page_size;
}

void *memory::pmm::stack(size_t req_pages) {
    return (char *) alloc(req_pages) + (req_pages * page_size);
}

void *memory::pmm::phys(size_t req_pages) {
    return (void *) (((uint64_t) alloc(req_pages)) - x86::virtualBase);
}

void memory::pmm::free(void *address) {
    pmm_lock.acquire();

    pmm::allocation *alloc = (pmm::allocation *) (((char *) address) - page_size);
    pmm::region *reg = alloc->reg;
    free_block(reg, alloc);

    pmm_lock.release();
}