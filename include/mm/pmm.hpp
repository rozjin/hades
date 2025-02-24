#ifndef PMM_HPP
#define PMM_HPP

#include <cstddef>
#include <cstdint>
#include <util/stivale.hpp>
#include <util/lock.hpp>
#include <mm/common.hpp>

#define pow2(x) (1 << (x))

namespace pmm {
    struct block {
        size_t sz;
        bool is_free;
    };

    struct region {
        region *next;

        block *head;
        block *tail;

        bool has_blocks;
        size_t alignment;
    };

    struct allocation {
        region *reg;
    };

    extern util::spinlock pmm_lock;
    extern region* head;
    extern size_t nr_pages;
    extern size_t nr_usable;

    void init(stivale::boot::tags::region_map *info);

    void *alloc(size_t nr_pages);
    void *stack(size_t nr_pages);
    void *phys(size_t nr_pages);
    void free(void *address);
};

#endif