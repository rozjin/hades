#ifndef VMM_HPP
#define VMM_HPP

#include "mm/common.hpp"
#include <cstddef>
#include <stdint.h>
#include <stddef.h>
#include <mm/pmm.hpp>
#include <util/lock.hpp>
#include <frg/vector.hpp>
#include <frg/rbtree.hpp>
#include <frg/tuple.hpp>
#include <arch/vmm.hpp>
#include <arch/x86/types.hpp>

namespace vmm {
    class vmm_ctx;

    void init();
    vmm_ctx *create();

    class vmm_ctx {
        private:            
            struct hole {
                public:
                    void *addr = nullptr;
                    uint64_t len = 0;
                    uint64_t largest_hole = 0;
                    void *map = nullptr;

                    frg::rbtree_hook hook;

                    hole(void *addr, uint64_t len, void *map): hook() {
                        this->addr = addr;
                        this->len = len;
                        this->largest_hole = 0;
                        this->map = map;
                    };
            };

            struct hole_comparator {
                bool operator() (hole& a, hole& b) {
                    return a.addr < b.addr;
                };
            };

            struct hole_aggregator;
            using hole_tree = frg::rbtree<hole, &hole::hook, hole_comparator, hole_aggregator>;

            struct hole_aggregator {
                static bool aggregate(hole *node);
                static bool check_invariant(hole_tree& tree, hole *node);
            };

            hole_tree holes;

            void setup_hole();
            void *create_hole(void *addr, uint64_t len);
            uint8_t delete_hole(void *addr, uint64_t len);
            void split_hole(hole *node, uint64_t offset, size_t len);

            struct mapping {
                public:
                    void *addr = nullptr;
                    uint64_t len = 0;
                    vmm_ctx_map map = nullptr;

                    struct mapping_perms {
                        bool read;
                        bool write;
                        bool user;

                        bool shared;
                        bool priv;

                        bool exec;
                    };

                    mapping_perms perms;
                    
                    bool free_pages;
                    frg::rbtree_hook hook;

                    mapping(void *addr, uint64_t len, vmm_ctx_map map) : addr(addr), len(len), map(map), perms(), free_pages(false) { };
            };

            struct mapping_comparator {
                bool operator() (mapping& a, mapping& b) {
                    return a.addr < b.addr;
                };
            };

            using mapping_tree = frg::rbtree<mapping, &mapping::hook, mapping_comparator, frg::null_aggregator>;
            mapping_tree mappings;

            void *create_mapping(void *addr, uint64_t len, map_flags flags, bool fill_now);
            mapping *get_mapping(void *addr);
            void delete_mapping(mapping *node);

            frg::tuple<mapping *, mapping *> split_mappings(void *addr, uint64_t len);

            void delete_mappings(void *addr, uint64_t len, mapping *start, mapping *end);
            void *delete_mappings(void *addr, uint64_t len);

            void unmap_pages(void *addr, size_t len, bool free_pages);

            vmm_ctx_map page_map;

            mapping::mapping_perms flags_to_perms(map_flags flags);
        public:
            util::spinlock lock;

            vmm_ctx();
            ~vmm_ctx();
            friend bool x86::handle_pf(arch::irq_regs *r);

            friend void vmm::init();
            friend vmm_ctx *vmm::create();

            void *map(void *virt, uint64_t len, map_flags flags, bool fixed = false);
            void *stack(void *virt, uint64_t len, map_flags flags);
            void *unmap(void *virt, uint64_t len, bool stack = false);
            
            void *resolve(void *virt);

            void modify(void *virt, uint64_t len, map_flags flags);

            vmm_ctx *fork();
            vmm_ctx_map get_page_map();
            void swap_in();
    };

    void destroy(vmm_ctx *ctx);
    extern vmm_ctx *boot;
};

#endif