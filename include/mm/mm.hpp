#ifndef MM_HPP
#define MM_HPP

#include <new>
#include <cstddef>
#include <mm/common.hpp>

extern void *kmalloc(size_t size);
extern void kfree(void *ptr);

inline void *kcalloc(size_t nr_items, size_t size) {
    return kmalloc(nr_items * size);
}

inline void kfree_sz(void *ptr, size_t _) {
    kfree(ptr);
}

namespace memory {
    namespace mm {
        namespace allocator {
            void *malloc(size_t req_size);
            void *calloc(size_t nr_items, size_t size);
            void free(void *ptr);
        };
        
        struct heap_allocator {
            void *allocate(size_t size) {
                return kmalloc(size);
            }
            
            void deallocate(void *ptr) {
                kfree(ptr);
            }

            void deallocate(void *ptr, size_t _) {
                kfree(ptr);
            }

            void free(void *ptr) {
                kfree(ptr);
            }
        };

        inline mm::heap_allocator heap{};
    };
}

#endif