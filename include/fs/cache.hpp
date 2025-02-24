#ifndef CACHE_HPP
#define CACHE_HPP

#include <cstddef>
#include <cstdint>
#include <frg/rcu_radixtree.hpp>
#include <fs/dev.hpp>
#include <frg/vector.hpp>
#include <sys/sched/event.hpp>
#include <mm/mm.hpp>

namespace cache {
    void halt_sync();
    void sync_worker();
    void init();

    class holder {
        private:
            util::spinlock lock;

            frg::rcu_radixtree<uintptr_t, memory::mm::heap_allocator> address_tree;
            vfs::devfs::blockdev *backing_device;
        public:
            void *write_page(size_t offset );
            void *read_page(size_t offset);
            int release_page(size_t offset);

            int free_pages();
            int sync_pages();

            holder(vfs::devfs::blockdev *backing_device): lock(), 
                address_tree(), backing_device(backing_device) {} 
            friend void sync_worker();
    };

    holder *create_cache(vfs::devfs::blockdev *backing_device);
}

#endif