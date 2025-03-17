#ifndef CACHE_HPP
#define CACHE_HPP

#include <cstddef>
#include <cstdint>
#include <fs/dev.hpp>
#include <frg/rcu_radixtree.hpp>
#include <frg/list.hpp>
#include <frg/vector.hpp>
#include <ipc/link.hpp>
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

            void *write_page(size_t offset );
            void *read_page(size_t offset);

            int release_page(size_t offset);

            void request_page(void *buffer, size_t offset, size_t buffer_len, size_t buffer_offset, size_t page_offset, bool rw);

            ipc::link link;

            struct request {
                size_t offset;
                size_t page_offset;

                size_t buffer_len;
                size_t buffer_offset;
                void *buffer;

                bool rw;
                size_t link_id;
            };

            size_t pending_reads;
            size_t pending_writes;

            bool syncing;

            frg::vector<shared_ptr<request>, memory::mm::heap_allocator> requests;
        public:
            void request_io(void *buffer, size_t offset, size_t len, bool rw);

            int free_pages();
            int sync_pages();

            void halt_syncing();

            frg::default_list_hook<holder> hook;

            holder(vfs::devfs::blockdev *backing_device): lock(), 
                address_tree(), backing_device(backing_device),
                link(),
                pending_reads(0), pending_writes(0), 
                syncing(true), requests(),
                hook() {} 

            friend void sync_worker();
    };

    holder *create_cache(vfs::devfs::blockdev *backing_device);
}

#endif