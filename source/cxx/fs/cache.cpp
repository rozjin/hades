#include "arch/x86/smp.hpp"
#include "arch/x86/types.hpp"
#include "mm/common.hpp"
#include "mm/vmm.hpp"
#include "sys/sched/sched.hpp"
#include "util/lock.hpp"
#include <cstddef>
#include <fs/cache.hpp>
#include <frg/vector.hpp>
#include <mm/mm.hpp>
#include <mm/pmm.hpp>

static frg::vector<cache::holder *, memory::mm::heap_allocator> caches{};

void *cache::holder::read_page(size_t offset) {
    util::lock_guard guard{lock};

    uintptr_t *page = address_tree.find(offset);
    if (page == nullptr) {
        void *new_page = pmm::alloc(1);
        address_tree.insert(offset, (uintptr_t) new_page);
        backing_device->read(new_page, memory::page_size, offset);
        return new_page;
    }

    return (void *) (*page);
}

// TODO: add disk flushing
void *cache::holder::write_page(size_t offset) {
    util::lock_guard guard{lock};

    uintptr_t *page = address_tree.find(offset);
    if (page == nullptr) {
        void *new_page = pmm::alloc(1);
        address_tree.insert(offset, (uintptr_t) new_page);
        backing_device->read(new_page, memory::page_size, offset);
        return new_page;
    }

    return (void *) (*page);
}

// TODO: add disk flushing
int cache::holder::release_page(size_t offset) {
    size_t page_offset = offset / memory::page_size;

    return -1;
}

cache::holder *cache::create_cache(vfs::devfs::blockdev *backing_device) {
    auto cache = frg::construct<cache::holder>(memory::mm::heap, backing_device);
    caches.push_back(cache);

    return cache;
}

void cache::halt_sync() {
    
}

void cache::sync_worker() {
    while (true) {

    }
}

void cache::init() {
    auto thread = sched::create_thread(sync_worker, (uint64_t) pmm::stack(x86::initialStackSize), vmm::boot, 0);
    thread->start();
}