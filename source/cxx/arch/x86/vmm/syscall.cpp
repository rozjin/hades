#include <arch/vmm.hpp>
#include <arch/x86/types.hpp>
#include <arch/types.hpp>
#include <sys/sched/sched.hpp>

#include <cstddef>

constexpr size_t PROT_NONE  = 0x00;
constexpr size_t PROT_READ  = 0x01;
constexpr size_t PROT_WRITE = 0x02;
constexpr size_t PROT_EXEC  = (1UL << 63);

constexpr size_t MAP_FAILED = size_t(-1);
constexpr size_t MAP_PRIVATE = 0x1;
constexpr size_t MAP_SHARED = 0x2;
constexpr size_t MAP_FIXED = 0x4;
constexpr size_t MAP_ANONYMOUS = 0x8;

vmm::map_flags translate(size_t in_flags, size_t in_prot) {
    vmm::map_flags flags = vmm::map_flags::USER;

    if (in_flags & MAP_FIXED)
        flags |= vmm::map_flags::FIXED;
    
    if (in_flags & MAP_SHARED)
        flags |= vmm::map_flags::SHARED;

    if (!(in_flags & MAP_ANONYMOUS))
        flags |= vmm::map_flags::FILE;
    
    if (in_prot & PROT_READ) {}
    if (in_prot & PROT_WRITE)
        flags |= vmm::map_flags::WRITE;
    
    if (in_prot & PROT_EXEC)
        flags |= vmm::map_flags::EXEC;

    return flags;
}

void syscall_mmap(arch::irq_regs *r) {
    auto process = arch::get_process();
    auto ctx = process->mem_ctx;

    void *addr = (void *) r->rdi;
    size_t len = r->rsi;
    int prot = r->rdx;
    int flags = r->r10;
    int fd = r->r8;
    size_t offset = r->r9;
    size_t pages = util::ceil(len, memory::page_size) * memory::page_size;

    ctx->lock.irq_acquire();
    if (pages == 0 || pages % memory::page_size != 0) {
        arch::set_errno(EINVAL);
        ctx->lock.irq_release();
        r->rax = -1;
        return;
    }

    if ((uint64_t) addr > 0) {
        if ((uint64_t) addr >= 0x7ffffff00000 || ((uint64_t) addr + len) >= 0x7ffffff00000) {
            arch::set_errno(EINVAL);
            r->rax = -1;
            return;
        }
    }

    if (prot & PROT_NONE) {
        if (flags & MAP_FIXED) {
            ctx->unmap(addr, pages);
            r->rax = (uint64_t) addr;
            return;
        }

        r->rax = (uint64_t) addr;
        return;
    }

    if (!(flags & MAP_ANONYMOUS)) {
        if (flags & MAP_SHARED) {
            // shared
        } else if (flags & MAP_PRIVATE) {
            // private file
        } else {
            arch::set_errno(EINVAL);
            ctx->lock.irq_release();
            r->rax = MAP_FAILED;
            return;
        }
    }

    auto base = ctx->map(addr, pages, translate(flags, prot));
    r->rax = (uint64_t) base;
    ctx->lock.irq_release();
}

void syscall_munmap(arch::irq_regs *r) {
    auto process = arch::get_process();
    auto ctx = process->mem_ctx;

    void *addr = (void *) r->rdi;
    size_t len = r->rsi;
    size_t pages = util::ceil(len, memory::page_size) * memory::page_size;

    if (pages == 0 || pages % memory::page_size != 0) {
        arch::set_errno(EINVAL);
        ctx->lock.irq_release();
        r->rax = -1;
        return;
    }

    if ((uint64_t) addr >= 0x7ffffff00000 || ((uint64_t) addr + len) >= 0x7ffffff00000) {
        arch::set_errno(EINVAL);
        r->rax = -1;
        return;
    }

    ctx->lock.irq_acquire();

    auto res = ctx->unmap(addr, pages);
    if (res == nullptr) {
        arch::set_errno(EINVAL);
        r->rax = -1;
        return;
    }

    r->rax = 0;
}