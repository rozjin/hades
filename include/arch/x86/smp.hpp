#ifndef SMP_HPP
#define SMP_HPP

#include <cstddef>
#include <cstdint>
#include <frg/vector.hpp>
#include <mm/mm.hpp>
#include <mm/vmm.hpp>
#include <mm/pmm.hpp>
#include <sys/acpi.hpp>
#include <sys/sched/sched.hpp>
#include <util/lock.hpp>

namespace x86 {
    namespace tss {
        constexpr auto TSS_OFFSET = 0x28;
        constexpr auto TSS_STACK_SIZE = 4;
    
        struct [[gnu::packed]] gdtr {
            uint16_t len;
            uint64_t ptr;
        };

        struct [[gnu::packed]] entry {
            uint32_t unused0;
            uint64_t rsp0;
            uint64_t rsp1;
            uint64_t rsp2;
            uint64_t unused1;
            uint64_t ist[7];
            uint64_t unused3;
            uint16_t unused4;
            uint16_t iopb_offset;
        };

        struct [[gnu::packed]] descriptor {
            uint16_t limit_lo;
            uint16_t base_lo;
            uint8_t base_mid;
            uint8_t type      : 4;
            uint8_t z_1       : 1;
            uint8_t dpl       : 2;
            uint8_t pr        : 1;
            uint8_t limit_mid : 4;
            uint8_t avl       : 1;
            uint8_t z_2       : 2;
            uint8_t g         : 1;
            uint8_t base_mid2;
            uint32_t base_hi;
            uint32_t z_3;
        };

        void init();
    };

    constexpr size_t initialStackSize = 16;
    constexpr size_t fsBase = 0xC0000100;
    constexpr size_t gsBase = 0xC0000101;

    struct [[gnu::packed]] processor {
        uintptr_t kstack;
        uintptr_t ustack;
        int errno;

        size_t processor_id;

        x86::tss::entry tss;

        int64_t tid, idle_tid;
        size_t pid;

        sched::thread *task;
        sched::process *proc;

        vmm::vmm_ctx *ctx;

        processor(size_t processor_id) : processor_id(processor_id) { }
    };
    
    extern frg::vector<x86::processor *, memory::mm::heap_allocator> cpus;

    x86::processor *get_locals();

    sched::thread *get_thread();
    sched::process *get_process();

    size_t get_pid();
    int64_t get_tid();
    uint64_t get_cpu();

    void set_errno(int errno);

    void init_smp();
    void stop_all_cpus();
};

#endif