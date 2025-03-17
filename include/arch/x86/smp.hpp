#ifndef SMP_HPP
#define SMP_HPP

#include "arch/x86/types.hpp"
#include "frg/intrusive.hpp"
#include "frg/list.hpp"
#include "frg/rbtree.hpp"
#include "util/types.hpp"
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

    enum ipi_events {
        INIT_TASK,
        START_TASK,
        STOP_TASK,
        KILL_TASK,

        GIVE_OWNERSHIP
    };

    struct [[gnu::packed]] processor {
        uintptr_t kstack;
        uintptr_t ustack;
        uint64_t errno;

        size_t processor_id;

        x86::tss::entry tss;

        sched::thread *idle_task;
        tid_t idle_tid;

        tid_t tid;
        size_t pid;

        void *ipi_data;
        size_t ipi_event;

        sched::thread   *current_task;
        sched::process *current_process;
        vmm::vmm_ctx *ctx;

        struct thread_comparator {
            bool operator() (sched::thread& a, sched::thread& b) {
                return a.uptime < b.uptime;
            };
        };

        using run_tree_t = frg::rbtree<
            sched::thread,
            &sched::thread::hook,
            thread_comparator
        >;

        run_tree_t *run_tree{};
        util::spinlock *run_lock;

        processor(size_t processor_id, run_tree_t *run_tree, util::spinlock *run_lock) : processor_id(processor_id), run_tree(run_tree), run_lock(run_lock) { }
    };

    extern frg::vector<x86::processor *, memory::mm::heap_allocator> cpus;

    void message_processor(ssize_t processor_id, size_t ipi_event, void *ipi_data);

    x86::processor *get_locals();

    sched::thread *get_thread();
    sched::process *get_process();

    size_t get_pid();
    int64_t get_tid();
    uint64_t get_cpu();

    void set_errno(int errno);
    int get_errno();

    void install_handlers();
    void init_smp();

    void stop_all_cpus();
};

#endif