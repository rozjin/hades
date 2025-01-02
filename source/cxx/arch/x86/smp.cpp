#include "util/types.hpp"
#include <arch/x86/types.hpp>
#include <arch/types.hpp>
#include <cstddef>
#include <frg/allocation.hpp>
#include <mm/common.hpp>
#include <mm/pmm.hpp>
#include <mm/vmm.hpp>
#include <mm/mm.hpp>
#include <sys/acpi.hpp>
#include <sys/x86/apic.hpp>
#include <arch/x86/smp.hpp>
#include <sys/sched/sched.hpp>
#include <util/io.hpp>
#include <util/lock.hpp>
#include <util/log/log.hpp>
#include <util/stivale.hpp>
#include <util/string.hpp>

frg::vector<x86::processor *, memory::mm::heap_allocator> x86::cpus{};

void arch::init_smp() {
    x86::init_smp();
}

void arch::stop_all_cpus() {
    x86::stop_all_cpus();
}

void x86::stop_all_cpus() {
    for (auto cpu : cpus) {
        if (cpu->processor_id == x86::get_cpu()) {
            continue;
        }
        
        apic::lapic::ipi(cpu->processor_id, (1 << 14) | 251);
    }
}

[[noreturn]]
static inline void processorPanic(arch::irq_regs *r) {
    x86::irq_off();
    while (true) {
        asm volatile("pause");
    }
}

static log::subsystem logger = log::make_subsystem("SMP");
static inline util::lock cpuBootupLock{};
extern "C" {
    void processorEntry(stivale::boot::info::processor *entry_ctx) {
        cpuBootupLock.acquire();
        
        auto *cpu = (x86::processor *) entry_ctx->extra_argument;
        x86::wrmsr(x86::gsBase, cpu);

        apic::lapic::setup();
        x86::hook_irqs();

        cpu->ctx->swap_in();
        x86::init_ap();
        x86::tss::init();

        kmsg(logger, "[CPU %u online]", x86::get_cpu());

        cpuBootupLock.release();

        apic::lapic::set_timer(1);
        x86::irq_on();
        while (true) {
            asm volatile("pause");
        }
    }
};

extern "C" {
    extern void smp64_start(stivale::boot::info::processor *_);
};

void x86::init_smp() {
    x86::install_irq(219, processorPanic);

    auto procs = stivale::parser.smp();
    for (auto stivale_cpu = procs->begin(); stivale_cpu != procs->end(); stivale_cpu++) {
        size_t lapic_id = stivale_cpu->lapic_id;
        if (lapic_id == get_cpu()) continue;

        auto processor = frg::construct<x86::processor>(memory::mm::heap, lapic_id);

        processor->kstack = (size_t) memory::pmm::stack(x86::initialStackSize);
        processor->ctx = vmm::boot;
        cpus.push_back(processor);

        stivale_cpu->extra_argument = (size_t) processor;
        stivale_cpu->target_stack = processor->kstack;
        stivale_cpu->goto_address = (size_t) &smp64_start;
    }

    cpuBootupLock.await();
}

x86::processor *x86::get_locals() {
    return x86::rdmsr<x86::processor *>(x86::gsBase);
}

x86::tss::gdtr real_gdt;
util::lock tssLock{};

void x86::tss::init() {
    tssLock.acquire();
    asm volatile("sgdt (%0)" : : "r"(&real_gdt));

    auto *cpuInfo = get_locals();
    auto *tss = &cpuInfo->tss;
    uint64_t tss_ptr = (uint64_t) tss;
    descriptor *desc = (descriptor *) (real_gdt.ptr + TSS_OFFSET);
    
    memset(desc, 0, sizeof(descriptor));

    desc->base_lo = (uint32_t) ((tss_ptr >> 0) & 0xFFFF);
    desc->base_mid = (uint32_t) ((tss_ptr >> 16) & 0xFF);
    desc->base_mid2 = (uint32_t) ((tss_ptr >> 24) & 0xFF);
    desc->base_hi = (uint32_t) ((tss_ptr >> 32) & 0xFFFFFFFF);

    desc->limit_lo = 0x68;
    desc->pr = 1;
    desc->type = 0b1001;

    tss->ist[0] = (uint64_t) memory::pmm::stack(4);
    tss->ist[1] = (uint64_t) memory::pmm::stack(4);

    asm volatile("ltr %%ax" :: "a"(TSS_OFFSET));
    tssLock.release();
}

sched::thread *x86::get_thread() {
    return get_locals()->task;
}

sched::process *x86::get_process() {
    return get_locals()->proc;
}

size_t x86::get_pid() {
    return get_locals()->pid;
}

int64_t x86::get_tid() {
    return get_locals()->tid;
}

uint64_t x86::get_cpu() {
    return apic::lapic::id();
}

void x86::set_errno(int errno) {
    get_locals()->errno = errno;
}

int x86::get_errno() {
    return get_locals()->errno;
}

void arch::set_errno(int errno) {
    x86::set_errno(errno);
}

int arch::get_errno() {
    return x86::get_errno();
}

sched::process *arch::get_process() {
    return x86::get_process();
}

sched::thread *arch::get_thread() {
    return x86::get_thread();
}

tid_t arch::get_tid() {
    return x86::get_tid();
}

tid_t arch::get_idle() {
    return x86::get_locals()->idle_tid;
}

pid_t arch::get_pid() {
    return x86::get_pid();
}

uint64_t arch::get_cpu() {
    return x86::get_cpu();
}

void arch::set_process(sched::process *process) {
    x86::get_locals()->proc = process;
    if (process) x86::get_locals()->pid = process->pid;
    else x86::get_locals()->pid = -1;
}

void arch::set_thread(sched::thread *task) {
    x86::get_locals()->task = task;
    x86::get_locals()->tid = task->tid;
}