#include "arch/x86/hpet.hpp"
#include "arch/x86/pit.hpp"
#include "ipc/evtable.hpp"
#include "mm/mm.hpp"
#include "sys/x86/apic.hpp"
#include "util/types.hpp"
#include <mm/vmm.hpp>
#include <arch/types.hpp>
#include <arch/x86/types.hpp>
#include <arch/x86/smp.hpp>
#include <cstddef>
#include <sys/sched/sched.hpp>
#include <atomic>

arch::sched_regs default_kernel_regs{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x8, 0, 0, 0x202, 0, 0x1F80, 0x33F };
arch::sched_regs default_user_regs{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x23, 0x1B, 0, 0, 0x202, 0, 0x1F80, 0x33F };

alignas(16)
char default_sse_region[512] {};

extern "C" {
    extern void syscall_enter();
}

static void _idle() {
    while (1) { asm volatile("hlt"); };
}

void x86::handle_tick(arch::irq_regs *r) {
    sched::swap_task(r);
}

void arch::tick() {
    x86::do_tick();
}

void x86::do_tick() {
    apic::lapic::ipi(x86::get_cpu(), 32);
}

void x86::save_sse(char *sse_region) {
    asm volatile("fxsaveq (%0)":: "r"(sse_region));
}

void x86::load_sse(char *sse_region) {
    asm volatile("fxrstor (%0)":: "r"(sse_region));
}

uint16_t x86::get_fcw() {
    uint16_t fcw;
    asm volatile("fnstcw (%0)":: "r"(&fcw) : "memory");
    return fcw;
}

void x86::set_fcw(uint16_t fcw) {
    asm volatile("fldcw (%0)":: "r"(&fcw) : "memory");
}

uint32_t x86::get_mxcsr() {
    uint32_t fcw;
    asm volatile("stmxcsr (%0)" :: "r"(&fcw) : "memory");
    return fcw;
}

void x86::set_mxcsr(uint32_t fcw) {
    asm volatile("ldmxcsr (%0)" :: "r"(&fcw) : "memory");
}

void x86::init_sse() {
    uint64_t cr0;
    asm volatile("mov %%cr0, %0": "=r"(cr0));

    cr0 &= ~(1 << 2);
    cr0 |= (1 << 1);

    asm volatile("mov %0, %%cr0":: "r"(cr0));

    uint64_t cr4;
    asm volatile("mov %%cr4, %0": "=r"(cr4));

    cr4 |= (1 << 9);
    cr4 |= (1 << 10);

    asm volatile("mov %0, %%cr4":: "r"(cr4));
}

void arch::init_sched() {
    x86::install_handlers();
    apic::init();

    x86::init_bsp();
    x86::init_smp();
}

void x86::init_bsp() {
    auto processor = frg::construct<x86::processor>(memory::mm::heap, apic::lapic::id(),
        frg::construct<processor::run_tree_t>(memory::mm::heap),
        frg::construct<util::spinlock>(memory::mm::heap));

    processor->kstack = (size_t) pmm::stack(x86::initialStackSize);
    processor->ctx = vmm::boot;

    x86::wrmsr(x86::MSR_GS_BASE, processor);
    x86::cpus.push_back(processor);
    x86::tss::init();
    arch::irq_on();

    init_syscalls();
    init_sse();
    save_sse(default_sse_region);
    init_idle();

    hpet::init();
    pit::init();

    x86::install_vector(32, x86::handle_tick);
    apic::lapic::set_timer(1);
}

void x86::init_ap() {
    init_syscalls();
    init_sse();
    init_idle();
}

void x86::init_idle() {
    uint64_t idle_rsp = (uint64_t) pmm::stack(1);

    auto idle_task = sched::create_thread(_idle, idle_rsp, vmm::boot, 0, false);

    idle_task->tid = arch::allocate_tid();
    idle_task->state = sched::thread::BLOCKED;

    auto idle_tid = idle_task->tid;

    x86::get_locals()->idle_tid = idle_tid;
    x86::get_locals()->idle_task = idle_task;

    x86::get_locals()->tid = idle_tid;
    x86::get_locals()->current_task = idle_task;
}

void x86::init_syscalls() {
    x86::wrmsr(EFER, x86::rdmsr<uint64_t>(EFER) | (1 << 0));
    x86::wrmsr(STAR, (0x18ull << 48 | 0x8ull << 32));
    x86::wrmsr(LSTAR, (uintptr_t) syscall_enter);
    x86::wrmsr(SFMASK, ~(2ULL));
}

void arch::cleanup_vmm_ctx(sched::process *process) {
    x86::cleanup_vmm_ctx(process);
}

void x86::cleanup_vmm_ctx(sched::process *process) {
    auto old_ctx = process->mem_ctx;
    process->mem_ctx = vmm::boot;
    process->main_thread->mem_ctx = process->mem_ctx;
    process->main_thread->ctx.reg.cr3 = get_cr3(vmm::boot->get_page_map());
    vmm::destroy(old_ctx);
}

void arch::init_thread(sched::thread *task) {
    x86::message_processor(-1, x86::ipi_events::INIT_TASK, task);
}

void arch::start_thread(sched::thread *task) {
    if (task->ctx.cpu == x86::get_cpu())  x86::start_thread(task);
    else x86::message_processor(task->ctx.cpu, x86::ipi_events::START_TASK, task);
}

void arch::stop_thread(sched::thread *task) {
    if (task->ctx.cpu == x86::get_cpu()) x86::stop_thread(task);
    else x86::message_processor(task->ctx.cpu, x86::ipi_events::STOP_TASK, task);
}

void arch::kill_thread(sched::thread *task) {
    if (task->ctx.cpu == x86::get_cpu()) x86::kill_thread(task);
    else x86::message_processor(task->ctx.cpu, x86::ipi_events::KILL_TASK, task);
}

void x86::init_thread(sched::thread *task) {
    auto run_tree = get_locals()->run_tree;
    auto tid = arch::allocate_tid();

    task->tid = tid;
    run_tree->insert(task);
}

void x86::start_thread(sched::thread *task) {
    task->state = sched::thread::READY;
}

void x86::stop_thread(sched::thread *task) {
    task->state = sched::thread::BLOCKED;
}

void x86::kill_thread(sched::thread *task) {
    auto run_tree = get_locals()->run_tree;
    run_tree->remove(task);

    task->state = sched::thread::DEAD;
}

void arch::init_context(sched::thread *task, void (*main)(), uint64_t rsp, uint8_t privilege) {
    if (privilege == 3) {
        task->ctx.reg = default_user_regs;
    } else {
        task->ctx.reg = default_kernel_regs;
    }

    memcpy(task->ctx.sse_region, default_sse_region, 512);

    task->ctx.reg.rip = (uint64_t) main;
    task->ctx.reg.rsp = rsp;
    task->ctx.privilege = privilege;
    task->pid = -1;
    task->proc = nullptr;

    task->ctx.reg.cr3 = x86::get_cr3(task->mem_ctx->get_page_map());
}

void arch::fork_context(sched::thread *original, sched::thread *task, irq_regs *r) {
    task->ctx.reg.rax = 0;
    task->ctx.reg.rbx = r->rbx;
    task->ctx.reg.rcx = r->rcx;
    task->ctx.reg.rdx = r->rdx;
    task->ctx.reg.rbp = r->rbp;
    task->ctx.reg.rdi = r->rdi;
    task->ctx.reg.rsi = r->rsi;
    task->ctx.reg.r8 = r->r8;
    task->ctx.reg.r9 = r->r9;
    task->ctx.reg.r10 = r->r10;
    task->ctx.reg.r11 = r->r11;
    task->ctx.reg.r12 = r->r12;
    task->ctx.reg.r13 = r->r13;
    task->ctx.reg.r14 = r->r14;
    task->ctx.reg.r15 = r->r15;

    task->ctx.reg.rflags = r->r11;
    task->ctx.reg.rip = r->rcx;
    task->ctx.reg.rsp = r->rsp;

    task->ctx.reg.cs = r->cs;
    task->ctx.reg.ss = r->ss;

    task->ctx.reg.fs = original->ctx.reg.fs;
    task->ctx.reg.gs = original->ctx.reg.gs;

    memcpy(task->ctx.sse_region, original->ctx.sse_region, 512);

    task->ctx.privilege = original->ctx.privilege;
    task->ctx.reg.cr3 = x86::get_cr3(task->mem_ctx->get_page_map());
}

void arch::save_context(irq_regs *r, sched::thread *task) {
    task->ctx.reg.rax = r->rax;
    task->ctx.reg.rbx = r->rbx;
    task->ctx.reg.rcx = r->rcx;
    task->ctx.reg.rdx = r->rdx;
    task->ctx.reg.rbp = r->rbp;
    task->ctx.reg.rdi = r->rdi;
    task->ctx.reg.rsi = r->rsi;
    task->ctx.reg.r8 = r->r8;
    task->ctx.reg.r9 = r->r9;
    task->ctx.reg.r10 = r->r10;
    task->ctx.reg.r11 = r->r11;
    task->ctx.reg.r12 = r->r12;
    task->ctx.reg.r13 = r->r13;
    task->ctx.reg.r14 = r->r14;
    task->ctx.reg.r15 = r->r15;

    task->ctx.reg.rflags = r->rflags;
    task->ctx.reg.rip = r->rip;
    task->ctx.reg.rsp = r->rsp;

    task->ctx.reg.cs = r->cs;
    task->ctx.reg.ss = r->ss;

    task->ctx.reg.fs = x86::get_user_fs();
    task->ctx.reg.gs = x86::get_user_gs();

    x86::save_sse(task->ctx.sse_region);
    task->ctx.reg.mxcsr = x86::get_mxcsr();
    task->ctx.reg.fcw = x86::get_fcw();

    task->kstack = x86::get_locals()->kstack;
    task->ustack = x86::get_locals()->ustack;

    task->stopped = x86::tsc();
    task->uptime += task->stopped - task->started;

    task->ctx.reg.cr3 = x86::read_cr3();

    if (task->running) {
        task->running = false;
    }

    if (task->state == sched::thread::RUNNING && task->tid != get_idle_tid()) {
        task->state = sched::thread::READY;
    }

    if (task->tid != get_idle_tid()) {
        auto run_tree = x86::get_locals()->run_tree;
        run_tree->remove(task);
        run_tree->insert(task);
    }
}

void arch::rstor_context(sched::thread *task, irq_regs *r) {
    r->rax = task->ctx.reg.rax;
    r->rbx = task->ctx.reg.rbx;
    r->rcx = task->ctx.reg.rcx;
    r->rdx = task->ctx.reg.rdx;
    r->rbp = task->ctx.reg.rbp;
    r->rdi = task->ctx.reg.rdi;
    r->rsi = task->ctx.reg.rsi;
    r->r8 = task->ctx.reg.r8;
    r->r9 = task->ctx.reg.r9;
    r->r10 = task->ctx.reg.r10;
    r->r11 = task->ctx.reg.r11;
    r->r12 = task->ctx.reg.r12;
    r->r13 = task->ctx.reg.r13;
    r->r14 = task->ctx.reg.r14;
    r->r15 = task->ctx.reg.r15;

    r->rflags = task->ctx.reg.rflags;
    r->rip = task->ctx.reg.rip;
    r->rsp = task->ctx.reg.rsp;

    r->cs = task->ctx.reg.cs;
    r->ss = task->ctx.reg.ss;

    x86::set_user_fs(task->ctx.reg.fs);
    x86::set_user_gs(task->ctx.reg.gs);

    x86::load_sse(task->ctx.sse_region);
    x86::set_mxcsr(task->ctx.reg.mxcsr);
    x86::set_fcw(task->ctx.reg.fcw);

    x86::get_locals()->kstack = task->kstack;
    x86::get_locals()->tss.rsp0 = task->kstack;
    x86::get_locals()->ustack = task->ustack;

    task->started = x86::tsc();

    if (x86::read_cr3() != task->ctx.reg.cr3) {
        x86::write_cr3(task->ctx.reg.cr3);
    }
}

int arch::do_futex(uintptr_t vaddr, int op, int expected, sched::timespec *timeout) {
    return x86::do_futex(vaddr, op, expected, timeout);
}

frg::hash_map<uint64_t, sched::futex *, frg::hash<uint64_t>, memory::mm::heap_allocator> futex_list{frg::hash<uint64_t>()};
ssize_t x86::do_futex(uintptr_t vaddr, int op, int expected, sched::timespec *timeout) {
    auto process = x86::get_process();

    uint64_t vpage = vaddr & ~(0xFFF);
    uint64_t ppage = (uint64_t) process->mem_ctx->resolve((void *) vpage);

    if (!ppage) {
        return -EFAULT;
    }

    uint64_t paddr = ppage + (vaddr & 0xFFF);
    uint64_t uaddr = paddr + memory::x86::virtualBase;
    switch (op) {
        case sched::FUTEX_WAIT: {
            if (*(uint32_t *) uaddr != expected) {
                return -EAGAIN;
            }

            sched::futex *futex;
            if (!futex_list.contains(paddr)) {
                futex = frg::construct<sched::futex>(memory::mm::heap, paddr);
                futex_list[paddr] = futex;
            } else {
                futex = futex_list[paddr];
            }

            futex->locked = 1;
            for (;;) {
                if (futex->locked == 0) {
                    break;
                }

                auto [evt, _] = futex->wire.wait(evtable::FUTEX_WAKE, true);
                if (evt < 0) {
                    return -1;
                }
            }

            break;
        }

        case sched::FUTEX_WAKE: {
            sched::futex *futex;
            if (!futex_list.contains(paddr)) {
                return 0;
            } else {
                futex = futex_list[paddr];
            }

            futex_list.remove(futex->paddr);

            futex->locked = 0;
            futex->wire.arise(evtable::FUTEX_WAKE);

            break;
        }
    }

    return 0;
}

static std::atomic<pid_t> last_pid = 0;
static std::atomic<tid_t> last_tid = 0;

pid_t arch::allocate_pid() {
    return last_pid++;
}

tid_t arch::allocate_tid() {
    return last_tid++;
}

frg::tuple<tid_t, sched::thread *> sched::pick_task() {
    auto run_tree = x86::get_locals()->run_tree;
    auto next_task = run_tree->first();
    while (next_task != nullptr) {
        if (next_task->state == thread::READY || next_task->dispatch_ready) return {next_task->tid, next_task};

        next_task = run_tree->successor(next_task);
    }

    return {-1, arch::get_idle()};
}

