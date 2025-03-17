#include "ipc/evtable.hpp"
#include "mm/common.hpp"
#include "util/lock.hpp"
#include <arch/x86/smp.hpp>
#include <arch/x86/types.hpp>
#include <arch/types.hpp>
#include <sys/sched/sched.hpp>
#include <sys/sched/signal.hpp>

extern "C" {
    [[noreturn]]
    extern void x86_sigreturn_exit(arch::irq_regs *r);
}

void x86::sigreturn_kill(sched::process *proc, ssize_t status) {
    irq_off();

    proc->kill(status);
    while (true) {
        do_tick();
    }
}

void x86::sigreturn_default(sched::process *proc, sched::thread *task) {
    irq_off();

    auto ctx = &task->sig_ctx;
    util::lock_guard ctx_guard{ctx->lock};

    ctx->sigdelivered |= SIGMASK(task->ucontext.signum);
    ctx->wire.arise(evtable::SIGNAL);

    ctx_guard.~lock_guard();

    auto regs = &task->ucontext.ctx.reg;
    task->ctx.reg = *regs;

    x86::get_locals()->ustack = task->ustack;
    x86::get_locals()->kstack = task->kstack;

    auto iretq_regs = x86::sched_to_irq(regs);

    x86::set_fcw(regs->fcw);
    x86::set_mxcsr(regs->mxcsr);
    x86::load_sse(task->ucontext.ctx.sse_region);
    
    x86::set_user_fs(regs->fs);
    x86::set_user_gs(regs->gs);

    task->dispatch_ready = false;
    task->pending_signal = false;
    task->in_syscall = false;
    
    pmm::free((void *) (task->ucontext.stack - (4 * memory::page_size)));

    if (regs->cs & 0x3) {
        x86::swapgs();
    }

    x86_sigreturn_exit(&iretq_regs);
}

void sig_default(sched::process *proc, sched::thread *task, int sig) {
    ssize_t status = sched::WSIGNALED_CONSTRUCT(sig);
    switch (sig) {
		case SIGHUP:
		case SIGINT:
		case SIGQUIT:
		case SIGILL:
		case SIGTRAP:
		case SIGBUS:
		case SIGFPE:
		case SIGKILL:
		case SIGUSR1:
		case SIGSEGV:
		case SIGUSR2:
		case SIGPIPE:
		case SIGALRM:
		case SIGSTKFLT:
		case SIGXCPU:
		case SIGXFSZ:
		case SIGVTALRM:
		case SIGPROF:
		case SIGSYS:
            return x86::sigreturn_kill(proc, status);
        case SIGSTOP:
        case SIGTTIN:
        case SIGTTOU:
        case SIGTSTP:
            proc->suspend();
            break;
        case SIGCONT:
            proc->cont();
            break;
        case SIGCHLD:
        case SIGWINCH:
            break;
    }

    x86::sigreturn_default(proc, task);
}

void arch::init_default_sigreturn(sched::thread *task, sched::signal::signal *signal, sched::signal::ucontext *context) {
    auto ctx = &task->ctx;

    context->ctx.reg = ctx->reg;
    memcpy(context->ctx.sse_region, ctx->sse_region, 512);

    context->signum = signal->signum;
    memset(&ctx->reg, 0, sizeof(sched_regs));

    ctx->reg.ss = 0x10;
    ctx->reg.cs = 0x8;
    ctx->reg.rsp = context->stack;
    ctx->reg.rflags = 0x202;

    ctx->reg.rdi = (uint64_t) task->proc;
    ctx->reg.rsi = (uint64_t) task;
    ctx->reg.rdx = signal->signum;
    ctx->reg.rip = (uint64_t) sig_default;

    ctx->reg.cr3 = x86::get_cr3(task->proc->mem_ctx->get_page_map());

    ctx->reg.mxcsr = 0x1F80;
    ctx->reg.fcw = 0x33F;
    memset(ctx->sse_region, 0, 512);
}

void arch::init_user_sigreturn(sched::thread *task,
    sched::signal::signal *signal, sched::signal::sigaction *action, 
    sched::signal::ucontext *context) {
    auto ctx = &task->ctx;

    context->ctx.reg = ctx->reg;
    memcpy(context->ctx.sse_region, ctx->sse_region, 512);

    context->signum = signal->signum;
    memset(&ctx->reg, 0, sizeof(sched_regs));

    auto stack = context->stack;

    stack -= 128;
    stack &= -16LL;
    stack -= sizeof(sched::signal::siginfo);
    sched::signal::siginfo *info = (sched::signal::siginfo *) stack;

    info->si_signo = signal->signum;

    stack -= sizeof(sched::signal::ucontext);
    sched::signal::ucontext *uctx = (sched::signal::ucontext *) stack;
    *uctx = *context;

    stack -= sizeof(uint64_t);
    *(uint64_t *) stack = (uint64_t) action->sa_restorer;

    task->ucontext = *context;

    ctx->reg.ss = 0x23;
    ctx->reg.cs = 0x1B;
    ctx->reg.rsp = stack;
    ctx->reg.rflags = 0x202;
    ctx->reg.cr3 = x86::get_cr3(task->proc->mem_ctx->get_page_map());

    ctx->reg.mxcsr = 0x1F80;
    ctx->reg.fcw = 0x33F;
    memset(ctx->sse_region, 0, 512);

    // [[noreturn]] sigenter_handler(void *handler_rip, bool is_sigaction, int sig, siginfo *info, ucontext_t *ctx)
    if (task->proc->trampoline) {
        ctx->reg.rip = task->proc->trampoline;
        ctx->reg.rdi = (uint64_t) action->handler.sa_sigaction;
        ctx->reg.rsi = action->handler.sa_sigaction != nullptr;
        ctx->reg.rdx = signal->signum;
        ctx->reg.rcx = (uint64_t) info;
        ctx->reg.r8 = (uint64_t) uctx;
    } else {
        ctx->reg.rip = (uint64_t) action->handler.sa_sigaction;
        ctx->reg.rdi = signal->signum;
        if (action->sa_flags & SA_SIGINFO) {
            ctx->reg.rsi = (uint64_t) info;
            ctx->reg.rdx = (uint64_t) uctx;
        }
    }
}