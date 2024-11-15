#include "fs/vfs.hpp"
#include "mm/common.hpp"
#include "mm/vmm.hpp"
#include "sys/sched/sched.hpp"
#include "sys/sched/signal.hpp"
#include "sys/sched/time.hpp"
#include "sys/smp.hpp"
#include <cstddef>
#include <mm/mm.hpp>
#include <sys/irq.hpp>
#include <util/string.hpp>

extern "C" {
    extern void sigreturn_exit(irq::regs *r);
}

void syscall_exec(irq::regs *r) {
    char *in_path = (char *) r->rdi;
    char **in_argv = (char **) r->rsi;
    char **in_envp = (char **) r->rdx;

    size_t envc = 0;
    for (;; envc++) {
        if (in_envp[envc] == nullptr) {
            break;
        }
    }

    size_t argc = 0;
    for (;; argc++) {
        if (in_argv[argc] == nullptr) {
            break;
        }
    }

    char *path = (char *) kmalloc(strlen(in_path) + 1);
    char **argv = (char **) kmalloc(sizeof(char *) * argc);
    char **envp = (char **) kmalloc(sizeof(char *) * envc);
    strcpy(path, in_path);

    for (size_t i = 0; i < envc; i++) {
        envp[i] = (char *) kmalloc(strlen(in_envp[i]));
        strcpy(envp[i], in_envp[i]);
    }

    for (size_t i = 0; i < argc; i++) {
        envp[i] = (char *) kmalloc(strlen(in_argv[i]));
        strcpy(argv[i], in_argv[i]);
    }    

    auto process = smp::get_process();
    auto current_task = smp::get_thread();
    auto fd = vfs::open(nullptr, path, process->fds, 0, 0);
    if (!fd) {
        smp::set_errno(EBADF);
        kfree(path);
        kfree(argv);
        kfree(envp);
        vfs::close(fd);

        r->rax = -1;
        return;
    }

    for (size_t i = 0; i < process->threads.size(); i++) {
        auto task = process->threads[i];
        if (task == nullptr) continue;
        if (task->tid == current_task->tid) continue;

        task->kill();
    }

    process->main_thread = current_task;
    current_task->stop();

    memory::vmm::destroy(process->mem_ctx);

    process->mem_ctx = (memory::vmm::vmm_ctx *) memory::vmm::create();
    memory::vmm::change(process->mem_ctx);

    auto res = process->env.load_elf(path, fd);
    if (!res) {
        kfree(path);
        kfree(argv);
        kfree(envp);

        r->rax = -1;
        return;
    }

    current_task->ustack = (uint64_t) memory::vmm::map(nullptr, 4 * memory::common::page_size, VMM_USER | VMM_WRITE, (void *) process->mem_ctx) + (4 * memory::common::page_size);
    current_task->reg.cr3 = (uint64_t) memory::vmm::cr3(process->mem_ctx);
    current_task->reg.rsp = current_task->ustack;

    current_task->reg.rip = process->env.entry;
    current_task->reg.cs = 0x1B;
    current_task->reg.ss = 0x23;
    current_task->reg.rflags = 0x202;

    current_task->proc->env.load_params(envp, argv);
    current_task->proc->env.place_params(envp, argv, current_task);

    for (auto [fd_number, fd]: process->fds->fd_list) {
        if (fd->flags & O_CLOEXEC) {
            vfs::close(fd);
        }
    }

    
    for (size_t i = 0; i < SIGNAL_MAX; i++) {
        sched::signal::sigaction *act = &process->sigactions[i];
        auto handler = act->handler.sa_handler;
        memset(act, 0, sizeof(sched::signal::sigaction));

        if (handler == SIG_IGN) {
            act->handler.sa_handler = (void(*)(int)) SIG_IGN;
        } else {
            act->handler.sa_handler = (void(*)(int)) SIG_DFL;
        }
    }

    current_task->cont();
    process->did_exec = true;
    sched::retick();
}

void syscall_fork(irq::regs *r) {
    auto child = sched::fork(smp::get_process(), smp::get_thread());
    
    child->main_thread->reg.rax = 0;
    child->main_thread->reg.rip = r->rcx;
    child->main_thread->reg.rflags = r->r11;

    child->start();
    
    r->rax = child->pid;
}

void syscall_exit(irq::regs *r) {
    auto process = smp::get_process();
    process->kill(r->rdi);
}

void syscall_futex(irq::regs *r) {
    uintptr_t uaddr = (uintptr_t) r->rdi;
    int op = r->rsi;
    uint32_t val = r->rdx;
    sched::timespec *timeout = (sched::timespec *) r->r10;

    r->rax = sched::do_futex(uaddr, op, val, timeout);
} 

void syscall_waitpid(irq::regs *r) {
    int pid = r->rdi;
    int *status = (int *) r->rsi;
    int options = r->rdx;

    auto current_task = smp::get_thread();
    auto current_process = smp::get_process();

    auto [exit_status, exit_pid] = current_process->waitpid(pid, current_task, options);

    *status = exit_status;
    r->rax = exit_pid;
}

void syscall_usleep(irq::regs *r) {
    sched::timespec *req = (sched::timespec *) r->rdi;
    sched::timespec *rem = (sched::timespec *) r->rsi;

    auto process = smp::get_process();
    process->waitq->set_timer(req);
    for (;;) {
        auto waker = process->waitq->block(smp::get_thread());
        if (waker == nullptr) {
            r->rax = -1;
            goto finish;
        }
    }

    *rem = *req;
    r->rax = 0;
    finish:
        process->waitq->timer_trigger->remove(process->waitq);
}

void syscall_clock_gettime(irq::regs *r) {
    clockid_t clkid = r->rdi;
    sched::timespec *spec = (sched::timespec *) r->rsi;

    switch(clkid) {
        case sched::CLOCK_REALTIME:
            *spec = sched::clock_rt;
            break;
        case sched::CLOCK_MONOTONIC:
            *spec = sched::clock_mono;
        default:
            smp::set_errno(EINVAL);
            r->rax = -1;
            return;
    }

    r->rax = 0;
}

void syscall_clock_get(irq::regs *r) {
    clockid_t clkid = r->rdi;

    switch(clkid) {
        case sched::CLOCK_REALTIME:
            r->rax = sched::clock_rt.tv_nsec;
            break;
        case sched::CLOCK_MONOTONIC:
            r->rax = sched::clock_mono.tv_nsec;
        default:
            smp::set_errno(EINVAL);
            r->rax = -1;
            return;
    }
}

void syscall_getpid(irq::regs *r) {
    r->rax = smp::get_process()->pid;
}

void syscall_getppid(irq::regs *r) {
    r->rax = smp::get_process()->parent->pid;
}

void syscall_gettid(irq::regs *r) {
    r->rax = smp::get_thread()->tid;
}

void syscall_setpgid(irq::regs *r) {
    pid_t pid = r->rdi == 0 ? smp::get_process()->pid : r->rdi;
    pid_t pgid = r->rsi == 0 ? smp::get_process()->pid : r->rsi;

    auto current_process = smp::get_process();
    auto process = sched::processes[pid];
    if (process == nullptr) {
        smp::set_errno(EINVAL);
        r->rax = -1;
        return;
    }

    if (process->group->pgid == pgid) {
        r->rax = 0;
        return;
    }

    if ((current_process->sess != process->sess) || (process->sess->leader_pgid == process->pid)) {
        smp::set_errno(EPERM);
        r->rax = -1;
        return;
    }

    if (process->pid != current_process->pid && 
        (process->did_exec || process->parent->pid != current_process->pid)) {
        smp::set_errno(EPERM);
        r->rax = -1;
        return;
    }

    auto session = process->sess;
    auto group = frg::construct<sched::process_group>(memory::mm::heap);

    group->pgid = pgid;
    group->sess = session;
    group->leader_pid = process->pid;
    group->leader = process;
    group->procs = frg::vector<sched::process *, memory::mm::heap_allocator>();

    session->groups.push(group);
    group->procs.push(process);

    process->group = group;

    r->rax = 0;
}

void syscall_getpgid(irq::regs *r) {
    pid_t pid = r->rdi == 0 ? smp::get_process()->pid : r->rdi;

    auto process = sched::processes[pid];
    if (process == nullptr) {
        smp::set_errno(EINVAL);
        r->rax = -1;
        return;
    }
    
    if (process->sess != smp::get_process()->sess) {
        smp::set_errno(EPERM);
        r->rax = -1;
        return;
    }

    r->rax = process->group->pgid;
}

void syscall_setsid(irq::regs *r) {
    auto current_process = smp::get_process();

    if (current_process->group->leader_pid == current_process->pid) {
        smp::set_errno(EPERM);
        r->rax = -1;
        return;
    }

    auto session = frg::construct<sched::session>(memory::mm::heap);
    auto group = frg::construct<sched::process_group>(memory::mm::heap);

    pid_t sid = current_process->pid;
    pid_t pgid = current_process->pid;

    session->sid = sid;
    session->leader_pgid = pgid;

    group->pgid = pgid;
    group->leader_pid = current_process->pid;
    group->leader = current_process;
    group->sess = session;
    group->procs = frg::vector<sched::process *, memory::mm::heap_allocator>();

    group->procs.push(current_process);
    session->groups.push(group);

    current_process->sess = session;
    current_process->group = group;
    
    r->rax = 0;
}

void syscall_getsid(irq::regs *r) {
    r->rax = smp::get_process()->sess->sid;
}

void syscall_sigreturn(irq::regs *r) {
    irq::off();

    auto current_task = smp::get_thread();
    auto process = smp::get_process();

    auto sig_queue = &process->sig_queue;
    sig_queue->sig_lock.irq_acquire();

    auto signal = &sig_queue->queue[current_task->sig_context.signum - 1];
    sig_queue->sigdelivered |= SIGMASK(current_task->sig_context.signum);
    signal->notify_queue->arise(smp::get_thread());
    frg::destruct(memory::mm::heap, signal->notify_queue);

    sig_queue->sig_lock.irq_release();

    auto regs = &current_task->sig_context.regs;
    current_task->reg = *regs;

    memory::vmm::unmap((void *) current_task->sig_context.stack, 4 * memory::common::page_size, process->mem_ctx);

    if (process->block_signals) {
        current_task->state = sched::thread::READY;
        process->block_signals = true;
    }

    auto tmp = current_task->kstack;
    current_task->kstack = current_task->sig_kstack;
    current_task->sig_kstack = tmp;

    tmp = current_task->ustack;
    current_task->ustack = current_task->sig_ustack;
    current_task->sig_ustack = tmp;

    if (regs->cs & 0x3) {
        io::swapgs();
    }

    auto iretq_regs = sched::to_irq(regs);

    sched::set_fcw(regs->fcw);
    sched::set_mxcsr(regs->mxcsr);
    sched::load_sse(current_task->sig_context.sse_region);
    
    sigreturn_exit(&iretq_regs);
}

void syscall_sigenter(irq::regs *r) {
    auto process = smp::get_process();
    process->sig_lock.irq_acquire();
    process->sigenter_rip = r->rdi;
    process->sig_lock.irq_release();
    
    r->rax = 0;
}

void syscall_sigaction(irq::regs *r) {
    int sig = r->rdi;
    sched::signal::sigaction *act = (sched::signal::sigaction *) r->rsi;
    sched::signal::sigaction *old = (sched::signal::sigaction *) r->rdx;

    r->rax = sched::signal::do_sigaction(smp::get_process(), sig, act, old);
}

void syscall_sigpending(irq::regs *r) {
    sigset_t *set = (sigset_t *) r->rdi;
    sched::signal::do_sigpending(smp::get_process(), set);
    r->rax = 0;
}

void syscall_sigprocmask(irq::regs *r) {
    int how = r->rdi;
    sigset_t *set = (sigset_t *) r->rsi;
    sigset_t *old_set = (sigset_t *) r->rdx;

    r->rax = sched::signal::do_sigprocmask(smp::get_process(), how, set, old_set);
}

void syscall_kill(irq::regs *r) {
    pid_t pid = r->rdi;
    int sig = r->rsi;

    r->rax = sched::signal::do_kill(pid, sig);
}

void syscall_pause(irq::regs *r) {
    auto task = smp::get_thread();
    auto process = smp::get_process();
    auto sig_queue = &process->sig_queue;

    sched::signal::wait_signal(task, sig_queue, ~0, nullptr);
    smp::set_errno(EINTR);
    r->rax = -1;
}

void syscall_sigsuspend(irq::regs *r) {
    sigset_t *mask = (sigset_t *) r->rdi;

    auto task = smp::get_thread();
    auto process = smp::get_process();
    auto sig_queue = &process->sig_queue;

    sigset_t prev;

    sched::signal::do_sigprocmask(process, SIG_SETMASK, mask, &prev);
    sched::signal::wait_signal(task, sig_queue, ~(*mask), nullptr);
    sched::signal::do_sigprocmask(process, SIG_SETMASK, &prev, mask);

    smp::set_errno(EINTR);
    r->rax = -1;
}

void syscall_getcwd(irq::regs *r) {
    char *buf = (char *) r->rdi;
    size_t size = r->rsi;

    auto process = smp::get_process();
    auto node = process->cwd;
    node->lock.irq_acquire();

    auto path = vfs::get_absolute(node);
    if (path->size() <= size) {
        memcpy(buf, path->data(), strlen(path->data()));
    } else {
        frg::destruct(memory::mm::heap, path);
        node->lock.irq_release();

        smp::set_errno(ERANGE);
        r->rax = 0;
        return;
    }

    frg::destruct(memory::mm::heap, path);
    node->lock.irq_release();
    r->rax = (uintptr_t) buf;
}

void syscall_chdir(irq::regs *r) {
    const char *path = (char *) r->rdi;

    auto process = smp::get_process();
    auto node = vfs::resolve_at(path, process->cwd);
    if (node == nullptr || node->type != vfs::node::type::DIRECTORY) {
        r->rax = -1;
        return;
    }

    process->cwd = node;
    r->rax = 0;
}