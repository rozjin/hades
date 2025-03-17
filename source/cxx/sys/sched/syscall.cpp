#include "arch/types.hpp"
#include "arch/vmm.hpp"
#include "arch/x86/smp.hpp"
#include "arch/x86/types.hpp"
#include "frg/allocation.hpp"
#include "ipc/evtable.hpp"
#include "util/lock.hpp"
#include <fs/vfs.hpp>
#include <mm/common.hpp>
#include <mm/vmm.hpp>
#include <sys/sched/sched.hpp>
#include <sys/sched/signal.hpp>
#include <sys/sched/time.hpp>
#include <cstddef>
#include <mm/mm.hpp>
#include <util/string.hpp>
#include <util/types.hpp>

extern "C" {
    extern void x86_sigreturn_exit(arch::irq_regs *r);
}

static bool has_recursive_access(vfs::node *target, uid_t effective_uid,
    gid_t effective_gid, uid_t real_uid, gid_t real_gid, mode_t mode, bool use_effective_id) {

    auto current = target;
    while (current) {
        if (!current->has_access(effective_uid, effective_gid, X_OK)) {
            return false;
        }

        current = current->parent;
    }

    if (!target->has_access(use_effective_id ? effective_uid : real_uid, use_effective_id ? effective_gid : real_gid, mode)) {
        return false;
    }

    return true;
}

// TODO: execveat
void syscall_exec(arch::irq_regs *r) {
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
    char **argv = (char **) kmalloc(sizeof(char *) * (argc + 1));
    char **envp = (char **) kmalloc(sizeof(char *) * (envc + 1));
    strcpy(path, in_path);

    for (size_t i = 0; i < envc; i++) {
        envp[i] = (char *) kmalloc(strlen(in_envp[i]));
        strcpy(envp[i], in_envp[i]);
    }

    for (size_t i = 0; i < argc; i++) {
        argv[i] = (char *) kmalloc(strlen(in_argv[i]));
        strcpy(argv[i], in_argv[i]);
    }    

    auto process = arch::get_process();
    auto current_task = arch::get_thread();

    auto fd = vfs::open(nullptr, path, process->fds, 0, 0, 0, 0);
    if (!fd) {
        arch::set_errno(EBADF);

        for (size_t i = 0; i < envc; i++) {
            kfree(envp[i]);
        }

        for (size_t i = 0; i < argc; i++) {
            kfree(argv[i]);
        }    

        kfree(path);
        kfree(argv);
        kfree(envp);
        vfs::close(fd);

        r->rax = -1;
        return;
    }

    auto node = fd->desc->node;
    if (!node->has_access(process->effective_uid, process->effective_gid, X_OK)) {
        arch::set_errno(EACCES);
        r->rax = -1;
        return;
    }

	bool is_suid = node->meta->st_mode & S_ISUID ? true : false;
	bool is_sgid = node->meta->st_mode & S_ISGID ? true : false;

    for (size_t i = 0; i < process->threads.size(); i++) {
        auto task = process->threads[i];
        if (task->tid == current_task->tid) {
            process->main_thread = task;
            continue;
        };

        arch::kill_thread(task);
        frg::destruct(memory::mm::heap, task);
    }

    process->main_thread = current_task;

    x86::cleanup_vmm_ctx(process);

    process->mem_ctx = vmm::create();
    process->mem_ctx->swap_in(); 
    current_task->mem_ctx = process->mem_ctx;
    current_task->ctx.reg.cr3 = x86::get_cr3(process->mem_ctx->get_page_map());
    
    current_task->proc->env = sched::process_env{};
    current_task->proc->env.proc = process;
 
    auto res = process->env.load_elf(path, fd);
    if (!res) {
        for (size_t i = 0; i < envc; i++) {
            kfree(envp[i]);
        }

        for (size_t i = 0; i < argc; i++) {
            kfree(argv[i]);
        }    

        kfree(path);
        kfree(argv);
        kfree(envp);

        r->rax = -1;
        return;
    }

    current_task->ustack = (uint64_t) process->mem_ctx->stack(nullptr, memory::user_stack_size, vmm::map_flags::USER | vmm::map_flags::WRITE | vmm::map_flags::DEMAND);

    arch::init_context(current_task, (void(*)()) process->env.entry, current_task->ustack, 3);
    current_task->pid = process->pid;
    current_task->proc = process;

    process->env.load_params(argv, envp);
    process->env.place_params(envp, argv, current_task);

    for (auto [fd_number, fd]: process->fds->fd_list) {
        if (fd == nullptr) continue;
        if (fd->flags & O_CLOEXEC) {
            vfs::close(fd);
        }
    }

    process->saved_uid = process->effective_uid;
    process->saved_gid = process->effective_gid;

    process->effective_uid = is_suid ? node->meta->st_uid : process->effective_uid;
    process->effective_gid = is_sgid ? node->meta->st_gid : process->effective_gid;

    current_task->in_syscall = false;
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

    for (size_t i = 0; i < envc; i++) {
        kfree(envp[i]);
    }

    for (size_t i = 0; i < argc; i++) {
        kfree(argv[i]);
    }    

    kfree(path);
    kfree(argv);
    kfree(envp);

    current_task->state = sched::thread::READY;
    process->did_exec = true;

    x86::get_locals()->ustack = current_task->ustack;
    auto iretq_regs = arch::sched_to_irq(&current_task->ctx.reg);

    x86::set_fcw(current_task->ctx.reg.fcw);
    x86::set_mxcsr(current_task->ctx.reg.mxcsr);
    x86::load_sse(current_task->ctx.sse_region);

    x86::swapgs();
    x86_sigreturn_exit(&iretq_regs);
}

void syscall_fork(arch::irq_regs *r) {
    auto child = sched::fork(arch::get_process(), arch::get_thread(), r);
    child->start();
    
    r->rax = child->pid;
}

void syscall_exit(arch::irq_regs *r) {
    auto process = arch::get_process();
    
    process->kill(r->rdi);

    arch::set_process(nullptr);
    arch::set_thread(arch::get_idle());
    arch::rstor_context(arch::get_idle(), r);

    auto iretq_regs = arch::sched_to_irq(&arch::get_idle()->ctx.reg);

    x86_sigreturn_exit(&iretq_regs);
}

void syscall_futex(arch::irq_regs *r) {
    uintptr_t uaddr = (uintptr_t) r->rdi;
    int op = r->rsi;
    uint32_t val = r->rdx;
    sched::timespec *timeout = (sched::timespec *) r->r10;

    r->rax = sched::do_futex(uaddr, op, val, timeout);
} 

void syscall_waitpid(arch::irq_regs *r) {
    int pid = r->rdi;
    int *status = (int *) r->rsi;
    int options = r->rdx;

    auto current_task = arch::get_thread();
    auto current_process = arch::get_process();

    auto [exit_status, exit_pid] = current_process->waitpid(pid, current_task, options);

    *status = exit_status;
    r->rax = exit_pid;
}

void syscall_sleep(arch::irq_regs *r) {
    time_t *secs = (time_t *) r->rdi;
    long *nanos = (long *) r->rsi;

    sched::timespec req = {
        .tv_sec = *secs,
        .tv_nsec = *nanos
    };

    auto task = arch::get_thread();
    auto [evt, thread] = task->wire.wait(evtable::TIME_WAKE, true, &req);
    if (evt < 0) {
        r->rax = req.tv_sec;
        return;
    }

    r->rax = 0;
}

void syscall_clock_gettime(arch::irq_regs *r) {
    clockid_t clkid = r->rdi;
    sched::timespec *spec = (sched::timespec *) r->rsi;

    switch(clkid) {
        case sched::CLOCK_REALTIME:
            *spec = sched::clock_rt;
            break;
        case sched::CLOCK_MONOTONIC:
            *spec = sched::clock_mono;
        default:
            arch::set_errno(EINVAL);
            r->rax = -1;
            return;
    }

    r->rax = 0;
}

void syscall_clock_get(arch::irq_regs *r) {
    clockid_t clkid = r->rdi;

    switch(clkid) {
        case sched::CLOCK_REALTIME:
            r->rax = sched::clock_rt.tv_nsec;
            break;
        case sched::CLOCK_MONOTONIC:
            r->rax = sched::clock_mono.tv_nsec;
        default:
            arch::set_errno(EINVAL);
            r->rax = -1;
            return;
    }
}

void syscall_getpid(arch::irq_regs *r) {
    r->rax = arch::get_process()->pid;
}

void syscall_getppid(arch::irq_regs *r) {
    if (arch::get_process()->parent == nullptr) {
        r->rax = 0;
        return;
    }
    
    r->rax = arch::get_process()->parent->pid;
}

void syscall_gettid(arch::irq_regs *r) {
    r->rax = arch::get_thread()->tid;
}

void syscall_setpgid(arch::irq_regs *r) {
    pid_t pid = r->rdi == 0 ? arch::get_process()->pid : r->rdi;
    pid_t pgid = r->rsi == 0 ? arch::get_process()->pid : r->rsi;

    auto current_process = arch::get_process();
    auto process = sched::get_process(pid);
    if (process == nullptr) {
        arch::set_errno(EINVAL);
        r->rax = -1;
        return;
    }

    if (process->group->pgid == pgid) {
        r->rax = 0;
        return;
    }

    if ((current_process->sess != process->sess) || (process->sess->leader_pgid == process->pid)) {
        arch::set_errno(EPERM);
        r->rax = -1;
        return;
    }

    if (process->pid != current_process->pid && 
        (process->did_exec || process->parent->pid != current_process->pid)) {
        arch::set_errno(EPERM);
        r->rax = -1;
        return;
    }

    auto old_group = process->group;
    sched::process_group *new_group = sched::get_process_group(pgid);
    if (new_group) {
        if (old_group && new_group->sess != old_group->sess) {
            arch::set_errno(EPERM);
            r->rax = -1;
            return;
        }

        process->group = new_group;
        new_group->add_process(process);
    } else {
        auto session = process->sess;
        auto group = sched::create_process_group(process);
    
        if (session) {
            group->sess = session;
            session->groups.push(group);
        }
    }

    if (old_group) {
        old_group->remove_process(process);
        if (old_group->process_count == 0) {
            old_group->sess->remove_group(old_group);
            sched::remove_process_group(old_group->pgid);
            frg::destruct(memory::mm::heap, old_group);            
        }
    }

    r->rax = 0;
}

void syscall_getpgid(arch::irq_regs *r) {
    pid_t pid = r->rdi == 0 ? arch::get_process()->pid : r->rdi;

    auto process = sched::get_process(pid);
    if (process == nullptr) {
        arch::set_errno(EINVAL);
        r->rax = -1;
        return;
    }
    
    if (process->sess != arch::get_process()->sess) {
        arch::set_errno(EPERM);
        r->rax = -1;
        return;
    }

    r->rax = process->group->pgid;
}

void syscall_setsid(arch::irq_regs *r) {
    auto current_process = arch::get_process();

    if (current_process->group->leader_pid == current_process->pid) {
        arch::set_errno(EPERM);
        r->rax = -1;
        return;
    }

    auto old_group = current_process->group;
    if (old_group) {
        old_group->remove_process(current_process);
        if (old_group->process_count == 0) {
            old_group->sess->remove_group(old_group);
            sched::remove_process_group(old_group->pgid);
            frg::destruct(memory::mm::heap, old_group);            
        }
    }

    auto group = sched::create_process_group(current_process);
    sched::create_session(current_process, group);

    r->rax = 0;
}

void syscall_getsid(arch::irq_regs *r) {
    r->rax = arch::get_process()->sess->sid;
}

void syscall_sigreturn(arch::irq_regs *r) {
    x86::irq_off();

    auto current_task = arch::get_thread();
    auto process = arch::get_process();

    auto ctx = &current_task->sig_ctx;

    util::lock_guard ctx_guard{ctx->lock};

    ctx->sigdelivered |= SIGMASK(current_task->ucontext.signum);
    ctx->wire.arise(evtable::SIGNAL);

    ctx_guard.~lock_guard();

    auto regs = &current_task->ucontext.ctx.reg;
    current_task->ctx.reg = *regs;

    current_task->dispatch_ready = false;
    current_task->pending_signal = false;
    current_task->in_syscall = false;

    auto tmp = current_task->kstack;
    current_task->kstack = current_task->sig_kstack;
    current_task->sig_kstack = tmp;

    tmp = current_task->ustack;
    current_task->ustack = current_task->sig_ustack;
    current_task->sig_ustack = tmp;

    auto iretq_regs = arch::sched_to_irq(regs);

    x86::set_fcw(regs->fcw);
    x86::set_mxcsr(regs->mxcsr);
    x86::load_sse(current_task->ucontext.ctx.sse_region);
    
    x86::set_user_fs(regs->fs);
    x86::set_user_gs(regs->gs);

    current_task->state = sched::thread::READY;
    process->mem_ctx->unmap((void *) current_task->ucontext.stack, 4 * memory::page_size, true);

    if (regs->cs & 0x3) {
        x86::swapgs();
    }

    x86_sigreturn_exit(&iretq_regs);
}

void syscall_sigenter(arch::irq_regs *r) {
    auto process = arch::get_process();
    
    util::lock_guard sig_guard{process->sig_lock};
    process->trampoline = r->rdi;
    
    r->rax = 0;
}

void syscall_sigaction(arch::irq_regs *r) {
    int sig = r->rdi;
    sched::signal::sigaction *act = (sched::signal::sigaction *) r->rsi;
    sched::signal::sigaction *old = (sched::signal::sigaction *) r->rdx;

    r->rax = sched::signal::do_sigaction(arch::get_process(), arch::get_thread(), sig, act, old);
}

void syscall_sigpending(arch::irq_regs *r) {
    sigset_t *set = (sigset_t *) r->rdi;
    sched::signal::do_sigpending(arch::get_thread(), set);
    r->rax = 0;
}

void syscall_sigprocmask(arch::irq_regs *r) {
    int how = r->rdi;
    sigset_t *set = (sigset_t *) r->rsi;
    sigset_t *old_set = (sigset_t *) r->rdx;

    r->rax = sched::signal::do_sigprocmask(arch::get_thread(), how, set, old_set);
}

void syscall_kill(arch::irq_regs *r) {
    pid_t pid = r->rdi;
    int sig = r->rsi;

    r->rax = sched::signal::do_kill(pid, sig);
}

void syscall_pause(arch::irq_regs *r) {
    auto task = arch::get_thread();
    sched::signal::wait_signal(task, ~0, nullptr);
    arch::set_errno(EINTR);
    r->rax = -1;
}

void syscall_sigsuspend(arch::irq_regs *r) {
    sigset_t *mask = (sigset_t *) r->rdi;

    auto task = arch::get_thread();

    sigset_t prev;

    sched::signal::do_sigprocmask(task, SIG_SETMASK, mask, &prev);
    sched::signal::wait_signal(task, ~(*mask), nullptr);
    sched::signal::do_sigprocmask(task, SIG_SETMASK, &prev, mask);

    arch::set_errno(EINTR);
    r->rax = -1;
}

void syscall_getcwd(arch::irq_regs *r) {
    char *buf = (char *) r->rdi;
    size_t size = r->rsi;

    auto process = arch::get_process();
    auto node = process->cwd;

    util::lock_guard guard{node->lock};
    auto path = vfs::get_absolute(node);

    if (path->size() <= size) {
        arch::copy_to_user(buf, path->data(), strlen(path->data()));
    } else {
        frg::destruct(memory::mm::heap, path);
        arch::set_errno(ERANGE);
        r->rax = 0;
        return;
    }

    frg::destruct(memory::mm::heap, path);
    r->rax = (uintptr_t) buf;
}

void syscall_chdir(arch::irq_regs *r) {
    const char *path = (char *) r->rdi;

    auto process = arch::get_process();
    auto node = vfs::resolve_at(path, process->cwd);
    if (node == nullptr || node->type != vfs::node::type::DIRECTORY) {
        r->rax = -1;
        return;
    }

    if (!has_recursive_access(node, process->effective_uid, process->effective_gid,
        0, 0, X_OK, true)) {
        arch::set_errno(EACCES);
        r->rax = -1;
        return;
    }

    process->cwd = node;
    r->rax = 0;
}

// User / Group functions

void syscall_getuid(arch::irq_regs *r) {
    r->rax = arch::get_process()->real_uid;
}

void syscall_geteuid(arch::irq_regs *r) {
    r->rax = arch::get_process()->effective_uid;
}

void syscall_getgid(arch::irq_regs *r) {
    r->rax = arch::get_process()->real_gid;
}

void syscall_getegid(arch::irq_regs *r) {
    r->rax = arch::get_process()->effective_gid;
}

void syscall_setuid(arch::irq_regs *r) {
    uid_t uid = r->rdi;

    auto process = arch::get_process();
    if (process->effective_uid == 0) {
        process->real_uid = uid;
        process->effective_uid = uid;
        process->saved_uid = uid;
        r->rax = 0;
        return;
    }

    if (process->real_uid == uid || process->effective_uid == uid || process->saved_uid == uid) {
        process->effective_uid = uid;
        r->rax = 0;
        return;
    }

    arch::set_errno(EPERM);
    r->rax = -1;
}

void syscall_seteuid(arch::irq_regs *r) {
    uid_t euid = r->rdi;

    auto process = arch::get_process();
    if (process->real_uid == euid || process->effective_uid == euid || process->saved_uid == euid) {
        process->effective_uid = euid;
        r->rax = 0;
        return;
    }

    arch::set_errno(EPERM);
    r->rax = -1;
}

void syscall_setgid(arch::irq_regs *r) {
    gid_t gid = r->rdi;

    auto process = arch::get_process();
    if (process->effective_gid == 0) {
        process->real_gid = gid;
        process->effective_gid = gid;
        process->saved_gid = gid;
        r->rax = 0;
        return;
    }

    if (process->real_gid == gid || process->effective_gid == gid || process->saved_gid == gid) {
        process->effective_gid = gid;
        r->rax = 0;
        return;
    }

    arch::set_errno(EPERM);
    r->rax = -1;
}

void syscall_setegid(arch::irq_regs *r) {
    gid_t egid = r->rdi;

    auto process = arch::get_process();
    if (process->real_gid == egid || process->effective_gid == egid || process->saved_gid == egid) {
        process->effective_gid = egid;
        r->rax = 0;
        return;
    }

    arch::set_errno(EPERM);
    r->rax = -1;
}
