#include "arch/x86/smp.hpp"
#include "arch/x86/types.hpp"
#include "frg/rcu_radixtree.hpp"
#include "frg/variant.hpp"
#include "ipc/evtable.hpp"
#include "util/types.hpp"
#include <arch/types.hpp>
#include <cstddef>
#include <cstdint>
#include <driver/tty/tty.hpp>
#include <fs/vfs.hpp>
#include <frg/allocation.hpp>
#include <frg/vector.hpp>
#include <mm/mm.hpp>
#include <mm/pmm.hpp>
#include <mm/vmm.hpp>
#include <sys/sched/sched.hpp>
#include <sys/sched/signal.hpp>
#include <util/io.hpp>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>
#include <util/lock.hpp>
#include <util/elf.hpp>

void sched::init() {
    arch::init_sched();
}

sched::thread *sched::create_thread(void (*main)(), uint64_t rsp, vmm::vmm_ctx *ctx, uint8_t privilege, bool assign_tid) {
    return frg::construct<thread>(memory::mm::heap,(uintptr_t) pmm::stack(x86::initialStackSize), rsp,
        (uintptr_t) pmm::stack(x86::initialStackSize), ctx,
        main, rsp, privilege,
        assign_tid);
}

sched::process *sched::create_process(char *name, void (*main)(), uint64_t rsp, vmm::vmm_ctx *ctx, uint8_t privilege) {
    process *proc = frg::construct<process>(memory::mm::heap);

    proc->threads = frg::vector<thread *, memory::mm::heap_allocator>();
    proc->children = frg::vector<process *, memory::mm::heap_allocator>();
    proc->zombies = frg::vector<process *, memory::mm::heap_allocator>();
    proc->fds = vfs::make_table();

    proc->main_thread = create_thread(main, rsp, ctx, privilege);
    proc->main_thread->proc = proc;
    proc->main_thread->pid = proc->pid;
    proc->threads.push_back(proc->main_thread);

    pid_t pid = add_process(proc);
    proc->pid = pid;
    proc->main_thread->pid = pid;

    proc->env = process_env{};
    proc->env.proc = proc;
    proc->mem_ctx = ctx;
    proc->parent = nullptr;
    proc->group = nullptr;
    proc->sess = nullptr;

    proc->trampoline = 0;
    // default sigactions
    for (size_t i = 0; i < SIGNAL_MAX; i++) {
        signal::sigaction *sa = &proc->sigactions[i];
        sa->handler.sa_sigaction = (void (*)(int, signal::siginfo *, void *)) SIG_DFL;
    }

    proc->real_uid = 0;
    proc->effective_uid = 0;
    proc->saved_uid = 0;

    proc->real_gid = 0;
    proc->effective_gid = 0;
    proc->saved_gid = 0;

    proc->umask = 022;

    proc->privilege = privilege;
    proc->status = WCONTINUED_CONSTRUCT;

    return proc;
}

sched::process_group *sched::create_process_group(process *leader) {
    auto group = frg::construct<sched::process_group>(memory::mm::heap, leader);
    add_process_group(group);

    return group;
}

sched::session *sched::create_session(process *leader, process_group *group) {
    auto sess = frg::construct<sched::session>(memory::mm::heap, leader, group);
    add_session(sess);

    return sess;
}

sched::thread *sched::fork(thread *original, vmm::vmm_ctx *ctx, arch::irq_regs *r) {
    return frg::construct<thread>(memory::mm::heap, original, ctx, r,
        (uintptr_t) pmm::stack(x86::initialStackSize), (uintptr_t) pmm::stack(x86::initialStackSize));
}

sched::process *sched::fork(process *original, thread *caller, arch::irq_regs *r) {
    process *proc = frg::construct<process>(memory::mm::heap);

    proc->threads = frg::vector<thread *, memory::mm::heap_allocator>();
    proc->children = frg::vector<process *, memory::mm::heap_allocator>();
    proc->zombies = frg::vector<process *, memory::mm::heap_allocator>();
    proc->fds = vfs::copy_table(original->fds);
    proc->cwd = original->cwd;

    proc->parent = original;
    proc->ppid = original->pid;
    proc->trampoline = original->trampoline;
    memcpy(&proc->sigactions, &original->sigactions, SIGNAL_MAX * sizeof(signal::sigaction));

    proc->env = original->env;
    proc->env.proc = proc;
    proc->mem_ctx = original->mem_ctx->fork();

    proc->main_thread = fork(caller, proc->mem_ctx, r);
    proc->main_thread->proc = proc;
    proc->threads.push_back(proc->main_thread);

    pid_t pid = add_process(proc);
    proc->pid = pid;
    proc->main_thread->pid = pid;

    proc->sess = original->sess;
    if (original->group) {
        original->group->add_process(proc);
    }

    if (original->sess) {
        proc->sess = original->sess;
    }

    proc->status = WCONTINUED_CONSTRUCT;

    proc->real_uid = original->real_uid;
    proc->effective_uid = original->effective_uid;
    proc->saved_uid = original->saved_uid;

    proc->real_gid = original->real_gid;
    proc->effective_gid = original->effective_gid;
    proc->saved_gid = original->saved_gid;

    proc->umask  = original->umask;

    original->children.push_back(proc);
    return proc;
}

int sched::do_futex(uintptr_t vaddr, int op, int expected, timespec *timeout) {
    return arch::do_futex(vaddr, op, expected, timeout);
}

sched::thread *sched::process::pick_thread(int signum) {
    for (size_t i = 0; i < threads.size(); i++) {
        if (threads[i]->state == thread::DEAD) continue;
        if (threads[i]->sig_ctx.sigpending & SIGMASK(signum)) continue;

        return threads[i];
    }

    return nullptr;
}

void sched::process::start() {
    main_thread->start();
}

void sched::process::kill(int exit_code) {
    if (this->pid == 0) {
        panic("Init exited.");
    }

    for (size_t i = 0; i < this->threads.size(); i++) {
        auto task = this->threads[i];
        if (task->tid == arch::get_tid()) {
            this->main_thread = task;
            continue;
        };

        arch::kill_thread(task);
        frg::destruct(memory::mm::heap, task);
    }

    arch::cleanup_vmm_ctx(this);

    util::lock_guard guard{parent->lock};

    for (size_t i = 0; i < children.size(); i++) {
        auto child = children[i];
        child->parent = parent;
        child->ppid = parent->pid;
        parent->children.push(child);
    }

    for (size_t i = 0; i < zombies.size(); i++) {
        auto zombie = zombies[i];
        zombie->parent = parent;
        zombie->ppid = parent->pid;
        parent->zombies.push(zombie);
    }

    parent->children.erase(this);
    parent->zombies.push_back(this);

    if (group) {
        group->remove_process(this);
        if (group->leader_pid == this->pid) {
            if (group->process_count == 0) {
                group->sess->remove_group(group);
                remove_process_group(group->pgid);
    
                frg::destruct(memory::mm::heap, group);
            } else {
                bool is_orphan = true;
                for (size_t i = 0; i < group->procs.size(); i++) {
                    sched::process *proc = group->procs[i];
                    if (proc->parent->group != group && proc->parent->group->sess != proc->sess) {
                        is_orphan = false;
                    }
                }
    
                if (is_orphan) {
                    signal::send_group(nullptr, group, SIGHUP);
                    signal::send_group(nullptr, group, SIGCONT);
                }
            }
        }
    }

    if (sess) {
        if (sess->leader_pgid == this->pid) {
            if (sess->tty) {
                sess->tty->sess = nullptr;
                signal::send_group(nullptr, sess->tty->fg, SIGHUP);
    
                auto foreground_group = sess->tty->fg;
                if (foreground_group) {
                    signal::send_group(nullptr, foreground_group, SIGHUP);
                }
            }
    
            for (size_t i = 0; i < sess->groups.size(); i++) {
                auto group = sess->groups[i];
    
                group->sess = nullptr;
                for (size_t j = 0; j < group->procs.size(); j++) {
                    auto process = group->procs[j];
    
                    process->sess = nullptr;
                }
            }
    
            sess->groups.clear();
    
            remove_session(sess->sid);
            frg::destruct(memory::mm::heap, sess);
        }
    }

    status = WEXITED_CONSTRUCT(exit_code) | STATUS_CHANGED;
    
    signal::send_process(nullptr, this->parent, SIGCHLD);
    parent->wire.arise(evtable::PROCESS_STATUS_CHANGE);

    main_thread->dispatch_ready = false;
    main_thread->pending_signal = false;
    main_thread->in_syscall = true;

    arch::kill_thread(main_thread);
}

void sched::process::suspend() {
    for (size_t i = 0; i < threads.size(); i++) {
        auto task = threads[i];
        task->stop();
    }

    status = WSTOPPED_CONSTRUCT | STATUS_CHANGED;
    signal::send_process(nullptr, parent, SIGCHLD);
    parent->wire.arise(evtable::PROCESS_STATUS_CHANGE);
}

void sched::process::cont() {
    for (size_t i = 0; i < threads.size(); i++) {
        auto task = threads[i];
        task->cont();
    }

    status = WCONTINUED_CONSTRUCT | STATUS_CHANGED;
    signal::send_process(nullptr, parent, SIGCHLD);
    parent->wire.arise(evtable::PROCESS_STATUS_CHANGE);
}

void sched::thread::start() {
    arch::start_thread(this);
    if (this->proc && WIFSTOPPED(this->proc->status)) {
        this->proc->status = WCONTINUED_CONSTRUCT | STATUS_CHANGED;
    }
}

void sched::thread::stop() {
    arch::stop_thread(this);
}

void sched::thread::cont() {
    arch::start_thread(this);
}

void sched::process::add_thread(thread *task) {
    util::lock_guard guard{this->lock};

    task->proc = this;
    task->pid = this->pid;
    this->threads.push(task);
}

void reap_process(sched::process *zombie) {
    auto task = zombie->main_thread;
    sched::remove_process(zombie->pid);

    frg::destruct(memory::mm::heap, task);
    frg::destruct(memory::mm::heap, zombie);
}

frg::tuple<int, pid_t> sched::process::waitpid(pid_t pid, thread *waiter, int options) {
    // Reap zombies first
    util::lock_guard guard{this->lock};
    for (size_t i = 0; i < zombies.size(); i++) {
        process *zombie = zombies[i];
        if (pid < -1) {
            if (zombie->group->pgid != zombie->pid) {
                continue;
            }
        } else if (pid == 0) {
            if (zombie->group->pgid != group->pgid) {
                continue;
            }
        } else if (pid > 0) {
            if (zombie->pid != pid) {
                continue;
            }
        }

        zombies.erase(zombie);

        uint8_t status = zombie->status;
        pid_t pid = zombie->pid;
        reap_process(zombie);

        return {status, pid};
    }

    if (options & WNOHANG) {
        return {0, 0};
    }

    guard.~lock_guard();

    process *proc = nullptr;
    pid_t return_pid = 0;
    int exit_status = 0;

    do_wait:
        while (true) {
            auto [evt, thread] = wire.wait(evtable::PROCESS_STATUS_CHANGE, true);
            if (evt < 0) {
                return {0, -1};
            }

            if (thread->proc->status & STATUS_CHANGED) {
                thread->proc->status &= ~STATUS_CHANGED;
            }

            if (pid < -1 && thread->proc->group->pgid != pid) {
                continue;
            } else if (pid == 0 && thread->proc->group->pgid != group->pgid) {
                continue;
            } else if (pid > 0 && thread->pid != pid){
                continue;
            }

            proc = thread->proc;
            break;
        }
        
        if (!(options & WUNTRACED) && WIFSTOPPED(proc->status)) goto do_wait;
        if (!(options & WUNTRACED) && WIFCONTINUED(proc->status)) goto do_wait;

        return_pid = proc->pid;
        exit_status = proc->status;

        util::lock_guard reguard{this->lock};
        if (!WIFSTOPPED(proc->status) && (WIFEXITED(proc->status) || WIFSIGNALED(proc->status))) {
            zombies.erase(proc);
            reap_process(proc);
        }

        return {exit_status, return_pid};
}


void sched::swap_task(arch::irq_regs *r) {
    auto running_task = arch::get_thread();
    arch::save_context(r, running_task);

    auto [next_tid, next_task] = pick_task(); 
    if (next_tid == arch::get_idle_tid()) {
        if (arch::get_tid() != arch::get_idle_tid() && arch::get_pid() != -1) {
            if (signal::process_signals(running_task->proc, running_task) == 0) {
                goto swap_regs;
            }
        }
 
        arch::set_process(nullptr);
        arch::set_thread(next_task);

        running_task = next_task;

        swap_regs:
        arch::rstor_context(running_task, r);
    } else {
        arch::rstor_context(next_task, r);
        arch::set_process(next_task->proc);
        arch::set_thread(next_task);

        running_task = next_task;
        running_task->running = true;
        running_task->state = thread::RUNNING;

        if (next_task->pid != -1) {
            signal::process_signals(next_task->proc, next_task);
        }
    }
}