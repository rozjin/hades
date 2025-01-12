#include "arch/x86/types.hpp"
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
#include <sys/sched/wait.hpp>
#include <sys/sched/signal.hpp>
#include <util/io.hpp>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>
#include <util/lock.hpp>
#include <util/elf.hpp>

util::lock sched::sched_lock{};

void sched::init() {
    arch::init_features();
    arch::init_sched();
}

sched::thread *sched::create_thread(void (*main)(), uint64_t rsp, vmm::vmm_ctx *ctx, uint8_t privilege) {
    thread *task = frg::construct<thread>(memory::mm::heap);

    task->kstack = (size_t) memory::pmm::stack(4);
    task->ustack = rsp;

    task->sig_ctx = signal::thread_ctx{};
    task->sig_ctx.waitq = frg::construct<ipc::queue>(memory::mm::heap);

    task->sig_kstack = (size_t) memory::pmm::stack(4);
    task->sig_ustack = (size_t) memory::pmm::stack(4);
    task->mem_ctx = ctx;

    task->waitq  = frg::construct<ipc::queue>(memory::mm::heap);
    task->dispatch_ready = false;
    task->pending_signal = false;
    task->in_syscall = false;

    arch::init_context(task, main, rsp, privilege);

    task->state = sched::thread::READY;
    task->cpu = -1;

    return task;
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

    proc->env = process_env{};
    proc->env.proc = proc;
    proc->mem_ctx = ctx;
    proc->parent = nullptr;
    proc->group = nullptr;
    proc->sess = nullptr;

    proc->lock = util::lock();
    proc->sig_lock = util::lock();
    proc->trampoline = 0;
    // default sigactions
    for (size_t i = 0; i < SIGNAL_MAX; i++) {
        signal::sigaction *sa = &proc->sigactions[i];
        sa->handler.sa_sigaction = (void (*)(int, signal::siginfo *, void *)) SIG_DFL;
    }

    proc->sig_ctx = signal::process_ctx{};

    proc->waitq = frg::construct<ipc::queue>(memory::mm::heap);;
    proc->notify_status = frg::construct<ipc::trigger>(memory::mm::heap);;

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
    return frg::construct<sched::process_group>(memory::mm::heap, leader);
}

sched::session *sched::create_session(process *leader, process_group *group) {
    return frg::construct<sched::session>(memory::mm::heap, leader, group);
}

sched::thread *sched::fork(thread *original, vmm::vmm_ctx *ctx, arch::irq_regs *r) {
    thread *task = frg::construct<thread>(memory::mm::heap);

    task->kstack = (size_t) memory::pmm::stack(4);
    task->sig_kstack = (size_t) memory::pmm::stack(4);

    task->sig_ustack = original->sig_ustack;
    task->ustack = original->ustack;

    task->sig_ctx = signal::thread_ctx{};
    task->sig_ctx.waitq = frg::construct<ipc::queue>(memory::mm::heap);
    task->sig_ctx.sigmask = original->sig_ctx.sigmask;

    task->mem_ctx = ctx;

    arch::fork_context(original, task, r);

    task->waitq = frg::construct<ipc::queue>(memory::mm::heap);
    task->dispatch_ready = original->dispatch_ready;
    task->pending_signal = original->pending_signal;
    task->in_syscall = original->in_syscall;

    task->state = thread::READY;
    task->cpu = -1;

    return task;
}

sched::process *sched::fork(process *original, thread *caller, arch::irq_regs *r) {
    sched_lock.irq_acquire();

    process *proc = frg::construct<process>(memory::mm::heap);

    proc->threads = frg::vector<thread *, memory::mm::heap_allocator>();
    proc->children = frg::vector<process *, memory::mm::heap_allocator>();
    proc->zombies = frg::vector<process *, memory::mm::heap_allocator>();
    proc->fds = vfs::copy_table(original->fds);
    proc->cwd = original->cwd;

    proc->parent = original;
    proc->ppid = original->ppid;
    proc->trampoline = original->trampoline;
    memcpy(&proc->sigactions, &original->sigactions, SIGNAL_MAX * sizeof(signal::sigaction));

    proc->env = original->env;
    proc->env.proc = proc;
    proc->mem_ctx = original->mem_ctx->fork();

    proc->main_thread = fork(caller, proc->mem_ctx, r);
    proc->main_thread->proc = proc;
    proc->threads.push_back(proc->main_thread);

    proc->sess = original->sess;
    if (original->group) {
        original->group->add_process(proc);
    }

    if (original->sess) {
        proc->sess = original->sess;
    }

    proc->lock = util::lock();
    proc->sig_lock = util::lock();
    proc->status = WCONTINUED_CONSTRUCT;

    proc->real_uid = original->real_uid;
    proc->effective_uid = original->effective_uid;
    proc->saved_uid = original->saved_uid;

    proc->real_gid = original->real_gid;
    proc->effective_gid = original->effective_gid;
    proc->saved_gid = original->saved_gid;

    proc->umask  = original->umask;

    proc->sig_ctx = signal::process_ctx{};

    proc->waitq = frg::construct<ipc::queue>(memory::mm::heap);
    proc->notify_status = frg::construct<ipc::trigger>(memory::mm::heap);
    proc->notify_status->add(original->waitq);

    original->children.push_back(proc);

    sched_lock.irq_release();

    return proc;
}

int sched::do_futex(uintptr_t vaddr, int op, int expected, timespec *timeout) {
    return arch::do_futex(vaddr, op, expected, timeout);
}

sched::thread *sched::process::pick_thread(int signum) {
    for (size_t i = 0; i < threads.size(); i++) {
        if (threads[i] == nullptr) continue;
        if (threads[i]->state == thread::DEAD) continue;
        if (threads[i]->sig_ctx.sigpending & SIGMASK(signum)) continue;

        return threads[i];
    }

    return nullptr;
}

sched::process *sched::find_process(pid_t pid) {
    for (size_t i = 0; i < processes.size(); i++) {
        process *proc = processes[i];
        if (proc->pid == pid) {
            return proc;
        }
    }

    return nullptr;
}

int64_t sched::process::start() {
    sched_lock.irq_acquire();

    processes.push_back(this);
    pid_t new_pid = processes.size() - 1;
    this->pid = new_pid;
    main_thread->pid = new_pid;
    this->status = WCONTINUED_CONSTRUCT;

    sched_lock.irq_release();

    main_thread->start();

    return pid;
}

void sched::process::kill(int exit_code) {
    if (this->pid == 0) {
        panic("Init exited.");
    }

    for (size_t i = 0; i < this->threads.size(); i++) {
        auto task = this->threads[i];
        if (task == nullptr) continue;
        if (task->tid == arch::get_tid()) {
            this->main_thread = task;
            continue;
        };

        task->kill();
        frg::destruct(memory::mm::heap, task);
    }

    vfs::delete_table(this->fds);
    arch::cleanup_vmm_ctx(this);
    signal::send_process(nullptr, this->parent, SIGCHLD);

    sched_lock.irq_acquire();
    for (size_t i = 0; i < children.size(); i++) {
        auto child = children[i];
        if (child == nullptr) continue;

        child->notify_status->clear();
        child->notify_status->add(parent->waitq);

        child->parent = parent;
        child->ppid = parent->ppid;
        parent->children.push(child);

        children[i] = nullptr;
    }

    for (size_t i = 0; i < zombies.size(); i++) {
        auto zombie = zombies[i];
        if (zombie == nullptr) continue;

        zombie->notify_status->clear();
        zombie->notify_status->add(parent->waitq);

        zombie->parent = parent;
        zombie->ppid = parent->ppid;
        parent->zombies.push(zombie);

        zombies[i] = nullptr;
    }

    parent->children[parent->find_child(this)] = nullptr;
    parent->zombies.push_back(this);

    if (group->leader_pid == this->pid) {
        group->remove_process(this);
        if (group->process_count > 0) {
            group->sess->remove_group(group);
            frg::destruct(memory::mm::heap, group);
        } else {
            bool is_orphan = true;
            for (size_t i = 0; i < group->procs.size(); i++) {
                sched::process *proc = group->procs[i];
                if (proc == nullptr) continue;
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
            if (group == nullptr) continue;

            group->sess = nullptr;
            for (size_t j = 0; j < group->procs.size(); j++) {
                auto process = group->procs[j];
                if (process == nullptr) continue;

                process->sess = nullptr;
            }
        }

        sess->groups.clear();
        frg::destruct(memory::mm::heap, sess);
    }

    status = WEXITED_CONSTRUCT(exit_code) | STATUS_CHANGED;
    notify_status->arise(main_thread);

    sched_lock.irq_release();
}

void sched::process::suspend() {
    for (size_t i = 0; i < threads.size(); i++) {
        auto task = threads[i];
        if (task == nullptr) continue;

        task->stop();
    }

    status = WSTOPPED_CONSTRUCT | STATUS_CHANGED;
    signal::send_process(nullptr, parent, SIGCHLD);
    notify_status->arise(main_thread);
}

void sched::process::cont() {
    for (size_t i = 0; i < threads.size(); i++) {
        auto task = threads[i];
        if (task == nullptr) continue;

        task->cont();
    }

    status = WCONTINUED_CONSTRUCT | STATUS_CHANGED;
    signal::send_process(nullptr, parent, SIGCHLD);
    notify_status->arise(main_thread);
}

int64_t sched::thread::start() {
    sched_lock.irq_acquire();

    threads.push_back(this);
    tid_t tid = threads.size() - 1;
    this->tid = tid;

    if (this->proc && WIFSTOPPED(this->proc->status)) {
        this->proc->status = WCONTINUED_CONSTRUCT | STATUS_CHANGED;
    }

    sched_lock.irq_release();

    return tid;
}

void sched::thread::stop() {
    sched_lock.irq_acquire();

    this->state = thread::BLOCKED;
    if (this->cpu != -1) {
        sched_lock.irq_release();

        arch::stop_thread(this);

        sched_lock.irq_acquire();
    }

    sched_lock.irq_release();
}

void sched::thread::cont() {
    sched_lock.irq_acquire();
    this->state = thread::READY;
    sched_lock.irq_release();
}

int64_t sched::thread::kill() {
    sched_lock.irq_acquire();

    this->state = thread::DEAD;
    if (this->cpu != -1) {
        sched_lock.irq_release();

        arch::stop_thread(this);

        sched_lock.irq_acquire();
    }

    threads[tid] = (sched::thread *) 0;
    sched_lock.irq_release();

    return this->tid;
}


void sched::process::add_thread(thread *task) {
    sched_lock.irq_acquire();

    task->proc = this;
    task->pid = this->pid;
    this->threads.push(task);

    sched_lock.irq_release();
}

size_t sched::process::find_child(sched::process *proc) {
    for (size_t i = 0; i < children.size(); i++) {
        if (children[i] && (proc->pid == children[i]->pid)) {
            return i;
        }
    }

    return -1;
}

size_t sched::process::find_zombie(sched::process *proc) {
    for (size_t i = 0; i < zombies.size(); i++) {
        if (zombies[i] && (proc->pid == zombies[i]->pid)) {
            return i;
        }
    }

    return -1;
}

void reap_process(sched::process *zombie) {
    sched::sched_lock.irq_acquire();

    auto task = zombie->main_thread;
    sched::processes[zombie->pid] = nullptr;

    frg::destruct(memory::mm::heap, task->sig_ctx.waitq);
    frg::destruct(memory::mm::heap, task);
    frg::destruct(memory::mm::heap, zombie->waitq);
    frg::destruct(memory::mm::heap, zombie->notify_status);
    frg::destruct(memory::mm::heap, zombie);

    sched::sched_lock.irq_release();
}

frg::tuple<int, pid_t> sched::process::waitpid(pid_t pid, thread *waiter, int options) {
    // Reap zombies first
    this->lock.irq_acquire();
    for (size_t i = 0; i < zombies.size(); i++) {
        process *zombie = zombies[i];
        if (zombie == nullptr) continue;
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

        zombies[i] = nullptr;

        uint8_t status = zombie->status;
        pid_t pid = zombie->pid;
        reap_process(zombie);

        this->lock.irq_release();
        return {status, pid};
    }

    if (options & WNOHANG) {
        this->lock.irq_release();
        return {0, 0};
    }

    process *proc = nullptr;
    pid_t return_pid = 0;
    int exit_status = 0;

    do_wait:
        while (true) {
            auto [thread, got_signal] = waitq->block(waiter);
            if (got_signal) {
                goto finish;
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

        if (!WIFSTOPPED(proc->status) && (WIFEXITED(proc->status) || WIFSIGNALED(proc->status))) {
            zombies[find_zombie(proc)] = nullptr;
            reap_process(proc);
        }
    finish:
        this->lock.irq_release();
        return {exit_status, return_pid};
}


int64_t sched::pick_task() {
    for (int64_t t = arch::get_tid() + 1; (uint64_t) t < threads.size(); t++) {
        auto task = threads[t];
        if (task) {
            if (task->cpu != -1) continue;
            if (task->state == thread::READY
                || task->dispatch_ready) {
                return task->tid;
            }
        }
    }

    for (int64_t t = 0; t < arch::get_tid() + 1; t++) {
        auto task = threads[t];
        if (task) {
            if (task->cpu != -1) continue;
            if (task->state == thread::READY
                || task->dispatch_ready) {
                return task->tid;
            }
        }
    }

    return -1;
}

void sched::swap_task(arch::irq_regs *r) {
    sched_lock.acquire();

    auto running_task = arch::get_thread();
    if (running_task) {
        arch::save_context(r, running_task);
    }

    int64_t next_tid = pick_task();

    if (next_tid == -1) {
        auto idle_task = threads[arch::get_idle()];

        if (arch::get_tid() != arch::get_idle() && arch::get_pid() != -1) {
            if (signal::process_signals(running_task->proc, running_task) == 0) {
                goto swap_regs;
            }
        }
 
        arch::set_process(nullptr);
        arch::set_thread(idle_task);

        running_task = idle_task;

        swap_regs:
        arch::rstor_context(running_task, r);
    } else {
        auto next_task = threads[next_tid];

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

    sched_lock.release();
}