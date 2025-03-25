#ifndef ARCH_TYPES_HPP
#define ARCH_TYPES_HPP

#include <cstddef>
#include <util/types.hpp>
#include <sys/sched/time.hpp>

namespace vfs {
    struct fd;
}

namespace sched {
    struct process_env;
    class process;
    class thread;

    namespace signal {
        struct ucontext;
        struct signal;
        struct sigaction;
    }
}

namespace vmm {
    class vmm_ctx;
}

namespace arch {
    size_t copy_to_user(void *dst, const void *src, size_t length);
    size_t copy_from_user(void *dst, const void *src, size_t length);

    struct [[gnu::packed]] irq_regs;
    struct [[gnu::packed]] sched_regs;
    struct thread_ctx;

    irq_regs sched_to_irq(sched_regs *regs);
    sched_regs irq_to_sched(irq_regs *regs);

    bool is_user(sched_regs *regs);

    using irq_fn = void(*)(irq_regs *r);
    using irq_ext = void(*)(irq_regs *r, void *aux);

    void init_irqs();

    void irq_on();
    void irq_off();
    void stall_cpu();
    bool get_irq_state();

    size_t alloc_vector();
    void install_vector(size_t vector, irq_fn handler);
    void install_vector(size_t vector, irq_ext handler, void *aux = nullptr);
    void route_irq(size_t irq, size_t vector);

    void init_context(sched::thread *task, void (*main)(), uint64_t rsp, uint8_t privilege);
    void fork_context(sched::thread *original, sched::thread *task, irq_regs *r);

    void save_context(irq_regs *r, sched::thread *task);
    void rstor_context(sched::thread *task, irq_regs *r);

    void init_default_sigreturn(sched::thread *task, 
        sched::signal::signal *signal, sched::signal::ucontext *context);
    void init_user_sigreturn(sched::thread *task,
        sched::signal::signal *signal, sched::signal::sigaction *action,
        sched::signal::ucontext *context);

    void cleanup_vmm_ctx(sched::process *process);

    void init_sched();
    void tick();
    void stop_all_cpus();

    int do_futex(uintptr_t vaddr, int op, int expected, sched::timespec *timeout);

    void set_process(sched::process *process);
    void set_thread(sched::thread *task);

    void init_thread(sched::thread *task);
    void start_thread(sched::thread *task);
    void stop_thread(sched::thread *task);
    void kill_thread(sched::thread *task);

    tid_t get_idle_tid();
    sched::thread *get_idle();

    sched::process *get_process();
    sched::thread *get_thread();

    tid_t get_tid();
    pid_t get_pid();

    uint64_t get_cpu();

    pid_t allocate_pid();
    tid_t allocate_tid();

    void set_errno(int errno);
    int get_errno();

    void add_timer(sched::timer timer);
    void tick_clock(long nanos);
};

#endif
