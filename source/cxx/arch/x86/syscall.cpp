#include "util/misc.hpp"
#include <arch/x86/smp.hpp>
#include <arch/x86/types.hpp>
#include <arch/x86/syscall.hpp>
#include <cstdint>
#include <util/log/log.hpp>

extern void syscall_openat(arch::irq_regs *);
extern void syscall_accessat(arch::irq_regs *);
extern void syscall_pipe(arch::irq_regs *);
extern void syscall_lseek(arch::irq_regs *);
extern void syscall_dup2(arch::irq_regs *);
extern void syscall_close(arch::irq_regs *);
extern void syscall_read(arch::irq_regs *);
extern void syscall_write(arch::irq_regs *);
extern void syscall_ioctl(arch::irq_regs *);
extern void syscall_statat(arch::irq_regs *);
extern void syscall_mkdirat(arch::irq_regs *);
extern void syscall_renameat(arch::irq_regs *);
extern void syscall_linkat(arch::irq_regs *);
extern void syscall_unlinkat(arch::irq_regs *);
extern void syscall_readdir(arch::irq_regs *);
extern void syscall_fcntl(arch::irq_regs *);

extern void syscall_mmap(arch::irq_regs *);
extern void syscall_munmap(arch::irq_regs *);
extern void syscall_mprotect(arch::irq_regs *);

extern void syscall_exec(arch::irq_regs *);
extern void syscall_fork(arch::irq_regs *);
extern void syscall_exit(arch::irq_regs *);
extern void syscall_futex(arch::irq_regs *);
extern void syscall_waitpid(arch::irq_regs *);
extern void syscall_sleep(arch::irq_regs *);
extern void syscall_clock_gettime(arch::irq_regs *);
extern void syscall_clock_get(arch::irq_regs *);
extern void syscall_getpid(arch::irq_regs *);
extern void syscall_getppid(arch::irq_regs *);
extern void syscall_gettid(arch::irq_regs *);
extern void syscall_setpgid(arch::irq_regs *);
extern void syscall_getpgid(arch::irq_regs *);
extern void syscall_setsid(arch::irq_regs *);
extern void syscall_getsid(arch::irq_regs *);
extern void syscall_sigenter(arch::irq_regs *);
extern void syscall_sigreturn(arch::irq_regs *);
extern void syscall_sigaction(arch::irq_regs *);
extern void syscall_sigpending(arch::irq_regs *);
extern void syscall_sigprocmask(arch::irq_regs *);
extern void syscall_kill(arch::irq_regs *);
extern void syscall_pause(arch::irq_regs *);
extern void syscall_sigsuspend(arch::irq_regs *);
extern void syscall_getcwd(arch::irq_regs *);
extern void syscall_chdir(arch::irq_regs *);

extern void syscall_getuid(arch::irq_regs *);
extern void syscall_setuid(arch::irq_regs *);
extern void syscall_geteuid(arch::irq_regs *);
extern void syscall_seteuid(arch::irq_regs *);
extern void syscall_getgid(arch::irq_regs *);
extern void syscall_setgid(arch::irq_regs *);
extern void syscall_getegid(arch::irq_regs *);
extern void syscall_setegid(arch::irq_regs *);

extern void syscall_sethostname(arch::irq_regs *);
extern void syscall_gethostname(arch::irq_regs *);
extern void syscall_poll(arch::irq_regs *);
extern void syscall_ppoll(arch::irq_regs *);

void syscall_set_fs_base(arch::irq_regs *r) {
    uint64_t addr = r->rdi;

    x86::get_thread()->ctx.reg.fs = addr;
    x86::set_user_fs(addr);
    r->rax = 0;
}

void syscall_get_fs_base(arch::irq_regs *r) {
    r->rax = x86::get_user_fs();
}

void syscall_set_gs_base(arch::irq_regs *r) {
    uint64_t addr = r->rdi;

    x86::get_thread()->ctx.reg.gs = addr;
    x86::set_user_gs(addr);
    r->rax = 0;
}

void syscall_get_gs_base(arch::irq_regs *r) {
    r->rax = x86::get_user_gs();
}

static log::subsystem logger = log::make_subsystem("USER");
void syscall_user_log(arch::irq_regs *r) {
    kmsg(logger, (char *) r->rdi);
    r->rax = 0;
}

static x86::syscall_handler syscalls_list[] = {
    syscall_openat,
    syscall_close,
    syscall_read,
    syscall_write,
    syscall_lseek,
    syscall_dup2,
    syscall_mmap,
    syscall_munmap,

    syscall_set_fs_base,
    syscall_set_gs_base,
    syscall_get_fs_base,
    syscall_get_gs_base,

    syscall_exit,
    syscall_getpid,
    syscall_gettid,
    syscall_getppid,

    syscall_fcntl,
    syscall_statat,
    syscall_ioctl,
    syscall_fork,
    syscall_exec,
    syscall_futex,
    syscall_waitpid,
    syscall_readdir,
    syscall_getcwd,
    syscall_chdir,
    nullptr, // TODO: faccesat
    syscall_pipe,
    nullptr, // TODO: umask,
    nullptr, // TODO: uid,
    nullptr, // TODO: euid,
    nullptr, // TODO: suid,
    nullptr, // TODO: seuid,
    nullptr, // TODO: gid,
    nullptr, // TDOO: egid,
    nullptr, // TODO: sgid,
    nullptr, // TODO: segid,

    nullptr, // TODO: chmod,
    nullptr, // TODO: chmodat,

    syscall_sigenter,
    syscall_sigaction,
    syscall_sigpending,
    syscall_sigprocmask,
    syscall_kill,
    syscall_setpgid,
    syscall_getpgid,
    syscall_setsid,
    syscall_getsid,
    syscall_pause,
    syscall_sigsuspend,
    syscall_sigreturn,

    syscall_unlinkat,
    syscall_renameat,
    // TODO: symlinkat, readlinkat
    syscall_mkdirat,
    syscall_sleep,
    syscall_clock_gettime,
    syscall_clock_get,
    syscall_linkat,

    syscall_user_log,

    syscall_getuid,
    syscall_setuid,
    syscall_geteuid,
    syscall_seteuid,
    syscall_getgid,
    syscall_setgid,
    syscall_getegid,
    syscall_setegid,

    syscall_mprotect,

    syscall_sethostname,
    syscall_gethostname,

    syscall_accessat,
    syscall_poll,
    syscall_ppoll
};

extern "C" {
    void syscall_handler(arch::irq_regs *r) {
        uint64_t syscall_num = r->rax;

        if (syscall_num >= util::lengthof(syscalls_list)) {
            r->rax = uint64_t(-1);
            x86::set_errno(ENOSYS);
            return;
        }

        // TODO: signal queue
        auto thread = x86::get_thread();
        thread->in_syscall = true;

        if (syscalls_list[syscall_num] != nullptr) {
            syscalls_list[syscall_num](r);
        }

        if (r->rax >= 0) {
            x86::set_errno(0);
        }

        thread->in_syscall = false;
    }
}