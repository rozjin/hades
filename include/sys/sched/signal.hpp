#ifndef SIG_HPP
#define SIG_HPP

#include <arch/x86/types.hpp>
#include <cstddef>
#include <cstdint>
#include <sys/sched/event.hpp>
#include <sys/sched/time.hpp>
#include <util/types.hpp>
#include <arch/types.hpp>

#define SIG_ERR ((void*) -1)
#define SIG_DFL ((void*) 0)
#define SIG_IGN ((void*) 1)

#define SIGABRT 6
#define SIGFPE 8
#define SIGILL 4
#define SIGINT 2
#define SIGSEGV 11
#define SIGTERM 15
#define SIGPROF 27
#define SIGIO 29
#define SIGPWR 30
#define SIGRTMIN 35
#define SIGRTMAX 64

#define SIGHUP    1
#define SIGQUIT   3
#define SIGTRAP   5
#define SIGIOT    SIGABRT
#define SIGBUS    7
#define SIGKILL   9
#define SIGUSR1   10
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGWINCH  28
#define SIGPOLL   29
#define SIGSYS    31
#define SIGUNUSED SIGSYS
#define SIGCANCEL 32

#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

#define SA_NOCLDSTOP 1
#define SA_NOCLDWAIT 2
#define SA_SIGINFO 4
#define SA_ONSTACK 0x08000000
#define SA_RESTART 0x10000000
#define SA_NODEFER 0x40000000
#define SA_RESETHAND 0x80000000

#define SIGNAL_MAX 32

constexpr size_t SIGMASK(size_t sig) {
    return (1ULL << (sig - 1));
}

// #define SIGMASK(SIG) (1ull << ((SIG) - 1))

namespace sched {
    class process;
    class process_group;

    namespace signal {
        union sigval {
            int sival_int;
            void *sival_ptr;
        };

        struct siginfo {
            int si_signo;
            int si_code;
            int si_errno;
            pid_t si_pid;
            uid_t si_uid;
            void *si_addr;
            int si_status;
            sigval si_value;
        };

        struct sigaction {
            union {
                void (*sa_handler)(int signum);
                void (*sa_sigaction)(int signum, siginfo *siginfo, void *context);
            } handler;

            sigset_t sa_mask;
            int sa_flags;
            void (*sa_restorer)(void);
        };

        struct ucontext {
            uint64_t flags;
            ucontext *prev;
            size_t stack;
            
            arch::thread_ctx ctx;
            
            sigset_t signum;
        };

        struct signal;
        struct process_ctx;
        struct thread_ctx;

        struct signal {
            int signum;
        };

        struct process_ctx {
            sigset_t sigpending;
            util::spinlock lock;
        };

        struct thread_ctx {
            sigset_t sigmask;
            signal queue[SIGNAL_MAX];

            sigset_t sigpending;
            sigset_t sigdelivered;

            util::spinlock lock;
        };

        int do_sigaction(process *proc, thread *task, int sig, sigaction *act, sigaction *old);
        void do_sigpending(thread *task, sigset_t *set);
        int do_sigprocmask(thread *task, int how, sigset_t *set, sigset_t *oldset);
        int do_kill(pid_t pid, int sig);
        
        int wait_signal(thread *task, sigset_t sigmask, timespec *time);

        bool send_process(process *sender, process *target, int sig);
        bool send_group(process *sender, process_group *target, int sig);
        bool check_perms(process *sender, process *target);
        bool is_valid(int sig);

        int issue_signals(process *proc);
        
        int dispatch_signals(process *proc, thread *task);
        int process_signals(process *proc, thread *task);

        bool is_blocked(thread *task, int sig);
        bool is_ignored(process *proc, int sig);
    }
}

#endif